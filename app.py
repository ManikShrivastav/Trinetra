"""
FastAPI Backend for Trinetra Security Scanner
Integrates frontend with orchestrator and worker modules.
"""

import csv
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Dict, List, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Request, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Import orchestrator functions
import main_orchestrator

# Import authentication module
from data_base import auth_db

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for maximum verbosity
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
)
logger = logging.getLogger(__name__)
logger.propagate = False

# Initialize FastAPI app
app = FastAPI(title="Trinetra Security Scanner API", version="1.0.0")

# Configure CORS to allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security scheme for JWT Bearer tokens
security = HTTPBearer()

# Global scan tracking
active_scans: Dict[str, Dict] = {}
SCANS_DIR = Path("scans")
SCANS_DIR.mkdir(exist_ok=True)
REPORTS_DIR = SCANS_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Request models
class LoginRequest(BaseModel):
    userid: str
    password: str
    role_id: int


class LoginResponse(BaseModel):
    token: str
    expires_in: int
    token_type: str
    user: Dict


class ScanRequest(BaseModel):
    targets: List[str]
    workers: List[str] = ["nmap", "nikto", "nuclei"]


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: Dict[str, str]
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str


# Helper functions
def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def verify_token_dependency(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Dependency to verify JWT token for protected routes.
    Extracts token from Authorization header and validates it.
    
    Args:
        credentials: HTTP Authorization credentials
    
    Returns:
        Token payload if valid
    
    Raises:
        HTTPException: If token is invalid or expired
    """
    token = credentials.credentials
    
    # Verify token using auth_db module
    payload = auth_db.verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token"
        )
    
    return payload


async def check_auth_for_page(request: Request):
    """
    Check authentication for HTML page requests.
    Looks for JWT token in Authorization header or localStorage (via query param).
    
    Returns:
        bool: True if authenticated, False otherwise
    """
    # Try to get token from Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.replace('Bearer ', '')
        payload = auth_db.verify_token(token)
        if payload:
            return True
    
    # For HTML pages, we rely on client-side auth.js to check localStorage
    # and redirect. But we can also check a cookie if set.
    token_cookie = request.cookies.get('trinetra_auth_token')
    if token_cookie:
        try:
            import json
            token_data = json.loads(token_cookie)
            token = token_data.get('token')
            payload = auth_db.verify_token(token)
            if payload:
                return True
        except:
            pass
    
    return False


def calculate_severity(cvss_score: float) -> str:
    """
    Calculate severity level from CVSS score.
    
    Args:
        cvss_score: CVSS score (0.0-10.0)
    
    Returns:
        Severity level: 'low', 'medium', 'high', or 'critical'
    """
    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score > 0.0:
        return 'low'
    else:
        return 'unknown'


def get_cvss_score(cve_data: Dict) -> float:
    """
    Extract CVSS score from CVE data, preferring v3 over v2.
    
    Args:
        cve_data: CVE data dictionary from NVD
    
    Returns:
        CVSS score as float
    """
    # Try CVSS v3 first
    if 'cvss_v3_score' in cve_data and cve_data['cvss_v3_score']:
        try:
            return float(cve_data['cvss_v3_score'])
        except (ValueError, TypeError):
            pass
    
    # Fall back to CVSS v2
    if 'cvss_v2_score' in cve_data and cve_data['cvss_v2_score']:
        try:
            return float(cve_data['cvss_v2_score'])
        except (ValueError, TypeError):
            pass
    
    return 0.0


def load_enriched_data(scan_id: str) -> List[Dict]:
    """
    Load enriched vulnerability data for a SPECIFIC scan only.
    Filters enriched files by matching targets and timestamps from scan result.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        List of vulnerability dictionaries for THIS scan only
    """
    vulnerabilities = []
    
    # First, load the scan result to get targets and timestamps
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    if not result_file.exists():
        logger.warning(f"Scan result file not found: {result_file}")
        return []
    
    with open(result_file, 'r') as f:
        scan_data = json.load(f)
    
    # Extract target-timestamp pairs for this scan
    scan_targets = {}
    for result in scan_data.get('results', []):
        target = result.get('target')
        timestamp = result.get('timestamp')
        if target and timestamp:
            scan_targets[target] = timestamp
    
    if not scan_targets:
        logger.warning(f"No targets found in scan {scan_id}")
        return []
    
    logger.info(f"Loading enriched data for scan {scan_id}: {len(scan_targets)} targets")
    
    # Check for enriched files matching THIS scan's targets and timestamps
    scan_dirs = ['nmap', 'nikto', 'nuclei']
    
    for scan_type in scan_dirs:
        enriched_dir = SCANS_DIR / scan_type / 'enriched'
        if not enriched_dir.exists():
            continue
        
        # Find enriched files matching our scan's targets and timestamps
        for target, timestamp in scan_targets.items():
            # Match pattern: files with this timestamp
            pattern = f"*{timestamp}*.json"
            matching_files = list(enriched_dir.glob(pattern))
            
            for enriched_file in matching_files:
                try:
                    with open(enriched_file, 'r') as f:
                        data = json.load(f)
                    
                    # Double-check this file is for our target and timestamp
                    file_target = data.get('target', '')
                    file_timestamp = data.get('timestamp', '')
                    
                    # Skip if timestamp doesn't match
                    if file_timestamp != timestamp:
                        continue
                    
                    # Parse enriched data structure - ALL SCANNERS USE "findings" ARRAY
                    if 'findings' in data and isinstance(data['findings'], list):
                        for finding in data['findings']:
                            # Extract CVSS score for severity calculation
                            cvss_v3 = finding.get('cvss_v3')
                            cvss_v2 = finding.get('cvss_v2')
                            cvss_score = cvss_v3 if cvss_v3 is not None else cvss_v2
                            
                            # Get CVE ID (may be in 'cve' or 'cve_id' field)
                            cve_id = finding.get('cve') or finding.get('cve_id', 'N/A')
                            
                            # Format references (may be list or string)
                            references = finding.get('references', [])
                            if isinstance(references, list):
                                references_str = ', '.join(references[:3])  # First 3 refs
                            else:
                                references_str = str(references)
                            
                            vulnerabilities.append({
                                'cve_id': cve_id,
                                'description': finding.get('description', finding.get('title', 'N/A')),
                                'cvss_v2': cvss_v2 if cvss_v2 is not None else 'N/A',
                                'cvss_v3': cvss_v3 if cvss_v3 is not None else 'N/A',
                                'severity': finding.get('risk', calculate_severity(cvss_score)),
                                'recommendation': references_str if references_str else 'See NVD for details',
                                'source_tool': scan_type.capitalize(),
                                'target': data.get('target', 'N/A'),
                                'timestamp': data.get('timestamp', 'N/A'),
                                'affected_hosts': finding.get('affected_hosts', []),
                                'scan_id': scan_id  # Add scan_id for tracking
                            })
                
                except Exception as e:
                    logger.error(f"Error loading enriched file {enriched_file}: {e}")
                    continue
    
    logger.info(f"Loaded {len(vulnerabilities)} vulnerabilities for scan {scan_id}")
    return vulnerabilities


def deduplicate_vulnerabilities(vulnerabilities: List[Dict]) -> List[Dict]:
    """
    Remove duplicate vulnerabilities based on CVE ID + target + source tool.
    Keeps first occurrence of each unique vulnerability.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        Deduplicated list
    """
    seen = set()
    unique_vulns = []
    
    for vuln in vulnerabilities:
        # Create unique key: CVE + target + source tool
        # This handles case where multiple scanners find same CVE
        key = (
            vuln.get('cve_id'),
            vuln.get('target'),
            vuln.get('source_tool')
        )
        
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)
    
    if len(vulnerabilities) != len(unique_vulns):
        logger.info(f"Deduplicated {len(vulnerabilities)} → {len(unique_vulns)} vulnerabilities")
    
    return unique_vulns


def generate_csv_from_scan(scan_id: str) -> str:
    """
    Generate CSV file from scan results with enriched data.
    First checks if scan-specific CSV already exists (generated by orchestrator).
    If not, falls back to legacy enriched data method.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        Path to generated CSV file
    """
    # Check if scan-specific CSV already exists (generated by orchestrator)
    orchestrator_csv = REPORTS_DIR / f"{scan_id}.csv"
    if orchestrator_csv.exists():
        logger.info(f"Using existing CSV for scan {scan_id}: {orchestrator_csv}")
        return str(orchestrator_csv)
    
    # Fallback: Generate from enriched data (legacy method)
    logger.info(f"Generating CSV from enriched data for scan {scan_id}")
    vulnerabilities = load_enriched_data(scan_id)
    
    # Create CSV file in reports directory
    csv_path = REPORTS_DIR / f"{scan_id}.csv"
    
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['CVE ID', 'Description', 'CVSS v2', 'CVSS v3', 'Severity', 
                      'Recommendation', 'Source Tool', 'Target', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for vuln in vulnerabilities:
            writer.writerow({
                'CVE ID': vuln['cve_id'],
                'Description': vuln['description'],
                'CVSS v2': vuln['cvss_v2'],
                'CVSS v3': vuln['cvss_v3'],
                'Severity': vuln['severity'].upper(),
                'Recommendation': vuln['recommendation'],
                'Source Tool': vuln['source_tool'],
                'Target': vuln['target'],
                'Timestamp': vuln['timestamp']
            })
    
    return str(csv_path)


def calculate_risk_summary(vulnerabilities: List[Dict]) -> Dict:
    """
    Calculate risk summary from vulnerability list.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
    
    Returns:
        Risk summary dictionary
    """
    if not vulnerabilities:
        return {
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'highest_severity': 'none',
            'average_cvss': 0.0
        }
    
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    cvss_scores = []
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'unknown').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        
        # Get CVSS score
        cvss_v3 = vuln.get('cvss_v3', 'N/A')
        cvss_v2 = vuln.get('cvss_v2', 'N/A')
        
        try:
            if cvss_v3 != 'N/A':
                cvss_scores.append(float(cvss_v3))
            elif cvss_v2 != 'N/A':
                cvss_scores.append(float(cvss_v2))
        except (ValueError, TypeError):
            pass
    
    # Determine highest severity
    if severity_counts['critical'] > 0:
        highest_severity = 'critical'
    elif severity_counts['high'] > 0:
        highest_severity = 'high'
    elif severity_counts['medium'] > 0:
        highest_severity = 'medium'
    elif severity_counts['low'] > 0:
        highest_severity = 'low'
    else:
        highest_severity = 'none'
    
    # Calculate average CVSS
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
    
    return {
        'total_vulnerabilities': len(vulnerabilities),
        'critical_count': severity_counts['critical'],
        'high_count': severity_counts['high'],
        'medium_count': severity_counts['medium'],
        'low_count': severity_counts['low'],
        'highest_severity': highest_severity,
        'average_cvss': round(avg_cvss, 2)
    }


def update_session_history(history: List[Dict]):
    """
    Update session history manifest file.
    
    Args:
        history: List of scan history dictionaries
    """
    manifest_file = SCANS_DIR / "session_history.json"
    
    try:
        with open(manifest_file, 'w') as f:
            json.dump({
                'last_updated': utc_timestamp(),
                'total_scans': len(history),
                'scans': history
            }, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to update session history: {e}")


def save_scan_status(scan_id: str, status: str, progress: Dict = None):
    """Save scan status to file."""
    status_file = SCANS_DIR / f"scan_{scan_id}_status.json"
    data = {
        "scan_id": scan_id,
        "status": status,
        "progress": progress or {},
        "updated_at": utc_timestamp()
    }
    
    # Update in-memory tracking
    if scan_id in active_scans:
        active_scans[scan_id]["status"] = status
        if progress:
            active_scans[scan_id]["progress"] = progress
        active_scans[scan_id]["updated_at"] = data["updated_at"]
    
    with open(status_file, 'w') as f:
        json.dump(data, f, indent=2)


def run_scan_background(scan_id: str, targets: List[str], worker_names: List[str]):
    """
    Background task to run the orchestrator scan.
    Updates status as scan progresses with accurate percentages.
    """
    try:
        logger.info(f"[{scan_id}] Starting background scan for {len(targets)} target(s)")
        
        # Initialize progress tracking with percentages
        total_tasks = len(targets) * len(worker_names)
        completed_tasks = 0
        
        progress = {
            "workers": {worker: {"status": "queued", "progress": 0} for worker in worker_names},
            "overall": 0,
            "completed_tasks": 0,
            "total_tasks": total_tasks
        }
        save_scan_status(scan_id, "running", progress)
        
        # Parse workers
        workers = main_orchestrator.parse_workers(",".join(worker_names))
        
        # Create a callback to update progress
        def update_worker_progress(worker_name: str, target: str, status: str):
            nonlocal completed_tasks
            
            if status == "running":
                progress["workers"][worker_name]["status"] = "running"
                progress["workers"][worker_name]["progress"] = 50
            elif status in ["done", "failed"]:
                completed_tasks += 1
                progress["workers"][worker_name]["status"] = status
                progress["workers"][worker_name]["progress"] = 100
                progress["completed_tasks"] = completed_tasks
                progress["overall"] = int((completed_tasks / total_tasks) * 100)
            
            save_scan_status(scan_id, "running", progress)
            logger.info(f"[{scan_id}] Progress: {progress['overall']}% ({completed_tasks}/{total_tasks})")
        
        # Mark all workers as running initially
        for worker in worker_names:
            progress["workers"][worker]["status"] = "running"
            progress["workers"][worker]["progress"] = 0
        save_scan_status(scan_id, "running", progress)
        
        # Run orchestrator with progress tracking
        results = main_orchestrator.run_orchestrator(
            targets=targets,
            workers=workers,
            max_target_workers=1,
            progress_callback=update_worker_progress
        )
        
        # Mark all as done with 100% progress
        progress["overall"] = 100
        progress["completed_tasks"] = total_tasks
        for worker in worker_names:
            progress["workers"][worker]["status"] = "done"
            progress["workers"][worker]["progress"] = 100
        
        # Save results
        result_file = SCANS_DIR / f"scan_{scan_id}.json"
        summary = {
            "scan_id": scan_id,
            "scan_timestamp": utc_timestamp(),
            "total_targets": len(results),
            "results": results
        }
        
        with open(result_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Generate CSV file for this scan
        try:
            csv_path = main_orchestrator.generate_scan_csv(scan_id, targets)
            logger.info(f"[{scan_id}] CSV report generated: {csv_path}")
            active_scans[scan_id]["csv_path"] = csv_path
        except Exception as csv_error:
            logger.error(f"[{scan_id}] Failed to generate CSV: {csv_error}")
            # Don't fail the entire scan if CSV generation fails
        
        # Update status to completed
        active_scans[scan_id]["result_path"] = str(result_file)
        active_scans[scan_id]["end_time"] = utc_timestamp()
        save_scan_status(scan_id, "completed", progress)
        
        logger.info(f"[{scan_id}] Scan completed successfully")
        
    except Exception as e:
        logger.exception(f"[{scan_id}] Scan failed: {e}")
        progress = {
            "workers": {worker: {"status": "error", "progress": 0} for worker in worker_names},
            "overall": 0,
            "error": str(e)
        }
        save_scan_status(scan_id, "failed", progress)
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Authenticate user and return JWT token.
    
    Request body:
        - userid: User ID (e.g., "admin_user", "test_user")
        - password: User password
        - role_id: Role ID (1=Admin, 2=User, 3=Guest)
    
    Returns:
        JWT token with 1-hour expiry and user information
    
    Mock Users:
        - admin_user / password123 / Role: Admin (role_id=1)
        - test_user / password123 / Role: User (role_id=2)
        - guest_user / guest123 / Role: Guest (role_id=3)
    """
    logger.info(f"Login attempt for user: {request.userid}")
    
    # Authenticate user
    user = auth_db.authenticate_user(
        userid=request.userid,
        password=request.password,
        role_id=request.role_id
    )
    
    if not user:
        logger.warning(f"Failed login attempt for user: {request.userid}")
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials or role mismatch"
        )
    
    # Create JWT token
    token_data = auth_db.create_access_token(user)
    
    logger.info(f"Successful login for user: {request.userid} (role: {user['role']})")
    
    return LoginResponse(**token_data)


@app.post("/api/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Logout user by blacklisting their JWT token.
    
    Note: With JWT, logout is primarily handled client-side by deleting the token.
    This endpoint adds the token to a blacklist to prevent reuse (optional).
    In production, use Redis with TTL equal to token expiry for efficient blacklisting.
    """
    token = credentials.credentials
    
    # Add token to blacklist
    auth_db.blacklist_token(token)
    
    logger.info("User logged out successfully")
    
    return {"message": "Logout successful"}


@app.get("/api/auth/verify")
async def verify_token(payload: Dict = Depends(verify_token_dependency)):
    """
    Verify JWT token validity.
    Protected route that returns user info if token is valid.
    
    Used by frontend to:
    - Check if user is still authenticated on page load
    - Validate token before making protected API calls
    - Get current user information
    """
    return {
        "valid": True,
        "user": {
            "userid": payload.get("userid"),
            "role": payload.get("role"),
            "role_id": payload.get("role_id")
        }
    }


@app.get("/api/dashboard")
async def get_dashboard(payload: Dict = Depends(verify_token_dependency)):
    """
    Protected dashboard endpoint.
    Returns dashboard data only if valid JWT token is provided.
    
    This demonstrates a protected route that requires authentication.
    """
    return {
        "message": "Access granted to secure dashboard",
        "user": {
            "userid": payload.get("userid"),
            "role": payload.get("role"),
            "role_id": payload.get("role_id"),
            "token_issued_at": datetime.fromtimestamp(payload.get("iat").timestamp()).isoformat()
        },
        "system_status": "operational",
        "timestamp": utc_timestamp()
    }


# ============================================================================
# SCAN API ROUTES (Protected with JWT Authentication)
# ============================================================================

@app.post("/api/scan/start", response_model=ScanStartResponse)
async def start_scan(request: ScanRequest, payload: Dict = Depends(verify_token_dependency)):
    """
    Start a new security scan (Protected Route - Requires JWT).
    Returns a scan_id that can be used to track progress.
    """
    if not request.targets:
        raise HTTPException(status_code=400, detail="No targets provided")
    
    if not request.workers:
        raise HTTPException(status_code=400, detail="No workers specified")
    
    # Validate workers
    valid_workers = ["nmap", "nikto", "nuclei"]
    for worker in request.workers:
        if worker.lower() not in valid_workers:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid worker: {worker}. Valid workers: {valid_workers}"
            )
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "started",
        "targets": request.targets,
        "workers": request.workers,
        "start_time": utc_timestamp(),
        "end_time": None,
        "result_path": None,
        "progress": {worker: "queued" for worker in request.workers}
    }
    
    # Save initial status
    save_scan_status(scan_id, "started")
    
    # Start scan in background thread
    thread = Thread(
        target=run_scan_background,
        args=(scan_id, request.targets, request.workers),
        daemon=True
    )
    thread.start()
    
    logger.info(f"Started scan {scan_id} for targets: {request.targets}")
    
    return ScanStartResponse(scan_id=scan_id, status="started")


@app.get("/api/scan/status/{scan_id}")
async def get_scan_status(scan_id: str, payload: Dict = Depends(verify_token_dependency)):
    """
    Get the current status of a scan (Protected Route - Requires JWT).
    """
    # Check in-memory first
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        return {
            "scan_id": scan_id,
            "status": scan["status"],
            "progress": scan.get("progress", {}),
            "start_time": scan.get("start_time"),
            "end_time": scan.get("end_time")
        }
    
    # Check for status file
    status_file = SCANS_DIR / f"scan_{scan_id}_status.json"
    if status_file.exists():
        with open(status_file, 'r') as f:
            data = json.load(f)
            return data
    
    raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")


@app.get("/api/scan/results/{scan_id}")
async def get_scan_results(scan_id: str, payload: Dict = Depends(verify_token_dependency)):
    """
    Get the results of a completed scan with enriched vulnerability data (Protected Route - Requires JWT).
    Returns ONLY vulnerabilities from THIS specific scan (not all historical scans).
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Results for scan {scan_id} not found. Scan may still be running or failed."
        )
    
    with open(result_file, 'r') as f:
        results = json.load(f)
    
    # Load enriched vulnerability data (now properly filtered by scan timestamp)
    vulnerabilities = load_enriched_data(scan_id)
    
    # Deduplicate in case multiple scanners find same CVE
    vulnerabilities = deduplicate_vulnerabilities(vulnerabilities)
    
    # Calculate risk summary
    risk_summary = calculate_risk_summary(vulnerabilities)
    
    # Add enriched data to results
    results['scan_id'] = scan_id  # Add scan_id for frontend
    results['vulnerabilities'] = vulnerabilities
    results['risk_summary'] = risk_summary
    
    logger.info(f"Returning {len(vulnerabilities)} unique vulnerabilities for scan {scan_id}")
    
    return results


@app.get("/api/export/csv/{scan_id}")
async def export_csv(scan_id: str, payload: Dict = Depends(verify_token_dependency)):
    """
    Export scan results as CSV file with deduplicated, scan-specific data (Protected Route - Requires JWT).
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )
    
    try:
        # Load properly filtered and deduplicated vulnerabilities
        vulnerabilities = load_enriched_data(scan_id)
        vulnerabilities = deduplicate_vulnerabilities(vulnerabilities)
        
        # Generate CSV from clean data
        csv_path = REPORTS_DIR / f"{scan_id}.csv"
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['CVE ID', 'Description', 'CVSS v2', 'CVSS v3', 'Severity', 
                          'Recommendation', 'Source Tool', 'Target', 'Timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    'CVE ID': vuln['cve_id'],
                    'Description': vuln['description'][:200] if len(vuln['description']) > 200 else vuln['description'],
                    'CVSS v2': vuln['cvss_v2'],
                    'CVSS v3': vuln['cvss_v3'],
                    'Severity': vuln['severity'].upper() if vuln['severity'] else 'UNKNOWN',
                    'Recommendation': vuln['recommendation'][:200] if len(vuln['recommendation']) > 200 else vuln['recommendation'],
                    'Source Tool': vuln['source_tool'],
                    'Target': vuln['target'],
                    'Timestamp': vuln['timestamp']
                })
        
        if not csv_path.exists():
            raise HTTPException(status_code=500, detail="Failed to generate CSV file")
        
        logger.info(f"Generated CSV with {len(vulnerabilities)} vulnerabilities for scan {scan_id}")
        
        return FileResponse(
            path=str(csv_path),
            filename=f"scan_{scan_id}_results.csv",
            media_type="text/csv",
            headers={
                'Content-Disposition': f'attachment; filename="scan_{scan_id}_results.csv"'
            }
        )
    except Exception as e:
        logger.exception(f"Error exporting CSV for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export CSV: {str(e)}"
        )


@app.get("/api/scans/history")
async def get_scan_history(payload: Dict = Depends(verify_token_dependency)):
    """
    Get a list of all previous scans with risk summaries (Protected Route - Requires JWT).
    """
    history = []
    
    # Look for all scan result files
    for result_file in SCANS_DIR.glob("scan_*.json"):
        # Skip status files and CSV result files
        if "_status" in result_file.name or "_results" in result_file.name:
            continue
        
        try:
            with open(result_file, 'r') as f:
                data = json.load(f)
                
                # Extract scan_id from filename
                scan_id = result_file.stem.replace("scan_", "")
                
                # Get target(s)
                targets = []
                if "results" in data:
                    targets = [r.get("target", "unknown") for r in data["results"]]
                
                # Get status
                status_file = SCANS_DIR / f"scan_{scan_id}_status.json"
                status = "completed"
                workers_used = []
                if status_file.exists():
                    with open(status_file, 'r') as sf:
                        status_data = json.load(sf)
                        status = status_data.get("status", "completed")
                        # Extract workers from progress data
                        progress = status_data.get("progress", {})
                        if isinstance(progress, dict) and "workers" in progress:
                            workers_used = list(progress["workers"].keys())
                
                # Load vulnerability data and calculate risk summary (deduplicated)
                vulnerabilities = load_enriched_data(scan_id)
                vulnerabilities = deduplicate_vulnerabilities(vulnerabilities)
                risk_summary = calculate_risk_summary(vulnerabilities)
                
                history.append({
                    "scan_id": scan_id,
                    "target": ", ".join(targets) if targets else "unknown",
                    "targets": targets,
                    "status": status,
                    "timestamp": data.get("scan_timestamp", "unknown"),
                    "total_targets": data.get("total_targets", len(targets)),
                    "workers": workers_used if workers_used else ["nmap", "nikto", "nuclei"],
                    "risk_summary": risk_summary
                })
        except Exception as e:
            logger.exception(f"Error reading scan file {result_file}: {e}")
            continue
    
    # Sort by timestamp (newest first)
    history.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Update session history manifest
    update_session_history(history)
    
    return history


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str, payload: Dict = Depends(verify_token_dependency)):
    """
    Get detailed scan information for details.js page (Protected Route - Requires JWT).
    Returns scan data formatted for the details page with DEDUPLICATED findings.
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )
    
    try:
        with open(result_file, 'r') as f:
            data = json.load(f)
        
        # Load enriched vulnerability data (scan-specific only)
        vulnerabilities = load_enriched_data(scan_id)
        
        # Deduplicate vulnerabilities
        vulnerabilities = deduplicate_vulnerabilities(vulnerabilities)
        
        # Calculate risk summary
        risk_summary = calculate_risk_summary(vulnerabilities)
        
        # Get target(s)
        targets = []
        if "results" in data:
            targets = [r.get("target", "unknown") for r in data["results"]]
        target = ", ".join(targets) if targets else "unknown"
        
        # Format vulnerabilities as "findings" for details.js compatibility
        findings = []
        for vuln in vulnerabilities:
            findings.append({
                "cve": vuln.get("cve_id", "N/A"),
                "title": vuln.get("description", "N/A"),
                "description": vuln.get("description", "N/A"),
                "severity": vuln.get("severity", "unknown"),
                "cvss_v3": vuln.get("cvss_v3", "N/A"),
                "cvss_v2": vuln.get("cvss_v2", "N/A"),
                "source_tool": vuln.get("source_tool", "Unknown"),
                "recommendation": vuln.get("recommendation", "N/A"),
                "target": vuln.get("target", "N/A"),
                "timestamp": vuln.get("timestamp", "N/A")
            })
        
        # Return formatted response for details.js
        return {
            "scan_id": scan_id,
            "target": target,
            "timestamp": data.get("scan_timestamp", "unknown"),
            "total_cves": risk_summary["total_vulnerabilities"],
            "critical_count": risk_summary["critical_count"],
            "high_count": risk_summary["high_count"],
            "medium_count": risk_summary["medium_count"],
            "low_count": risk_summary["low_count"],
            "unknown_count": 0,  # Can be calculated if needed
            "findings": findings,
            "risk_summary": risk_summary
        }
    
    except Exception as e:
        logger.exception(f"Error loading scan details for {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load scan details: {str(e)}"
        )


@app.get("/api/scans/{scan_id}/download-csv")
async def download_scan_csv(scan_id: str, payload: Dict = Depends(verify_token_dependency)):
    """
    Download CSV report for a specific scan (Protected Route - Requires JWT).
    Used by details.js page.
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} not found"
        )
    
    try:
        csv_path = generate_csv_from_scan(scan_id)
        
        if not os.path.exists(csv_path):
            raise HTTPException(
                status_code=500,
                detail="Failed to generate CSV file"
            )
        
        return FileResponse(
            path=csv_path,
            filename=f"scan_results_{scan_id}.csv",
            media_type="text/csv"
        )
    except Exception as e:
        logger.exception(f"Error downloading CSV for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to download CSV: {str(e)}"
        )


@app.get("/api/system/info")
async def get_system_info(payload: Dict = Depends(verify_token_dependency)):
    """
    Get system information and available workers (Protected Route - Requires JWT).
    """
    # Get last scan time
    last_scan_time = None
    scan_files = list(SCANS_DIR.glob("scan_*.json"))
    if scan_files:
        latest = max(scan_files, key=lambda p: p.stat().st_mtime)
        last_scan_time = datetime.fromtimestamp(latest.stat().st_mtime).isoformat()
    
    return {
        "available_workers": ["nmap", "nikto", "nuclei"],
        "active_scans": len([s for s in active_scans.values() if s["status"] == "running"]),
        "total_scans": len(list(SCANS_DIR.glob("scan_*.json"))) // 2,  # Divide by 2 (status + result files)
        "last_scan_time": last_scan_time,
        "version": "1.0.0"
    }


# Serve static files (frontend)
# Mount static directories
app.mount("/css", StaticFiles(directory="css"), name="css")
app.mount("/js", StaticFiles(directory="js"), name="js")


# Serve HTML pages
@app.get("/")
async def serve_index(request: Request):
    """
    Serve dashboard/index page.
    Client-side auth.js will check localStorage for valid JWT and redirect if needed.
    """
    return FileResponse("index.html")


@app.get("/index")
async def serve_index_route(request: Request):
    """
    Serve dashboard at /index route.
    Redirect to login if no valid token in cookies.
    """
    return FileResponse("index.html")


@app.get("/index.html")
async def serve_index_html(request: Request):
    """
    Serve dashboard at /index.html route.
    Client-side auth.js will check localStorage for valid JWT and redirect if needed.
    """
    return FileResponse("index.html")


@app.get("/login")
async def serve_login_route():
    """Serve login page at /login route."""
    return FileResponse("login.html")


@app.get("/login.html")
async def serve_login():
    """Serve login page at /login.html route."""
    return FileResponse("login.html")


@app.get("/scan.html")
async def serve_scan(request: Request):
    """
    Serve scan page (protected).
    Client-side auth.js will check localStorage for valid JWT and redirect if needed.
    """
    return FileResponse("scan.html")


@app.get("/past-scans.html")
async def serve_past_scans(request: Request):
    """
    Serve past scans page (protected).
    Client-side auth.js will check localStorage for valid JWT and redirect if needed.
    """
    return FileResponse("past-scans.html")


@app.get("/bot.html")
async def serve_bot(request: Request):
    """
    Serve bot page (protected).
    Client-side auth.js will check localStorage for valid JWT and redirect if needed.
    """
    return FileResponse("bot.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
