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

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

# Import orchestrator functions
import main_orchestrator

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for maximum verbosity
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s [in %(pathname)s:%(lineno)d]'
)
logger = logging.getLogger(__name__)
logger.propagate = False

# Initialize FastAPI app
app = FastAPI(title="Trinetra Security Scanner API", version="1.0.0")

# Global scan tracking
active_scans: Dict[str, Dict] = {}
SCANS_DIR = Path("scans")
SCANS_DIR.mkdir(exist_ok=True)

# Request models
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
    Load enriched vulnerability data from scan results.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities = []
    
    # Check for enriched files in scans directory
    scan_dirs = ['nmap', 'nikto', 'nuclei']
    
    for scan_type in scan_dirs:
        enriched_dir = SCANS_DIR / scan_type / 'enriched'
        if not enriched_dir.exists():
            continue
        
        # Find enriched files related to this scan
        for enriched_file in enriched_dir.glob(f'*enriched*.json'):
            try:
                with open(enriched_file, 'r') as f:
                    data = json.load(f)
                    
                    # Parse enriched data structure
                    if 'enriched_cves' in data:
                        for cve_id, cve_data in data['enriched_cves'].items():
                            cvss_score = get_cvss_score(cve_data)
                            
                            vulnerabilities.append({
                                'cve_id': cve_id,
                                'description': cve_data.get('description', 'N/A'),
                                'cvss_v2': cve_data.get('cvss_v2_score', 'N/A'),
                                'cvss_v3': cve_data.get('cvss_v3_score', 'N/A'),
                                'severity': calculate_severity(cvss_score),
                                'recommendation': cve_data.get('references', 'See NVD for details'),
                                'source_tool': scan_type.capitalize(),
                                'target': data.get('target', 'N/A'),
                                'timestamp': data.get('timestamp', 'N/A')
                            })
            except Exception as e:
                logger.error(f"Error loading enriched file {enriched_file}: {e}")
                continue
    
    return vulnerabilities


def generate_csv_from_scan(scan_id: str) -> str:
    """
    Generate CSV file from scan results with enriched data.
    
    Args:
        scan_id: Scan ID
    
    Returns:
        Path to generated CSV file
    """
    vulnerabilities = load_enriched_data(scan_id)
    
    # Create CSV file
    csv_path = SCANS_DIR / f"scan_{scan_id}_results.csv"
    
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


# API Routes
@app.post("/api/scan/start", response_model=ScanStartResponse)
async def start_scan(request: ScanRequest):
    """
    Start a new security scan.
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
async def get_scan_status(scan_id: str):
    """
    Get the current status of a scan.
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
async def get_scan_results(scan_id: str):
    """
    Get the results of a completed scan with enriched vulnerability data.
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Results for scan {scan_id} not found. Scan may still be running or failed."
        )
    
    with open(result_file, 'r') as f:
        results = json.load(f)
    
    # Load enriched vulnerability data
    vulnerabilities = load_enriched_data(scan_id)
    
    # Calculate risk summary
    risk_summary = calculate_risk_summary(vulnerabilities)
    
    # Add enriched data to results
    results['vulnerabilities'] = vulnerabilities
    results['risk_summary'] = risk_summary
    
    return results


@app.get("/api/export/csv/{scan_id}")
async def export_csv(scan_id: str):
    """
    Export scan results as CSV file.
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
            filename=f"scan_{scan_id}_results.csv",
            media_type="text/csv"
        )
    except Exception as e:
        logger.exception(f"Error exporting CSV for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to export CSV: {str(e)}"
        )


@app.get("/api/scans/history")
async def get_scan_history():
    """
    Get a list of all previous scans with risk summaries.
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
                
                # Load vulnerability data and calculate risk summary
                vulnerabilities = load_enriched_data(scan_id)
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


@app.get("/api/system/info")
async def get_system_info():
    """
    Get system information and available workers.
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
async def serve_index():
    return FileResponse("index.html")


@app.get("/scan.html")
async def serve_scan():
    return FileResponse("scan.html")


@app.get("/past-scans.html")
async def serve_past_scans():
    return FileResponse("past-scans.html")


@app.get("/bot.html")
async def serve_bot():
    return FileResponse("bot.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
