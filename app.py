"""
FastAPI Backend for Trinetra Security Scanner
Integrates frontend with orchestrator and worker modules.
"""

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
from fastapi.responses import FileResponse, JSONResponse
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
    Updates status as scan progresses.
    """
    try:
        logger.info(f"[{scan_id}] Starting background scan for {len(targets)} target(s)")
        
        # Initialize progress tracking
        progress = {worker: "queued" for worker in worker_names}
        save_scan_status(scan_id, "running", progress)
        
        # Parse workers
        workers = main_orchestrator.parse_workers(",".join(worker_names))
        
        # Update progress as each worker starts/completes
        # Note: This is a simplified version. For real-time updates,
        # you'd need to modify the orchestrator to accept callbacks
        for worker in worker_names:
            progress[worker] = "running"
            save_scan_status(scan_id, "running", progress)
        
        # Run orchestrator
        results = main_orchestrator.run_orchestrator(
            targets=targets,
            workers=workers,
            max_target_workers=1
        )
        
        # Mark all as done
        for worker in worker_names:
            progress[worker] = "done"
        
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
        save_scan_status(scan_id, "failed", {worker: "error" for worker in worker_names})
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
    Get the results of a completed scan.
    """
    result_file = SCANS_DIR / f"scan_{scan_id}.json"
    
    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Results for scan {scan_id} not found. Scan may still be running or failed."
        )
    
    with open(result_file, 'r') as f:
        results = json.load(f)
    
    return results


@app.get("/api/scans/history")
async def get_scan_history():
    """
    Get a list of all previous scans.
    """
    history = []
    
    # Look for all scan result files
    for result_file in SCANS_DIR.glob("scan_*.json"):
        # Skip status files
        if "_status" in result_file.name:
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
                if status_file.exists():
                    with open(status_file, 'r') as sf:
                        status_data = json.load(sf)
                        status = status_data.get("status", "completed")
                
                history.append({
                    "scan_id": scan_id,
                    "target": ", ".join(targets) if targets else "unknown",
                    "targets": targets,
                    "status": status,
                    "timestamp": data.get("scan_timestamp", "unknown"),
                    "total_targets": data.get("total_targets", len(targets))
                })
        except Exception as e:
            logger.exception(f"Error reading scan file {result_file}: {e}")
            continue
    
    # Sort by timestamp (newest first)
    history.sort(key=lambda x: x["timestamp"], reverse=True)
    
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
