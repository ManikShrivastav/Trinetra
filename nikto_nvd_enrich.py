# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nikto Scanner Worker Module
Provides standardized run() interface for the orchestrator.
"""

import subprocess
import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration
NIKTO_TIMEOUT = 3600
NIKTO_TUNING = "0123456789abc"

# Utilities
def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]

def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def run(target: str, outdir: str = None, timeout: int = None, **kwargs) -> str:
    """
    Executes Nikto scanner against `target`.
    Returns output file path on success, raises exception on critical error.
    
    Args:
        target: URL or IP to scan
        outdir: Output directory (default: scans/nikto/)
        timeout: Scan timeout in seconds (default: 1800)
        **kwargs: Additional options (tuning, etc.)
    
    Returns:
        Path to the output file
        
    Raises:
        RuntimeError: If nikto not found or scan fails critically
    """
    if outdir is None:
        outdir = "scans/nikto"
    if timeout is None:
        timeout = NIKTO_TIMEOUT
    
    os.makedirs(outdir, exist_ok=True)
    
    # Sanitize target for filename
    name = safe_filename(target)
    timestamp = utc_timestamp()
    out_path = os.path.join(outdir, f"nikto_{name}_{timestamp}.txt")
    
    # Build command
    tuning = kwargs.get("tuning", NIKTO_TUNING)
    cmd = [
        "nikto", 
        "-h", target, 
        "-Format", "txt",
        "-output", out_path,
        "-nointeractive",
        "-Tuning", tuning
    ]
    
    logger.info(f"Running Nikto scan on {target}")
    logger.debug(f"Command: {' '.join(cmd)}")
    logger.debug(f"Output: {out_path}")
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("nikto not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nikto scan timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Nikto execution error: {e}")
    
    # Nikto may return non-zero even on success
    if proc.returncode != 0:
        logger.warning(f"Nikto returned exit code {proc.returncode}")
        logger.debug(f"stderr: {proc.stderr[:500]}")
    
    # Check if output file was created
    if not os.path.exists(out_path):
        raise RuntimeError("Nikto did not create output file")
    
    logger.info(f"Nikto scan completed: {out_path}")
    return out_path


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nikto scanner worker")
    parser.add_argument("target", help="Target URL or IP")
    parser.add_argument("--outdir", default="scans/nikto", help="Output directory")
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout in seconds")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout)
        print(f"Success: {output}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
