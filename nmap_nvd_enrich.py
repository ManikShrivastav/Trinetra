# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nmap Scanner Worker Module
Provides standardized run() interface for the orchestrator.
"""

import subprocess
import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration
NMAP_TIMEOUT = 3600

# Utilities
def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]

def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def run(target: str, outdir: str = None, timeout: int = None, **kwargs) -> str:
    """
    Executes Nmap scanner with vuln scripts against `target`.
    Returns output file path on success, raises exception on critical error.
    
    Args:
        target: IP or hostname to scan
        outdir: Output directory (default: scans/nmap/)
        timeout: Scan timeout in seconds (default: 600)
        **kwargs: Additional options (script_args, ports, etc.)
    
    Returns:
        Path to the output XML file
        
    Raises:
        RuntimeError: If nmap not found or scan fails critically
    """
    if outdir is None:
        outdir = "scans/nmap"
    if timeout is None:
        timeout = NMAP_TIMEOUT
    
    os.makedirs(outdir, exist_ok=True)
    
    # Sanitize target for filename
    name = safe_filename(target)
    timestamp = utc_timestamp()
    out_path = os.path.join(outdir, f"nmap_{name}_{timestamp}.xml")
    
    # Build command
    scripts = kwargs.get("scripts", "vulners,vuln")
    ports = kwargs.get("ports", None)
    
    cmd = [
        "nmap",
        "-sV",
        f"--script={scripts}",
        "-oX", out_path,
        target
    ]
    
    if ports:
        cmd.insert(2, f"-p{ports}")
    
    logger.info(f"Running Nmap scan on {target}")
    logger.debug(f"Command: {' '.join(cmd)}")
    logger.debug(f"Output: {out_path}")
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("nmap not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Nmap execution error: {e}")
    
    # Nmap usually returns 0 on success
    if proc.returncode != 0:
        logger.warning(f"Nmap returned exit code {proc.returncode}")
        logger.debug(f"stderr: {proc.stderr[:500]}")
    
    # Check if output file was created
    if not os.path.exists(out_path):
        raise RuntimeError("Nmap did not create output file")
    
    logger.info(f"Nmap scan completed: {out_path}")
    return out_path


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nmap scanner worker")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--outdir", default="scans/nmap", help="Output directory")
    parser.add_argument("--timeout", type=int, default=600, help="Timeout in seconds")
    parser.add_argument("--scripts", default="vulners,vuln", help="NSE scripts to run")
    parser.add_argument("--ports", default=None, help="Ports to scan (e.g., 80,443 or 1-1000)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout, scripts=args.scripts, ports=args.ports)
        print(f"Success: {output}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
