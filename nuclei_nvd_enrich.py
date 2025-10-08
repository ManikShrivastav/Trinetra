# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nuclei Scanner Worker Module
Provides standardized run() interface for the orchestrator.
"""

import subprocess
import os
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration
NUCLEI_TIMEOUT = 3600

# Utilities
def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]

def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def run(target: str, outdir: str = None, timeout: int = None, **kwargs) -> str:
    """
    Executes Nuclei scanner against `target`.
    Returns output file path on success, raises exception on critical error.
    
    Args:
        target: URL, IP, or CIDR to scan
        outdir: Output directory (default: scans/nuclei/)
        timeout: Scan timeout in seconds (default: 3600)
        **kwargs: Additional options (templates, severity, tags, etc.)
    
    Returns:
        Path to the output JSON file
        
    Raises:
        RuntimeError: If nuclei not found or scan fails critically
    """
    if outdir is None:
        outdir = "scans/nuclei"
    if timeout is None:
        timeout = NUCLEI_TIMEOUT
    
    os.makedirs(outdir, exist_ok=True)
    
    # Sanitize target for filename
    name = safe_filename(target)
    timestamp = utc_timestamp()
    out_path = os.path.join(outdir, f"nuclei_{name}_{timestamp}.jsonl")
    
    # Build command
    templates = kwargs.get("templates", "cves/")
    severity = kwargs.get("severity", None)
    tags = kwargs.get("tags", None)
    
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl",
        "-o", out_path,
        "-silent",
        "-nc"
    ]
    
    # Add template filters
    if templates:
        cmd.extend(["-t", templates])
    
    # Add severity filter
    if severity:
        cmd.extend(["-severity", severity])
    
    # Add tags filter
    if tags:
        cmd.extend(["-tags", tags])
    
    logger.info(f"Running Nuclei scan on {target}")
    logger.debug(f"Command: {' '.join(cmd)}")
    logger.debug(f"Output: {out_path}")
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("nuclei not found in PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nuclei scan timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Nuclei execution error: {e}")
    
    # Nuclei may return non-zero even on success (e.g., when vulnerabilities found)
    if proc.returncode != 0:
        logger.warning(f"Nuclei returned exit code {proc.returncode}")
        logger.debug(f"stderr: {proc.stderr[:500]}")
    
    # Create empty file if no vulnerabilities found
    if not os.path.exists(out_path):
        logger.info("No vulnerabilities found, creating empty output file")
        with open(out_path, 'w') as f:
            pass
    
    logger.info(f"Nuclei scan completed: {out_path}")
    return out_path


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nuclei scanner worker")
    parser.add_argument("target", help="Target URL, IP, or CIDR")
    parser.add_argument("--outdir", default="scans/nuclei", help="Output directory")
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    parser.add_argument("--templates", default="cves/", help="Nuclei templates to use")
    parser.add_argument("--severity", default=None, help="Severity filter (e.g., critical,high)")
    parser.add_argument("--tags", default=None, help="Tag filter (e.g., cve,rce)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout, 
                    templates=args.templates, severity=args.severity, tags=args.tags)
        print(f"Success: {output}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
