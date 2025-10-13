# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nikto Scanner Worker Module with NVD Enrichment
Provides standardized run() interface for the orchestrator.
Includes NVD CVE enrichment capabilities.
"""

import subprocess
import os
import re
import json
import logging
import xmltodict
from datetime import datetime
from pathlib import Path
from typing import Optional, Set, Dict, Any, List

# Import shared NVD utilities
try:
    from nvd_utils import extract_cves_regex, enrich_cves, fetch_nvd_details
except ImportError:
    print("[!] Warning: nvd_utils.py not found. NVD enrichment will not be available.")
    extract_cves_regex = None
    enrich_cves = None
    fetch_nvd_details = None

logger = logging.getLogger(__name__)

# Configuration
NIKTO_TIMEOUT = 5000
NIKTO_TUNING = "0123456789abc"


def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]


def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def run_nikto_scan(target: str, outdir: str, timeout: int, tuning: str = None) -> tuple:
    """
    Execute Nikto scanner and return output path and format.
    
    Args:
        target: URL or IP to scan
        outdir: Output directory
        timeout: Scan timeout in seconds
        tuning: Nikto tuning options
    
    Returns:
        Tuple of (output_path, format) where format is 'xml' or 'txt'
    
    Raises:
        RuntimeError: If nikto not found or scan fails critically
    """
    os.makedirs(outdir, exist_ok=True)
    
    name = safe_filename(target)
    timestamp = utc_timestamp()
    
    # FIX: Ensure target has protocol for Nikto
    if not target.startswith(('http://', 'https://')):
        # Default to http:// for Nikto (it's a web scanner)
        target = f"http://{target}"
        logger.info(f"Added http:// protocol to target: {target}")
    
    # Try XML format first
    out_path = os.path.join(outdir, f"nikto_{name}_{timestamp}.xml")
    
    if tuning is None:
        tuning = NIKTO_TUNING
    
    cmd = [
        "nikto",
        "-h", target,
        "-Format", "xml",
        "-output", out_path,
        "-nointeractive",
        "-Tuning", tuning
    ]
    
    logger.info(f"Running Nikto scan on {target}")
    logger.info(f"Command: {' '.join(cmd)}")  # FIX: Changed to INFO for debugging
    logger.debug(f"Output: {out_path}")
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("nikto not found in PATH. Install from https://github.com/sullo/nikto")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nikto scan timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Nikto execution error: {e}")
    
    # FIX: Add detailed logging
    logger.info(f"Nikto exit code: {proc.returncode}")
    if proc.stdout:
        logger.debug(f"Nikto stdout (first 500 chars): {proc.stdout[:500]}")
    if proc.stderr:
        logger.warning(f"Nikto stderr: {proc.stderr[:500]}")
    
    # FIX: Exit code -13 is SIGPIPE - usually means Nikto had issues with the target
    # Exit code 0 = clean scan, non-zero can still have results
    if proc.returncode == -13:
        logger.warning(
            f"Nikto exit code -13 (SIGPIPE) - possible causes:\n"
            f"  - Target '{target}' is not a web server\n"
            f"  - Target is unreachable or times out\n"
            f"  - SSL/TLS handshake failure\n"
            f"  - Try adding http:// or https:// explicitly\n"
            f"  Continuing to check if any output was generated..."
        )
    
    # Check if output exists despite error code (Nikto can still produce output)
    if os.path.exists(out_path) and os.path.getsize(out_path) > 100:
        logger.info(f"Nikto produced output despite exit code {proc.returncode}")
        return out_path, "xml"
    
    # If XML failed, try txt format
    if proc.returncode != 0:
        logger.warning(f"Nikto returned exit code {proc.returncode} (may be normal)")
        
        # FIX: Try txt format as fallback
        logger.info("Trying txt format as fallback...")
        out_path_txt = os.path.join(outdir, f"nikto_{name}_{timestamp}.txt")
        cmd_txt = [
            "nikto",
            "-h", target,
            "-Format", "txt",
            "-output", out_path_txt,
            "-nointeractive",
            "-Tuning", tuning
        ]
        
        try:
            proc2 = subprocess.run(cmd_txt, capture_output=True, text=True, timeout=timeout)
            if os.path.exists(out_path_txt) and os.path.getsize(out_path_txt) > 0:
                logger.info(f"Nikto scan completed with txt format: {out_path_txt}")
                return out_path_txt, "txt"
        except Exception as e:
            logger.warning(f"Txt format also failed: {e}")
    
    # Check if XML output was created
    if os.path.exists(out_path):
        file_size = os.path.getsize(out_path)
        if file_size > 0:
            logger.info(f"Nikto scan completed: {out_path} ({file_size} bytes)")
            return out_path, "xml"
        else:
            logger.warning(f"Nikto created empty XML file")
    
    # FIX: Better error message
    raise RuntimeError(
        f"Nikto did not create valid output file.\n"
        f"Exit code: {proc.returncode}\n"
        f"Possible causes:\n"
        f"  1. Target is unreachable\n"
        f"  2. Nikto configuration issue\n"
        f"  3. Network/firewall blocking scan\n"
        f"Stderr: {proc.stderr[:200] if proc.stderr else 'None'}"
    )


def extract_vulnerabilities_from_nikto(file_path: str, file_format: str = "xml") -> List[Dict[str, str]]:
    """
    Extract vulnerabilities from Nikto output file.
    Nikto reports web configuration issues, NOT CVE IDs.
    
    Args:
        file_path: Path to Nikto output file
        file_format: Format of the file ('xml' or 'txt')
    
    Returns:
        List of vulnerability dictionaries with keys: description, osvdb, method
    """
    vulnerabilities = []
    
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}")
        return vulnerabilities
    
    if file_format == "xml":
        try:
            import xml.etree.ElementTree as ET
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            root = ET.fromstring(content)
            
            # Extract all vulnerability items
            for item in root.findall('.//item'):
                description = item.get('description', '')
                osvdb = item.get('osvdb', 'N/A')
                method = item.get('method', 'GET')
                
                if description:
                    vulnerabilities.append({
                        "description": description,
                        "osvdb": osvdb,
                        "method": method
                    })
            
            logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities from XML")
        except Exception as e:
            logger.warning(f"Could not parse XML: {e}")
            return vulnerabilities
    
    elif file_format == "txt":
        # Parse text format if XML failed
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    vulnerabilities.append({
                        "description": line,
                        "osvdb": "N/A",
                        "method": "N/A"
                    })
            
            logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities from text")
        except Exception as e:
            logger.warning(f"Could not parse text file: {e}")
    
    return vulnerabilities


def enrich_nikto_results(scan_output_path: str, target: str, timestamp: str, nvd_api_key: Optional[str] = None) -> str:
    """
    Process Nikto scan results - report web vulnerabilities found.
    Since Nikto reports config issues, not CVE IDs, we report findings as-is.
    """
    file_format = "xml" if scan_output_path.endswith(".xml") else "txt"
    
    logger.info(f"Processing Nikto results from {scan_output_path}")
    logger.info("Nikto reports web configuration vulnerabilities, not CVEs")
    
    findings = []
    
    # Extract vulnerabilities using the new function
    vulnerabilities = extract_vulnerabilities_from_nikto(scan_output_path, file_format)
    
    # Convert to findings format
    for vuln in vulnerabilities:
        finding = {
            "title": vuln["description"],
            "description": vuln["description"],
            "type": "Web Configuration Vulnerability",
            "severity": "Medium",
            "source": "Nikto Web Scanner",
            "osvdb_id": vuln.get("osvdb", "N/A"),
            "method": vuln.get("method", "N/A")
        }
        findings.append(finding)
    
    logger.info(f"Found {len(findings)} web vulnerability(ies)")
    
    # Create output JSON
    output_data = {
        "scanner": "nikto",
        "target": target,
        "timestamp": timestamp,
        "scan_output": scan_output_path,
        "total_findings": len(findings),
        "findings": findings
    }
    
    # Save enriched results
    output_dir = os.path.dirname(scan_output_path)
    enriched_dir = os.path.join(output_dir, "enriched")
    os.makedirs(enriched_dir, exist_ok=True)
    
    output_filename = f"nikto_enriched_{safe_filename(target)}_{timestamp}.json"
    output_path = os.path.join(enriched_dir, output_filename)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    logger.info(f"Results saved to: {output_path}")
    
    # Print summary
    print(f"\n{'='*80}")
    print("=== NIKTO WEB VULNERABILITY SCAN ===")
    print(f"{'='*80}")
    print(f"Target: {target}")
    print(f"Total vulnerabilities found: {len(findings)}")
    
    if findings:
        print(f"\nFindings:")
        for i, finding in enumerate(findings[:10], 1):  # Show first 10
            print(f"  {i}. {finding['title']}")
    
    print(f"\nDetailed results: {output_path}")
    print(f"{'='*80}\n")
    
    return output_path


def run(target: str, outdir: str = None, timeout: int = None, nvd_api_key: Optional[str] = None, **kwargs) -> str:
    """
    Executes Nikto scanner against `target` and enriches results with NVD data.
    Returns enriched output file path on success, raises exception on critical error.
    
    Args:
        target: URL or IP to scan
        outdir: Output directory (default: scans/nikto/)
        timeout: Scan timeout in seconds (default: 3600)
        nvd_api_key: Optional NVD API key for enrichment
        **kwargs: Additional options (tuning, etc.)
    
    Returns:
        Path to the enriched output file
        
    Raises:
        RuntimeError: If nikto not found or scan fails critically
    """
    # Set defaults
    if outdir is None:
        outdir = "scans/nikto"
    if timeout is None:
        timeout = NIKTO_TIMEOUT
    
    # Ensure output directory exists
    os.makedirs(outdir, exist_ok=True)
    logger.info(f"Nikto worker starting for target: {target}")
    logger.info(f"Output directory: {outdir}")
    logger.info(f"Timeout: {timeout}s")
    
    timestamp = utc_timestamp()
    
    try:
        # Run Nikto scan
        logger.info(f"Executing Nikto scan...")
        scan_output, file_format = run_nikto_scan(target, outdir, timeout, kwargs.get("tuning"))
        logger.info(f"Nikto scan completed: {scan_output} (format: {file_format})")
        
        # Verify scan output exists
        if not os.path.exists(scan_output):
            raise RuntimeError(f"Nikto output file not found: {scan_output}")
        
        # Enrich results with NVD data
        logger.info(f"Starting NVD enrichment...")
        enriched_output = enrich_nikto_results(scan_output, target, timestamp, nvd_api_key)
        
        # Verify enriched output exists
        if not os.path.exists(enriched_output):
            logger.warning(f"Enriched file not created, returning original: {scan_output}")
            return scan_output
            
        logger.info(f"Enrichment completed: {enriched_output}")
        return enriched_output
        
    except RuntimeError as e:
        # Re-raise RuntimeError with additional context
        logger.error(f"Nikto scan failed for {target}: {e}")
        raise
    except Exception as e:
        # Log unexpected errors and re-raise
        logger.exception(f"Unexpected error in Nikto worker for {target}: {e}")
        raise RuntimeError(f"Nikto worker failed: {e}") from e


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nikto scanner worker with NVD enrichment")
    parser.add_argument("target", help="Target URL or IP")
    parser.add_argument("--outdir", default="scans/nikto", help="Output directory")
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    parser.add_argument("--nvd-key", default=None, help="NVD API key (optional)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout, nvd_api_key=args.nvd_key)
        print(f"\n[SUCCESS] Output: {output}")
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
