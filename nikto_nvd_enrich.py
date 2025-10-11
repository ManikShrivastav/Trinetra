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
NIKTO_TIMEOUT = 300
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
        
        # Try txt format as fallback
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
            if os.path.exists(out_path_txt):
                logger.info(f"Nikto scan completed with txt format: {out_path_txt}")
                return out_path_txt, "txt"
        except Exception:
            pass
    
    # Check if XML output was created
    if os.path.exists(out_path):
        logger.info(f"Nikto scan completed: {out_path}")
        return out_path, "xml"
    
    raise RuntimeError("Nikto did not create output file")


def extract_cves_from_nikto_output(file_path: str, file_format: str = "xml") -> Set[str]:
    """
    Extract CVE IDs from Nikto output file.
    
    Args:
        file_path: Path to Nikto output file
        file_format: Format of the file ('xml' or 'txt')
    
    Returns:
        Set of CVE IDs (uppercase)
    """
    cves = set()
    
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}")
        return cves
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return cves
    
    # Use regex to find all CVE IDs
    if extract_cves_regex:
        cves = extract_cves_regex(text)
    else:
        # Fallback regex if nvd_utils not available
        matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        cves = set(match.upper() for match in matches)
    
    # If XML, also try to parse structure
    if file_format == "xml":
        try:
            doc = xmltodict.parse(text)
            
            def recursive_search(obj):
                if isinstance(obj, dict):
                    for key, value in obj.items():
                        if key.lower() in ("cve", "cves", "cveid", "cve-id", "reference"):
                            if isinstance(value, list):
                                for item in value:
                                    if isinstance(item, str):
                                        matches = re.findall(r"CVE-\d{4}-\d{4,7}", item, re.IGNORECASE)
                                        for match in matches:
                                            cves.add(match.upper())
                            elif isinstance(value, str):
                                matches = re.findall(r"CVE-\d{4}-\d{4,7}", value, re.IGNORECASE)
                                for match in matches:
                                    cves.add(match.upper())
                        else:
                            recursive_search(value)
                elif isinstance(obj, list):
                    for item in obj:
                        recursive_search(item)
            
            recursive_search(doc)
        except Exception as e:
            logger.debug(f"XML parsing note: {e}")
    
    return cves


def enrich_nikto_results(scan_output_path: str, target: str, timestamp: str, nvd_api_key: Optional[str] = None) -> str:
    """
    Enrich Nikto scan results with NVD data.
    
    Args:
        scan_output_path: Path to Nikto output file
        target: Target that was scanned
        timestamp: Timestamp of the scan
        nvd_api_key: Optional NVD API key
    
    Returns:
        Path to enriched JSON output file
    """
    # Determine file format
    file_format = "xml" if scan_output_path.endswith(".xml") else "txt"
    
    logger.info(f"Enriching Nikto results from {scan_output_path}")
    
    # Extract CVEs
    cves = extract_cves_from_nikto_output(scan_output_path, file_format)
    
    if not cves:
        logger.info("No CVEs found in Nikto output")
    else:
        logger.info(f"Found {len(cves)} CVE(s): {sorted(cves)}")
    
    # Enrich with NVD data
    enriched_data = {}
    if cves and enrich_cves:
        enriched_data = enrich_cves(cves, api_key=nvd_api_key)
    
    # Build findings list
    findings = []
    for cve_id in sorted(cves):
        nvd_data = enriched_data.get(cve_id, {})
        
        finding = {
            "cve": cve_id,
            "title": f"Nikto identified vulnerability: {cve_id}",
            "description": nvd_data.get("description", "No description available"),
            "cvss_v3": nvd_data.get("cvss_v3_score"),
            "cvss_v2": nvd_data.get("cvss_v2_score"),
            "severity": nvd_data.get("cvss_v3_severity") or nvd_data.get("cvss_v2_severity") or "UNKNOWN",
            "risk": nvd_data.get("risk", "Unknown"),
            "references": nvd_data.get("references", [f"https://nvd.nist.gov/vuln/detail/{cve_id}"])
        }
        
        findings.append(finding)
    
    # Create output JSON
    output_data = {
        "scanner": "nikto",
        "target": target,
        "timestamp": timestamp,
        "scan_output": scan_output_path,
        "total_cves": len(cves),
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
    
    logger.info(f"Enriched results saved to: {output_path}")
    
    # Print summary
    print(f"\n{'='*80}")
    print("=== NIKTO SCAN ENRICHMENT SUMMARY ===")
    print(f"{'='*80}")
    print(f"Target: {target}")
    print(f"Total CVEs found: {len(cves)}")
    
    if findings:
        # Count by risk level
        risk_counts = {}
        for finding in findings:
            risk = finding.get("risk", "Unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        print(f"\nRisk Distribution:")
        for risk in ["Critical", "High", "Medium", "Low", "None", "Unknown"]:
            count = risk_counts.get(risk, 0)
            if count > 0:
                print(f"  {risk}: {count}")
        
        print(f"\nTop 5 Vulnerabilities:")
        sorted_findings = sorted(findings, key=lambda x: x.get("cvss_v3") or x.get("cvss_v2") or 0.0, reverse=True)
        for i, finding in enumerate(sorted_findings[:5], 1):
            cvss = finding.get("cvss_v3") or finding.get("cvss_v2") or "N/A"
            print(f"  {i}. {finding['cve']} - CVSS: {cvss} - Risk: {finding['risk']}")
    
    print(f"\nEnriched results: {output_path}")
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
