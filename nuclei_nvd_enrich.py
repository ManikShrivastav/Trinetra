# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nuclei Scanner Worker Module with NVD Enrichment
Provides standardized run() interface for the orchestrator.
Includes NVD CVE enrichment capabilities.
"""

import subprocess
import os
import re
import json
import logging
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
NUCLEI_TIMEOUT = 300


def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]


def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def run_nuclei_scan(target: str, outdir: str, timeout: int, templates: str = None, 
                    severity: str = None, tags: str = None) -> str:
    """
    Execute Nuclei scanner and return output path.
    
    Args:
        target: URL, IP, or CIDR to scan
        outdir: Output directory
        timeout: Scan timeout in seconds
        templates: Nuclei templates to use
        severity: Severity filter
        tags: Tags filter
    
    Returns:
        Path to the output JSONL file
    
    Raises:
        RuntimeError: If nuclei not found or scan fails critically
    """
    os.makedirs(outdir, exist_ok=True)
    
    name = safe_filename(target)
    timestamp = utc_timestamp()
    out_path = os.path.join(outdir, f"nuclei_{name}_{timestamp}.jsonl")
    
    # Build command
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
    else:
        cmd.extend(["-t", "cves/"])  # Default to CVE templates
    
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


def parse_nuclei_jsonl(jsonl_path: str) -> List[Dict[str, Any]]:
    """
    Parse Nuclei JSONL output.
    
    Args:
        jsonl_path: Path to Nuclei JSONL output file
    
    Returns:
        List of parsed findings
    """
    findings = []
    
    if not os.path.exists(jsonl_path):
        logger.warning(f"File not found: {jsonl_path}")
        return findings
    
    if os.path.getsize(jsonl_path) == 0:
        logger.info("Empty output file - no findings")
        return findings
    
    try:
        with open(jsonl_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    data = json.loads(line)
                    finding = {
                        'template_id': data.get('template-id', 'N/A'),
                        'template_name': data.get('info', {}).get('name', 'N/A'),
                        'severity': data.get('info', {}).get('severity', 'unknown'),
                        'host': data.get('host', 'N/A'),
                        'matched_at': data.get('matched-at', data.get('matched', 'N/A')),
                        'description': data.get('info', {}).get('description', ''),
                        'tags': data.get('info', {}).get('tags', []),
                        'cve_ids': [],
                        'cwe_ids': [],
                        'reference': data.get('info', {}).get('reference', []),
                        'metadata': data.get('info', {}).get('metadata', {}),
                        'extracted_results': data.get('extracted-results', []),
                        'matcher_name': data.get('matcher-name', ''),
                        'type': data.get('type', 'N/A'),
                    }
                    
                    # Extract CVE IDs from multiple sources
                    info = data.get('info', {})
                    
                    # From classification
                    classification = info.get('classification', {})
                    if 'cve-id' in classification:
                        cve_list = classification['cve-id']
                        if isinstance(cve_list, list):
                            finding['cve_ids'].extend(cve_list)
                        elif isinstance(cve_list, str):
                            finding['cve_ids'].append(cve_list)
                    
                    # From CWE
                    if 'cwe-id' in classification:
                        cwe_list = classification['cwe-id']
                        if isinstance(cwe_list, list):
                            finding['cwe_ids'].extend(cwe_list)
                        elif isinstance(cwe_list, str):
                            finding['cwe_ids'].append(cwe_list)
                    
                    # From tags (e.g., cve,cve2021,cve-2021-1234)
                    tags = finding['tags']
                    if isinstance(tags, list):
                        for tag in tags:
                            if isinstance(tag, str):
                                # Match CVE pattern
                                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', tag.upper())
                                finding['cve_ids'].extend(cve_matches)
                    
                    # From template ID (e.g., CVE-2021-1234)
                    template_id = finding['template_id']
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', template_id.upper())
                    finding['cve_ids'].extend(cve_matches)
                    
                    # From description and other text fields
                    text_to_search = f"{finding['template_name']} {finding['description']}"
                    cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', text_to_search.upper())
                    finding['cve_ids'].extend(cve_matches)
                    
                    # Deduplicate CVE IDs
                    finding['cve_ids'] = list(set([cve.upper() for cve in finding['cve_ids']]))
                    finding['cwe_ids'] = list(set([cwe.upper() for cwe in finding['cwe_ids']]))
                    
                    findings.append(finding)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse error at line {line_num}: {e}")
                    continue
    
    except Exception as e:
        logger.error(f"Error reading Nuclei output: {e}")
    
    return findings


def enrich_nuclei_results(scan_output_path: str, target: str, timestamp: str, nvd_api_key: Optional[str] = None) -> str:
    """
    Enrich Nuclei scan results with NVD data.
    
    Args:
        scan_output_path: Path to Nuclei JSONL output file
        target: Target that was scanned
        timestamp: Timestamp of the scan
        nvd_api_key: Optional NVD API key
    
    Returns:
        Path to enriched JSON output file
    """
    logger.info(f"Enriching Nuclei results from {scan_output_path}")
    
    # Parse Nuclei output
    raw_findings = parse_nuclei_jsonl(scan_output_path)
    
    if not raw_findings:
        logger.info("No findings in Nuclei output")
    else:
        logger.info(f"Found {len(raw_findings)} raw finding(s)")
    
    # Collect all unique CVEs
    all_cves = set()
    for finding in raw_findings:
        all_cves.update(finding['cve_ids'])
    
    if not all_cves:
        logger.info("No CVE IDs found in Nuclei scan results")
    else:
        logger.info(f"Found {len(all_cves)} unique CVE(s)")
    
    # Enrich with NVD data
    enriched_data = {}
    if all_cves and enrich_cves:
        enriched_data = enrich_cves(all_cves, api_key=nvd_api_key)
    
    # Build enriched findings list
    enriched_findings = []
    for raw_finding in raw_findings:
        if raw_finding['cve_ids']:
            # Create one enriched finding per CVE
            for cve_id in raw_finding['cve_ids']:
                nvd_data = enriched_data.get(cve_id, {})
                
                finding = {
                    "cve": cve_id,
                    "title": raw_finding['template_name'],
                    "description": nvd_data.get("description") or raw_finding['description'] or "No description available",
                    "cvss_v3": nvd_data.get("cvss_v3_score"),
                    "cvss_v2": nvd_data.get("cvss_v2_score"),
                    "severity": nvd_data.get("cvss_v3_severity") or nvd_data.get("cvss_v2_severity") or raw_finding['severity'].upper(),
                    "risk": nvd_data.get("risk", "Unknown"),
                    "references": nvd_data.get("references", [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]),
                    "template_id": raw_finding['template_id'],
                    "host": raw_finding['host'],
                    "matched_at": raw_finding['matched_at'],
                    "nuclei_severity": raw_finding['severity'],
                    "weaknesses": nvd_data.get("weaknesses", []),
                }
                
                enriched_findings.append(finding)
        else:
            # No CVE IDs - include finding without enrichment
            finding = {
                "cve": "N/A",
                "title": raw_finding['template_name'],
                "description": raw_finding['description'] or "No description available",
                "cvss_v3": None,
                "cvss_v2": None,
                "severity": raw_finding['severity'].upper(),
                "risk": "Unknown",
                "references": [],
                "template_id": raw_finding['template_id'],
                "host": raw_finding['host'],
                "matched_at": raw_finding['matched_at'],
                "nuclei_severity": raw_finding['severity'],
                "weaknesses": [],
            }
            
            enriched_findings.append(finding)
    
    # Create output JSON
    output_data = {
        "scanner": "nuclei",
        "target": target,
        "timestamp": timestamp,
        "scan_output": scan_output_path,
        "total_findings": len(raw_findings),
        "total_cves": len(all_cves),
        "findings": enriched_findings
    }
    
    # Save enriched results
    output_dir = os.path.dirname(scan_output_path)
    enriched_dir = os.path.join(output_dir, "enriched")
    os.makedirs(enriched_dir, exist_ok=True)
    
    output_filename = f"nuclei_enriched_{safe_filename(target)}_{timestamp}.json"
    output_path = os.path.join(enriched_dir, output_filename)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    logger.info(f"Enriched results saved to: {output_path}")
    
    # Print summary
    print(f"\n{'='*80}")
    print("=== NUCLEI SCAN ENRICHMENT SUMMARY ===")
    print(f"{'='*80}")
    print(f"Target: {target}")
    print(f"Total findings: {len(raw_findings)}")
    print(f"Total CVEs found: {len(all_cves)}")
    
    if enriched_findings:
        # Count by risk level
        risk_counts = {}
        for finding in enriched_findings:
            risk = finding.get("risk", "Unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        print(f"\nRisk Distribution:")
        for risk in ["Critical", "High", "Medium", "Low", "None", "Unknown"]:
            count = risk_counts.get(risk, 0)
            if count > 0:
                print(f"  {risk}: {count}")
        
        print(f"\nTop 5 Vulnerabilities:")
        sorted_findings = sorted(enriched_findings, key=lambda x: x.get("cvss_v3") or x.get("cvss_v2") or 0.0, reverse=True)
        for i, finding in enumerate(sorted_findings[:5], 1):
            cvss = finding.get("cvss_v3") or finding.get("cvss_v2") or "N/A"
            cve = finding.get("cve", "N/A")
            print(f"  {i}. {cve} - CVSS: {cvss} - Risk: {finding['risk']}")
    
    print(f"\nEnriched results: {output_path}")
    print(f"{'='*80}\n")
    
    return output_path


def run(target: str, outdir: str = None, timeout: int = None, nvd_api_key: Optional[str] = None, **kwargs) -> str:
    """
    Executes Nuclei scanner against `target` and enriches results with NVD data.
    Returns enriched output file path on success, raises exception on critical error.
    
    Args:
        target: URL, IP, or CIDR to scan
        outdir: Output directory (default: scans/nuclei/)
        timeout: Scan timeout in seconds (default: 3600)
        nvd_api_key: Optional NVD API key for enrichment
        **kwargs: Additional options (templates, severity, tags, etc.)
    
    Returns:
        Path to the enriched output file
        
    Raises:
        RuntimeError: If nuclei not found or scan fails critically
    """
    if outdir is None:
        outdir = "scans/nuclei"
    if timeout is None:
        timeout = NUCLEI_TIMEOUT
    
    timestamp = utc_timestamp()
    
    # Run Nuclei scan
    scan_output = run_nuclei_scan(
        target, outdir, timeout,
        templates=kwargs.get("templates"),
        severity=kwargs.get("severity"),
        tags=kwargs.get("tags")
    )
    
    # Enrich results with NVD data
    try:
        enriched_output = enrich_nuclei_results(scan_output, target, timestamp, nvd_api_key)
        return enriched_output
    except Exception as e:
        logger.error(f"Error enriching results: {e}")
        # Return scan output even if enrichment fails
        return scan_output


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nuclei scanner worker with NVD enrichment")
    parser.add_argument("target", help="Target URL, IP, or CIDR")
    parser.add_argument("--outdir", default="scans/nuclei", help="Output directory")
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    parser.add_argument("--templates", default="cves/", help="Nuclei templates to use")
    parser.add_argument("--severity", default=None, help="Severity filter (e.g., critical,high)")
    parser.add_argument("--tags", default=None, help="Tag filter (e.g., cve,rce)")
    parser.add_argument("--nvd-key", default=None, help="NVD API key (optional)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout, nvd_api_key=args.nvd_key,
                    templates=args.templates, severity=args.severity, tags=args.tags)
        print(f"\n[SUCCESS] Output: {output}")
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
