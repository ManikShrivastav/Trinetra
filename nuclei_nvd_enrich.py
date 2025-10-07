
import argparse
import subprocess
import os
import re
import time
import json
from urllib.parse import quote_plus
from datetime import datetime
from pathlib import Path
import requests
import pandas as pd
from collections import defaultdict

# Configuration
NUCLEI_TIMEOUT = 3600  # 1 hour for large scans
OUTDIR = "nuclei_scans"
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP_BETWEEN_NVD_WITH_KEY = 0.6  # Max 50 requests per 30 seconds with API key
SLEEP_BETWEEN_NVD_NO_KEY = 6      # Max 5 requests per 30 seconds without API key

# Nuclei template paths (common locations)
NUCLEI_TEMPLATES = [
    "cves/",           # CVE templates
    "vulnerabilities/",# Vulnerability templates
    "exposures/",      # Exposure templates
    "misconfiguration/",# Misconfig templates
]

# Helpers
def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]  # Limit length

def run_cmd(cmd_list, timeout=None):
    """Execute command with timeout handling."""
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 1, "", f"Timeout: {e}"
    except Exception as e:
        return 1, "", f"Error: {e}"

def check_nuclei_installation():
    """Check if Nuclei is installed and get version."""
    rc, out, err = run_cmd(["nuclei", "-version"], timeout=10)
    if rc != 0:
        raise RuntimeError(
            "Nuclei is not installed or not in PATH.\n"
            "Install: https://github.com/projectdiscovery/nuclei\n"
            "Quick install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
    version = out.strip() if out else "unknown"
    print(f"[+] Nuclei version: {version}")
    return version

def update_nuclei_templates():
    """Update Nuclei templates to latest version."""
    print("[+] Updating Nuclei templates...")
    rc, out, err = run_cmd(["nuclei", "-update-templates"], timeout=300)
    if rc == 0:
        print("[+] Templates updated successfully")
    else:
        print(f"[!] Template update warning: {err[:200]}")

def run_nuclei_scan(target, templates=None, outdir=OUTDIR, severity=None, tags=None):
    """
    Run Nuclei scan and return output path.
    
    Args:
        target: Target URL, IP, CIDR, or file path
        templates: List of template paths or None for default CVE templates
        outdir: Output directory
        severity: Filter by severity (critical,high,medium,low,info)
        tags: Filter by tags (cve,oast,xss,etc)
    """
    os.makedirs(outdir, exist_ok=True)
    
    # Determine target type
    if os.path.isfile(target):
        target_name = Path(target).stem
        target_flag = ["-list", target]
    else:
        target_name = safe_filename(target)
        target_flag = ["-target", target]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(outdir, f"nuclei_{target_name}_{timestamp}.json")
    
    # Build Nuclei command
    cmd = [
        "nuclei",
        *target_flag,
        "-jsonl",  # JSON Lines output
        "-o", out_path,
        "-silent",
        "-nc",  # No color
    ]
    
    # Add template filters
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    else:
        # Default: scan with CVE templates
        cmd.extend(["-t", "cves/"])
    
    # Add severity filter
    if severity:
        cmd.extend(["-severity", severity])
    
    # Add tags filter
    if tags:
        cmd.extend(["-tags", tags])
    
    print(f"\n[+] Running Nuclei scan...")
    print(f"[+] Target: {target}")
    print(f"[+] Output: {out_path}")
    print(f"[+] Command: {' '.join(cmd)}")
    print(f"[+] This may take several minutes...\n")
    
    rc, out, err = run_cmd(cmd, timeout=NUCLEI_TIMEOUT)
    
    if rc != 0 and not os.path.exists(out_path):
        raise RuntimeError(f"Nuclei scan failed: {err[:500]}")
    
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        print("[!] No vulnerabilities found or output file is empty")
        return out_path, []
    
    return out_path, parse_nuclei_json(out_path)

def parse_nuclei_json(json_path):
    """Parse Nuclei JSON Lines output."""
    findings = []
    
    if not os.path.exists(json_path):
        return findings
    
    try:
        with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
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
                    print(f"[!] JSON parse error at line {line_num}: {e}")
                    continue
    
    except Exception as e:
        print(f"[!] Error reading Nuclei output: {e}")
    
    return findings

def get_cve_details_nvd(cve, api_key=None, sleep_time=6):
    """Query NVD API 2.0 for CVE details including affected components."""
    url = f"{NVD_CVE_ENDPOINT}?cveId={quote_plus(cve)}"
    headers = {}
    
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        
        if r.status_code != 200:
            if r.status_code == 404:
                print(f"[*] {cve} not found in NVD")
            else:
                print(f"[!] NVD query for {cve} returned HTTP {r.status_code}")
            time.sleep(sleep_time)
            return None
        
        data = r.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            time.sleep(sleep_time)
            return None
        
        vuln = vulnerabilities[0]
        cve_data = vuln.get("cve", {})
        
        # Extract description
        desc = ""
        descriptions = cve_data.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        
        # Extract CVSS scores
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v3_severity = None
        cvss_v2_score = None
        cvss_v2_vector = None
        cvss_v2_severity = None
        
        metrics = cve_data.get("metrics", {})
        
        # CVSSv3.1 (preferred)
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            try:
                metric = metrics["cvssMetricV31"][0]
                cvss_v3_score = metric["cvssData"]["baseScore"]
                cvss_v3_vector = metric["cvssData"]["vectorString"]
                cvss_v3_severity = metric["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # CVSSv3.0 (fallback)
        if not cvss_v3_score and "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            try:
                metric = metrics["cvssMetricV30"][0]
                cvss_v3_score = metric["cvssData"]["baseScore"]
                cvss_v3_vector = metric["cvssData"]["vectorString"]
                cvss_v3_severity = metric["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # CVSSv2
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            try:
                metric = metrics["cvssMetricV2"][0]
                cvss_v2_score = metric["cvssData"]["baseScore"]
                cvss_v2_vector = metric["cvssData"]["vectorString"]
                cvss_v2_severity = metric["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # Extract affected components (CPE configurations)
        affected_components = []
        configurations = cve_data.get("configurations", [])
        
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    if cpe.get("vulnerable", False):
                        cpe_uri = cpe.get("criteria", "")
                        # Parse CPE to extract product info
                        # Format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = parts[5] if len(parts) > 5 else "*"
                            
                            version_start = cpe.get("versionStartIncluding") or cpe.get("versionStartExcluding")
                            version_end = cpe.get("versionEndIncluding") or cpe.get("versionEndExcluding")
                            
                            comp_str = f"{vendor}/{product}"
                            if version and version != "*":
                                comp_str += f" {version}"
                            elif version_start or version_end:
                                comp_str += f" {version_start or ''}-{version_end or ''}"
                            
                            affected_components.append(comp_str)
        
        # Deduplicate components
        affected_components = list(set(affected_components))
        
        # Extract references
        references = []
        refs = cve_data.get("references", [])
        for ref in refs[:5]:  # Limit to first 5 references
            url_ref = ref.get("url", "")
            if url_ref:
                references.append(url_ref)
        
        # Extract weaknesses (CWE)
        weaknesses = []
        weakness_data = cve_data.get("weaknesses", [])
        for weakness in weakness_data:
            descriptions = weakness.get("description", [])
            for desc_item in descriptions:
                if desc_item.get("lang") == "en":
                    value = desc_item.get("value", "")
                    if value:
                        weaknesses.append(value)
        
        # Published and modified dates
        published = cve_data.get("published", "")
        last_modified = cve_data.get("lastModified", "")
        
        time.sleep(sleep_time)
        
        return {
            "cve_id": cve,
            "description": desc,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v2_score": cvss_v2_score,
            "cvss_v2_vector": cvss_v2_vector,
            "cvss_v2_severity": cvss_v2_severity,
            "affected_components": ", ".join(affected_components[:10]),  # Limit display
            "affected_components_count": len(affected_components),
            "weaknesses": ", ".join(weaknesses),
            "references": ", ".join(references),
            "published_date": published,
            "last_modified_date": last_modified,
        }
    
    except Exception as e:
        print(f"[!] Exception querying NVD for {cve}: {e}")
        time.sleep(sleep_time)
        return None

def enrich_findings(findings, nvd_key=None):
    """Enrich Nuclei findings with NVD data."""
    sleep_time = SLEEP_BETWEEN_NVD_WITH_KEY if nvd_key else SLEEP_BETWEEN_NVD_NO_KEY
    
    # Collect all unique CVEs
    all_cves = set()
    for finding in findings:
        all_cves.update(finding['cve_ids'])
    
    if not all_cves:
        print("[!] No CVE IDs found in Nuclei scan results")
        return findings
    
    print(f"\n[+] Found {len(all_cves)} unique CVE IDs")
    print(f"[+] Enriching with NVD data (this may take a while)...\n")
    
    # Query NVD for each CVE
    nvd_data = {}
    for i, cve in enumerate(sorted(all_cves), 1):
        print(f"[*] Querying NVD {i}/{len(all_cves)}: {cve}")
        details = get_cve_details_nvd(cve, api_key=nvd_key, sleep_time=sleep_time)
        if details:
            nvd_data[cve] = details
    
    print(f"\n[+] Successfully enriched {len(nvd_data)}/{len(all_cves)} CVEs")
    
    # Merge NVD data into findings
    enriched = []
    for finding in findings:
        # Create enriched record for each CVE in the finding
        if finding['cve_ids']:
            for cve in finding['cve_ids']:
                enriched_finding = finding.copy()
                
                # Add NVD data if available
                if cve in nvd_data:
                    enriched_finding.update(nvd_data[cve])
                else:
                    # Add empty NVD fields
                    enriched_finding.update({
                        'cve_id': cve,
                        'description': finding.get('description', ''),
                        'cvss_v3_score': None,
                        'cvss_v3_vector': None,
                        'cvss_v3_severity': None,
                        'cvss_v2_score': None,
                        'cvss_v2_vector': None,
                        'cvss_v2_severity': None,
                        'affected_components': '',
                        'affected_components_count': 0,
                        'weaknesses': '',
                        'references': '',
                        'published_date': '',
                        'last_modified_date': '',
                    })
                
                enriched.append(enriched_finding)
        else:
            # No CVE IDs, keep finding as-is
            enriched_finding = finding.copy()
            enriched_finding.update({
                'cve_id': 'N/A',
                'description': finding.get('description', ''),
                'cvss_v3_score': None,
                'cvss_v3_vector': None,
                'cvss_v3_severity': None,
                'cvss_v2_score': None,
                'cvss_v2_vector': None,
                'cvss_v2_severity': None,
                'affected_components': '',
                'affected_components_count': 0,
                'weaknesses': '',
                'references': '',
                'published_date': '',
                'last_modified_date': '',
            })
            enriched.append(enriched_finding)
    
    return enriched

def generate_report(enriched_findings, target, outdir=OUTDIR):
    """Generate detailed CSV report and summary."""
    if not enriched_findings:
        print("[!] No findings to report")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(enriched_findings)
    
    # Clean up tags and lists for CSV
    if 'tags' in df.columns:
        df['tags'] = df['tags'].apply(lambda x: ','.join(x) if isinstance(x, list) else str(x))
    if 'reference' in df.columns:
        df['reference'] = df['reference'].apply(lambda x: ','.join(x) if isinstance(x, list) else str(x))
    if 'cve_ids' in df.columns:
        df['cve_ids'] = df['cve_ids'].apply(lambda x: ','.join(x) if isinstance(x, list) else str(x))
    
    # Select and order columns for report
    report_columns = [
        'cve_id',
        'cvss_v3_score',
        'cvss_v3_severity',
        'cvss_v2_score',
        'template_name',
        'severity',
        'host',
        'matched_at',
        'affected_components',
        'weaknesses',
        'description',
        'references',
        'published_date',
        'template_id',
        'type',
    ]
    
    # Only include columns that exist
    report_columns = [col for col in report_columns if col in df.columns]
    
    # Generate filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = safe_filename(target)
    csv_path = os.path.join(outdir, f"nuclei_report_{target_name}_{timestamp}.csv")
    
    # Save to CSV
    df[report_columns].to_csv(csv_path, index=False)
    print(f"\n[+] Detailed report saved to: {csv_path}")
    
    # Generate summary statistics
    print(f"\n{'='*80}")
    print("=== VULNERABILITY SCAN SUMMARY ===")
    print(f"{'='*80}\n")
    
    print(f"Target: {target}")
    print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total findings: {len(enriched_findings)}")
    
    # Count unique CVEs
    unique_cves = df[df['cve_id'] != 'N/A']['cve_id'].nunique()
    print(f"Unique CVEs found: {unique_cves}")
    
    # Count unique hosts
    unique_hosts = df['host'].nunique()
    print(f"Hosts affected: {unique_hosts}")
    
    # Severity breakdown (from Nuclei)
    print(f"\n--- Nuclei Severity Distribution ---")
    severity_counts = df['severity'].value_counts()
    for sev, count in severity_counts.items():
        print(f"{sev.upper():12s}: {count}")
    
    # CVSS v3 severity breakdown
    if 'cvss_v3_score' in df.columns and df['cvss_v3_score'].notna().any():
        print(f"\n--- CVSS v3.x Severity Distribution ---")
        
        critical = df[df['cvss_v3_score'] >= 9.0]['cvss_v3_score'].count()
        high = df[(df['cvss_v3_score'] >= 7.0) & (df['cvss_v3_score'] < 9.0)]['cvss_v3_score'].count()
        medium = df[(df['cvss_v3_score'] >= 4.0) & (df['cvss_v3_score'] < 7.0)]['cvss_v3_score'].count()
        low = df[df['cvss_v3_score'] < 4.0]['cvss_v3_score'].count()
        
        print(f"CRITICAL (≥9.0): {critical}")
        print(f"HIGH (7.0-8.9):  {high}")
        print(f"MEDIUM (4.0-6.9): {medium}")
        print(f"LOW (<4.0):       {low}")
        
        avg_cvss = df['cvss_v3_score'].mean()
        print(f"\nAverage CVSS v3 Score: {avg_cvss:.2f}")
    
    # Top 10 most critical vulnerabilities
    print(f"\n--- Top 10 Most Critical Vulnerabilities ---")
    
    # Sort by CVSS v3 score
    top_vulns = df.nlargest(10, 'cvss_v3_score', keep='first')
    
    if not top_vulns.empty and top_vulns['cvss_v3_score'].notna().any():
        for idx, row in top_vulns.iterrows():
            if pd.notna(row.get('cvss_v3_score')):
                print(f"\n{row.get('cve_id', 'N/A')} - CVSS: {row.get('cvss_v3_score', 'N/A')} ({row.get('cvss_v3_severity', 'N/A')})")
                print(f"  Template: {row.get('template_name', 'N/A')}")
                print(f"  Host: {row.get('host', 'N/A')}")
                if row.get('affected_components'):
                    print(f"  Affected: {row.get('affected_components', '')[:100]}...")
    else:
        print("No CVSS scores available for top vulnerabilities")
    
    # Recommendations
    print(f"\n{'='*80}")
    print("=== RECOMMENDATIONS ===")
    print(f"{'='*80}\n")
    
    if critical > 0:
        print("⚠️  URGENT: Address CRITICAL severity vulnerabilities immediately")
    if high > 0:
        print("⚠️  HIGH priority: Remediate HIGH severity vulnerabilities as soon as possible")
    if medium > 0:
        print("⚡ MEDIUM priority: Plan remediation for MEDIUM severity vulnerabilities")
    
    print("\n1. Review the detailed CSV report for complete vulnerability information")
    print("2. Prioritize remediation based on CVSS scores and affected components")
    print("3. Check vendor advisories and apply security patches")
    print("4. Verify fixes by rescanning after remediation")
    print(f"\n{'='*80}\n")
    
    return csv_path

def orchestrate(target, nvd_key=None, templates=None, severity=None, tags=None, update_templates=False):
    """Main orchestration function."""
    print(f"\n{'='*80}")
    print("=== NUCLEI VULNERABILITY SCANNER WITH NVD ENRICHMENT ===")
    print(f"{'='*80}\n")
    
    # Check Nuclei installation
    try:
        check_nuclei_installation()
    except RuntimeError as e:
        print(f"[!] {e}")
        return
    
    # Update templates if requested
    if update_templates:
        update_nuclei_templates()
    
    # Determine sleep time based on API key
    if nvd_key:
        print("[+] Using NVD API key (faster rate limit)")
    else:
        print("[*] No NVD API key provided (slower rate limit - consider getting one)")
        print("[*] Get API key at: https://nvd.nist.gov/developers/request-an-api-key\n")
    
    # Run Nuclei scan
    try:
        scan_file, findings = run_nuclei_scan(target, templates, OUTDIR, severity, tags)
        print(f"[+] Nuclei scan completed: {scan_file}")
        print(f"[+] Raw findings: {len(findings)}")
    except Exception as e:
        print(f"[!] Error during Nuclei scan: {e}")
        return
    
    if not findings:
        print("\n[!] No vulnerabilities found in scan")
        print("[*] This could mean:")
        print("    - Target is secure (good!)")
        print("    - Target is unreachable")
        print("    - Templates need updating (use --update)")
        return
    
    # Enrich with NVD data
    enriched = enrich_findings(findings, nvd_key)
    
    # Generate report
    generate_report(enriched, target, OUTDIR)

def main():
    parser = argparse.ArgumentParser(
        description="Nuclei Template Scanner with NVD CVE Enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan single target
  python3 nuclei_nvd_enrich.py https://example.com
  
  # Scan with API key (faster)
  python3 nuclei_nvd_enrich.py https://example.com --nvd-key YOUR_KEY
  
  # Scan multiple targets from file
  python3 nuclei_nvd_enrich.py targets.txt --nvd-key YOUR_KEY
  
  # Scan CIDR range
  python3 nuclei_nvd_enrich.py 192.168.1.0/24 --severity critical,high
  
  # Use specific templates
  python3 nuclei_nvd_enrich.py https://example.com --templates cves/2024/
  
  # Filter by severity
  python3 nuclei_nvd_enrich.py https://example.com --severity critical,high,medium
  
  # Filter by tags
  python3 nuclei_nvd_enrich.py https://example.com --tags cve,rce,sqli
  
  # Update templates before scanning
  python3 nuclei_nvd_enrich.py https://example.com --update

Get your NVD API key at: https://nvd.nist.gov/developers/request-an-api-key
Install Nuclei: https://github.com/projectdiscovery/nuclei
        """
    )
    
    parser.add_argument(
        "target",
        help="Target URL, IP, CIDR range, or file containing targets"
    )
    
    parser.add_argument(
        "--nvd-key",
        help="NVD API key (optional, enables faster rate limit)",
        default=None
    )
    
    parser.add_argument(
        "--templates", "-t",
        help="Nuclei template paths (comma-separated, e.g., cves/,vulnerabilities/)",
        default=None
    )
    
    parser.add_argument(
        "--severity", "-s",
        help="Filter by severity (comma-separated: critical,high,medium,low,info)",
        default=None
    )
    
    parser.add_argument(
        "--tags",
        help="Filter by tags (comma-separated: cve,rce,xss,sqli,etc)",
        default=None
    )
    
    parser.add_argument(
        "--update", "-u",
        help="Update Nuclei templates before scanning",
        action="store_true"
    )
    
    args = parser.parse_args()
    
    # Get API key from args or environment variable
    nvd_key = args.nvd_key or os.environ.get("NVD_API_KEY")
    
    # Parse templates if provided
    templates = None
    if args.templates:
        templates = [t.strip() for t in args.templates.split(",")]
    
    # Run orchestration
    orchestrate(
        target=args.target,
        nvd_key=nvd_key,
        templates=templates,
        severity=args.severity,
        tags=args.tags,
        update_templates=args.update
    )

if __name__ == "__main__":
    # Silence insecure request warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()