
import argparse
import subprocess
import os
import re
import time
from urllib.parse import quote_plus, urlparse
import requests
import xmltodict
import pandas as pd
from datetime import datetime

NIKTO_TIMEOUT = 1800
NIKTO_TUNING = "0123456789abc"   # full tuning (use with caution); change to "32ab5" for safer default
OUTDIR = "nikto_scans"

# NVD API 2.0 endpoints (API 1.0 is deprecated)
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SLEEP_BETWEEN_NVD_WITH_KEY = 0.6  # Max 50 requests per 30 seconds with API key
SLEEP_BETWEEN_NVD_NO_KEY = 6      # Max 5 requests per 30 seconds without API key

# Helpers
def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)

def run_cmd(cmd_list, timeout=None):
    """Execute command with timeout handling."""
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 1, "", f"Timeout: {e}"
    except Exception as e:
        return 1, "", f"Error: {e}"

def run_nikto_xml(target, outdir=OUTDIR):
    """Run Nikto scan and return output path and format."""
    os.makedirs(outdir, exist_ok=True)
    name = safe_filename(target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(outdir, f"nikto_{name}_{timestamp}.xml")
    
    cmd = ["nikto", "-h", target, "-Format", "xml", "-output", out_path, 
           "-nointeractive", "-Tuning", NIKTO_TUNING]
    
    print(f"[+] Running Nikto (XML) -> {out_path}")
    print(f"[+] Command: {' '.join(cmd)}")
    
    rc, out, err = run_cmd(cmd, timeout=NIKTO_TIMEOUT)
    
    if rc != 0:
        print(f"[!] Nikto returned rc={rc}. stderr (truncated):\n{err[:500]}")
        # Try txt format as fallback
        print("[*] Trying 'txt' fallback format...")
        out_path = os.path.join(outdir, f"nikto_{name}_{timestamp}.txt")
        cmd2 = ["nikto", "-h", target, "-Format", "txt", "-output", out_path, 
                "-nointeractive", "-Tuning", NIKTO_TUNING]
        rc2, out2, err2 = run_cmd(cmd2, timeout=NIKTO_TIMEOUT)
        
        if rc2 != 0:
            raise RuntimeError(
                "Nikto failed for both xml and txt formats. "
                "Check nikto installation and target reachability."
            )
        return out_path, "txt"
    
    return out_path, "xml"

def extract_cves_from_xml(path):
    """Extract CVE IDs from Nikto XML/text output."""
    cves = set()
    
    if not os.path.exists(path):
        print(f"[!] File not found: {path}")
        return cves
    
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return cves
    
    # Regex scan over entire output
    found = re.findall(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE)
    for f in found:
        cves.add(f.upper())
    
    # Attempt to parse XML structure for 'cve' keys
    try:
        doc = xmltodict.parse(text)
        
        def rec(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.lower() in ("cve", "cves", "cveid", "cve-id", "reference"):
                        if isinstance(v, list):
                            for it in v:
                                if isinstance(it, str):
                                    m = re.findall(r"(CVE-\d{4}-\d{4,7})", it, flags=re.IGNORECASE)
                                    for mm in m:
                                        cves.add(mm.upper())
                        elif isinstance(v, str):
                            m = re.findall(r"(CVE-\d{4}-\d{4,7})", v, flags=re.IGNORECASE)
                            for mm in m:
                                cves.add(mm.upper())
                    else:
                        rec(v)
            elif isinstance(o, list):
                for it in o:
                    rec(it)
        
        rec(doc)
    except Exception as e:
        # XML parse failed – keep regex results
        print(f"[*] XML parsing note: {e}")
    
    return cves

def fetch_server_header(target):
    """Fetch Server header from target."""
    parsed = urlparse(target)
    if not parsed.scheme:
        url = "http://" + target
    else:
        url = target
    
    try:
        # Try HEAD first
        r = requests.head(url, timeout=15, verify=False, allow_redirects=True)
        s = r.headers.get("Server") or r.headers.get("server")
        if s:
            return s
        
        # Fallback to GET
        r2 = requests.get(url, timeout=15, verify=False, allow_redirects=True)
        return r2.headers.get("Server") or r2.headers.get("server")
    except Exception as e:
        print(f"[!] Could not fetch Server header: {e}")
        return None

def parse_product_version(header):
    """Parse product name and version from server header."""
    if not header:
        return None, None
    
    # Try to match Product/Version pattern
    m = re.search(r"([A-Za-z0-9_\-\.]+)\/([0-9]+(?:\.[0-9]+)*)", header)
    if m:
        return m.group(1), m.group(2)
    
    # Fallback: return first word as product
    parts = header.split()
    return parts[0] if parts else None, None

def get_cve_details_nvd(cve, api_key=None, sleep_time=6):
    """Query NVD API 2.0 for CVE details."""
    url = f"{NVD_CVE_ENDPOINT}?cveId={quote_plus(cve)}"
    headers = {}
    
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        
        if r.status_code != 200:
            print(f"[!] NVD query for {cve} returned HTTP {r.status_code}")
            time.sleep(sleep_time)
            return None
        
        data = r.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            print(f"[*] No data found for {cve}")
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
        cvss_v3 = None
        cvss_v2 = None
        severity_v3 = None
        severity_v2 = None
        
        metrics = cve_data.get("metrics", {})
        
        # Try CVSSv3.1 first, then CVSSv3.0
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            try:
                cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity_v3 = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        if not cvss_v3 and "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            try:
                cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                severity_v3 = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # CVSSv2
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            try:
                cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity_v2 = metrics["cvssMetricV2"][0]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        time.sleep(sleep_time)
        
        return {
            "cve_id": cve,
            "description": desc,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "severity_v3": severity_v3,
            "severity_v2": severity_v2
        }
    
    except Exception as e:
        print(f"[!] Exception querying NVD for {cve}: {e}")
        time.sleep(sleep_time)
        return None

def search_nvd_keywords(product, version=None, api_key=None, max_results=20, sleep_time=6):
    """Search NVD API 2.0 by keywords."""
    # Build keyword query
    kw = product if not version else f"{product} {version}"
    url = f"{NVD_CVE_ENDPOINT}?keywordSearch={quote_plus(kw)}"
    headers = {}
    
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        r = requests.get(url, headers=headers, timeout=30)
        
        if r.status_code != 200:
            print(f"[!] NVD keyword search returned HTTP {r.status_code}")
            time.sleep(sleep_time)
            return []
        
        data = r.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        out = []
        for vuln in vulnerabilities[:max_results]:
            try:
                cve_id = vuln["cve"]["id"]
                out.append(cve_id)
            except (KeyError, TypeError):
                continue
        
        time.sleep(sleep_time)
        return out
    
    except Exception as e:
        print(f"[!] Exception searching NVD for keyword '{kw}': {e}")
        time.sleep(sleep_time)
        return []

def orchestrate(target, nvd_key=None):
    """Main orchestration function."""
    print(f"\n{'='*60}")
    print(f"[+] Target: {target}")
    print(f"[+] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # Determine sleep time based on API key presence
    sleep_time = SLEEP_BETWEEN_NVD_WITH_KEY if nvd_key else SLEEP_BETWEEN_NVD_NO_KEY
    
    if nvd_key:
        print("[+] Using NVD API key (faster rate limit)")
    else:
        print("[*] No NVD API key provided (slower rate limit)")
    
    # Run Nikto
    try:
        nikto_file, fmt = run_nikto_xml(target)
        print(f"[+] Nikto output: {nikto_file} (format={fmt})")
    except Exception as e:
        print(f"[!] Error running Nikto: {e}")
        return
    
    # Extract CVEs
    cves = set()
    if fmt == "xml":
        cves = extract_cves_from_xml(nikto_file)
    else:
        # Fallback: regex on raw text
        try:
            with open(nikto_file, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
            cves = set(re.findall(r"(CVE-\d{4}-\d{4,7})", text, flags=re.IGNORECASE))
        except Exception as e:
            print(f"[!] Error reading Nikto output: {e}")
    
    if cves:
        print(f"[+] CVEs found in Nikto output: {sorted(cves)}")
    else:
        print("[*] No CVEs reported directly by Nikto.")
    
    # Fetch server header
    server = fetch_server_header(target)
    if server:
        print(f"[+] Server header: {server}")
    else:
        print("[!] Server header not available (may be hidden by target).")
    
    findings = []
    
    # Enrich CVEs found
    if cves:
        print(f"\n[+] Enriching {len(cves)} CVEs from NVD...")
        for i, cve in enumerate(sorted(cves), 1):
            print(f"[*] Querying {i}/{len(cves)}: {cve}")
            det = get_cve_details_nvd(cve, api_key=nvd_key, sleep_time=sleep_time)
            if det:
                det["source"] = "nikto"
                findings.append(det)
            else:
                findings.append({
                    "cve_id": cve,
                    "description": None,
                    "cvss_v3": None,
                    "cvss_v2": None,
                    "severity_v3": None,
                    "severity_v2": None,
                    "source": "nikto"
                })
    
    # If no CVEs found, try keyword search
    if not findings:
        prod, ver = parse_product_version(server)
        if prod:
            print(f"\n[*] Searching NVD by product/version: {prod} {ver or ''}")
            candidates = search_nvd_keywords(prod, ver, api_key=nvd_key, 
                                            max_results=20, sleep_time=sleep_time)
            
            if not candidates:
                print("[*] No candidate CVEs returned by keyword search.")
            else:
                print(f"[+] Found {len(candidates)} candidate CVEs")
                print(f"[+] Top candidates: {candidates[:5]}")
                
                for i, c in enumerate(candidates[:10], 1):  # Limit to 10 to avoid rate limits
                    print(f"[*] Querying {i}/{min(10, len(candidates))}: {c}")
                    det = get_cve_details_nvd(c, api_key=nvd_key, sleep_time=sleep_time)
                    if det:
                        det["source"] = f"keyword:{prod}{(' '+ver) if ver else ''}"
                        findings.append(det)
    
    # Print results
    if findings:
        df = pd.DataFrame(findings)
        
        # Shorten description for terminal view
        df["description_short"] = df["description"].fillna("").str.replace("\n", " ").str.slice(0, 100)
        
        print(f"\n{'='*60}")
        print("=== FINDINGS ===")
        print(f"{'='*60}\n")
        
        display_cols = ["cve_id", "cvss_v3", "severity_v3", "cvss_v2", "source", "description_short"]
        print(df[display_cols].to_string(index=False))
        
        # Save CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csvname = f"nikto_enriched_{safe_filename(target)}_{timestamp}.csv"
        df.to_csv(csvname, index=False)
        print(f"\n[+] Full findings written to: {csvname}")
        
        # Print summary statistics
        print(f"\n{'='*60}")
        print("=== SUMMARY ===")
        print(f"{'='*60}")
        print(f"Total CVEs found: {len(findings)}")
        
        if df["cvss_v3"].notna().any():
            high_severity = df[df["cvss_v3"] >= 7.0]["cvss_v3"].count()
            medium_severity = df[(df["cvss_v3"] >= 4.0) & (df["cvss_v3"] < 7.0)]["cvss_v3"].count()
            low_severity = df[df["cvss_v3"] < 4.0]["cvss_v3"].count()
            
            print(f"High severity (CVSS ≥ 7.0): {high_severity}")
            print(f"Medium severity (4.0 ≤ CVSS < 7.0): {medium_severity}")
            print(f"Low severity (CVSS < 4.0): {low_severity}")
    else:
        print(f"\n{'='*60}")
        print("[!] No CVEs or candidate CVEs found for this target.")
        print(f"{'='*60}")
    
    print(f"\n[+] Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[+] Done.\n")

def main():
    parser = argparse.ArgumentParser(
        description="Nikto (XML) + NVD API 2.0 enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nikto_xml_nvd_enrich.py https://example.com
  python3 nikto_xml_nvd_enrich.py 192.168.1.1 --nvd-key YOUR_API_KEY
  python3 nikto_xml_nvd_enrich.py example.com:8080
        """
    )
    parser.add_argument("target", help="Target URL or IP:PORT")
    parser.add_argument("--nvd-key", help="NVD API key (optional, enables faster rate limit)", default=None)
    
    args = parser.parse_args()
    
    # Get API key from args or environment variable
    nvd_key = args.nvd_key or os.environ.get("NVD_API_KEY")
    
    orchestrate(args.target, nvd_key)

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