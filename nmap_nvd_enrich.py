# ⚠️  Use responsibly: Only scan targets you own or have explicit permission to test.

"""
Nmap Scanner Worker Module with NVD Enrichment
Provides standardized run() interface for the orchestrator.
Includes NVD CVE enrichment capabilities and XML parsing.
"""

import subprocess
import os
import re
import json
import logging
import html
import xmltodict
from datetime import datetime
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
NMAP_TIMEOUT = 5000


def extract_host_from_target(target: str) -> str:
    """
    Remove URL schemes and paths from targets so Nmap can parse them.
    
    Args:
        target: Target string (could be "http://example.com", "example.com", or "1.2.3.4")
    
    Returns:
        Just the hostname or IP that Nmap expects
    
    Examples:
        "http://example.com" -> "example.com"
        "https://example.com:443/path" -> "example.com"
        "example.com:8080" -> "example.com"
        "192.168.1.1" -> "192.168.1.1"
        "2001:db8::1" -> "2001:db8::1" (IPv6 preserved)
    """
    # Remove scheme (http://, https://, ftp://, etc.)
    if "://" in target:
        target = target.split("://", 1)[1]
    
    # Remove path (everything after first /)
    if "/" in target:
        target = target.split("/", 1)[0]
    
    # Remove port for non-IPv6 addresses
    # IPv6 addresses contain colons, so we need to check for brackets or multiple colons
    if ":" in target:
        # If it has brackets, it's IPv6 with port like [2001:db8::1]:8080
        if target.startswith("["):
            target = target.split("]")[0] + "]"
            target = target.strip("[]")
        # If it has multiple colons, it's likely IPv6 without port
        elif target.count(":") > 1:
            pass  # Keep as-is, it's IPv6
        # Single colon means it's hostname:port or IPv4:port
        else:
            target = target.split(":", 1)[0]
    
    return target.strip()


def safe_filename(s):
    """Sanitize filename by replacing unsafe characters."""
    return re.sub(r'[^A-Za-z0-9\-_.]', '_', s)[:100]


def utc_timestamp():
    """Return UTC timestamp string."""
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")


def run_nmap_scan(target: str, outdir: str, timeout: int, scripts: str = None, ports: str = None) -> str:
    """
    Execute Nmap scanner with vuln scripts and return output path.
    
    Args:
        target: IP or hostname to scan (can include URL scheme)
        outdir: Output directory
        timeout: Scan timeout in seconds
        scripts: NSE scripts to run (default: "vuln")
        ports: Ports to scan (default: 1-10000)
    
    Returns:
        Path to the output XML file
    
    Raises:
        RuntimeError: If nmap not found or scan fails critically
    """
    os.makedirs(outdir, exist_ok=True)
    
    # Clean the target for Nmap (remove http://, paths, etc.)
    nmap_target = extract_host_from_target(target)
    
    name = safe_filename(nmap_target)
    timestamp = utc_timestamp()
    out_path = os.path.join(outdir, f"nmap_{name}_{timestamp}.xml")
    
    # FIX: Use correct script name - "vuln" is built-in, "vulners" requires separate installation
    if scripts is None:
        scripts = "vuln"
    
    # FIX: Scan first 10000 ports for better coverage
    if ports is None:
        ports = "1-10000"
    
    # Build command with better options
    cmd = [
        "nmap",
        "-sV",  # Service version detection
        "--script", scripts,  # FIX: Use --script instead of --script=
        "-p", ports,  # FIX: Use -p flag separately
        "--host-timeout", f"{timeout}s",  # FIX: Add Nmap-level timeout
        "-oX", out_path,
        nmap_target  # Use cleaned target
    ]
    
    logger.info(f"Running Nmap scan on {nmap_target} (original: {target})")
    logger.info(f"Command: {' '.join(cmd)}")  # FIX: Changed to INFO for better debugging
    logger.debug(f"Output: {out_path}")
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)  # FIX: Add buffer to subprocess timeout
    except FileNotFoundError:
        raise RuntimeError("nmap not found in PATH. Install from https://nmap.org/download.html")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Nmap scan timed out after {timeout}s")
    except Exception as e:
        raise RuntimeError(f"Nmap execution error: {e}")
    
    # FIX: Add detailed logging for debugging
    logger.info(f"Nmap exit code: {proc.returncode}")
    if proc.stdout:
        logger.debug(f"Nmap stdout (first 500 chars): {proc.stdout[:500]}")
    if proc.stderr:
        logger.warning(f"Nmap stderr: {proc.stderr[:500]}")
    
    # Nmap usually returns 0 on success, but can return non-zero even with partial results
    if proc.returncode != 0:
        logger.warning(f"Nmap returned exit code {proc.returncode}")
        # Don't fail immediately - check if output was created
    
    # Check if output file was created
    if not os.path.exists(out_path):
        raise RuntimeError(f"Nmap did not create output file. Exit code: {proc.returncode}. "
                          f"Stderr: {proc.stderr[:200] if proc.stderr else 'None'}")
    
    # FIX: Check if output file has content
    file_size = os.path.getsize(out_path)
    if file_size == 0:
        raise RuntimeError(f"Nmap created empty output file. Scan may have failed. "
                          f"Exit code: {proc.returncode}")
    
    logger.info(f"Nmap scan completed: {out_path} ({file_size} bytes)")
    return out_path


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """
    Parse Nmap XML output to extract hosts, ports, services, and script outputs.
    
    Args:
        xml_path: Path to Nmap XML output file
    
    Returns:
        Dictionary with parsed data
    """
    if not os.path.exists(xml_path):
        logger.warning(f"File not found: {xml_path}")
        return {"hosts": []}
    
    try:
        with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
            xml_text = f.read()
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return {"hosts": []}
    
    if not xml_text or not xml_text.strip():
        logger.warning("Empty XML file")
        return {"hosts": []}
    
    try:
        parsed = xmltodict.parse(xml_text)
    except Exception as e:
        logger.error(f"Error parsing XML: {e}")
        return {"hosts": []}
    
    nmaprun = parsed.get("nmaprun", {}) or {}
    hosts_data = nmaprun.get("host", []) or []
    
    if isinstance(hosts_data, dict):
        hosts_data = [hosts_data]
    
    hosts = []
    
    for host in hosts_data:
        # Extract address
        addr = None
        addr_node = host.get("address")
        if isinstance(addr_node, dict):
            addr = addr_node.get("@addr")
        elif isinstance(addr_node, list) and addr_node:
            addr = addr_node[0].get("@addr")
        
        host_info = {
            "address": addr,
            "ports": [],
            "hostscripts": []
        }
        
        # Extract ports
        ports_node = host.get("ports", {}).get("port", []) if host.get("ports") else []
        if isinstance(ports_node, dict):
            ports_node = [ports_node]
        
        for port in ports_node:
            port_id = port.get("@portid")
            protocol = port.get("@protocol")
            service_node = port.get("service") or {}
            
            port_info = {
                "portid": port_id,
                "protocol": protocol,
                "service": service_node.get("@name"),
                "product": service_node.get("@product"),
                "version": service_node.get("@version"),
                "extrainfo": service_node.get("@extrainfo"),
                "scripts": []
            }
            
            # Extract scripts for this port
            scripts_node = port.get("script")
            if isinstance(scripts_node, dict):
                scripts_node = [scripts_node]
            elif scripts_node is None:
                scripts_node = []
            
            for script in scripts_node:
                script_info = {
                    "id": script.get("@id"),
                    "output": script.get("@output") or script.get("output") or ""
                }
                port_info["scripts"].append(script_info)
            
            host_info["ports"].append(port_info)
        
        # Extract host-level scripts
        hostscript = host.get("hostscript")
        if hostscript:
            scripts_node = hostscript.get("script")
            if isinstance(scripts_node, dict):
                scripts_node = [scripts_node]
            elif scripts_node is None:
                scripts_node = []
            
            for script in scripts_node:
                script_info = {
                    "id": script.get("@id"),
                    "output": script.get("@output") or script.get("output") or ""
                }
                host_info["hostscripts"].append(script_info)
        
        hosts.append(host_info)
    
    return {"hosts": hosts}


def extract_cves_from_nmap_xml(xml_path: str) -> Set[str]:
    """
    Extract CVE IDs from Nmap XML output.
    
    Args:
        xml_path: Path to Nmap XML output file
    
    Returns:
        Set of CVE IDs (uppercase)
    """
    cves = set()
    
    # Parse XML
    parsed_data = parse_nmap_xml(xml_path)
    
    # Extract CVEs from all script outputs
    for host in parsed_data.get("hosts", []):
        # From port scripts
        for port in host.get("ports", []):
            for script in port.get("scripts", []):
                output = script.get("output", "")
                script_id = script.get("id", "")
                
                # FIX: Decode HTML/XML entities BEFORE regex matching
                # This converts &#xa; to \n, &#x9; to \t, etc.
                output = html.unescape(output)
                
                text = f"{output} {script_id}"
                
                if extract_cves_regex:
                    cves.update(extract_cves_regex(text))
                else:
                    matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
                    cves.update(match.upper() for match in matches)
        
        # From host scripts
        for script in host.get("hostscripts", []):
            output = script.get("output", "")
            script_id = script.get("id", "")
            
            # FIX: Decode HTML/XML entities BEFORE regex matching
            output = html.unescape(output)
            
            text = f"{output} {script_id}"
            
            if extract_cves_regex:
                cves.update(extract_cves_regex(text))
            else:
                matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
                cves.update(match.upper() for match in matches)
    
    return cves


def enrich_nmap_results(scan_output_path: str, target: str, timestamp: str, nvd_api_key: Optional[str] = None) -> str:
    """
    Enrich Nmap scan results with NVD data.
    
    Args:
        scan_output_path: Path to Nmap XML output file
        target: Target that was scanned
        timestamp: Timestamp of the scan
        nvd_api_key: Optional NVD API key
    
    Returns:
        Path to enriched JSON output file
    """
    logger.info(f"Enriching Nmap results from {scan_output_path}")
    
    # Parse Nmap XML
    parsed_data = parse_nmap_xml(scan_output_path)
    
    # Extract CVEs
    cves = extract_cves_from_nmap_xml(scan_output_path)
    
    if not cves:
        logger.info("No CVEs found in Nmap output")
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
        
        # Find which hosts/ports have this CVE
        affected_hosts = []
        for host in parsed_data.get("hosts", []):
            host_addr = host.get("address", "N/A")
            
            # Check port scripts
            for port in host.get("ports", []):
                for script in port.get("scripts", []):
                    output = script.get("output", "")
                    if cve_id.upper() in output.upper():
                        affected_hosts.append({
                            "host": host_addr,
                            "port": port.get("portid"),
                            "service": port.get("service"),
                            "product": port.get("product"),
                            "version": port.get("version")
                        })
            
            # Check host scripts
            for script in host.get("hostscripts", []):
                output = script.get("output", "")
                if cve_id.upper() in output.upper():
                    affected_hosts.append({
                        "host": host_addr,
                        "port": None,
                        "service": "host-level",
                        "product": None,
                        "version": None
                    })
        
        finding = {
            "cve": cve_id,
            "title": f"Nmap identified vulnerability: {cve_id}",
            "description": nvd_data.get("description", "No description available"),
            "cvss_v3": nvd_data.get("cvss_v3_score"),
            "cvss_v2": nvd_data.get("cvss_v2_score"),
            "risk": nvd_data.get("risk", "Unknown"),
            "references": nvd_data.get("references", [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]),
            "affected_hosts": affected_hosts,
            "weaknesses": nvd_data.get("weaknesses", [])
        }
        
        findings.append(finding)
    
    # Create output JSON
    output_data = {
        "scanner": "nmap",
        "target": target,
        "timestamp": timestamp,
        "scan_output": scan_output_path,
        "total_hosts": len(parsed_data.get("hosts", [])),
        "total_cves": len(cves),
        "findings": findings
    }
    
    # Save enriched results
    output_dir = os.path.dirname(scan_output_path)
    enriched_dir = os.path.join(output_dir, "enriched")
    os.makedirs(enriched_dir, exist_ok=True)
    
    output_filename = f"nmap_enriched_{safe_filename(target)}_{timestamp}.json"
    output_path = os.path.join(enriched_dir, output_filename)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    logger.info(f"Enriched results saved to: {output_path}")
    
    # Print summary
    print(f"\n{'='*80}")
    print("=== NMAP SCAN ENRICHMENT SUMMARY ===")
    print(f"{'='*80}")
    print(f"Target: {target}")
    print(f"Total hosts scanned: {len(parsed_data.get('hosts', []))}")
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
            if finding.get("affected_hosts"):
                for affected in finding["affected_hosts"][:2]:  # Show first 2 affected hosts
                    host = affected.get("host", "N/A")
                    port = affected.get("port", "N/A")
                    service = affected.get("service", "N/A")
                    print(f"      - {host}:{port} ({service})")
    
    print(f"\nEnriched results: {output_path}")
    print(f"{'='*80}\n")
    
    return output_path


def run(target: str, outdir: str = None, timeout: int = None, nvd_api_key: Optional[str] = None, **kwargs) -> str:
    """
    Executes Nmap scanner against `target` with vuln scripts and enriches results with NVD data.
    Returns enriched output file path on success, raises exception on critical error.
    
    Args:
        target: IP or hostname to scan
        outdir: Output directory (default: scans/nmap/)
        timeout: Scan timeout in seconds (default: 3600)
        nvd_api_key: Optional NVD API key for enrichment
        **kwargs: Additional options (script_args, ports, etc.)
    
    Returns:
        Path to the enriched output file
        
    Raises:
        RuntimeError: If nmap not found or scan fails critically
    """
    if outdir is None:
        outdir = "scans/nmap"
    if timeout is None:
        timeout = NMAP_TIMEOUT
    
    timestamp = utc_timestamp()
    
    # Run Nmap scan
    scan_output = run_nmap_scan(target, outdir, timeout, kwargs.get("scripts"), kwargs.get("ports"))
    
    # Enrich results with NVD data
    try:
        enriched_output = enrich_nmap_results(scan_output, target, timestamp, nvd_api_key)
        return enriched_output
    except Exception as e:
        logger.error(f"Error enriching results: {e}")
        # Return scan output even if enrichment fails
        return scan_output


if __name__ == "__main__":
    # For standalone testing purposes only
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Nmap scanner worker with NVD enrichment")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--outdir", default="scans/nmap", help="Output directory")
    parser.add_argument("--timeout", type=int, default=3600, help="Timeout in seconds")
    parser.add_argument("--scripts", default="vuln", help="NSE scripts to run (default: vuln)")
    parser.add_argument("--ports", default=None, help="Ports to scan (default: common vulnerable ports)")
    parser.add_argument("--nvd-key", default=None, help="NVD API key (optional)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='[%(levelname)s] %(name)s: %(message)s'
    )
    
    try:
        output = run(args.target, args.outdir, args.timeout, nvd_api_key=args.nvd_key,
                    scripts=args.scripts, ports=args.ports)
        print(f"\n[SUCCESS] Output: {output}")
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
