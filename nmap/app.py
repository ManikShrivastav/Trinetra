#!/usr/bin/env python3
"""
app.py - Trinetra silent scanner + exporter

Behavior:
- Prompt user for target (stdin)
- Run nmap (vulners,vuln scripts) and capture XML (in-memory)
- Parse XML to extract CVE IDs and service metadata
- Enrich each CVE via NVD REST API (description, CVSS, references)
- Create folder: exports/<YYYY-MM-DD_HH-MM-SS>/
  - report.csv  (one row per CVE, aggregated components)
  - json_objects/<CVE-ID>.json  (one file per CVE)
- No terminal printing (silent). Exceptions will propagate.
"""

import subprocess
import re
import os
import csv
import json
import time
import sys
from datetime import datetime

try:
    import xmltodict
    import requests
except Exception:
    # dependencies missing - fail with meaningful message
    raise RuntimeError("Missing required libraries. Run: pip install xmltodict requests")

# ---------- Configuration ----------
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
NVD_API_KEY = None            # optional: put your API key string here
NVD_PAUSE_SEC = 0.6          # polite pause between NVD queries
EXPORT_BASE = "exports"
NMAP_TIMEOUT = 300           # seconds for nmap run
# -----------------------------------

os.makedirs(EXPORT_BASE, exist_ok=True)


def run_nmap_with_nse(target: str, timeout: int = NMAP_TIMEOUT) -> str:
    """Run nmap with vuln scripts and return XML output (stdout)."""
    cmd = ["nmap", "-sV", "--script=vulners,vuln", "-oX", "-", target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    xml = proc.stdout or proc.stderr or ""
    if not xml:
        # return minimal valid xml so downstream parse won't crash
        return "<?xml version='1.0'?><nmaprun></nmaprun>"
    return xml


def safe_xml_parse(xml_text: str) -> dict:
    """Parse XML text to dict, return a safe structure on failure."""
    try:
        parsed = xmltodict.parse(xml_text)
        return parsed if parsed else {"nmaprun": {}}
    except Exception:
        return {"nmaprun": {}}


def extract_cves_and_services(parsed: dict) -> list:
    """
    From xmltodict parsed Nmap result, return list of CVE entries with service context.
    Each entry is a dict:
      {
        "cve_id": "CVE-YYYY-NNNN",
        "ip": "<address>",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache",
        "version": "2.4.29",
        "script_outputs": [ {"id": "...", "output": "..."}, ... ]
      }
    """
    nmaprun = parsed.get("nmaprun", {}) or {}
    hosts = nmaprun.get("host", []) or []
    if isinstance(hosts, dict):
        hosts = [hosts]

    results = []

    for host in hosts:
        # address
        addr = None
        addr_node = host.get("address")
        if isinstance(addr_node, dict):
            addr = addr_node.get("@addr")
        elif isinstance(addr_node, list) and addr_node:
            addr = addr_node[0].get("@addr")

        # ports
        ports_node = host.get("ports", {}).get("port", []) if host.get("ports") else []
        if isinstance(ports_node, dict):
            ports = [ports_node]
        else:
            ports = ports_node or []

        for p in ports:
            portid = p.get("@portid")
            proto = p.get("@protocol")
            svcnode = p.get("service") or {}
            svc_name = svcnode.get("@name")
            product = svcnode.get("@product")
            version = svcnode.get("@version")
            extrainfo = svcnode.get("@extrainfo")

            # gather scripts associated to this port
            scripts = []
            s_node = p.get("script")
            if isinstance(s_node, dict):
                scripts = [s_node]
            elif isinstance(s_node, list):
                scripts = s_node

            script_outputs = []
            for s in scripts:
                sid = s.get("@id")
                sout = s.get("@output") or s.get("output") or ""
                script_outputs.append({"id": sid, "output": sout})

            # extract CVEs inside script outputs
            cves_found = set()
            for s in script_outputs:
                outtxt = (s.get("output") or "") + " " + (s.get("id") or "")
                for m in CVE_REGEX.findall(outtxt):
                    cves_found.add(m.upper())

            for cve in sorted(list(cves_found)):
                results.append({
                    "cve_id": cve,
                    "ip": addr,
                    "port": int(portid) if portid and portid.isdigit() else None,
                    "protocol": proto,
                    "service": svc_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "script_outputs": script_outputs
                })

    # Also check host-level scripts for CVEs
    # hostscript may be under host -> hostscript -> script
    for host in hosts:
        addr = None
        addr_node = host.get("address")
        if isinstance(addr_node, dict):
            addr = addr_node.get("@addr")
        elif isinstance(addr_node, list) and addr_node:
            addr = addr_node[0].get("@addr")

        hostscript = host.get("hostscript")
        if hostscript:
            s_node = hostscript.get("script")
            if isinstance(s_node, dict):
                s_node = [s_node]
            for s in s_node or []:
                outtxt = (s.get("@output") or s.get("output") or "") + " " + (s.get("@id") or "")
                for m in CVE_REGEX.findall(outtxt):
                    results.append({
                        "cve_id": m.upper(),
                        "ip": addr,
                        "port": None,
                        "protocol": None,
                        "service": None,
                        "product": None,
                        "version": None,
                        "extrainfo": None,
                        "script_outputs": [{"id": s.get("@id"), "output": s.get("@output") or s.get("output") or ""}]
                    })

    return results


def nvd_fetch(cve_id: str) -> dict:
    """Fetch CVE metadata from NVD; return minimal dict on errors."""
    url = NVD_BASE + cve_id
    headers = {"User-Agent": "TrinetraScanner"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except Exception:
        return {"cve_id": cve_id, "error": "request-failed"}

    if resp.status_code != 200:
        return {"cve_id": cve_id, "error": f"http-{resp.status_code}"}

    try:
        data = resp.json()
    except Exception:
        return {"cve_id": cve_id, "error": "json-parse-error"}

    out = {"cve_id": cve_id}
    try:
        item = data["result"]["CVE_Items"][0]
        desc = item["cve"]["description"]["description_data"]
        out["description"] = desc[0]["value"] if desc else ""
    except Exception:
        out["description"] = ""

    try:
        cv3 = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3")
        out["cvss_v3"] = {
            "score": cv3.get("baseScore"),
            "severity": cv3.get("baseSeverity"),
            "vector": cv3.get("vectorString")
        } if cv3 else None
    except Exception:
        out["cvss_v3"] = None

    try:
        cv2 = item.get("impact", {}).get("baseMetricV2", {}).get("cvssV2")
        out["cvss_v2"] = {
            "score": cv2.get("baseScore"),
            "vector": cv2.get("vectorString")
        } if cv2 else None
    except Exception:
        out["cvss_v2"] = None

    try:
        refs = item["cve"]["references"]["reference_data"]
        out["references"] = [r.get("url") for r in refs if r.get("url")]
    except Exception:
        out["references"] = []

    return out


def aggregate_cves_with_enrichment(entries: list) -> dict:
    """
    entries: list of per-script CVE dicts returned by extract_cves_and_services
    Return: dictionary keyed by CVE ID with aggregated components and enrichment
    """
    cve_map = {}
    for e in entries:
        cid = e.get("cve_id")
        if not cid:
            continue
        if cid not in cve_map:
            cve_map[cid] = {
                "cve_id": cid,
                "components": [],
                "service_contexts": [],
                "nvd": None
            }
        comp = {
            "ip": e.get("ip"),
            "component": f"{e.get('protocol')}/{e.get('port')}" if e.get("port") else "host-level",
            "service": e.get("service"),
            "product": e.get("product"),
            "version": e.get("version"),
            "extrainfo": e.get("extrainfo")
        }
        cve_map[cid]["components"].append(comp)
        cve_map[cid]["service_contexts"].append(comp)

    # Enrich each CVE from NVD sequentially (with pause)
    for cid in list(cve_map.keys()):
        enriched = nvd_fetch(cid)
        cve_map[cid]["nvd"] = enriched
        time.sleep(NVD_PAUSE_SEC)

    return cve_map


def write_exports(cve_map: dict, target_input: str, timestamp: str):
    """
    Create folder:
      exports/<timestamp>/
        report.csv
        json_objects/<CVE>.json
    CSV rows: one row per CVE with aggregated components and NVD fields.
    """
    folder = os.path.join(EXPORT_BASE, timestamp)
    os.makedirs(folder, exist_ok=True)
    json_dir = os.path.join(folder, "json_objects")
    os.makedirs(json_dir, exist_ok=True)

    csv_path = os.path.join(folder, "report.csv")
    fieldnames = [
        "scan_time", "target_input", "cve_id",
        "cvss_v3_score", "cvss_v3_severity", "cvss_v3_vector",
        "cvss_v2_score", "description", "references", "components"
    ]

    # Write CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for cid, data in cve_map.items():
            nvd = data.get("nvd") or {}
            cvss3 = nvd.get("cvss_v3") or {}
            cvss2 = nvd.get("cvss_v2") or {}
            desc = nvd.get("description") or ""
            refs = nvd.get("references") or []
            # flatten components list into semicolon-separated strings
            comps_flat = []
            for c in data.get("components", []):
                compstr = "|".join([
                    str(c.get("ip") or ""),
                    str(c.get("component") or ""),
                    str(c.get("service") or ""),
                    str(c.get("product") or ""),
                    str(c.get("version") or "")
                ])
                comps_flat.append(compstr)
            writer.writerow({
                "scan_time": timestamp,
                "target_input": target_input,
                "cve_id": cid,
                "cvss_v3_score": cvss3.get("score"),
                "cvss_v3_severity": cvss3.get("severity"),
                "cvss_v3_vector": cvss3.get("vector"),
                "cvss_v2_score": cvss2.get("score"),
                "description": desc.replace("\n", " ").strip(),
                "references": ";".join(refs),
                "components": ";".join(comps_flat)
            })

    # Write individual JSON files
    for cid, data in cve_map.items():
        json_path = os.path.join(json_dir, f"{cid}.json")
        # tidy structure to write
        out = {
            "scan_time": timestamp,
            "target_input": target_input,
            "cve_id": cid,
            "components": data.get("components", []),
            "nvd": data.get("nvd", {})
        }
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(out, jf, indent=2)


def main():
    # Prompt (still interactive) - no terminal prints during process
    target = input().strip() if not sys.stdin.isatty() else input("Enter target IP/domain: ").strip()
    if not target:
        target = "127.0.0.1"

    # run nmap -> parse -> aggregate -> export
    xml = run_nmap_with_nse(target)
    parsed = safe_xml_parse(xml)
    entries = extract_cves_and_services(parsed)
    # aggregate and enrich (may be empty)
    cve_map = aggregate_cves_with_enrichment(entries)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    write_exports(cve_map, target, ts)
    # Silent end (no prints)

if __name__ == "__main__":
    main()
