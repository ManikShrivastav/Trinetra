#!/usr/bin/env python3
"""
app.py - Trinetra: Nmap (vuln scripts) -> parse -> NVD enrich -> EXPORT CSVs (services + CVEs)

- Runs nmap -sV --script=vulners,vuln -oX - <target> (in-memory)
- Parses results, extracts services & CVEs
- Enriches found CVEs via NVD REST API
- Exports two CSV files under ./exports/
    - services_<ts>.csv
    - cves_<ts>.csv

Notes:
- This writes CSV files (you asked for export). No DB is used.
- Use small targets for demo (127.0.0.1, scanme.nmap.org).
- Install dependencies: xmltodict, requests
"""

import subprocess
import sys
import re
import time
import json
import csv
import os
from datetime import datetime

try:
    import xmltodict
except Exception:
    print("Install dependency: pip install xmltodict requests")
    sys.exit(1)

try:
    import requests
except Exception:
    print("Install dependency: pip install xmltodict requests")
    sys.exit(1)

# ----- Config -----
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
NVD_API_KEY = None  # set string if you have an API key
NVD_PAUSE_SEC = 0.6  # polite pause between NVD queries
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
EXPORT_DIR = "exports"

os.makedirs(EXPORT_DIR, exist_ok=True)

# ----- Helpers -----
def run_nmap_with_nse(target: str, timeout: int = 300) -> str:
    cmd = ["nmap", "-sV", "--script=vulners,vuln", "-oX", "-", target]
    print(f"[NMAP] Running: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        xml = proc.stdout or proc.stderr or ""
        if not xml.strip():
            print("[NMAP] Warning: empty XML from nmap; returning minimal placeholder.")
            return "<?xml version='1.0'?><nmaprun></nmaprun>"
        return xml
    except FileNotFoundError:
        print("[ERROR] nmap not found on PATH.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[NMAP] Timeout expired; returning placeholder XML.")
        return "<?xml version='1.0'?><nmaprun></nmaprun>"
    except Exception as e:
        print(f"[NMAP] Unexpected error: {e}")
        return "<?xml version='1.0'?><nmaprun></nmaprun>"

def safe_xml_parse(xml_text: str):
    try:
        parsed = xmltodict.parse(xml_text)
        return parsed if parsed else {"nmaprun": {}}
    except Exception as e:
        print(f"[PARSE] xmltodict.parse error: {e}")
        return {"nmaprun": {}}

def nvd_query_cve(cve_id: str):
    url = NVD_BASE + cve_id
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    try:
        r = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        return {"cve_id": cve_id, "error": f"request-exception: {e}"}
    if r.status_code != 200:
        return {"cve_id": cve_id, "error": f"HTTP {r.status_code}"}
    try:
        data = r.json()
    except Exception as e:
        return {"cve_id": cve_id, "error": f"json-parse-error: {e}"}
    out = {"cve_id": cve_id}
    # description
    try:
        desc_list = data["result"]["CVE_Items"][0]["cve"]["description"]["description_data"]
        out["description"] = desc_list[0]["value"] if desc_list else ""
    except Exception:
        out["description"] = ""
    # cvss v3
    try:
        cvssv3 = data["result"]["CVE_Items"][0]["impact"]["baseMetricV3"]["cvssV3"]
        out["cvssV3"] = {
            "baseScore": cvssv3.get("baseScore"),
            "baseSeverity": cvssv3.get("baseSeverity"),
            "vectorString": cvssv3.get("vectorString")
        }
    except Exception:
        out["cvssV3"] = None
    # cvss v2
    try:
        cvssv2 = data["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["cvssV2"]
        out["cvssV2"] = {
            "baseScore": cvssv2.get("baseScore"),
            "vectorString": cvssv2.get("vectorString")
        }
    except Exception:
        out["cvssV2"] = None
    # refs
    try:
        refs = data["result"]["CVE_Items"][0]["cve"]["references"]["reference_data"]
        out["references"] = [r.get("url") for r in refs if r.get("url")]
    except Exception:
        out["references"] = []
    return out

# ----- Parsing function (extract services + CVEs) -----
def extract_info_from_nmap_parsed(parsed: dict):
    nmaprun = parsed.get("nmaprun", {}) or {}
    host = nmaprun.get("host", {}) or {}
    if isinstance(host, list):
        host = host[0] if host else {}
    # address
    addr = None
    try:
        addr_node = host.get("address")
        if isinstance(addr_node, dict):
            addr = addr_node.get("@addr")
        elif isinstance(addr_node, list) and addr_node:
            addr = addr_node[0].get("@addr")
    except Exception:
        addr = None
    # host status
    status = None
    try:
        st = host.get("status")
        if isinstance(st, dict):
            status = st.get("@state")
    except Exception:
        status = None
    # os fingerprint
    os_match = None
    try:
        osnode = host.get("os", {})
        osmatch = osnode.get("osmatch")
        if isinstance(osmatch, dict):
            os_match = osmatch.get("@name")
        elif isinstance(osmatch, list) and osmatch:
            os_match = osmatch[0].get("@name")
    except Exception:
        os_match = None

    # collect services
    items = []
    ports_node = host.get("ports", {}).get("port", []) if host.get("ports") else []
    if isinstance(ports_node, dict):
        ports = [ports_node]
    else:
        ports = ports_node or []

    for p in ports:
        portid = p.get("@portid")
        proto = p.get("@protocol")
        state = None
        if isinstance(p.get("state"), dict):
            state = p.get("state", {}).get("@state")
        svcnode = p.get("service")
        svc_name = None
        product = None
        version = None
        extrainfo = None
        if isinstance(svcnode, dict):
            svc_name = svcnode.get("@name")
            product = svcnode.get("@product")
            version = svcnode.get("@version")
            extrainfo = svcnode.get("@extrainfo")
        # scripts under port
        scripts = []
        script_node = p.get("script")
        if script_node:
            if isinstance(script_node, list):
                for s in script_node:
                    scripts.append({"id": s.get("@id"), "output": s.get("@output")})
            elif isinstance(script_node, dict):
                scripts.append({"id": script_node.get("@id"), "output": script_node.get("@output")})
        # extract CVEs from script outputs
        cves = set()
        for s in scripts:
            txt = (s.get("output") or "") + " " + (s.get("id") or "")
            for m in CVE_REGEX.findall(txt):
                cves.add(m.upper())
        item = {
            "port": int(portid) if portid else None,
            "protocol": proto,
            "state": state,
            "service_name": svc_name,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
            "scripts": scripts,
            "cves": sorted(list(cves))
        }
        items.append(item)

    # host scripts
    host_scripts = []
    host_cves = set()
    hostscript_node = host.get("hostscript")
    if hostscript_node:
        s_node = hostscript_node.get("script")
        if isinstance(s_node, dict):
            s_node = [s_node]
        for s in s_node or []:
            out = s.get("@output") or s.get("output")
            host_scripts.append({"id": s.get("@id"), "output": out})
            for m in CVE_REGEX.findall((out or "")):
                host_cves.add(m.upper())

    return {
        "target": addr,
        "host_status": status,
        "os": os_match,
        "items": items,
        "host_scripts": host_scripts,
        "host_cves": sorted(list(host_cves))
    }

# ----- Build CVE map & enrich with NVD -----
def build_and_enrich_cve_map(parsed_info: dict):
    cve_map = {}
    # port-level
    for item in parsed_info.get("items", []):
        for c in item.get("cves", []):
            if c not in cve_map:
                cve_map[c] = {"cve_id": c, "components": [], "service_meta": [], "nvd": None}
            comp = {
                "component": f"{item.get('protocol')}/{item.get('port')}",
                "service": item.get("service_name"),
                "product": item.get("product"),
                "version": item.get("version")
            }
            cve_map[c]["components"].append(comp)
            cve_map[c]["service_meta"].append(comp)
    # host-level
    for c in parsed_info.get("host_cves", []):
        if c not in cve_map:
            cve_map[c] = {"cve_id": c, "components": [], "service_meta": [], "nvd": None}
        cve_map[c]["components"].append({"component": "host-level"})
    # enrich
    for cve in list(cve_map.keys()):
        print(f"[NVD] Querying {cve} ...")
        info = nvd_query_cve(cve)
        cve_map[cve]["nvd"] = info
        time.sleep(NVD_PAUSE_SEC)
    return cve_map

# ----- CSV export helpers -----
def safe_filename(name: str) -> str:
    return "".join([c if c.isalnum() or c in "-._" else "_" for c in name])

def export_services_csv(parsed_info: dict, target_input: str, ts: str):
    """Write services_{ts}.csv with one row per detected open port/service."""
    fname_tmp = os.path.join(EXPORT_DIR, f"services_{ts}.tmp.csv")
    fname = os.path.join(EXPORT_DIR, f"services_{ts}.csv")
    fields = [
        "scan_time", "target_input", "address", "host_status", "os",
        "port", "protocol", "state", "service_name", "product", "version", "extrainfo", "script_ids"
    ]
    with open(fname_tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for item in parsed_info.get("items", []):
            writer.writerow({
                "scan_time": ts,
                "target_input": target_input,
                "address": parsed_info.get("target"),
                "host_status": parsed_info.get("host_status"),
                "os": parsed_info.get("os"),
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "state": item.get("state"),
                "service_name": item.get("service_name"),
                "product": item.get("product"),
                "version": item.get("version"),
                "extrainfo": item.get("extrainfo"),
                "script_ids": ";".join([s.get("id") for s in item.get("scripts")]) if item.get("scripts") else ""
            })
    os.replace(fname_tmp, fname)
    print(f"[EXPORT] Services CSV written: {fname}")
    return fname

def export_cves_csv(cve_map: dict, target_input: str, ts: str):
    """Write cves_{ts}.csv with one row per discovered CVE (with aggregated components)."""
    fname_tmp = os.path.join(EXPORT_DIR, f"cves_{ts}.tmp.csv")
    fname = os.path.join(EXPORT_DIR, f"cves_{ts}.csv")
    fields = [
        "scan_time", "target_input", "cve_id", "cvss_v3_score", "cvss_v3_severity",
        "cvss_v2_score", "description", "references", "components"
    ]
    with open(fname_tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for cve, entry in cve_map.items():
            nvd = entry.get("nvd") or {}
            cvssv3 = nvd.get("cvssV3") or {}
            cvssv2 = nvd.get("cvssV2") or {}
            desc = nvd.get("description") or ""
            refs = nvd.get("references") or []
            components = entry.get("components") or []
            # flatten components to semicolon-separated strings like "tcp/80|http|Apache|2.4.29"
            comps_flat = []
            for c in components:
                compstr = "|".join([
                    str(c.get("component") or ""),
                    str(c.get("service") or ""),
                    str(c.get("product") or ""),
                    str(c.get("version") or "")
                ])
                comps_flat.append(compstr)
            writer.writerow({
                "scan_time": ts,
                "target_input": target_input,
                "cve_id": cve,
                "cvss_v3_score": cvssv3.get("baseScore"),
                "cvss_v3_severity": cvssv3.get("baseSeverity") if cvssv3 else "",
                "cvss_v2_score": cvssv2.get("baseScore"),
                "description": desc.replace("\n", " ").strip(),
                "references": ";".join(refs),
                "components": ";".join(comps_flat)
            })
    os.replace(fname_tmp, fname)
    print(f"[EXPORT] CVEs CSV written: {fname}")
    return fname

# ----- Main CLI -----
def main():
    print("Trinetra — Nmap (vuln scripts) -> CSV export (services + CVEs)")
    target = input("Enter target IP/domain (default 127.0.0.1): ").strip() or "127.0.0.1"
    confirm = input(f"Run scanning on '{target}'? (y/N): ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        sys.exit(0)

    xml = run_nmap_with_nse(target, timeout=300)
    parsed = safe_xml_parse(xml)
    parsed_info = extract_info_from_nmap_parsed(parsed)

    # build & enrich CVE map
    cve_map = build_and_enrich_cve_map(parsed_info)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    # export services CSV
    services_csv = export_services_csv(parsed_info, target, ts)
    # export CVEs CSV
    cves_csv = export_cves_csv(cve_map, target, ts)

    # final summary
    print("\nSummary:")
    print(" Target:", target)
    print(" Address detected:", parsed_info.get("target"))
    print(" Open services:", len(parsed_info.get("items", [])))
    print(" CVEs discovered:", len(cve_map))
    print(" Exports:")
    print("  -", services_csv)
    print("  -", cves_csv)
    print("Done.")

if __name__ == "__main__":
    main()
