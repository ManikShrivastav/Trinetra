"""
NVD Utilities Module
Provides shared functions for NVD API interaction and risk calculation.
Used by nikto_nvd_enrich.py, nmap_nvd_enrich.py, and nuclei_nvd_enrich.py
"""

import re
import time
import requests
from urllib.parse import quote_plus
from typing import Optional, Dict, Any, Set

# NVD API 2.0 endpoint
NVD_CVE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting (API 2.0 limits)
SLEEP_BETWEEN_NVD_WITH_KEY = 0.6  # Max 50 requests per 30 seconds with API key
SLEEP_BETWEEN_NVD_NO_KEY = 6      # Max 5 requests per 30 seconds without API key

# CVE regex pattern
CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def calculate_risk(cvss_score: Optional[float]) -> str:
    """
    Calculate risk level from CVSS score.
    
    Mapping:
        0.0         = None
        0.1 - 3.9   = Low
        4.0 - 6.9   = Medium
        7.0 - 8.9   = High
        9.0 - 10.0  = Critical
    
    Args:
        cvss_score: CVSS score (0.0 - 10.0) or None
    
    Returns:
        Risk level string: "None", "Low", "Medium", "High", "Critical", or "Unknown"
    """
    if cvss_score is None:
        return "Unknown"
    
    if cvss_score == 0.0:
        return "None"
    elif 0.1 <= cvss_score <= 3.9:
        return "Low"
    elif 4.0 <= cvss_score <= 6.9:
        return "Medium"
    elif 7.0 <= cvss_score <= 8.9:
        return "High"
    elif 9.0 <= cvss_score <= 10.0:
        return "Critical"
    else:
        return "Unknown"


def extract_cves_regex(text: str) -> Set[str]:
    """
    Extract CVE IDs from text using regex.
    
    Args:
        text: Text to search for CVE IDs
    
    Returns:
        Set of CVE IDs (uppercase)
    """
    if not text:
        return set()
    
    cves = set()
    matches = CVE_REGEX.findall(text)
    for match in matches:
        cves.add(match.upper())
    
    return cves


def fetch_nvd_details(cve_id: str, api_key: Optional[str] = None, sleep_time: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """
    Fetch CVE details from NVD API 2.0.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-12345")
        api_key: Optional NVD API key for faster rate limit
        sleep_time: Optional custom sleep time between requests
    
    Returns:
        Dictionary with CVE details or None if not found/error:
        {
            "cve_id": str,
            "description": str,
            "cvss_v3_score": float or None,
            "cvss_v3_vector": str or None,
            "cvss_v3_severity": str or None,
            "cvss_v2_score": float or None,
            "cvss_v2_vector": str or None,
            "cvss_v2_severity": str or None,
            "references": list of str,
            "published_date": str,
            "last_modified_date": str,
            "weaknesses": list of str (CWE IDs),
            "risk": str ("Low", "Medium", "High", "Critical", "Unknown")
        }
    """
    # Determine sleep time
    if sleep_time is None:
        sleep_time = SLEEP_BETWEEN_NVD_WITH_KEY if api_key else SLEEP_BETWEEN_NVD_NO_KEY
    
    url = f"{NVD_CVE_ENDPOINT}?cveId={quote_plus(cve_id)}"
    headers = {"User-Agent": "TrinetraScanner/1.0"}
    
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code != 200:
            if response.status_code == 404:
                print(f"[*] {cve_id} not found in NVD")
            else:
                print(f"[!] NVD query for {cve_id} returned HTTP {response.status_code}")
            time.sleep(sleep_time)
            return None
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            print(f"[*] No data found for {cve_id}")
            time.sleep(sleep_time)
            return None
        
        vuln = vulnerabilities[0]
        cve_data = vuln.get("cve", {})
        
        # Extract description
        description = ""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Extract CVSS scores
        cvss_v3_score = None
        cvss_v3_vector = None
        cvss_v3_severity = None
        cvss_v2_score = None
        cvss_v2_vector = None
        cvss_v2_severity = None
        
        metrics = cve_data.get("metrics", {})
        
        # Try CVSSv3.1 first (preferred)
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            try:
                metric = metrics["cvssMetricV31"][0]
                cvss_v3_score = metric["cvssData"]["baseScore"]
                cvss_v3_vector = metric["cvssData"]["vectorString"]
                cvss_v3_severity = metric["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # Try CVSSv3.0 as fallback
        if not cvss_v3_score and "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            try:
                metric = metrics["cvssMetricV30"][0]
                cvss_v3_score = metric["cvssData"]["baseScore"]
                cvss_v3_vector = metric["cvssData"]["vectorString"]
                cvss_v3_severity = metric["cvssData"]["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # Try CVSSv2
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            try:
                metric = metrics["cvssMetricV2"][0]
                cvss_v2_score = metric["cvssData"]["baseScore"]
                cvss_v2_vector = metric["cvssData"]["vectorString"]
                cvss_v2_severity = metric["baseSeverity"]
            except (KeyError, IndexError):
                pass
        
        # Extract references
        references = []
        refs = cve_data.get("references", [])
        for ref in refs[:10]:  # Limit to first 10 references
            url_ref = ref.get("url", "")
            if url_ref:
                references.append(url_ref)
        
        # Extract weaknesses (CWE)
        weaknesses = []
        weakness_data = cve_data.get("weaknesses", [])
        for weakness in weakness_data:
            descriptions_weak = weakness.get("description", [])
            for desc_item in descriptions_weak:
                if desc_item.get("lang") == "en":
                    value = desc_item.get("value", "")
                    if value:
                        weaknesses.append(value)
        
        # Published and modified dates
        published_date = cve_data.get("published", "")
        last_modified_date = cve_data.get("lastModified", "")
        
        # Calculate risk based on CVSS v3 score (preferred) or v2 score (fallback)
        risk_score = cvss_v3_score if cvss_v3_score is not None else cvss_v2_score
        risk = calculate_risk(risk_score)
        
        time.sleep(sleep_time)
        
        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_v3_score": cvss_v3_score,
            "cvss_v3_vector": cvss_v3_vector,
            "cvss_v3_severity": cvss_v3_severity,
            "cvss_v2_score": cvss_v2_score,
            "cvss_v2_vector": cvss_v2_vector,
            "cvss_v2_severity": cvss_v2_severity,
            "references": references,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "weaknesses": weaknesses,
            "risk": risk
        }
    
    except Exception as e:
        print(f"[!] Exception querying NVD for {cve_id}: {e}")
        time.sleep(sleep_time)
        return None


def enrich_cves(cve_ids: Set[str], api_key: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Enrich multiple CVE IDs with NVD data.
    
    Args:
        cve_ids: Set of CVE IDs to enrich
        api_key: Optional NVD API key
    
    Returns:
        Dictionary mapping CVE ID to enrichment data
    """
    if not cve_ids:
        return {}
    
    enriched = {}
    total = len(cve_ids)
    
    print(f"[+] Enriching {total} unique CVE(s) from NVD...")
    
    for i, cve_id in enumerate(sorted(cve_ids), 1):
        print(f"[*] Querying NVD {i}/{total}: {cve_id}")
        details = fetch_nvd_details(cve_id, api_key=api_key)
        
        if details:
            enriched[cve_id] = details
        else:
            # Create placeholder for missing CVE data
            enriched[cve_id] = {
                "cve_id": cve_id,
                "description": "No details available from NVD",
                "cvss_v3_score": None,
                "cvss_v3_vector": None,
                "cvss_v3_severity": None,
                "cvss_v2_score": None,
                "cvss_v2_vector": None,
                "cvss_v2_severity": None,
                "references": [],
                "published_date": "",
                "last_modified_date": "",
                "weaknesses": [],
                "risk": "Unknown"
            }
    
    print(f"[+] Successfully enriched {len([e for e in enriched.values() if e.get('cvss_v3_score') or e.get('cvss_v2_score')])}/{total} CVEs")
    
    return enriched
