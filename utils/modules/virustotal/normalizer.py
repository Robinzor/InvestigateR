"""
VirusTotal normalizer - standardizes output format
"""
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


def normalize_virustotal_result(raw_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize VirusTotal API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_virustotal_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {"virustotal": {"error": "No data received from VirusTotal"}}

    if "error" in raw_result:
        # Preserve upstream context if available
        error_payload = {"error": raw_result.get("error", "Unknown error")}
        if "status" in raw_result:
            error_payload["status"] = raw_result["status"]
        if "body" in raw_result:
            error_payload["body"] = raw_result["body"]
        return {"virustotal": error_payload}
    
    results = raw_result.get("raw_data")
    if not results or "data" not in results:
        return {"virustotal": {"error": "No results found"}}

    data_section = results.get("data")
    if isinstance(data_section, list):
        result = data_section[0] if data_section else {}
    elif isinstance(data_section, dict):
        result = data_section
    else:
        return {"virustotal": {"error": "Unexpected response format"}}

    attributes = result.get("attributes", {}) or {}
    
    # Process analysis results
    analysis_stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = analysis_stats.get("malicious", 0)
    suspicious = analysis_stats.get("suspicious", 0)
    harmless = analysis_stats.get("harmless", 0)
    undetected = analysis_stats.get("undetected", 0)

    # Fallback: derive stats from per-engine results if aggregate stats missing
    if (malicious + suspicious + harmless + undetected) == 0:
        per_engine = attributes.get("last_analysis_results") or {}
        if isinstance(per_engine, dict):
            for details in per_engine.values():
                category = (details or {}).get("category")
                if category == "malicious":
                    malicious += 1
                elif category == "suspicious":
                    suspicious += 1
                elif category == "harmless":
                    harmless += 1
                elif category == "undetected":
                    undetected += 1

    # Calculate total engines and detection ratio
    total_engines = malicious + suspicious + harmless + undetected
    malicious_engines = malicious + suspicious  # Consider suspicious as malicious
    detection_ratio = f"{malicious_engines}/{total_engines}" if total_engines > 0 else "0/0"
    
    # Calculate risk score (0-100)
    risk_score = int((malicious_engines * 100) / total_engines) if total_engines > 0 else 0
    
    # Get last analysis date
    last_analysis_date = attributes.get("last_analysis_date")
    if last_analysis_date:
        last_analysis_date = datetime.fromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_analysis_date = "Unknown"
    
    # Get categories (dict of vendor -> category)
    categories = attributes.get("categories", {})
    category_list = list(categories.keys()) if isinstance(categories, dict) else categories or []
    
    # Get tags
    tags = attributes.get("tags", []) or []
    
    # Get reputation score
    reputation = attributes.get("reputation", 0)
    
    # Get DNS records if available
    dns_records = attributes.get("last_dns_records", []) or []
    dns_info = []
    for record in dns_records:
        if record.get("type") == "A":
            dns_info.append(f"A: {record.get('value')}")
        elif record.get("type") == "MX":
            dns_info.append(f"MX: {record.get('value')} (Priority: {record.get('priority')})")
    
    # Get SSL certificate info if available
    cert_info = {}
    cert = attributes.get("last_https_certificate")
    if cert:
        cert_info = {
            "issuer": cert.get("issuer", {}).get("CN", "Unknown"),
            "valid_from": cert.get("validity", {}).get("not_before", "Unknown"),
            "valid_until": cert.get("validity", {}).get("not_after", "Unknown"),
            "subject": cert.get("subject", {}).get("CN", "Unknown"),
        }
    
    # Build a meaningful link
    vt_type = result.get("type") or attributes.get("type")
    vt_id = result.get("id", "")
    if vt_type and vt_id:
        link = f"https://www.virustotal.com/gui/{vt_type}/{vt_id}"
    else:
        link = f"https://www.virustotal.com/gui/search/{raw_result.get('observable', '')}"
    
    normalized = {
        "virustotal": {
            "risk_score": risk_score,
            "is_safe": False if (malicious_engines > 0 or risk_score > 0) else None,
            "last_analysis_date": last_analysis_date,
            "detection_ratio": detection_ratio,
            "total_engines": total_engines,
            "malicious_engines": malicious_engines,
            "malicious": malicious,
            "malicious_count": malicious,  # compatibility for is_module_result_safe
            "suspicious": suspicious,
            "suspicious_count": suspicious,  # compatibility for is_module_result_safe
            "harmless": harmless,
            "undetected": undetected,
            "categories": category_list,
            "tags": tags,
            "reputation": reputation,
            "dns_records": dns_info,
            "ssl_certificate": cert_info,
            "link": link,
        }
    }
    
    logger.info(f"Normalized VirusTotal result for {raw_result.get('observable', 'Unknown')}")
    return normalized

