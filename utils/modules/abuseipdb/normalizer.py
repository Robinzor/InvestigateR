"""
AbuseIPDB normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_abuseipdb_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize AbuseIPDB API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_abuseipdb_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {
            "abuseipdb": {
                "error": "No data received from AbuseIPDB"
            }
        }
    
    # Check if there's an error in the raw result
    if "error" in raw_result:
        ip = raw_result.get("ip", "Unknown")
        return {
            "abuseipdb": {
                "error": raw_result.get("error", "Unknown error"),
                "ip": ip
            }
        }
    
    # Check if raw_data exists
    if "raw_data" not in raw_result:
        ip = raw_result.get("ip", "Unknown")
        error_msg = raw_result.get("error", "No data received from AbuseIPDB")
        logger.warning(f"AbuseIPDB normalization: {error_msg} for IP {ip}")
        return {
            "abuseipdb": {
                "error": error_msg,
                "ip": ip
            }
        }
    
    data = raw_result["raw_data"]
    ip = raw_result.get("ip", "Unknown")
    
    # Ensure data is a dictionary
    if not isinstance(data, dict):
        logger.warning(f"AbuseIPDB raw_data is not a dict: {type(data)}")
        return {
            "abuseipdb": {
                "error": f"Unexpected data format: {type(data)}",
                "ip": ip
            }
        }
    
    reports = data.get("totalReports", 0)
    risk_score = data.get("abuseConfidenceScore", 0)
    link = f"https://www.abuseipdb.com/check/{ip}"

    normalized = {
        "abuseipdb": {
            "reports": reports,
            "risk_score": risk_score,
            "link": link,
            "isp": data.get("isp", "Unknown"),
            "country": data.get("countryCode", "Unknown"),
            "last_reported": data.get("lastReportedAt", "Never")
        }
    }
    
    logger.info(f"Normalized AbuseIPDB result for {ip}: {reports} reports, {risk_score}% risk")
    return normalized

