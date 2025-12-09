"""
ShodanInternetDB normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_shodan_internetdb_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize Shodan InternetDB API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_shodan_internetdb_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "shodan_internetdb": {
                "error": "No data received from Shodan InternetDB"
            }
        }
    
    data = raw_result["raw_data"]
    
    normalized = {
        "shodan_internetdb": {
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", []),
            "cpes": data.get("cpes", []),
            "tags": data.get("tags", []),
            "ip": raw_result.get("ip", "Unknown")
        }
    }
    
    logger.info(f"Normalized Shodan InternetDB result for {raw_result.get('ip', 'Unknown')}")
    return normalized

