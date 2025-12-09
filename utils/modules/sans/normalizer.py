"""
SANS normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_sans_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize SANS API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_sans_async (parsed XML)
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "sans": {
                "error": "No data received from SANS"
            }
        }
    
    data = raw_result["raw_data"]
    
    # Check if we have meaningful data (not just empty fields)
    has_data = False
    if data:
        # Check if we have any non-empty fields besides IP
        for key, value in data.items():
            if key not in ['ip', 'number'] and value and str(value).strip():
                has_data = True
                break
    
    ip_address = data.get("ip") or data.get("number") or raw_result.get("ip", "Unknown")
    count = data.get("count", 0)
    attacks = data.get("attacks", 0)
    comment = data.get("comment", "").strip()
    
    # Determine if IP is found in threat feeds (has attacks or threat feed data)
    threatfeeds = data.get("threatfeeds", [])
    # threatfeeds can be a list of feed names or a dict
    if isinstance(threatfeeds, dict):
        # Convert dict to list of feed names where value is truthy
        threatfeeds = [feed_name for feed_name, feed_value in threatfeeds.items() if feed_value]
    elif not isinstance(threatfeeds, list):
        threatfeeds = []
    has_threatfeeds = len(threatfeeds) > 0
    found = attacks > 0 or count > 0 or has_threatfeeds or bool(comment)
    
    if not has_data and not found:
        return {
            "sans": {
                "error": "No data found for this IP"
            }
        }
    
    # SANS API returns XML data, normalize to consistent structure
    # Format to match template expectations
    normalized = {
        "sans": {
            "ip": ip_address,
            "found": found,
            "description": comment or f"AS {data.get('as', 'N/A')} - {data.get('asname', 'Unknown')} ({data.get('ascountry', 'N/A')})",
            "match_count": attacks or count,
            "count": count,
            "attacks": attacks,
            "maxrisk": data.get("maxrisk", 0),
            "as": data.get("as", ""),
            "asname": data.get("asname", ""),
            "ascountry": data.get("ascountry", ""),
            "assize": data.get("assize", 0),
            "network": data.get("network", ""),
            "asabusecontact": data.get("asabusecontact", ""),
            "maxdate": data.get("maxdate", ""),
            "mindate": data.get("mindate", ""),
            "updated": data.get("updated", ""),
            "threatfeeds": threatfeeds,
            "link": f"https://isc.sans.edu/ipinfo.html?ip={ip_address}"
        }
    }
    
    logger.info(f"Normalized SANS result for {normalized['sans']['ip']}")
    return normalized

