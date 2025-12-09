"""
IPInfo normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_ipinfo_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize IPInfo API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_ipinfo_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "ipinfo": {
                "error": "No data received from IPInfo"
            }
        }
    
    data = raw_result["raw_data"]
    
    normalized = {
        "ipinfo": {
            "hostname": data.get("hostname", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("region", "Unknown"),
            "country": data.get("country", "Unknown"),
            "loc": data.get("loc", "Unknown"),
            "org": data.get("org", "Unknown"),
            "postal": data.get("postal", "Unknown"),
            "timezone": data.get("timezone", "Unknown")
        }
    }
    
    logger.info(f"Normalized IPInfo result for {raw_result.get('observable', 'Unknown')}")
    return normalized

