"""
GreyNoise normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_greynoise_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize GreyNoise API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_greynoise_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {
            "greynoise": {
                "error": "No response from GreyNoise"
            }
        }
    
    if "error" in raw_result:
        return {
            "greynoise": {
                "error": raw_result.get("error", "Unknown error"),
                "details": raw_result.get("details", "")
            }
        }
    
    if "raw_data" not in raw_result:
        return {
            "greynoise": {
                "error": "No data received from GreyNoise"
            }
        }
    
    data = raw_result["raw_data"]
    ip = raw_result.get("ip", "Unknown")
    
    normalized = {
        "greynoise": {
            "ip": data.get("ip", ip),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "link": f"https://viz.greynoise.io/ip/{ip}",
            "raw": data,
        }
    }
    
    logger.info(f"Normalized GreyNoise result for {ip}")
    return normalized

