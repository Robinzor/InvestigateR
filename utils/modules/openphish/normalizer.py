"""
OpenPhish normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_openphish_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize OpenPhish lookup result into a standardized format.
    
    Args:
        raw_result: Raw result from query_openphish_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "openphish": {
                "error": "No data received from OpenPhish"
            }
        }
    
    data = raw_result["raw_data"]
    observable = raw_result.get("observable", "Unknown")
    
    # Check for errors
    if "error" in data:
        return {
            "openphish": {
                "observable": observable,
                "error": data["error"]
            }
        }
    
    # Extract results
    in_feed = data.get("in_feed", False)
    is_phishing = data.get("is_phishing", False)
    domain = data.get("domain", observable)
    
    # Calculate value: 1 if in feed, 0 if safe
    value = 1 if in_feed else 0
    
    # Primary link
    link = "https://openphish.com"
    
    normalized = {
        "openphish": {
            "observable": observable,
            "domain": domain,
            "in_feed": in_feed,
            "is_phishing": is_phishing,
            "link": link,
            "value": value  # 1 = has data (phishing), 0 = safe (not in feed)
        }
    }
    
    logger.info(f"Normalized OpenPhish result for {observable}: is_phishing={is_phishing}")
    return normalized

