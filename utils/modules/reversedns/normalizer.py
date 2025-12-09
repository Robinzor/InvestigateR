"""
ReverseDNS normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_reversedns_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize reverse DNS lookup result into a standardized format.
    
    Args:
        raw_result: Raw DNS lookup result from query_reversedns_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "reversedns": {
                "error": "No reverse DNS data found"
            }
        }
    
    data = raw_result["raw_data"]
    
    normalized = {
        "reversedns": {
            "hostname": data.get("hostname", "Unknown"),
            "aliases": data.get("aliases", []),
            "addresses": data.get("addresses", [])
        }
    }
    
    logger.info(f"Normalized reverse DNS result for {raw_result.get('ip', 'Unknown')}")
    return normalized

