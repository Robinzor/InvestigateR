"""
DNSRecords normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_dns_records_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize DNS records result into a standardized format.
    
    Args:
        raw_result: Raw DNS records from query_dns_records_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "dns_records": {
                "error": "No DNS records found"
            }
        }
    
    data = raw_result["raw_data"]
    
    # Format MX records properly (they come as "priority exchange" strings)
    mx_records = []
    for mx in data.get("MX", []):
        if isinstance(mx, str):
            # Parse "priority exchange" format
            parts = mx.split(" ", 1)
            if len(parts) == 2:
                mx_records.append({"preference": parts[0], "exchange": parts[1]})
            else:
                mx_records.append({"preference": "0", "exchange": mx})
        else:
            mx_records.append(mx)
    
    normalized = {
        "dns_records": {
            "domain": raw_result.get("domain", "Unknown"),
            "a_records": data.get("A", []),
            "aaaa_records": data.get("AAAA", []),
            "mx_records": mx_records,
            "ns_records": data.get("NS", []),
            "txt_records": data.get("TXT", []),
            "cname_records": data.get("CNAME", []),
            # Also keep uppercase versions for backwards compatibility
            "A": data.get("A", []),
            "AAAA": data.get("AAAA", []),
            "MX": data.get("MX", []),
            "NS": data.get("NS", []),
            "TXT": data.get("TXT", []),
            "CNAME": data.get("CNAME", [])
        }
    }
    
    logger.info(f"Normalized DNS records result for {raw_result.get('domain', 'Unknown')}")
    return normalized

