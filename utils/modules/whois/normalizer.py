"""
WHOIS normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_whois_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize WHOIS result into a standardized format.
    
    Args:
        raw_result: Raw WHOIS data from query_whois_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "rdap": {
                "error": "Failed to retrieve WHOIS data"
            }
        }
    
    data = raw_result["raw_data"]
    
    normalized = {
        "rdap": {
            'creation_date': data.get('creation_date'),
            'expiration_date': data.get('expiration_date'),
            'registrar': data.get('registrar'),
            'registrant': data.get('registrant'),
            'name_servers': data.get('name_servers', []),
            'all_emails': data.get('all_emails', []),
            'link': data.get('link', f"https://who.is/whois/{raw_result.get('domain', '')}")
        }
    }
    
    logger.info(f"Normalized WHOIS result for {raw_result.get('domain', 'Unknown')}")
    return normalized

