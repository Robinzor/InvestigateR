"""
PhishTank normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_phishtank_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize PhishTank blacklist lookup result into a standardized format.
    
    Args:
        raw_result: Raw result from query_phishtank_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "phishtank": {
                "error": "No data received from PhishTank"
            }
        }
    
    data = raw_result["raw_data"]
    url = raw_result.get("url", "Unknown")
    host = raw_result.get("host", "")
    
    # Check for errors
    if "error" in data:
        return {
            "phishtank": {
                "url": url,
                "host": host,
                "error": data["error"]
            }
        }
    
    # Extract results from PhishTank blacklist lookup
    in_database = data.get("in_database", False)
    phish_id = data.get("phish_id")
    verified = data.get("verified", "no")
    
    # All entries in online-valid.csv are verified, so if in_database is True, it's verified
    is_phishing = in_database and verified == "yes"
    
    # Build PhishTank detail URL
    phish_detail_url = None
    if phish_id:
        phish_detail_url = f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}"
    
    # Remove protocol from URL for display (consistent with other modules)
    from urllib.parse import urlparse
    display_url = url
    if url.startswith(('http://', 'https://')):
        parsed = urlparse(url)
        display_url = parsed.netloc
        if parsed.path:
            display_url += parsed.path
        if parsed.query:
            display_url += '?' + parsed.query
        if parsed.fragment:
            display_url += '#' + parsed.fragment
        logger.debug(f"PhishTank: Removed protocol from URL '{url}' -> '{display_url}' for display")
    
    normalized = {
        "phishtank": {
            "url": display_url,  # URL without protocol for display
            "host": host,
            "in_database": in_database,
            "verified": verified == "yes",
            "is_phishing": is_phishing,
            "phish_id": phish_id,
            "phish_detail_url": phish_detail_url,
            "link": phish_detail_url or "https://www.phishtank.com"
        }
    }
    
    logger.info(f"Normalized PhishTank result for {url} (host: {host}): in_database={in_database}, verified={is_phishing}, phish_id={phish_id}")
    return normalized

