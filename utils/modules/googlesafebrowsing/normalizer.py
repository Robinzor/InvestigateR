"""
Google Safe Browsing normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_googlesafebrowsing_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize Google Safe Browsing API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_googlesafebrowsing_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {
            "googlesafebrowsing": {
                "error": "No data received from Google Safe Browsing"
            }
        }
    
    if "error" in raw_result:
        return {
            "googlesafebrowsing": {
                "observable": raw_result.get("observable", "Unknown"),
                "error": raw_result.get("error", "Unknown error")
            }
        }
    
    data = raw_result.get("raw_data", {})
    observable = raw_result.get("observable", "Unknown")
    threat_entries = raw_result.get("threat_entries", [])
    
    # Check if there are any matches
    # Google Safe Browsing API returns {} (empty dict) when no threats, or {"matches": [...]} when threats found
    matches = data.get("matches", [])
    
    # Log the raw data for debugging
    logger.debug(f"Google Safe Browsing normalizer - raw_data keys: {list(data.keys())}, matches: {matches}, checked {len(threat_entries)} URLs")
    
    if not matches:
        # No threats found for any of the checked URLs
        checked_count = len(threat_entries) if threat_entries else 1
        normalized = {
            "googlesafebrowsing": {
                "observable": observable,
                "threat_entries": threat_entries,
                "safe": True,
                "threats": [],
                "message": f"No threats detected (checked {checked_count} URL(s))",
                "checked_urls": threat_entries
            }
        }
    else:
        # Threats found - extract threat information
        threats = []
        threat_types = set()
        platform_types = set()
        
        for match in matches:
            threat_type = match.get("threatType", "UNKNOWN")
            platform_type = match.get("platformType", "UNKNOWN")
            threat_entry_type = match.get("threatEntryType", "UNKNOWN")
            cache_duration = match.get("cacheDuration", "")
            
            threat_types.add(threat_type)
            platform_types.add(platform_type)
            
            threats.append({
                "threat_type": threat_type,
                "platform_type": platform_type,
                "threat_entry_type": threat_entry_type,
                "cache_duration": cache_duration
            })
        
        # Extract URLs from matches to show which specific URLs are flagged
        flagged_urls = []
        for match in matches:
            threat_url = match.get("threat", {}).get("url", "Unknown")
            if threat_url and threat_url not in flagged_urls:
                flagged_urls.append(threat_url)
        
        normalized = {
            "googlesafebrowsing": {
                "observable": observable,
                "threat_entries": threat_entries,
                "safe": False,
                "threats": threats,
                "threat_types": sorted(list(threat_types)),
                "platform_types": sorted(list(platform_types)),
                "flagged_urls": flagged_urls,
                "message": f"Threat detected: {', '.join(sorted(threat_types))} on {len(flagged_urls)} URL(s)"
            }
        }
    
    logger.info(f"Normalized Google Safe Browsing result for {observable}: safe={normalized['googlesafebrowsing'].get('safe', False)}")
    return normalized

