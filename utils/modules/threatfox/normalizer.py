"""
ThreatFox normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_threatfox_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize ThreatFox API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_threatfox_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {
            "threatfox": {
                "error": "No data received from ThreatFox",
                "is_safe": True
            }
        }
    
    # Check for error in raw_result
    if "error" in raw_result:
        return {
            "threatfox": {
                "error": raw_result["error"],
                "observable": raw_result.get("observable", "Unknown"),
                "is_safe": True
            }
        }
    
    if "raw_data" not in raw_result:
        return {
            "threatfox": {
                "error": "Invalid response format from ThreatFox",
                "is_safe": True
            }
        }
    
    data = raw_result["raw_data"]
    observable = raw_result.get("observable", "Unknown")
    found = raw_result.get("found", False)
    ioc_type = raw_result.get("ioc_type", "unknown")
    
    # Check if data is a dict (error/no_results case) or empty list
    if isinstance(data, dict):
        # Check if IOC was not found (dict with query_status)
        query_status = data.get("query_status", "")
        if query_status == "no_results" or not found:
            return {
                "threatfox": {
                    "found": False,
                    "status": "IOC not found in ThreatFox database",
                    "observable": observable,
                    "ioc_type": ioc_type,
                    "is_safe": True  # Safe to hide when no results
                }
            }
        # If it's a dict but not no_results, might be an error response
        return {
            "threatfox": {
                "found": False,
                "status": f"Unexpected response: {query_status}",
                "observable": observable,
                "ioc_type": ioc_type,
                "is_safe": True
            }
        }
    
    # IOC was found - extract relevant information
    # ThreatFox returns a list of IOC entries when found
    if isinstance(data, list):
        if len(data) == 0:
            # Empty list means no results
            return {
                "threatfox": {
                    "found": False,
                    "status": "IOC not found in ThreatFox database",
                    "observable": observable,
                    "ioc_type": ioc_type,
                    "is_safe": True  # Safe to hide when no results
                }
            }
        
        # Process all results
        ioc_entries = []
        for entry in data:
            ioc_id = entry.get("id", "Unknown")
            ioc_value = entry.get("ioc", observable)
            ioc_type_entry = entry.get("ioc_type", ioc_type)
            threat_type = entry.get("threat_type", "Unknown")
            malware = entry.get("malware", "Unknown")
            # Handle malware_alias - can be null, string, or list
            malware_alias_raw = entry.get("malware_alias")
            if malware_alias_raw is None:
                malware_alias = []
            elif isinstance(malware_alias_raw, str):
                malware_alias = [malware_alias_raw]  # Convert string to list
            elif isinstance(malware_alias_raw, list):
                malware_alias = malware_alias_raw
            else:
                malware_alias = []  # Fallback for unexpected types
            malware_printable = entry.get("malware_printable", malware)
            first_seen = entry.get("first_seen", "Unknown")
            last_seen = entry.get("last_seen", "Unknown")
            confidence_level = entry.get("confidence_level", 0)
            reference = entry.get("reference")  # Can be string (URL) or null
            tags = entry.get("tags", [])
            reporter = entry.get("reporter", "Unknown")
            
            # Build ThreatFox link
            link = f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id != "Unknown" else None
            
            ioc_entries.append({
                "id": ioc_id,
                "ioc": ioc_value,
                "ioc_type": ioc_type_entry,
                "threat_type": threat_type,
                "malware": malware,
                "malware_alias": malware_alias,
                "malware_printable": malware_printable,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "confidence_level": confidence_level,
                "reference": reference,
                "tags": tags,
                "reporter": reporter,
                "link": link
            })
        
        normalized = {
            "threatfox": {
                "found": True,
                "status": f"Found {len(ioc_entries)} IOC(s) in ThreatFox database",
                "observable": observable,
                "ioc_type": ioc_type,
                "total_results": len(ioc_entries),
                "results": ioc_entries,
                "is_safe": False  # Always show when results are found
            }
        }
        
        logger.info(f"Normalized ThreatFox result for {observable}: {len(ioc_entries)} IOC(s) found")
        return normalized
    else:
        # Unexpected data format
        return {
            "threatfox": {
                "found": False,
                "status": "Unexpected response format",
                "observable": observable,
                "ioc_type": ioc_type,
                "is_safe": True
            }
        }

