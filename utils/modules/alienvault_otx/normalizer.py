"""
AlienVault OTX normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def format_otx_date(date_str: str) -> str:
    """
    Format OTX timestamp to dd-mm-yyyy HH:MM:SS format.
    
    Args:
        date_str: ISO timestamp string (e.g., "2018-02-10T00:36:00.396000")
        
    Returns:
        Formatted date string (e.g., "10-02-2018 00:36:00")
    """
    if not date_str:
        return ""
    
    try:
        # Try parsing ISO format with microseconds
        # Formats: "2018-02-10T00:36:00.396000" or "2025-12-01T00:00:06.005000"
        if 'T' in date_str:
            # Split date and time parts
            parts = date_str.split('T')
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            
            # Remove microseconds if present (everything after the dot)
            if '.' in time_part:
                time_part = time_part.split('.')[0]
            
            # Ensure time has at least HH:MM:SS format
            time_parts = time_part.split(':')
            if len(time_parts) < 3:
                time_part = f"{time_part}:00" if len(time_parts) == 2 else f"{time_part}:00:00"
            
            # Parse and format
            dt = datetime.strptime(f"{date_part} {time_part}", '%Y-%m-%d %H:%M:%S')
            return dt.strftime('%d-%m-%Y %H:%M:%S')
        else:
            # Try parsing as date only
            dt = datetime.strptime(date_str, '%Y-%m-%d')
            return dt.strftime('%d-%m-%Y 00:00:00')
    except (ValueError, AttributeError) as e:
        logger.warning(f"Error formatting OTX date '{date_str}': {e}")
        return date_str  # Return original if parsing fails


def normalize_otx_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize AlienVault OTX API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_otx_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "alienvault_otx": {
                "error": "No data received from AlienVault OTX"
            }
        }
    
    data = raw_result["raw_data"]
    observable = raw_result.get("observable", "Unknown")
    obs_type = raw_result.get("type", "unknown")
    
    # Check if not found
    if raw_result.get("not_found") or not data:
        return {
            "alienvault_otx": {
                "observable": observable,
                "found": False,
                "message": "No threat intelligence found"
            }
        }
    
    # Extract key information from OTX response
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    pulses = data.get("pulse_info", {}).get("pulses", [])
    
    # Extract reputation
    reputation = data.get("reputation", 0)
    
    # Extract validation
    validation = data.get("validation", [])
    
    # Extract sections (threat intelligence data)
    sections = {}
    if "sections" in data:
        sections = data["sections"]
    
    # Extract pulse details
    pulse_details = []
    for pulse in pulses[:10]:  # Limit to 10 most recent pulses
        created = pulse.get("created", "")
        modified = pulse.get("modified", "")
        
        pulse_details.append({
            "name": pulse.get("name", ""),
            "id": pulse.get("id", ""),
            "created": format_otx_date(created),
            "modified": format_otx_date(modified),
            "author": pulse.get("author", {}).get("username", ""),
            "tags": pulse.get("tags", []),
            "references": pulse.get("references", [])
        })
    
    # Extract additional info based on type
    additional_info = {}
    if obs_type == "ip":
        additional_info = {
            "country_code": data.get("country_code", ""),
            "asn": data.get("asn", ""),
            "base_indicator": data.get("base_indicator", {})
        }
    elif obs_type == "domain":
        additional_info = {
            "whois": data.get("whois", ""),
            "base_indicator": data.get("base_indicator", {})
        }
    elif obs_type == "hash":
        additional_info = {
            "file_type": data.get("file_type", ""),
            "file_size": data.get("file_size", 0),
            "md5": data.get("md5", ""),
            "sha1": data.get("sha1", ""),
            "sha256": data.get("sha256", ""),
            "ssdeep": data.get("ssdeep", "")
        }
    
    normalized = {
        "alienvault_otx": {
            "observable": observable,
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "reputation": reputation,
            "validation": validation,
            "pulses": pulse_details,
            "sections": sections,
            **additional_info,
            "link": f"https://otx.alienvault.com/indicator/{obs_type}/{observable}"
        }
    }
    
    logger.info(f"Normalized AlienVault OTX result for {observable}: {pulse_count} pulses found")
    return normalized

