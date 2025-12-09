"""
WaybackMachine normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_waybackmachine_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize Wayback Machine API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_waybackmachine_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        logger.warning("Wayback Machine: No raw_result or raw_data missing")
        return {
            "wayback_machine": {
                "error": "No snapshots found",
                "is_safe": True  # Safe to hide when no results
            }
        }
    
    data = raw_result["raw_data"]
    domain = raw_result.get("domain", "Unknown")
    
    # Check if data is empty or invalid
    if not data:
        logger.warning(f"Wayback Machine: Empty data for {domain}")
        return {
            "wayback_machine": {
                "error": "No snapshots found",
                "is_safe": True  # Safe to hide when no results
            }
        }
    
    if not isinstance(data, list):
        logger.warning(f"Wayback Machine: Data is not a list, type: {type(data)}")
        return {
            "wayback_machine": {
                "error": "Invalid response format",
                "is_safe": True  # Safe to hide when invalid format
            }
        }
    
    # Process snapshots
    # Wayback Machine CDX API returns: [urlkey, timestamp, original, mimetype, statuscode, digest, redirect, ...]
    # urlkey is the canonicalized URL (e.g., "nl,nu)/")
    # timestamp is in format YYYYMMDDHHmmss
    # original is the original URL
    snapshots = []
    
    # Check if first row is headers (contains text like "timestamp" or "urlkey")
    start_index = 0
    if len(data) > 0 and isinstance(data[0], list):
        first_row = data[0]
        # If first row looks like headers (contains string "timestamp" or similar), skip it
        if len(first_row) > 0 and isinstance(first_row[0], str) and ("timestamp" in first_row[0].lower() or "urlkey" in first_row[0].lower()):
            start_index = 1
            logger.debug("Skipping header row in Wayback Machine response")
    
    if len(data) > start_index:
        for row in data[start_index:]:
            if not isinstance(row, list) or len(row) < 2:
                continue
                
            # Default CDX format: [urlkey, timestamp, original, mimetype, statuscode, digest, ...]
            # urlkey is the canonicalized URL (e.g., "nl,nu)/")
            # timestamp is in format YYYYMMDDHHmmss
            # original is the original URL
            urlkey = str(row[0]).strip() if len(row) > 0 and row[0] else ""
            timestamp = str(row[1]).strip() if len(row) > 1 and row[1] else ""
            original_url = str(row[2]).strip() if len(row) > 2 and row[2] else ""
            
            # Skip empty rows
            if not timestamp:
                logger.debug(f"Skipping row with empty timestamp: {row[:3]}")
                continue
            
            # If original_url is empty, try to reconstruct from urlkey
            if not original_url and urlkey:
                # Reconstruct URL from urlkey - urlkey format is "domain,path)/"
                # For "nl,nu)/" we need to reconstruct to "http://nu.nl/"
                try:
                    if urlkey.endswith(")/"):
                        parts = urlkey[:-2].split(",")
                        if len(parts) >= 2:
                            # Reverse the domain parts and reconstruct
                            domain_parts = parts[:-1]
                            path = parts[-1] if parts[-1] else ""
                            domain = ".".join(reversed(domain_parts))
                            original_url = f"http://{domain}/{path}" if path else f"http://{domain}/"
                            logger.debug(f"Reconstructed URL from urlkey {urlkey} to {original_url}")
                except Exception as e:
                    logger.debug(f"Error reconstructing URL from urlkey {urlkey}: {e}")
            
            # Use original_url, or fallback to domain from query if we have it
            display_url = original_url if original_url else domain
            
            # Skip if we don't have a URL to display
            if not display_url:
                logger.debug(f"Skipping row - no URL to display: timestamp={timestamp}, urlkey={urlkey}")
                continue
            
            # Format timestamp to readable date (YYYYMMDDHHmmss -> YYYY-MM-DD HH:mm:ss)
            formatted_date = ""
            if timestamp and len(timestamp) >= 8:
                try:
                    year = timestamp[0:4]
                    month = timestamp[4:6]
                    day = timestamp[6:8]
                    hour = timestamp[8:10] if len(timestamp) >= 10 else "00"
                    minute = timestamp[10:12] if len(timestamp) >= 12 else "00"
                    second = timestamp[12:14] if len(timestamp) >= 14 else "00"
                    formatted_date = f"{year}-{month}-{day} {hour}:{minute}:{second}"
                except Exception as e:
                    logger.debug(f"Error formatting timestamp {timestamp}: {e}")
                    formatted_date = timestamp
            else:
                formatted_date = timestamp
            
            # Create archive URL
            archive_url = f"http://web.archive.org/web/{timestamp}/{display_url}" if timestamp and display_url else ""
            
            snapshots.append({
                "timestamp": timestamp,
                "date": formatted_date,
                "original_url": display_url,
                "url": archive_url  # For backwards compatibility
            })
            
            logger.debug(f"Added snapshot: date={formatted_date}, url={display_url}")
    
    # Check if we have any snapshots
    if not snapshots:
        logger.warning(f"Wayback Machine: No snapshots extracted for {domain}, data length: {len(data)}")
        return {
            "wayback_machine": {
                "error": "No snapshots found",
                "is_safe": True  # Safe to hide when no results
            }
        }
    
    # Get first and last snapshot dates
    first_snapshot = None
    last_snapshot = None
    if snapshots:
        # Snapshots are typically in reverse chronological order (newest first)
        last_snapshot = snapshots[0].get("date", "") if snapshots else ""
        first_snapshot = snapshots[-1].get("date", "") if snapshots else ""
    
    normalized = {
        "wayback_machine": {
            "domain": domain,
            "snapshots": snapshots[:50],  # Limit to 50 most recent
            "total_snapshots": len(snapshots),
            "first_snapshot": first_snapshot,
            "last_snapshot": last_snapshot,
            "is_safe": False  # Always show when snapshots are found
        }
    }
    
    logger.info(f"Normalized Wayback Machine result for {domain}: {len(snapshots)} snapshots")
    return normalized

