"""
URLScanSearch normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def format_urlscan_date(date_str: str) -> str:
    """
    Format URLScan timestamp to dd-mm-yyyy HH:MM:SS format.
    
    Args:
        date_str: ISO timestamp string or Unix timestamp (e.g., "2024-01-15T10:30:00.000Z" or "1705315800")
        
    Returns:
        Formatted date string (e.g., "15-01-2024 10:30:00")
    """
    if not date_str or date_str == "Unknown":
        return "Unknown"
    
    try:
        # Try parsing ISO format (e.g., "2024-01-15T10:30:00.000Z")
        if 'T' in date_str:
            # Split date and time parts
            parts = date_str.split('T')
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            
            # Remove timezone and microseconds if present
            if 'Z' in time_part:
                time_part = time_part.replace('Z', '')
            if '+' in time_part:
                time_part = time_part.split('+')[0]
            if '-' in time_part and ':' in time_part.split('-')[1]:
                # Handle timezone offset like "-05:00"
                time_part = time_part.split('-')[0] if time_part.count('-') > 1 else time_part
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
            # Try parsing as Unix timestamp (integer string)
            try:
                timestamp = int(float(date_str))
                dt = datetime.fromtimestamp(timestamp)
                return dt.strftime('%d-%m-%Y %H:%M:%S')
            except (ValueError, OSError):
                # Try parsing as date only
                dt = datetime.strptime(date_str, '%Y-%m-%d')
                return dt.strftime('%d-%m-%Y 00:00:00')
    except (ValueError, AttributeError) as e:
        logger.warning(f"Error formatting URLScan date '{date_str}': {e}")
        return date_str  # Return original if parsing fails


def normalize_urlscan_search_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize URLScan search API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_urlscan_search_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "urlscan_search": {
                "error": "No search results found"
            }
        }
    
    data = raw_result["raw_data"]
    
    # Transform results into scan_history format expected by template
    scan_history = []
    results = data.get("results", [])
    
    for result in results:
        raw_time = result.get("task", {}).get("time", "Unknown")
        formatted_time = format_urlscan_date(raw_time) if raw_time != "Unknown" else "Unknown"
        scan_entry = {
            "scan_date": formatted_time,
            "url": result.get("page", {}).get("url", "Unknown"),
            "report_url": f"https://urlscan.io/result/{result.get('_id', '')}",
            "screenshot_url": result.get("screenshot", "")
        }
        scan_history.append(scan_entry)
    
    # Build report URL for viewing all results
    observable = raw_result.get("observable", "Unknown")
    report_url = f"https://urlscan.io/search/#q={observable}"
    
    normalized = {
        "urlscan_search": {
            "observable": observable,
            "results": results,  # Keep original results for backwards compatibility
            "total": data.get("total", 0),
            "scan_history": scan_history,  # Format expected by template
            "report_url": report_url
        }
    }
    
    logger.info(f"Normalized URLScan search result for {observable}: {len(scan_history)} scans found")
    return normalized

