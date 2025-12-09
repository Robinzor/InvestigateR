"""
crt.sh normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime
import re

logger = logging.getLogger(__name__)


def format_crtsh_date(date_str: str) -> str:
    """
    Format crt.sh timestamp to dd-mm-yyyy HH:MM:SS format (same as URLScan).
    
    Args:
        date_str: ISO timestamp string (e.g., "2024-01-15T10:30:00" or "2024-01-15T10:30:00.123456")
        
    Returns:
        Formatted date string (e.g., "15-01-2024 10:30:00")
    """
    if not date_str or date_str == "Unknown":
        return "Unknown"
    
    try:
        # Try parsing ISO format (e.g., "2024-01-15T10:30:00" or "2024-01-15T10:30:00.123456")
        if 'T' in date_str:
            # Split date and time parts
            parts = date_str.split('T')
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            
            # Remove microseconds if present
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
        logger.warning(f"Error formatting crt.sh date '{date_str}': {e}")
        return date_str  # Return original if parsing fails


def normalize_crtsh_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize crt.sh API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_crtsh_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "crtsh": {
                "error": "No certificates found"
            }
        }
    
    certificates = raw_result["raw_data"]
    domain = raw_result.get("domain", "Unknown")
    
    # Process certificates
    processed_certificates = []
    unique_domains = {}
    
    for cert in certificates:
        try:
            # Parse dates
            raw_not_before = cert.get('not_before', '')
            raw_not_after = cert.get('not_after', '')
            raw_logged_at = cert.get('entry_timestamp', '') or cert.get('entry_date', '') or cert.get('first_seen', '')
            
            not_before = ''
            not_after = ''
            logged_at = ''
            status = 'Unknown'
            
            try:
                if raw_not_before:
                    not_before = format_crtsh_date(raw_not_before)
                if raw_not_after:
                    # Parse to check status, but format for display
                    try:
                        dt_na = datetime.strptime(raw_not_after.split('.')[0], '%Y-%m-%dT%H:%M:%S')
                        status = 'Valid' if dt_na > datetime.utcnow() else 'Expired'
                    except ValueError:
                        try:
                            dt_na = datetime.strptime(raw_not_after, '%Y-%m-%dT%H:%M:%S')
                            status = 'Valid' if dt_na > datetime.utcnow() else 'Expired'
                        except ValueError:
                            status = 'Unknown'
                    not_after = format_crtsh_date(raw_not_after)
                if raw_logged_at:
                    logged_at = format_crtsh_date(raw_logged_at)
                else:
                    # Use not_before if available, otherwise current time
                    if raw_not_before:
                        logged_at = format_crtsh_date(raw_not_before)
                    else:
                        logged_at = datetime.utcnow().strftime('%d-%m-%Y %H:%M:%S')
            except Exception as e:
                logger.warning(f"Error formatting dates: {e}")
                logged_at = datetime.utcnow().strftime('%d-%m-%Y %H:%M:%S')
            
            # Extract issuer name
            issuer_name = cert.get('issuer_name', '')
            if issuer_name:
                issuer_name = re.sub(r'CN=([^,]+).*', r'\1', issuer_name)
            
            common_name = cert.get('common_name', '')
            if not common_name:
                continue
            
            processed_certificates.append({
                'common_name': common_name,
                'issuer_name': issuer_name,
                'not_before': not_before,
                'not_after': not_after,
                'status': status,
                'url': f"https://crt.sh/?id={cert.get('id', '')}",
                'logged_at': logged_at
            })
            
            # Track unique domains
            cn = common_name.lower()
            if cn not in unique_domains or logged_at > unique_domains[cn].get('logged_at', ''):
                unique_domains[cn] = {
                    'logged_at': logged_at,
                    'issuer': issuer_name
                }
        except Exception as e:
            logger.warning(f"Error processing certificate: {str(e)}")
            continue
    
    # Sort certificates by logged_at date (newest first)
    processed_certificates.sort(key=lambda c: c.get('logged_at', ''), reverse=True)
    
    # Convert unique domains to list
    unique_domains_list = [
        {
            'domain': domain_name,
            'last_issued': info['logged_at'],
            'issuer': info['issuer']
        }
        for domain_name, info in unique_domains.items()
    ]
    unique_domains_list.sort(key=lambda x: x['last_issued'], reverse=True)
    
    normalized = {
        "crtsh": {
            "certificates": processed_certificates,
            "unique_domains": unique_domains_list,
            "total_certificates": len(processed_certificates),
            "total_unique_domains": len(unique_domains_list)
        }
    }
    
    logger.info(f"Normalized crt.sh result for {domain}")
    return normalized

