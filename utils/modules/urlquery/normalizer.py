"""
URLQuery normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def format_urlquery_date(date_str: str) -> str:
    """
    Format URLQuery timestamp to dd-mm-yyyy HH:MM:SS format (same as URLScan).
    
    Args:
        date_str: ISO timestamp string (e.g., "2025-12-06T18:18:42Z")
        
    Returns:
        Formatted date string (e.g., "06-12-2025 18:18:42")
    """
    if not date_str or date_str == "Unknown":
        return "Unknown"
    
    try:
        # Try parsing ISO format (e.g., "2025-12-06T18:18:42Z")
        if 'T' in date_str:
            # Split date and time parts
            parts = date_str.split('T')
            date_part = parts[0]
            time_part = parts[1] if len(parts) > 1 else "00:00:00"
            
            # Remove timezone if present (Z, +HH:MM, -HH:MM)
            if time_part.endswith('Z'):
                time_part = time_part[:-1]
            elif '+' in time_part:
                time_part = time_part.split('+')[0]
            elif '-' in time_part and len(time_part.split('-')) > 2:
                # Check if it's a timezone offset (has more than 2 parts when split by -)
                time_parts = time_part.split('-')
                if len(time_parts) > 2:
                    time_part = '-'.join(time_parts[:-1])  # Remove timezone part
            
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
        logger.warning(f"Error formatting URLQuery date '{date_str}': {e}")
        return date_str  # Return original if parsing fails


def normalize_urlquery_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize URLQuery API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_urlquery_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result:
        return {
            "urlquery": {
                "observable": "Unknown",
                "query_string": "Unknown",
                "total_hits": 0,
                "safe": True,
                "message": "No data received from URLQuery",
                "verdicts": [],
                "reports": [],
                "error": "No data received from URLQuery"
            }
        }
    
    if "error" in raw_result:
        return {
            "urlquery": {
                "observable": raw_result.get("observable", raw_result.get("url", "Unknown")),
                "query_string": raw_result.get("query_string", raw_result.get("observable", raw_result.get("url", "Unknown"))),
                "total_hits": 0,
                "safe": True,
                "message": raw_result.get("error", "Unknown error"),
                "verdicts": [],
                "reports": [],
                "error": raw_result.get("error", "Unknown error")
            }
        }
    
    data = raw_result.get("raw_data", {})
    observable_original = raw_result.get("observable", raw_result.get("url", "Unknown"))
    query_string = raw_result.get("query_string", observable_original)
    
    # Remove protocol from observable if present (for consistency)
    observable = observable_original
    if observable.startswith(('http://', 'https://')):
        # Remove protocol from observable
        parsed = urlparse(observable)
        observable = parsed.netloc
        if parsed.path:
            observable += parsed.path
        if parsed.query:
            observable += '?' + parsed.query
        if parsed.fragment:
            observable += '#' + parsed.fragment
        logger.debug(f"URLQuery: Removed protocol from observable '{observable_original}' -> '{observable}'")
    
    # Determine if the ORIGINAL observable is a domain (not a URL)
    # We use the original observable to determine query type, not the query_string
    # because query_string might be the domain if URL query had no results
    is_domain_query_original = not observable_original.startswith(('http://', 'https://')) and '/' not in observable_original and '?' not in observable_original
    is_url_query_original = observable_original.startswith(('http://', 'https://')) or (not is_domain_query_original and ('/' in observable_original or '?' in observable_original))
    
    # Also check the observable without protocol
    is_domain_query = '/' not in observable and '?' not in observable
    is_url_query = not is_domain_query
    
    # Use original query type if it was a URL query
    is_url_query = is_url_query_original or (is_url_query and not is_domain_query_original)
    is_domain_query = is_domain_query_original and not is_url_query_original
    
    domain_to_match = None
    url_to_match = None
    
    if is_domain_query:
        # Normalize domain (lowercase, remove www. if present for matching)
        domain_to_match = observable.lower().strip()
        if domain_to_match.startswith('www.'):
            domain_to_match = domain_to_match[4:]
        logger.info(f"URLQuery: Filtering reports for domain query '{observable_original}' (normalized: '{domain_to_match}')")
    elif is_url_query:
        # For URLs, use the observable (without protocol) for matching, not query_string
        # query_string might be the domain if the URL query had no results and we fell back to domain
        # But we still want to match on the original URL path
        url_to_match = observable.lower().strip()  # Use observable (URL without protocol), not query_string
        logger.info(f"URLQuery: Filtering reports for URL query '{observable_original}' (matching against: '{url_to_match}')")
        logger.debug(f"URLQuery: query_string='{query_string}', observable='{observable}', url_to_match='{url_to_match}'")
    
    # URLQuery API returns: query, total_hits, time_used, limit, offset, reports[]
    # Ensure we handle None values properly
    total_hits = data.get("total_hits") or 0
    reports = data.get("reports") or []
    
    # Ensure reports is always a list, never None
    if reports is None:
        reports = []
    
    logger.debug(f"URLQuery normalizer: total_hits={total_hits}, reports_count={len(reports)}")
    
    # If no reports at all, return early
    if total_hits == 0 and not reports:
        return {
            "urlquery": {
                "observable": observable,
                "query_string": query_string,
                "total_hits": 0,
                "safe": True,
                "message": "No reports found in URLQuery database",
                "verdicts": [],
                "reports": [],
                "time_used": data.get("time_used", "") or ""
            }
        }
    
    # Process reports
    processed_reports = []
    all_detections = []
    all_verdicts = set()
    
    for report in reports:
        # Extract URL info first (needed for filtering)
        url_info = report.get("url", {})
        report_url = url_info.get("addr", "")
        
        # For domain queries, filter reports to only include those where the domain exactly matches
        if is_domain_query and domain_to_match:
            report_domain = url_info.get("domain", "")
            report_fqdn = url_info.get("fqdn", "")
            
            # Normalize report domain for comparison
            report_domain_normalized = report_domain.lower().strip() if report_domain else ""
            report_fqdn_normalized = report_fqdn.lower().strip() if report_fqdn else ""
            
            # Remove www. prefix for comparison
            if report_domain_normalized.startswith('www.'):
                report_domain_normalized = report_domain_normalized[4:]
            if report_fqdn_normalized.startswith('www.'):
                report_fqdn_normalized = report_fqdn_normalized[4:]
            
            # Check if domain matches (exact match on domain or fqdn)
            domain_matches = (
                report_domain_normalized == domain_to_match or
                report_fqdn_normalized == domain_to_match
            )
            
            if not domain_matches:
                # Skip this report - domain doesn't match
                logger.debug(f"URLQuery: Skipping report with domain '{report_domain}' (normalized: '{report_domain_normalized}') - doesn't match '{domain_to_match}'")
                continue
        
        # For URL queries, filter reports to only include those where the URL matches
        # Match on base URL (without query parameters) to include URLs with query params
        elif is_url_query and url_to_match:
            # Normalize report URL for comparison (remove protocol if present)
            report_url_normalized = report_url.lower().strip() if report_url else ""
            if report_url_normalized.startswith(('http://', 'https://')):
                parsed = urlparse(report_url_normalized)
                report_url_normalized = parsed.netloc
                if parsed.path:
                    report_url_normalized += parsed.path
                if parsed.query:
                    report_url_normalized += '?' + parsed.query
                if parsed.fragment:
                    report_url_normalized += '#' + parsed.fragment
            
            # Extract base URL (without query parameters) for both report and query
            # This allows matching webeasyt.com/mVttL7CH with webeasyt.com/mVttL7CH?utm=a...
            report_base_url = report_url_normalized.split('?')[0].split('#')[0]
            query_base_url = url_to_match.split('?')[0].split('#')[0]
            
            # Check if base URLs match (exact match on base URL)
            url_matches = report_base_url == query_base_url
            
            if not url_matches:
                # Skip this report - URL doesn't match
                logger.debug(f"URLQuery: Skipping report with URL '{report_url}' (base: '{report_base_url}') - doesn't match query base '{query_base_url}'")
                continue
            else:
                logger.debug(f"URLQuery: URL match found! '{report_base_url}' matches '{query_base_url}'")
        
        report_id = report.get("report_id", "")
        report_date = report.get("date", "")
        report_status = report.get("status", "unknown")
        
        # report_url is already extracted above for filtering
        # url_info is also already available from filtering logic
        fqdn = url_info.get("fqdn", "")
        domain = url_info.get("domain", "")
        
        # Extract IP info
        ip_info = report.get("ip", {})
        ip_addr = ip_info.get("addr", "")
        asn = ip_info.get("asn", "")
        as_name = ip_info.get("as", "")
        country = ip_info.get("country", "")
        country_code = ip_info.get("country_code", "")
        
        # Extract detection information
        detection = report.get("detection", {})
        analyzer_detections = detection.get("analyzer", []) or []  # Ensure it's always a list, even if None
        
        report_detections = []
        if analyzer_detections:  # Only iterate if not empty
            for det in analyzer_detections:
                verdict = det.get("verdict", "").lower()
                all_verdicts.add(verdict)
                
                report_detections.append({
                    "sensor_name": det.get("sensor_name", ""),
                    "sensor_type": det.get("sensor_type", ""),
                    "title": det.get("title", ""),
                    "alert": det.get("alert", ""),
                    "verdict": verdict,
                    "severity": det.get("severity", ""),
                    "comment": det.get("comment", ""),
                    "link": det.get("link", ""),
                    "scan_date": format_urlquery_date(det.get("scan_date", ""))
                })
                all_detections.append(det)
        
        # Extract final URL info
        final = report.get("final", {})
        final_url = final.get("url", {})
        title = final.get("title", "")
        
        processed_reports.append({
            "report_id": report_id,
            "date": format_urlquery_date(report_date),
            "status": report_status,
            "url": report_url,
            "fqdn": fqdn,
            "domain": domain,
            "ip": ip_addr,
            "asn": asn,
            "as_name": as_name,
            "country": country,
            "country_code": country_code,
            "title": title,
            "detections": report_detections if report_detections else [],  # Ensure it's always a list, never None
            "report_url": f"https://urlquery.net/report/{report_id}" if report_id else None
        })
    
    # For domain and URL queries, update total_hits to reflect filtered reports
    if is_domain_query or is_url_query:
        filtered_total_hits = len(processed_reports)
        query_type = "domain" if is_domain_query else "URL"
        logger.info(f"URLQuery: {query_type.capitalize()} query filtered {total_hits} total hits down to {filtered_total_hits} matching reports")
        total_hits = filtered_total_hits
    
    # Determine overall safety
    is_safe = not any(v in ["phishing", "malicious", "suspicious"] for v in all_verdicts)
    
    # Build message
    if all_verdicts:
        verdicts_list = sorted(list(all_verdicts))
        message = f"Found {total_hits} report(s) with verdicts: {', '.join(verdicts_list)}"
    else:
        message = f"Found {total_hits} report(s) with no detections"
    
    normalized = {
        "urlquery": {
            "observable": observable,
            "query_string": query_string,
            "total_hits": total_hits or 0,  # Ensure it's always a number (filtered for domain queries)
            "safe": is_safe,
            "message": message,
            "verdicts": sorted(list(all_verdicts)) if all_verdicts else [],  # Ensure it's always a list
            "reports": processed_reports if processed_reports else [],  # Ensure it's always a list (filtered for domain queries)
            "time_used": data.get("time_used", "") or ""
        }
    }
    
    logger.info(f"Normalized URLQuery result for {observable}: safe={is_safe}, total_hits={total_hits}, verdicts={list(all_verdicts)}")
    return normalized

