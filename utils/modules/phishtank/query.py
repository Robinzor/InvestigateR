"""
PhishTank query module - handles blacklist download and lookup
Uses the PhishTank CSV blacklist like SpiderFoot does
"""
import aiohttp
import logging
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
from pathlib import Path
import time

logger = logging.getLogger(__name__)

# PhishTank CSV blacklist URL
PHISHTANK_BLACKLIST_URL = "https://data.phishtank.com/data/online-valid.csv"
CACHE_DIR = Path.home() / ".investigateR" / "cache"
CACHE_FILE = CACHE_DIR / "phishtank_blacklist.csv"
CACHE_PERIOD_HOURS = 18  # Cache for 18 hours like SpiderFoot


def _ensure_cache_dir():
    """Ensure cache directory exists"""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _is_cache_valid() -> bool:
    """Check if cache is still valid"""
    if not CACHE_FILE.exists():
        return False
    
    cache_age = time.time() - CACHE_FILE.stat().st_mtime
    cache_age_hours = cache_age / 3600
    
    return cache_age_hours < CACHE_PERIOD_HOURS


async def _download_blacklist() -> Optional[str]:
    """
    Download PhishTank blacklist CSV.
    
    Returns:
        str: CSV content or None if download fails
    """
    try:
        logger.info("Downloading PhishTank blacklist from phishtank.com")
        async with aiohttp.ClientSession() as session:
            async with session.get(
                PHISHTANK_BLACKLIST_URL,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'investigateR/1.0'}
            ) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.info(f"Successfully downloaded PhishTank blacklist ({len(content)} bytes)")
                    return content
                else:
                    logger.error(f"PhishTank blacklist returned status {response.status}")
                    return None
    except Exception as e:
        logger.error(f"Error downloading PhishTank blacklist: {e}", exc_info=True)
        return None


def _parse_blacklist(csv_content: str) -> List[Tuple[str, str, str]]:
    """
    Parse PhishTank CSV blacklist.
    Uses SpiderFoot's parsing method: extract host from URL by splitting on "/"
    
    Args:
        csv_content: CSV content from PhishTank
        
    Returns:
        List of tuples: [(phish_id, host, url), ...]
        - phish_id: PhishTank ID
        - host: Extracted host from URL (SpiderFoot method)
        - url: Full URL from blacklist (with protocol)
    """
    entries = []
    
    if not csv_content:
        return entries
    
    for line in csv_content.split('\n'):
        if not line or line.startswith('#'):
            continue
        
        try:
            parts = line.strip().split(',')
            if len(parts) < 2:
                continue
            
            phish_id = parts[0].strip()
            url = str(parts[1].strip()).lower()
            
            # SpiderFoot method: split URL on "/" and take index 2 (host)
            # This handles URLs like "https://example.com/path" -> ["https:", "", "example.com", "path"]
            url_parts = url.split("/")
            if len(url_parts) < 3:
                continue
            
            host = url_parts[2]
            if not host or '.' not in host:
                continue
            
            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]
            
            entries.append((phish_id, host.lower(), url))
        except Exception as e:
            logger.debug(f"Error parsing blacklist line: {line[:50]}... Error: {e}")
            continue
    
    logger.info(f"Parsed {len(entries)} entries from PhishTank blacklist")
    return entries


async def _get_blacklist() -> Optional[List[Tuple[str, str, str]]]:
    """
    Get PhishTank blacklist (from cache or download).
    
    Returns:
        List of tuples: [(phish_id, host, url), ...] or None if error
    """
    _ensure_cache_dir()
    
    # Try to load from cache first
    if _is_cache_valid():
        try:
            logger.info("Loading PhishTank blacklist from cache")
            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
                blacklist = _parse_blacklist(content)
                if blacklist:
                    logger.info(f"Loaded {len(blacklist)} entries from cache")
                    return blacklist
        except Exception as e:
            logger.warning(f"Error reading cache file: {e}")
    
    # Download fresh blacklist
    content = await _download_blacklist()
    if not content:
        # If download fails, try to use stale cache
        if CACHE_FILE.exists():
            logger.warning("Download failed, using stale cache")
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    content = f.read()
                    blacklist = _parse_blacklist(content)
                    if blacklist:
                        return blacklist
            except Exception as e:
                logger.error(f"Error reading stale cache: {e}")
        return None
    
    # Save to cache
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Cached PhishTank blacklist to {CACHE_FILE}")
    except Exception as e:
        logger.warning(f"Error caching blacklist: {e}")
    
    return _parse_blacklist(content)


def _extract_host_from_url(url: str) -> Optional[str]:
    """
    Extract host from URL.
    Handles URLs with or without protocol, with or without query strings.
    
    Args:
        url: URL to extract host from
        
    Returns:
        Host name or None
    """
    try:
        # If URL doesn't start with http:// or https://, add it for parsing
        url_to_parse = url
        if not url.startswith(('http://', 'https://')):
            url_to_parse = 'http://' + url
        
        parsed = urlparse(url_to_parse)
        host = parsed.netloc
        
        # If netloc is empty, try to extract from path (for URLs without protocol)
        if not host and parsed.path:
            # Try to extract host from path (e.g., "example.com/path" -> "example.com")
            path_parts = parsed.path.split('/')
            if path_parts[0] and '.' in path_parts[0]:
                host = path_parts[0]
        
        if not host:
            return None
        
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        
        # Remove any trailing slashes or paths
        host = host.strip('/')
        
        return host.lower() if host else None
    except Exception as e:
        logger.debug(f"Error extracting host from URL {url}: {e}")
        return None


async def query_phishtank_async(observable: str) -> Optional[Dict[str, Any]]:
    """
    Query PhishTank blacklist to check if a URL or domain is in their phishing database.
    Uses the CSV blacklist like SpiderFoot does.
    
    Args:
        observable (str): The URL or domain to check.
        
    Returns:
        dict: Raw API response data with phish_id and host if found.
        None: If an error occurs or URL/domain not found.
    """
    try:
        # Extract host from URL or use domain as-is
        # If it's a domain (no / or ://), use it directly as host
        if '/' not in observable and not observable.startswith(('http://', 'https://')):
            # It's a domain, use it as host
            host = observable.lower().strip()
            # Remove port if present
            if ':' in host:
                host = host.split(':')[0]
            url = observable  # Keep original for display
        else:
            # It's a URL, extract host
            host = _extract_host_from_url(observable)
            if not host:
                logger.warning(f"Could not extract host from URL: {observable}")
                return {
                    "raw_data": {
                        "in_database": False,
                        "url": observable
                    },
                    "url": observable
                }
            url = observable
        
        logger.info(f"Querying PhishTank blacklist for host: {host} (from observable: {observable})")
        logger.debug(f"PhishTank: Extracted host '{host}' from URL '{url}'")
        
        # Get blacklist
        blacklist = await _get_blacklist()
        if not blacklist:
            logger.error("Failed to retrieve PhishTank blacklist")
            return {
                "raw_data": {
                    "error": "Failed to retrieve PhishTank blacklist",
                    "url": url
                },
                "url": url
            }
        
        # Search for host in blacklist using SpiderFoot's simple matching method
        # SpiderFoot uses: if target.lower() in item[1] (substring match on host)
        host_lower = host.lower()
        url_lower = url.lower()
        
        logger.debug(f"PhishTank: Searching for host '{host_lower}' (from URL: {url}) in blacklist")
        
        # For URLs, also prepare URL variants for exact matching
        url_variants = []
        if url_lower.startswith(('http://', 'https://')):
            # URL with protocol - also try without protocol
            parsed = urlparse(url_lower)
            url_without_protocol = parsed.netloc
            if parsed.path:
                url_without_protocol += parsed.path
            if parsed.query:
                url_without_protocol += '?' + parsed.query
            if parsed.fragment:
                url_without_protocol += '#' + parsed.fragment
            url_variants = [url_lower, url_without_protocol]
        else:
            # URL without protocol - try with https:// and http://
            url_variants = [url_lower, 'https://' + url_lower, 'http://' + url_lower]
        
        # Normalize all variants to lowercase
        url_variants = [v.lower() for v in url_variants]
        
        logger.debug(f"PhishTank: URL variants to try: {url_variants}")
        logger.debug(f"PhishTank: Searching in {len(blacklist)} blacklist entries")
        
        # Debug: log first few entries to see format
        if blacklist:
            logger.debug(f"PhishTank: Sample blacklist entry: phish_id={blacklist[0][0]}, host={blacklist[0][1]}, url={blacklist[0][2][:100]}")
        
        match_count = 0
        for phish_id, blacklisted_host, blacklisted_url in blacklist:
            match_count += 1
            blacklisted_host_lower = blacklisted_host.lower()
            blacklisted_url_lower = blacklisted_url.lower()
            
            # SpiderFoot method: simple substring match on host
            # if target.lower() in item[1] (where item[1] is the host)
            # Check exact match first, then substring match in both directions
            host_matches = False
            if host_lower == blacklisted_host_lower:
                # Exact match
                host_matches = True
            elif host_lower in blacklisted_host_lower:
                # Input host is substring of blacklisted host (e.g., "yu383.com" in "2.yu383.com")
                host_matches = True
            elif blacklisted_host_lower in host_lower:
                # Blacklisted host is substring of input host (e.g., "2.yu383.com" in "yu383.com")
                host_matches = True
            
            # Debug first few matches
            if match_count <= 5:
                logger.debug(f"PhishTank: Entry {match_count}: host='{blacklisted_host_lower}', checking against '{host_lower}' -> host_matches={host_matches}")
            
            # For URLs, also try exact URL matching
            url_matches = False
            if url_variants:
                for url_variant in url_variants:
                    # Exact match against blacklisted URL
                    if url_variant == blacklisted_url_lower:
                        url_matches = True
                        logger.debug(f"PhishTank: Exact URL match found: {url_variant} == {blacklisted_url_lower}")
                        break
                    # Also try matching without protocol
                    if blacklisted_url_lower.startswith(('http://', 'https://')):
                        parsed_blacklisted = urlparse(blacklisted_url_lower)
                        blacklisted_no_protocol = parsed_blacklisted.netloc
                        if parsed_blacklisted.path:
                            blacklisted_no_protocol += parsed_blacklisted.path
                        if parsed_blacklisted.query:
                            blacklisted_no_protocol += '?' + parsed_blacklisted.query
                        if parsed_blacklisted.fragment:
                            blacklisted_no_protocol += '#' + parsed_blacklisted.fragment
                        if url_variant == blacklisted_no_protocol:
                            url_matches = True
                            logger.debug(f"PhishTank: URL match (no protocol): {url_variant} == {blacklisted_no_protocol}")
                            break
            
            if host_matches or url_matches:
                match_type = "URL" if url_matches else "host"
                logger.info(f"PhishTank: Found {match_type} match: {url} (host: {host_lower}) in PhishTank blacklist entry {blacklisted_url} (host: {blacklisted_host_lower}, Phish ID: {phish_id})")
                return {
                    "raw_data": {
                        "in_database": True,
                        "phish_id": phish_id,
                        "host": host,
                        "url": url,
                        "verified": "yes"  # All entries in online-valid.csv are verified
                    },
                    "url": url,
                    "host": host
                }
        
        logger.info(f"Host {host} not found in PhishTank blacklist")
        return {
            "raw_data": {
                "in_database": False,
                "url": url,
                "host": host
            },
            "url": url,
            "host": host
        }
    
    except Exception as e:
        logger.error(f"Error querying PhishTank for {url}: {e}", exc_info=True)
        return None
