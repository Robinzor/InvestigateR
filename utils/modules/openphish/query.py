"""
OpenPhish query module - handles OpenPhish feed
"""
import aiohttp
import logging
import asyncio
from typing import Optional, Dict, Any, Set
from urllib.parse import urlparse
from pathlib import Path
import time

logger = logging.getLogger(__name__)

# OpenPhish feed URL
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

CACHE_DIR = Path.home() / ".investigateR" / "cache" / "openphish"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

CACHE_FILE = CACHE_DIR / "openphish.txt"
CACHE_PERIOD_HOURS = 0.25  # 15 minutes


def _is_cache_valid() -> bool:
    """Check if cache is still valid"""
    if not CACHE_FILE.exists():
        return False
    cache_age = time.time() - CACHE_FILE.stat().st_mtime
    return (cache_age / 3600) < CACHE_PERIOD_HOURS


def _extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain.lower() if domain else None
    except Exception:
        return None


async def _download_openphish() -> Optional[Set[str]]:
    """Download and parse OpenPhish feed"""
    try:
        # Check cache first
        if _is_cache_valid():
            try:
                logger.debug("Loading OpenPhish from cache")
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    urls = set()
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            urls.add(line.lower())
                            domain = _extract_domain_from_url(line)
                            if domain:
                                urls.add(domain)
                    if urls:
                        logger.debug(f"Loaded {len(urls)} entries from OpenPhish cache")
                        return urls
            except Exception as e:
                logger.warning(f"Error reading OpenPhish cache: {e}")
        
        # Download
        logger.debug("Downloading OpenPhish feed")
        timeout = aiohttp.ClientTimeout(total=5, connect=3)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.get(
                    OPENPHISH_FEED_URL,
                    headers={'User-Agent': 'investigateR/1.0'},
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        urls = set()
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and not line.startswith('#'):
                                urls.add(line.lower())
                                domain = _extract_domain_from_url(line)
                                if domain:
                                    urls.add(domain)
                        
                        # Save to cache
                        try:
                            with open(CACHE_FILE, 'w', encoding='utf-8') as f:
                                f.write(content)
                            logger.debug(f"Cached OpenPhish with {len(urls)} entries")
                        except Exception as e:
                            logger.warning(f"Error caching OpenPhish: {e}")
                        
                        return urls if urls else None
                    else:
                        logger.warning(f"OpenPhish returned status {response.status}")
                        # Try stale cache
                        if CACHE_FILE.exists():
                            logger.debug("Using stale OpenPhish cache")
                            with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                                urls = set()
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith('#'):
                                        urls.add(line.lower())
                                        domain = _extract_domain_from_url(line)
                                        if domain:
                                            urls.add(domain)
                                return urls if urls else None
                        return None
            except asyncio.TimeoutError:
                logger.debug("Timeout downloading OpenPhish")
                # Try stale cache
                if CACHE_FILE.exists():
                    try:
                        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                            urls = set()
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    urls.add(line.lower())
                                    domain = _extract_domain_from_url(line)
                                    if domain:
                                        urls.add(domain)
                            return urls if urls else None
                    except Exception:
                        pass
                return None
            except Exception as e:
                logger.warning(f"Error downloading OpenPhish: {e}")
                return None
    except Exception as e:
        logger.error(f"Error in _download_openphish: {e}", exc_info=True)
        return None


async def query_openphish_async(observable: str) -> Optional[Dict[str, Any]]:
    """
    Query OpenPhish feed to check if URL/domain is malicious.
    
    Args:
        observable: The URL or domain to check
        
    Returns:
        dict: Raw response data with phishing status
    """
    try:
        logger.info(f"Querying OpenPhish for: {observable}")
        
        # Normalize observable
        observable_lower = observable.lower().strip()
        domain = _extract_domain_from_url(observable_lower) if '://' in observable_lower else observable_lower
        
        # Download feed
        openphish_set = await _download_openphish()
        
        # Check if observable is in feed
        in_feed = False
        if openphish_set:
            in_feed = (observable_lower in openphish_set) or (domain in openphish_set)
        
        return {
            "raw_data": {
                "in_feed": in_feed,
                "is_phishing": in_feed,
                "observable": observable,
                "domain": domain
            },
            "observable": observable
        }
    
    except Exception as e:
        logger.error(f"Error querying OpenPhish for {observable}: {e}", exc_info=True)
        return None

