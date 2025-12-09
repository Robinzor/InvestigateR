"""
Domain Blocklists query module - handles multiple domain blacklist downloads and lookups
"""
import aiohttp
import logging
import re
import asyncio
import time
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Locks to prevent race conditions when downloading the same blacklist simultaneously
_download_locks: Dict[str, asyncio.Lock] = {}

# In-memory cache for blacklists (15 minutes TTL)
_blacklist_cache: Dict[str, set] = {}
_cache_timestamps: Dict[str, float] = {}
CACHE_TTL_SECONDS = 15 * 60  # 15 minutes

# Domain blacklist configurations
BLACKLISTS = {
    "oisd_big": {
        "url": "https://big.oisd.nl",
        "type": "hosts"
    },
    "kadhosts": {
        "url": "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
        "type": "hosts",
    },
    "fademind_spam": {
        "url": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
        "type": "hosts",
    },
    "firebog_w3kbl": {
        "url": "https://v.firebog.net/hosts/static/w3kbl.txt",
        "type": "hosts",
    },
    "adaway": {
        "url": "https://adaway.org/hosts.txt",
        "type": "hosts",
    },
    "firebog_adguard": {
        "url": "https://v.firebog.net/hosts/AdguardDNS.txt",
        "type": "hosts",
    },
    "firebog_admiral": {
        "url": "https://v.firebog.net/hosts/Admiral.txt",
        "type": "hosts",
    },
    "anudeep_adservers": {
        "url": "https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
        "type": "hosts",
    },
    "disconnect_simple_ad": {
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
        "type": "hosts",
    },
    "firebog_easylist": {
        "url": "https://v.firebog.net/hosts/Easylist.txt",
        "type": "hosts",
    },
    "pgl_yoyo": {
        "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        "type": "hosts",
    },
    "fademind_unchecky": {
        "url": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
        "type": "hosts",
    },
    "bigdargon_hosts_vn": {
        "url": "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
        "type": "hosts",
    },
    "firebog_easyprivacy": {
        "url": "https://v.firebog.net/hosts/Easyprivacy.txt",
        "type": "hosts",
    },
    "fademind_2o7net": {
        "url": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
        "type": "hosts",
    },
    "windows_spyblocker": {
        "url": "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
        "type": "hosts",
    },
    "frogeye_firstparty": {
        "url": "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
        "type": "hosts",
    },
    "dandelion_antimalware": {
        "url": "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
        "type": "hosts",
    },
    "disconnect_malvertising": {
        "url": "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
        "type": "hosts",
    },
    "firebog_prigent_crypto": {
        "url": "https://v.firebog.net/hosts/Prigent-Crypto.txt",
        "type": "hosts",
    },
    "fademind_risk": {
        "url": "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
        "type": "hosts",
    },
    "mandiant_apt1": {
        "url": "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt",
        "type": "plaintext",
    },
    "phishing_army": {
        "url": "https://phishing.army/download/phishing_army_blocklist_extended.txt",
        "type": "plaintext",
    },
    "notrack_malware": {
        "url": "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt",
        "type": "hosts",
    },
    "firebog_rpimlist_malware": {
        "url": "https://v.firebog.net/hosts/RPiList-Malware.txt",
        "type": "hosts",
    },
    "firebog_rpimlist_phishing": {
        "url": "https://v.firebog.net/hosts/RPiList-Phishing.txt",
        "type": "hosts",
    },
    "spam404": {
        "url": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
        "type": "hosts",
    },
    "assoechap_stalkerware": {
        "url": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/hosts",
        "type": "hosts",
    },
    "urlhaus_hostfile": {
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "type": "hosts",
    },
    "hagezi_ultimate": {
        "url": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
        "type": "adblock",
    },
    "stevenblack_hosts": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "type": "hosts",
    },
}

def _is_valid_domain(domain: str) -> bool:
    """Validate if a string is a valid domain name"""
    if not domain or len(domain) > 253:
        return False
    # Basic domain validation
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))


# Shared session for all downloads
_shared_session: Optional[aiohttp.ClientSession] = None

async def _get_shared_session() -> aiohttp.ClientSession:
    """Get or create shared aiohttp session for better performance"""
    global _shared_session
    try:
        # Check if event loop is still running
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            _shared_session = None
    except RuntimeError:
        _shared_session = None
    
    if _shared_session is None or _shared_session.closed:
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ttl_dns_cache=300)
        _shared_session = aiohttp.ClientSession(timeout=timeout, connector=connector)
    return _shared_session

async def _download_blacklist(url: str) -> Optional[bytes]:
    """Download blacklist content with improved error handling"""
    session = None
    try:
        logger.debug(f"Downloading domain blacklist from {url}")
        try:
            session = await _get_shared_session()
        except RuntimeError as e:
            logger.debug(f"Event loop issue, creating new session: {e}")
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ttl_dns_cache=300)
            session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        
        try:
            async with session.get(
                url,
                headers={'User-Agent': 'investigateR/1.0'},
                ssl=False
            ) as response:
                if response.status == 200:
                    content = await response.read()
                    logger.info(f"Successfully downloaded domain blacklist ({len(content)} bytes) from {url}")
                    return content
                else:
                    logger.warning(f"Domain blacklist returned status {response.status} for {url}")
                    return None
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                logger.warning(f"Event loop closed while downloading {url}")
            else:
                logger.warning(f"Runtime error downloading domain blacklist from {url}: {e}")
            return None
        except asyncio.TimeoutError:
            logger.warning(f"Timeout downloading domain blacklist from {url}")
            return None
        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Connection error downloading domain blacklist from {url}: {e}")
            return None
        except aiohttp.ClientError as e:
            logger.warning(f"Client error downloading domain blacklist from {url}: {e}")
            return None
        finally:
            if session is not None and session != _shared_session:
                try:
                    await session.close()
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Error downloading domain blacklist from {url}: {e}")
        return None


def _parse_hosts(content: str) -> List[str]:
    """Parse hosts file format - extracts domains (robust to inline comments and dot-prefixed entries)"""
    domains: set[str] = set()
    for raw_line in content.split('\n'):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        # Strip inline comments first
        if '#' in line:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
        parts = line.split()
        if len(parts) < 2:
            continue
        # Skip the first token (IP), collect the rest as domains
        for domain in parts[1:]:
            d = domain.strip().lstrip('.').rstrip('.')
            if not d:
                continue
            if d.startswith('[') and d.endswith(']'):
                # Skip bracketed comments like [1rx.io]
                continue
            if _is_valid_domain(d):
                domains.add(d.lower())
    return list(domains)


def _parse_plaintext(content: str) -> List[str]:
    """Parse plaintext domain list (one per line)"""
    domains = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Remove comments
        if '#' in line:
            line = line.split('#')[0].strip()
        if line and _is_valid_domain(line):
            domains.append(line.lower())
    return domains


def _parse_adblock(content: str) -> List[str]:
    """Parse AdBlock format - extract domains from rules"""
    domains = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        # AdBlock format examples:
        # ||example.com^
        # ||example.com
        # example.com
        # Remove || prefix and ^ suffix
        domain = line.replace('||', '').replace('^', '').strip()
        # Remove other AdBlock syntax
        domain = re.sub(r'[|$].*$', '', domain)  # Remove | and $ and everything after
        if domain and _is_valid_domain(domain):
            domains.append(domain.lower())
    return domains


async def _get_blacklist(blacklist_name: str, config: Dict[str, Any]) -> Optional[set]:
    """Get blacklist by downloading fresh data - returns set of domains
    Uses locks to prevent race conditions when multiple checks download the same blacklist simultaneously
    """
    # Use a lock per blacklist to prevent multiple simultaneous downloads
    if blacklist_name not in _download_locks:
        _download_locks[blacklist_name] = asyncio.Lock()
    
    async with _download_locks[blacklist_name]:
        # Download fresh data
        logger.info(f"Downloading fresh data for {blacklist_name}...")
        
        # Download
        content_bytes = await _download_blacklist(config["url"])
        if not content_bytes:
            logger.warning(f"Download failed for {blacklist_name}")
            return None
        
        # Parse based on type
        blacklist_type = config.get("type", "hosts")
        content_str = content_bytes.decode('utf-8', errors='ignore')
        logger.debug(f"Parsing {blacklist_name} as {blacklist_type}, content length: {len(content_str)} chars")
        
        domains = []
        if blacklist_type == "hosts":
            domains = _parse_hosts(content_str)
        elif blacklist_type == "plaintext":
            domains = _parse_plaintext(content_str)
        elif blacklist_type == "adblock":
            domains = _parse_adblock(content_str)
        
        domain_set = set(domains)
        
        if domain_set:
            logger.info(f"Parsed {blacklist_name}: {len(domain_set)} domains")
        else:
            logger.debug(f"No domains parsed from {blacklist_name} (empty or failed to parse)")
        
        # Cache the result
        _blacklist_cache[blacklist_name] = domain_set
        _cache_timestamps[blacklist_name] = time.time()
        logger.debug(f"Cached {blacklist_name} in memory")
        
        return domain_set


async def query_domainblocklists_async(domain: str) -> Optional[Dict[str, Any]]:
    """
    Query multiple domain blocklists to check if a domain is malicious.
    
    Args:
        domain: The domain to check
        
    Returns:
        dict: Raw response data with blacklist status
    """
    try:
        if not _is_valid_domain(domain):
            logger.warning(f"Invalid domain format: {domain}")
            return {
                "raw_data": {
                    "error": f"Invalid domain format: {domain}",
                    "domain": domain
                },
                "domain": domain
            }
        
        logger.info(f"Querying domain blocklists for domain: {domain}")
        
        # Normalize domain (lowercase, remove www.)
        domain_normalized = domain.lower().strip()
        if domain_normalized.startswith('www.'):
            domain_normalized = domain_normalized[4:]
        
        found_in = []
        failed = 0
        blacklist_results = {}
        
        # Create tasks for parallel execution
        async def check_blacklist(blacklist_name: str, config: Dict[str, Any]) -> tuple:
            """Check a single blacklist and return (name, result)"""
            try:
                blacklist = await _get_blacklist(blacklist_name, config)
                if not blacklist:
                    logger.debug(f"Blacklist {blacklist_name} returned None or empty")
                    return (blacklist_name, False)
                
                if not isinstance(blacklist, set):
                    logger.warning(f"Blacklist {blacklist_name} is not a set: {type(blacklist)}")
                    return (blacklist_name, False)
                
                logger.debug(f"Checking {blacklist_name}: {len(blacklist)} domains")
                
                # Check exact domain match first
                if domain_normalized in blacklist:
                    logger.info(f"Domain {domain} found in {blacklist_name} (exact match)")
                    return (blacklist_name, True)
                
                # Check subdomain matches (e.g., if example.com is blocked, sub.example.com should also match)
                # Only check if the queried domain is a subdomain of a blocked domain
                for blocked_domain in blacklist:
                    # Skip if blocked_domain is the same as domain_normalized (already checked above)
                    if blocked_domain == domain_normalized:
                        continue
                    # Check if domain_normalized is a subdomain of blocked_domain
                    # e.g., sub.example.com should match if example.com is blocked
                    if domain_normalized.endswith('.' + blocked_domain):
                        logger.info(f"Domain {domain} found in {blacklist_name} (subdomain match: {blocked_domain})")
                        return (blacklist_name, True)
                
                return (blacklist_name, False)
            except Exception as e:
                logger.warning(f"Error checking {blacklist_name}: {e}", exc_info=True)
                return (blacklist_name, None)
        
        # Execute all checks in parallel
        tasks = [check_blacklist(name, config) for name, config in BLACKLISTS.items()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Exception in blacklist check: {result}")
                continue
            blacklist_name, found = result
            blacklist_results[blacklist_name] = found
            if found is True:
                found_in.append(blacklist_name)
            elif found is None:
                blacklist_results[blacklist_name] = None
                failed += 1
        
        in_any_blacklist = len(found_in) > 0
        
        return {
            "raw_data": {
                "in_blacklist": in_any_blacklist,
                "domain": domain,
                "found_in": found_in,
                "blacklist_results": blacklist_results,
                "total_blacklists_checked": len(BLACKLISTS),
                "total_blacklists_found": len(found_in),
                "total_blacklists_failed": failed
            },
            "domain": domain
        }
    
    except Exception as e:
        logger.error(f"Error querying domain blocklists for {domain}: {e}", exc_info=True)
        return None

