"""
IP Blocklists query module - handles multiple blacklist downloads and lookups
"""
import aiohttp
import logging
import gzip
import re
import asyncio
import ipaddress
import time
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# Locks to prevent race conditions when downloading the same blacklist simultaneously
_download_locks: Dict[str, asyncio.Lock] = {}

# In-memory cache for blacklists (15 minutes TTL)
_blacklist_cache: Dict[str, Dict[str, Any]] = {}
_cache_timestamps: Dict[str, float] = {}
CACHE_TTL_SECONDS = 15 * 60  # 15 minutes

# Blacklist configurations
# 
# Feeds included in this module:
# - AlienVault IP Reputation (alienvault_reputation) - Note: Replaces separate AlienVault IP Reputation module
# - Binary Defense ATIF (bds_atif)
# - CIArmy (ciarmy)
# - Spamhaus DROP/EDROP (spamhaus_drop, spamhaus_edrop)
# - Emerging Threats BotCC (et_botcc)
# - Pushing Inertia (pushing_inertia)
# - Turris Greylist (turris_greylist)
# - iBlocklist: badpeers, ciarmy_malicious, level1-3, spyware, webexploit
# - BBcan177 Malicious Threats (bbcan177_ms1, bbcan177_ms3)
# - CTA CryptoWall (cta_cryptowall)
# - CyberCrime Tracker (cybercrime)
# - Abuse.ch Feodo Tracker (feodo, feodo_c2) - Note: Replaces separate Abuse.ch module
# - Abuse.ch SSL Blacklist (sslbl, sslbl_aggressive) - Note: Replaces separate Abuse.ch module
# - Abuse.ch URLhaus (urlhaus) - Note: Replaces separate Abuse.ch module
# - iBlocklist Abuse: Palevo, SpyEye, Zeus (iblocklist_abuse_*)
# - iBlocklist Malc0de (iblocklist_malc0de)
# - VxVault (vxvault)
# Note: Removed feeds due to timeouts/connection errors: tracker_c2, dyndns_ponmocup, urlvir, urlvir_last, threatcrowd
BLACKLISTS = {
    # AlienVault IP Reputation (replaces separate AlienVault IP Reputation module)
    "alienvault_reputation": {
        "url": "https://reputation.alienvault.com/reputation.generic",
        "type": "plaintext",
    },
    # Binary Defense ATIF
    "bds_atif": {
        "url": "https://www.binarydefense.com/banlist.txt",
        "type": "plaintext",
    },
    # CIArmy
    "ciarmy": {
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "type": "plaintext",
    },
    # Spamhaus DROP/EDROP
    "spamhaus_drop": {
        "url": "http://www.spamhaus.org/drop/drop.txt",
        "type": "plaintext_semicolon",
    },
    "spamhaus_edrop": {
        "url": "http://www.spamhaus.org/drop/edrop.txt",
        "type": "plaintext_semicolon",
    },
    # Emerging Threats BotCC
    "et_botcc": {
        "url": "http://rules.emergingthreats.net/fwrules/emerging-PIX-CC.rules",
        "type": "pix_rules",
    },
    # Pushing Inertia
    "pushing_inertia": {
        "url": "https://raw.githubusercontent.com/pushinginertia/ip-blacklist/master/ip_blacklist.conf",
        "type": "pushing_inertia",
    },
    # Turris Greylist
    "turris_greylist": {
        "url": "https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv",
        "type": "csv",
    },
    # BBcan177 Malicious Threats
    "bbcan177_ms1": {
        "url": "https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw",
        "type": "plaintext",
    },
    "bbcan177_ms3": {
        "url": "https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw",
        "type": "plaintext",
    },
    # CTA CryptoWall
    "cta_cryptowall": {
        "url": "https://public.tableau.com/views/CTAOnlineViz/DashboardData.csv?:embed=y&:showVizHome=no&:showTabs=y&:display_count=y&:display_static_image=y&:bootstrapWhenNotified=true",
        "type": "cta_cryptowall",
    },
    # CyberCrime Tracker
    "cybercrime": {
        "url": "http://cybercrime-tracker.net/fuckerz.php",
        "type": "extract_ipv4",
    },
    # Abuse.ch Feodo Tracker
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "plaintext",
    },
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "plaintext",
    },
    # Abuse.ch SSL Blacklist
    "sslbl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "type": "csv_first_column",
    },
    "sslbl_aggressive": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv",
        "type": "csv_first_column",
    },
    # Abuse.ch URLhaus
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "urlhaus_text",
    },
    # iBlocklist blacklists (P2P GZ format)
    "iblocklist_badpeers": {
        "url": "http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_ciarmy_malicious": {
        "url": "http://list.iblocklist.com/?list=npkuuhuxcsllnhoamkvm&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_level1": {
        "url": "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_level2": {
        "url": "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_level3": {
        "url": "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_spyware": {
        "url": "http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_webexploit": {
        "url": "http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    # iBlocklist Abuse trackers
    "iblocklist_abuse_palevo": {
        "url": "http://list.iblocklist.com/?list=erqajhwrxiuvjxqrrwfj&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_abuse_spyeye": {
        "url": "http://list.iblocklist.com/?list=zvjxsfuvdhoxktpeiokq&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    "iblocklist_abuse_zeus": {
        "url": "http://list.iblocklist.com/?list=ynkdjqsjyfmilsgbogqf&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    # iBlocklist Malc0de
    "iblocklist_malc0de": {
        "url": "http://list.iblocklist.com/?list=pbqcylkejciyhmwttify&fileformat=p2p&archiveformat=gz",
        "type": "p2p_gz",
    },
    # VxVault
    "vxvault": {
        "url": "http://vxvault.net/ViriList.php?s=0&m=100",
        "type": "extract_ipv4",
    },
    # FireHOL Blocklists
    "firehol_level1": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "type": "netset",
    },
    "firehol_level2": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
        "type": "netset",
    },
    "firehol_level3": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset",
        "type": "netset",
    },
    "firehol_level4": {
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level4.netset",
        "type": "netset",
    },
}

def _is_valid_ip(ip: str) -> bool:
    """Validate if a string is a valid IP address"""
    try:
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False


def _ip_to_int(ip: str) -> int:
    """Convert IP address to integer"""
    try:
        parts = ip.strip().split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except (ValueError, AttributeError, IndexError):
        return 0


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if IP address is within a CIDR range using ipaddress module"""
    try:
        if '/' not in cidr:
            return False
        
        # Use ipaddress module for robust CIDR matching
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(cidr, strict=False)  # strict=False to allow host bits in network address
        
        return ip_obj in network_obj
    except (ValueError, AttributeError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


# Shared session for all downloads (created once, reused for better performance)
_shared_session: Optional[aiohttp.ClientSession] = None

async def _get_shared_session() -> aiohttp.ClientSession:
    """Get or create shared aiohttp session for better performance"""
    global _shared_session
    try:
        # Check if event loop is still running
        loop = asyncio.get_running_loop()
        if loop.is_closed():
            # Event loop is closed, reset session
            _shared_session = None
    except RuntimeError:
        # No running event loop, reset session
        _shared_session = None
    
    if _shared_session is None or _shared_session.closed:
        # Increased timeout for large blocklists (some can be 200KB+)
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ttl_dns_cache=300)
        _shared_session = aiohttp.ClientSession(timeout=timeout, connector=connector)
    return _shared_session

async def _download_blacklist(url: str) -> Optional[bytes]:
    """Download blacklist content with improved error handling"""
    session = None
    try:
        logger.debug(f"Downloading blacklist from {url}")
        try:
            session = await _get_shared_session()
        except RuntimeError as e:
            # Event loop is closed, create a new session for this download
            logger.debug(f"Event loop issue, creating new session: {e}")
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            connector = aiohttp.TCPConnector(limit=50, limit_per_host=10, ttl_dns_cache=300)
            session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        
        try:
            async with session.get(
                url,
                headers={'User-Agent': 'investigateR/1.0'},
                ssl=False  # Some feeds may have SSL issues
            ) as response:
                if response.status == 200:
                    content = await response.read()
                    logger.info(f"Successfully downloaded blacklist ({len(content)} bytes) from {url}")
                    return content
                else:
                    logger.warning(f"Blacklist returned status {response.status} for {url}")
                    return None
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                logger.warning(f"Event loop closed while downloading {url}")
            else:
                logger.warning(f"Runtime error downloading blacklist from {url}: {e}")
            return None
        except asyncio.TimeoutError:
            logger.warning(f"Timeout downloading blacklist from {url}")
            return None
        except aiohttp.ClientConnectorError as e:
            logger.warning(f"Connection error downloading blacklist from {url}: {e}")
            return None
        except aiohttp.ClientError as e:
            logger.warning(f"Client error downloading blacklist from {url}: {e}")
            return None
        finally:
            # Only close session if we created a temporary one (not the shared one)
            if session is not None and session != _shared_session:
                try:
                    await session.close()
                except Exception:
                    pass
    except Exception as e:
        logger.warning(f"Error downloading blacklist from {url}: {e}")
        return None


def _parse_plaintext(content: str) -> List[str]:
    """Parse plaintext blacklist (remove comments) - supports both IPs and CIDR ranges"""
    entries = []
    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        # Remove comments (lines starting with # or containing # after the data)
        if '#' in line:
            line = line.split('#')[0].strip()
        if not line or line.startswith('#'):
            continue
        # Check if it's a CIDR range (contains /)
        if '/' in line:
            parts = line.split('/')
            if len(parts) == 2:
                network = parts[0].strip()
                prefix = parts[1].strip()
                if _is_valid_ip(network) and prefix.isdigit() and 0 <= int(prefix) <= 32:
                    entries.append(line)  # Keep full CIDR notation
        elif _is_valid_ip(line):
            entries.append(line)  # Individual IP
    return entries


def _parse_plaintext_semicolon(content: str) -> List[str]:
    """Parse plaintext blacklist with semicolon comments - supports both IPs and CIDR ranges"""
    entries = []
    for line in content.split('\n'):
        line = line.split(';')[0].strip()  # Remove comments after semicolon
        if not line or line.startswith('#'):
            continue
        # Check if it's a CIDR range (contains /)
        if '/' in line:
            parts = line.split('/')
            if len(parts) == 2:
                network = parts[0].strip()
                prefix = parts[1].strip()
                if _is_valid_ip(network) and prefix.isdigit() and 0 <= int(prefix) <= 32:
                    entries.append(line)  # Keep full CIDR notation
        elif _is_valid_ip(line):
            entries.append(line)  # Individual IP
    return entries


def _parse_pix_rules(content: str) -> List[str]:
    """Parse PIX deny rules to extract IPs"""
    ips = []
    # Pattern: deny ip host <IP> any
    pattern = r'deny\s+ip\s+host\s+(\d+\.\d+\.\d+\.\d+)\s+any'
    for match in re.finditer(pattern, content, re.IGNORECASE):
        ip = match.group(1)
        if _is_valid_ip(ip):
            ips.append(ip)
    return ips


def _parse_pushing_inertia(content: str) -> List[str]:
    """Parse Pushing Inertia blacklist format"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Format: deny <IP>;
        if line.startswith('deny '):
            ip = line.replace('deny ', '').replace(';', '').strip()
            if _is_valid_ip(ip):
                ips.append(ip)
    return ips


def _parse_csv(content: str, ip_column: int = 0) -> List[str]:
    """Parse CSV blacklist"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) > ip_column:
            ip = parts[ip_column].strip().strip('"')
            if _is_valid_ip(ip):
                ips.append(ip)
    return ips


def _parse_p2p_gz(content: bytes) -> List[str]:
    """Parse P2P GZ format blacklist"""
    try:
        # Decompress gzip
        decompressed = gzip.decompress(content)
        content_str = decompressed.decode('utf-8', errors='ignore')
        
        ips = []
        for line in content_str.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # P2P format can have ranges like 1.2.3.4-1.2.3.5
            if '-' in line:
                # Extract start IP
                start_ip = line.split('-')[0].strip()
                if _is_valid_ip(start_ip):
                    ips.append(start_ip)
            elif _is_valid_ip(line):
                ips.append(line)
        return ips
    except Exception as e:
        logger.error(f"Error parsing P2P GZ content: {e}")
        return []


def _parse_corpus(content: str) -> List[str]:
    """Parse corpus format (h3x.eu tracker)"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Extract IP from various formats
        # Try to find IP pattern in the line
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(ip_pattern, line)
        for match in matches:
            if _is_valid_ip(match):
                ips.append(match)
    return ips


def _parse_cta_cryptowall(content: str) -> List[str]:
    """Parse CTA CryptoWall CSV format"""
    ips = []
    lines = content.split('\n')
    # Skip header line
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split(',')
        # IP is typically in one of the columns
        for part in parts:
            part = part.strip().strip('"')
            if _is_valid_ip(part):
                ips.append(part)
                break
    return ips


def _extract_ipv4_from_any_file(content: str) -> List[str]:
    """Extract all IPv4 addresses from any file format"""
    ips = []
    # Use regex to find all IP addresses
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    matches = re.findall(ip_pattern, content)
    for match in matches:
        if _is_valid_ip(match):
            if match not in ips:  # Avoid duplicates
                ips.append(match)
    return ips


def _parse_csv_first_column(content: str) -> List[str]:
    """Parse CSV with IP in first column"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) > 0:
            ip = parts[0].strip().strip('"')
            if _is_valid_ip(ip):
                ips.append(ip)
    return ips


def _parse_dyndns_ponmocup(content: str) -> List[str]:
    """Parse DynDNS Ponmocup CSV format"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(',')
        # IP is typically in first or second column
        for part in parts[:2]:
            part = part.strip().strip('"')
            if _is_valid_ip(part):
                ips.append(part)
                break
    return ips


def _parse_urlvir_last(content: str) -> List[str]:
    """Parse URLVir last format (HTML page)"""
    ips = []
    # Extract IPs from HTML content
    ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    matches = re.findall(ip_pattern, content)
    for match in matches:
        if _is_valid_ip(match):
            if match not in ips:
                ips.append(match)
    return ips


def _parse_urlhaus_text(content: str) -> List[str]:
    """Parse URLhaus text format (extract IPs from URLs)"""
    ips = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Extract IP from URL if present
        # URLs might contain IPs like http://1.2.3.4/path
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        matches = re.findall(ip_pattern, line)
        for match in matches:
            if _is_valid_ip(match):
                if match not in ips:
                    ips.append(match)
    return ips


def _parse_netset(content: str) -> List[str]:
    """Parse FireHOL netset format - returns both individual IPs and CIDR ranges"""
    entries = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Netset format can contain:
        # - Single IPs: 1.2.3.4
        # - CIDR ranges: 1.2.3.0/24
        # Keep both individual IPs and CIDR ranges for proper matching
        if '/' in line:
            # CIDR range - keep the full CIDR notation
            parts = line.split('/')
            if len(parts) == 2:
                network = parts[0].strip()
                prefix = parts[1].strip()
                if _is_valid_ip(network) and prefix.isdigit() and 0 <= int(prefix) <= 32:
                    entries.append(line)  # Keep full CIDR notation
        elif _is_valid_ip(line):
            entries.append(line)  # Individual IP
    return entries


async def _get_blacklist(blacklist_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Get blacklist from cache or download fresh data - returns dict with individual IPs and CIDR ranges
    Uses in-memory cache with 15 minute TTL to avoid re-downloading on every query
    Uses locks to prevent race conditions when multiple checks download the same blacklist simultaneously
    """
    # Check cache first
    current_time = time.time()
    if blacklist_name in _blacklist_cache:
        cache_age = current_time - _cache_timestamps.get(blacklist_name, 0)
        if cache_age < CACHE_TTL_SECONDS:
            logger.debug(f"Using cached {blacklist_name} (age: {cache_age/60:.1f} minutes)")
            return _blacklist_cache[blacklist_name]
        else:
            logger.debug(f"Cache expired for {blacklist_name} (age: {cache_age/60:.1f} minutes)")
    
    # Use a lock per blacklist to prevent multiple simultaneous downloads
    if blacklist_name not in _download_locks:
        _download_locks[blacklist_name] = asyncio.Lock()
    
    async with _download_locks[blacklist_name]:
        # Double-check cache after acquiring lock (another coroutine might have updated it)
        if blacklist_name in _blacklist_cache:
            cache_age = time.time() - _cache_timestamps.get(blacklist_name, 0)
            if cache_age < CACHE_TTL_SECONDS:
                logger.debug(f"Using cached {blacklist_name} (after lock)")
                return _blacklist_cache[blacklist_name]
        
        # Download fresh data
        logger.info(f"Downloading fresh data for {blacklist_name}...")
        
        # Download
        content_bytes = await _download_blacklist(config["url"])
        if not content_bytes:
            logger.warning(f"Download failed for {blacklist_name}")
            # Return stale cache if available
            if blacklist_name in _blacklist_cache:
                logger.info(f"Using stale cache for {blacklist_name} after download failure")
                return _blacklist_cache[blacklist_name]
            return None
        
        # Parse based on type
        blacklist_type = config.get("type", "plaintext")
        entries = []
        
        if blacklist_type == "p2p_gz":
            entries = _parse_p2p_gz(content_bytes)
        else:
            content_str = content_bytes.decode('utf-8', errors='ignore')
            logger.debug(f"Parsing {blacklist_name} as {blacklist_type}, content length: {len(content_str)} chars")
            if blacklist_type == "plaintext":
                entries = _parse_plaintext(content_str)
                logger.info(f"Parsed {blacklist_name}: {len(entries)} entries")
            elif blacklist_type == "plaintext_semicolon":
                entries = _parse_plaintext_semicolon(content_str)
            elif blacklist_type == "pix_rules":
                entries = _parse_pix_rules(content_str)
            elif blacklist_type == "pushing_inertia":
                entries = _parse_pushing_inertia(content_str)
            elif blacklist_type == "csv":
                entries = _parse_csv(content_str)
            elif blacklist_type == "corpus":
                entries = _parse_corpus(content_str)
            elif blacklist_type == "cta_cryptowall":
                entries = _parse_cta_cryptowall(content_str)
            elif blacklist_type == "extract_ipv4":
                entries = _extract_ipv4_from_any_file(content_str)
            elif blacklist_type == "csv_first_column":
                entries = _parse_csv_first_column(content_str)
            elif blacklist_type == "dyndns_ponmocup":
                entries = _parse_dyndns_ponmocup(content_str)
            elif blacklist_type == "urlvir_last":
                entries = _parse_urlvir_last(content_str)
            elif blacklist_type == "urlhaus_text":
                entries = _parse_urlhaus_text(content_str)
            elif blacklist_type == "netset":
                entries = _parse_netset(content_str)
        
        # Separate individual IPs and CIDR ranges
        ip_set = set()
        cidr_list = []
        for entry in entries:
            if '/' in entry:
                cidr_list.append(entry)
            else:
                ip_set.add(entry)
        
        if ip_set or cidr_list:
            logger.info(f"Parsed {blacklist_name}: {len(ip_set)} IPs and {len(cidr_list)} CIDR ranges")
        else:
            logger.debug(f"No IPs/CIDRs parsed from {blacklist_name} (empty or failed to parse)")
        
        result = {"ips": ip_set, "cidrs": cidr_list}
        
        # Cache the result
        _blacklist_cache[blacklist_name] = result
        _cache_timestamps[blacklist_name] = time.time()
        logger.debug(f"Cached {blacklist_name} in memory")
        
        return result


async def query_ipblocklists_async(ip: str) -> Optional[Dict[str, Any]]:
    """
    Query multiple IP blocklists to check if an IP address is malicious.
    
    Args:
        ip: The IP address to check
        
    Returns:
        dict: Raw response data with blacklist status
    """
    try:
        if not _is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return {
                "raw_data": {
                    "error": f"Invalid IP address format: {ip}",
                    "ip": ip
                },
                "ip": ip
            }
        
        logger.info(f"Querying IP blocklists for IP: {ip}")
        
        # Check against all blacklists in parallel
        ip_stripped = ip.strip()
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
                
                # Ensure blacklist is a dict with ips and cidrs keys
                if not isinstance(blacklist, dict):
                    logger.warning(f"Blacklist {blacklist_name} is not a dict: {type(blacklist)}")
                    return (blacklist_name, False)
                
                ip_set = blacklist.get("ips", set())
                if not isinstance(ip_set, set):
                    logger.warning(f"Blacklist {blacklist_name} ips is not a set: {type(ip_set)}")
                    ip_set = set()
                
                logger.debug(f"Checking {blacklist_name}: {len(ip_set)} IPs, {len(blacklist.get('cidrs', []))} CIDR ranges")
                
                # Check exact IP match
                if ip_stripped in ip_set:
                    logger.info(f"IP {ip} found in {blacklist_name} (exact match)")
                    return (blacklist_name, True)
                
                # Check if IP matches any .0 IP treated as /24 subnet
                # If blocklist contains 37.49.148.0, treat it as 37.49.148.0/24
                ip_parts = ip_stripped.split('.')
                if len(ip_parts) == 4:
                    # Check if any IP ending in .0 exists in the blocklist
                    subnet_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
                    if subnet_base in ip_set:
                        logger.info(f"IP {ip} found in {blacklist_name} (matches subnet {subnet_base}/24)")
                        return (blacklist_name, True)
                
                # Check CIDR ranges
                cidrs = blacklist.get("cidrs", [])
                if cidrs:
                    logger.debug(f"Checking {len(cidrs)} CIDR ranges in {blacklist_name} for IP {ip}")
                    for cidr in cidrs:
                        if _ip_in_cidr(ip_stripped, cidr):
                            logger.info(f"IP {ip} found in {blacklist_name} (CIDR range: {cidr})")
                            return (blacklist_name, True)
                else:
                    logger.debug(f"No CIDR ranges to check in {blacklist_name}")
                
                return (blacklist_name, False)
            except Exception as e:
                logger.warning(f"Error checking {blacklist_name}: {e}", exc_info=True)
                return (blacklist_name, None)  # None means error/unknown
        
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
                "ip": ip,
                "found_in": found_in,
                "blacklist_results": blacklist_results,
                "total_blacklists_checked": len(BLACKLISTS),
                "total_blacklists_found": len(found_in),
                "total_blacklists_failed": failed
            },
            "ip": ip
        }
    
    except Exception as e:
        logger.error(f"Error querying IP blocklists for {ip}: {e}", exc_info=True)
        return None

