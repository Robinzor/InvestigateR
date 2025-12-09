import os
import asyncio
import re
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file, session, Response, stream_with_context
import json
import logging
from typing import List, Dict, Any, Optional
import aiohttp
import socket
from datetime import datetime
from utils.module_executor import module_executor
from utils.modules.base import InputType
from utils.ip_resolver import resolve_domain_to_ips
from urllib.parse import urljoin, urlparse
import ssl
import requests
from bs4 import BeautifulSoup
import io

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logging.getLogger('utils.urlscan').setLevel(logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'json'}
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

def current_timestamp_ms() -> str:
    now = datetime.now()
    return now.strftime("%Y%m%d_%H%M%S_") + f"{int(now.microsecond / 1000):03d}"

app.config['ASYNC_MODE'] = True

@app.context_processor
def inject_datetime():
    from utils.module_helpers import is_module_result_safe
    return dict(
        now=datetime.now,
        datetime=datetime,
        is_module_result_safe=is_module_result_safe
    )

API_KEYS_FILE = 'api_keys.json'

_api_keys_cache = None
_api_keys_cache_mtime = None

_results_storage = {}

def load_api_keys(force_reload=False):
    """
    Load API keys from api_keys.json file with caching.
    
    Args:
        force_reload: If True, force reload even if cached
    
    Returns:
        dict: API keys dictionary
    """
    global _api_keys_cache, _api_keys_cache_mtime
    
    try:
        file_mtime = None
        if os.path.exists(API_KEYS_FILE) and os.path.isfile(API_KEYS_FILE):
            file_mtime = os.path.getmtime(API_KEYS_FILE)
        
        if not force_reload and _api_keys_cache is not None:
            if file_mtime is None:
                return _api_keys_cache
            elif _api_keys_cache_mtime == file_mtime:
                return _api_keys_cache
        
        from utils.module_helpers import get_required_api_keys
        required_keys = list(get_required_api_keys())
        if 'opencti_url' not in required_keys:
            required_keys.append('opencti_url')
        
        if os.path.exists(API_KEYS_FILE) and os.path.isfile(API_KEYS_FILE):
            with open(API_KEYS_FILE, 'r') as f:
                keys = json.load(f)
                logger.debug(f"Loaded API keys from {API_KEYS_FILE}")
                for key in required_keys:
                    if key not in keys:
                        keys[key] = ""
                        logger.debug(f"Added missing key: {key}")
                
                urlscan_key = keys.get('urlscan', '')
                if urlscan_key and len(urlscan_key) < 36:
                    logger.warning("URLScan API key appears to be too short")
                
                _api_keys_cache = keys
                _api_keys_cache_mtime = file_mtime
                return keys
        else:
            logger.debug(f"{API_KEYS_FILE} not found, creating default keys")
            default_keys = {key: "" for key in required_keys}
            _api_keys_cache = default_keys
            _api_keys_cache_mtime = None
            return default_keys
    except Exception as e:
        logger.error(f"Error loading API keys: {str(e)}")
        from utils.module_helpers import get_required_api_keys
        required_keys = list(get_required_api_keys())
        if 'opencti_url' not in required_keys:
            required_keys.append('opencti_url')
        fallback_keys = {key: "" for key in required_keys}
        _api_keys_cache = fallback_keys
        _api_keys_cache_mtime = None
        return fallback_keys

def save_api_keys(keys):
    global _api_keys_cache, _api_keys_cache_mtime
    
    existing_keys = load_api_keys()
    
    for key, value in keys.items():
        if value and value.strip():
            existing_keys[key] = value.strip()
    
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(existing_keys, f)
    
    _api_keys_cache = None
    _api_keys_cache_mtime = None

async def check_api_key_status(api_key, service, api_keys=None):
    """Check if an API key is valid for a specific service"""
    if not api_key:
        logger.info(f"No API key provided for {service}")
        return 'invalid'
    
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        async with aiohttp.ClientSession() as session:
            if service == 'abuseipdb':
                try:
                    url = 'https://api.abuseipdb.com/api/v2/check'
                    headers = {'Key': api_key, 'Accept': 'application/json'}
                    params = {'ipAddress': '8.8.8.8', 'maxAgeInDays': '90'}
                    async with session.get(url, headers=headers, params=params, ssl=ssl_context) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            return 'unknown'
                except asyncio.TimeoutError:
                    return 'unknown'
                except Exception as e:
                    logger.error(f"Error validating AbuseIPDB API key: {e}")
                    return 'invalid'
            
            elif service == 'virustotal':
                try:
                    url = 'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8'
                    headers = {'x-apikey': api_key}
                    async with session.get(url, headers=headers, ssl=ssl_context) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            return 'unknown'
                except asyncio.TimeoutError:
                    return 'unknown'
                except Exception as e:
                    logger.error(f"Error validating VirusTotal API key: {e}")
                    return 'invalid'
            
            elif service == 'ipinfo':
                try:
                    url = 'https://ipinfo.io/8.8.8.8/json'
                    headers = {'Authorization': f'Bearer {api_key}'}
                    async with session.get(url, headers=headers, ssl=ssl_context) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            return 'unknown'
                except asyncio.TimeoutError:
                    return 'unknown'
                except Exception as e:
                    logger.error(f"Error validating IPInfo API key: {e}")
                    return 'invalid'
            
            elif service == 'urlscan':
                try:
                    test_url = 'https://urlscan.io/api/v1/scan/'
                    headers = {
                        'API-Key': api_key,
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    }
                    data = {
                        'url': 'https://example.com',
                        'visibility': 'public',
                        'tags': ['test']
                    }
                    async with session.post(test_url, headers=headers, json=data, ssl=ssl_context) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            return 'unknown'
                except asyncio.TimeoutError:
                    return 'unknown'
                except Exception as e:
                    logger.error(f"Error validating URLScan API key: {e}")
                    return 'invalid'
            
            elif service == 'opencti':
                try:
                    if not api_keys or 'opencti_url' not in api_keys:
                        logger.error("OpenCTI URL not found in configuration")
                        return 'invalid'
                    
                    opencti_url = api_keys['opencti_url']
                    if not opencti_url:
                        logger.error("OpenCTI URL is empty")
                        return 'invalid'
                    
                    query = """
                    query {
                        about {
                            version
                        }
                    }
                    """
                    
                    headers = {
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {api_key}'
                    }
                    
                    payload = {
                        "query": query
                    }
                    
                    base_url = urljoin(opencti_url, "/").rstrip("/")
                    url = f"{base_url}/graphql"
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with session.post(url, headers=headers, json=payload, ssl=ssl_context, timeout=timeout) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            return 'unknown'
                except asyncio.TimeoutError:
                    logger.warning(f"OpenCTI API key validation timed out (server may be unreachable)")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating OpenCTI API key: {e}")
                    if '401' in str(e) or '403' in str(e) or 'Unauthorized' in str(e) or 'Forbidden' in str(e):
                        return 'invalid'
                    return 'unknown'
            
            elif service == 'alienvault_otx':
                try:
                    url = 'https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general'
                    headers = {
                        'X-OTX-API-KEY': api_key,
                        'Accept': 'application/json'
                    }
                    timeout = aiohttp.ClientTimeout(total=30)
                    async with session.get(url, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            logger.warning(f"AlienVault OTX API returned status {response.status}")
                            return 'unknown'
                except asyncio.TimeoutError:
                    logger.warning(f"AlienVault OTX API key validation timed out")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating AlienVault OTX API key: {e}")
                    if '401' in str(e) or '403' in str(e) or 'Unauthorized' in str(e) or 'Forbidden' in str(e):
                        return 'invalid'
                    return 'unknown'
            
            elif service == 'googlesafebrowsing':
                try:
                    url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + api_key
                    payload = {
                        "client": {
                            "clientId": "investigateR",
                            "clientVersion": "1.0"
                        },
                        "threatInfo": {
                            "threatTypes": ["MALWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": "http://example.com"}]
                        }
                    }
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with session.post(url, json=payload, headers={'Content-Type': 'application/json'}, ssl=ssl_context, timeout=timeout) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status == 400:
                            # 400 might mean invalid request format, but API key might be valid
                            return 'unknown'
                        elif response.status == 403:
                            # 403 means invalid API key or quota exceeded
                            return 'invalid'
                        else:
                            logger.warning(f"Google Safe Browsing API returned status {response.status}")
                            return 'unknown'
                except asyncio.TimeoutError:
                    logger.warning(f"Google Safe Browsing API key validation timed out")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating Google Safe Browsing API key: {e}")
                    return 'unknown'
            
            elif service == 'urlquery':
                try:
                    from urllib.parse import quote
                    test_url = 'https://api.urlquery.net/public/v1/search/reports/'
                    headers = {
                        'x-apikey': api_key,
                        'accept': 'application/json'
                    }
                    params = {
                        "query": quote("https://example.com", safe=''),
                        "limit": 1
                    }
                    timeout = aiohttp.ClientTimeout(total=15)
                    
                    async with session.get(test_url, params=params, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                        response_text = await response.text()
                        logger.debug(f"URLQuery validation response status: {response.status}, body: {response_text[:200]}")
                        
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            logger.warning(f"URLQuery API returned status {response.status}: Invalid API key or rate limited")
                            return 'invalid'
                        elif response.status == 400:
                            if 'api' in response_text.lower() and ('key' in response_text.lower() or 'auth' in response_text.lower()):
                                return 'invalid'
                            return 'valid'
                        elif response.status == 404:
                            return 'valid'
                        else:
                            logger.warning(f"URLQuery API returned status {response.status}: {response_text[:100]}")
                            return 'valid'
                except asyncio.TimeoutError:
                    logger.warning(f"URLQuery API key validation timed out")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating URLQuery API key: {e}")
                    return 'unknown'
            
            elif service == 'malwarebazaar':
                try:
                    test_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
                    url = 'https://mb-api.abuse.ch/api/v1/'
                    data = {
                        "query": "get_info",
                        "hash": test_hash
                    }
                    headers = {
                        "Auth-Key": api_key,
                        "User-Agent": "investigateR/1.0"
                    }
                    timeout = aiohttp.ClientTimeout(total=10, connect=5)
                    async with session.post(url, data=data, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                        response_text = await response.text()
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            logger.warning(f"MalwareBazaar API returned {response.status}: {response_text[:200]}")
                            return 'invalid'
                        elif 400 <= response.status < 500:
                            return 'invalid'
                        else:
                            logger.warning(f"MalwareBazaar API returned status {response.status}: {response_text[:200]}")
                            return 'unknown'
                except asyncio.TimeoutError:
                    logger.warning(f"MalwareBazaar API key validation timed out")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating MalwareBazaar API key: {e}")
                    return 'unknown'
            
            elif service == 'hybridanalysis':
                try:
                    # Test Hybrid Analysis API key by checking API status
                    url = 'https://www.hybrid-analysis.com/api/v2/key/current'
                    headers = {
                        "api-key": api_key,
                        "User-Agent": "investigateR/1.0",
                        "Accept": "application/json"
                    }
                    timeout = aiohttp.ClientTimeout(total=10, connect=5)
                    async with session.get(url, headers=headers, ssl=ssl_context, timeout=timeout) as response:
                        if response.status == 200:
                            return 'valid'
                        elif response.status in [401, 403, 429]:
                            return 'invalid'  # 401/403/429 = invalid key or rate limited
                        elif 400 <= response.status < 500:
                            return 'invalid'  # Client errors = invalid key
                        else:
                            logger.warning(f"Hybrid Analysis API returned status {response.status}")
                            return 'unknown'
                except asyncio.TimeoutError:
                    logger.warning(f"Hybrid Analysis API key validation timed out")
                    return 'unknown'
                except Exception as e:
                    logger.warning(f"Error validating Hybrid Analysis API key: {e}")
                    return 'unknown'
            
            # Unknown service - if a key is provided, mark as invalid (key exists but service not recognized)
            logger.warning(f"Unknown service '{service}' for API key check")
            return 'invalid'  # If key exists but service unknown, likely invalid
    except aiohttp.ClientError as e:
        logger.error(f"Error checking {service} API key: {str(e)}")
        return 'invalid'  # Client errors with a key present = likely invalid
    except Exception as e:
        logger.error(f"Unexpected error checking {service} API key: {str(e)}")
        return 'invalid'  # Unexpected errors with a key present = likely invalid

def is_valid_ip(ip: str) -> bool:
    ip_regex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return bool(re.match(ip_regex, ip))

def is_valid_ip_with_port(value: str) -> bool:
    """
    Check if value is in IP:port format (IPv4 only).
    """
    if ':' not in value:
        return False
    if value.count(':') != 1:
        return False  # avoid IPv6 or malformed
    ip_part, port_part = value.rsplit(':', 1)
    if not port_part.isdigit():
        return False
    return is_valid_ip(ip_part)

def strip_port_from_ip(value: str) -> str:
    """
    Return IP portion if value is IP:port, otherwise return original.
    """
    if is_valid_ip_with_port(value):
        return value.rsplit(':', 1)[0]
    return value

def is_valid_domain(domain: str) -> bool:
    """
    Validates a domain name, including subdomains.
    Examples of valid domains:
    - example.com
    - sub.example.com
    - sub.sub.example.com
    - example.co.uk
    """
    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,6}$"
    return bool(re.match(domain_regex, domain))

def is_valid_url(url: str) -> bool:
    """
    Check if a string is a valid URL.
    Recognizes:
    - URLs with protocol: http://example.com/path, https://example.com/path
    - URLs without protocol but with path: example.com/path, example.com/path?query=1
    """
    # First check if it starts with http:// or https://
    if url.startswith(('http://', 'https://')):
        url_regex = r"^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        return bool(re.match(url_regex, url))
    
    # Check if it's a domain with a path (e.g., example.com/path or example.com/path?query=1)
    # This indicates it's a URL without protocol
    if '/' in url or '?' in url:
        # Split by / or ? to get the domain part
        domain_part = url.split('/')[0].split('?')[0]
        # Check if the domain part is a valid domain
        if is_valid_domain(domain_part):
            return True
    
    return False

def normalize_url(url: str) -> str:
    """
    Normalize a URL by adding https:// protocol if missing.
    
    Args:
        url (str): The URL to normalize (e.g., "example.com/path" or "https://example.com/path")
        
    Returns:
        str: The normalized URL with protocol (e.g., "https://example.com/path")
    """
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extracts the domain from a URL.
    
    Args:
        url (str): The URL to extract domain from (e.g., "https://example.com/path?query=1" or "example.com/path")
        
    Returns:
        str: The domain name (e.g., "example.com") or None if extraction fails
    """
    try:
        normalized_url = normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        if domain and is_valid_ip(domain):
            return domain.lower()
        if domain and is_valid_domain(domain):
            return domain.lower()
        return None
    except Exception as e:
        logger.warning(f"Error extracting domain from URL {url}: {e}")
        return None

def is_valid_file_hash(file_hash: str) -> bool:
    """
    Check if the input is a valid file hash.
    Supports MD5 (32), SHA1 (40), SHA256 (64), and ssdeep hashes.
    """
    hash_regex = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if re.match(hash_regex, file_hash):
        return True
    
    ssdeep_pattern = r"^\d+:[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+$"
    if re.match(ssdeep_pattern, file_hash):
        return True
    
    return False

def detect_input_type(input_str: str) -> str:
    if is_valid_ip(input_str) or is_valid_ip_with_port(input_str):
        return "IP"
    elif is_valid_domain(input_str):
        return "Domain"
    elif is_valid_url(input_str):
        return "URL"
    elif is_valid_file_hash(input_str):
        return "Hash"
    return "Unknown"

def format_abuseipdb_result(result: dict) -> dict:
    if not result:
        return {
            "reports": "N/A",
            "risk_score": "N/A",
            "isp": "N/A",
            "country": "N/A",
            "last_reported": "N/A",
            "link": "#"
        }
    return {
        "reports": result.get("reports", "N/A"),
        "risk_score": f"{result.get('risk_score', 0)}%",
        "isp": result.get("isp", "Unknown"),
        "country": result.get("country", "Unknown"),
        "last_reported": result.get("last_reported", "Never"),
        "link": result.get("link", "#")
    }

async def process_observable_streaming(observable: str, selected_tools: List[str], api_keys: Dict[str, str], form_data: Dict[str, Any], processing_id: str) -> List[Dict[str, Any]]:
    """Process observable with streaming results per tool"""
    return await process_observable(observable, selected_tools, api_keys, form_data, processing_id)

async def process_observable(observable: str, selected_tools: List[str], api_keys: Dict[str, str], form_data: Dict[str, Any] = None, processing_id: str = None) -> List[Dict[str, Any]]:
    """
    Process a single observable with selected tools using the uniform task manager.
    This is now much cleaner and easier to maintain!
    """
    results = []
    if is_valid_ip_with_port(observable):
        observable = strip_port_from_ip(observable)
    observable_type_str = detect_input_type(observable)
    
    if observable_type_str == "URL" and not observable.startswith(('http://', 'https://')):
        observable = normalize_url(observable)
        logger.debug(f"Normalized URL observable to: {observable}")
    type_mapping = {
        "IP": InputType.IP,
        "Domain": InputType.DOMAIN,
        "URL": InputType.URL,
        "Hash": InputType.HASH
    }
    input_type = type_mapping.get(observable_type_str, InputType.ANY)
    
    # Create main result object
    # For URLs, remove protocol from observable for display (but keep full URL for modules)
    display_observable = observable
    if observable_type_str == "URL" and observable.startswith(('http://', 'https://')):
        from urllib.parse import urlparse
        parsed = urlparse(observable)
        display_observable = parsed.netloc
        if parsed.path:
            display_observable += parsed.path
        if parsed.query:
            display_observable += '?' + parsed.query
        if parsed.fragment:
            display_observable += '#' + parsed.fragment
        logger.debug(f"Removed protocol from observable for display: '{observable}' -> '{display_observable}'")
    
    result = {
        "observable": display_observable,
        "type": observable_type_str,
        "data": {}
    }
    results.append(result)
    
    resolved_ip = None
    
    tool_kwargs = {}
    if form_data is None:
        try:
            form_data = {
                'crtsh_exclude_expired': request.form.get('crtsh_exclude_expired') == 'on'
            }
        except RuntimeError:
            form_data = {
                'crtsh_exclude_expired': False
            }
    
    if "crt.sh" in selected_tools:
        tool_kwargs['exclude_expired'] = form_data.get('crtsh_exclude_expired', False)
    
    from utils.module_helpers import get_ip_only_modules, get_domain_only_modules, get_slow_modules
    
    tools_to_execute = selected_tools.copy()
    if observable_type_str == "Domain":
        ip_only_tools = get_ip_only_modules()
        tools_to_execute = [tool for tool in tools_to_execute if tool not in ip_only_tools]
        if not tools_to_execute:
            logger.warning(f"No domain-compatible tools selected for {observable}. Selected tools were: {selected_tools}")
        if "DomainBlocklists" in selected_tools and "DomainBlocklists" not in tools_to_execute:
            logger.warning(f"DomainBlocklists was selected but missing from tools_to_execute for domain observable - adding explicitly")
            tools_to_execute.append("DomainBlocklists")
    elif observable_type_str == "IP":
        domain_only_tools = get_domain_only_modules()
        from utils.module_helpers import get_url_only_modules
        url_only_tools = get_url_only_modules()
        tools_to_execute = [tool for tool in tools_to_execute if tool not in domain_only_tools and tool not in url_only_tools]
        ip_only_tools = get_ip_only_modules()
        for ip_tool in ip_only_tools:
            if ip_tool in selected_tools and ip_tool not in tools_to_execute:
                logger.warning(f"Adding {ip_tool} to tools_to_execute for IP observable (was missing)")
                tools_to_execute.append(ip_tool)
        if "IPBlocklists" in selected_tools and "IPBlocklists" not in tools_to_execute:
            logger.warning(f"IPBlocklists was selected but missing from tools_to_execute - adding it explicitly")
            tools_to_execute.append("IPBlocklists")
    
    slow_tools = get_slow_modules()
    fast_tools = [tool for tool in tools_to_execute if tool not in slow_tools]
    slow_tools_in_list = [tool for tool in tools_to_execute if tool in slow_tools]
    tools_to_execute = fast_tools + slow_tools_in_list
    logger.info(f"Processing {observable} (type: {observable_type_str})")
    logger.info(f"Selected tools: {selected_tools}")
    logger.info(f"Tools to execute: {tools_to_execute}")
    
    if not tools_to_execute:
        logger.error(f"No compatible tools to execute for {observable} (type: {observable_type_str}). Selected: {selected_tools}")
        return results
    
    if "AbuseIPDB" in selected_tools and "AbuseIPDB" not in tools_to_execute:
        logger.warning(f"AbuseIPDB was selected but filtered out for {observable} (type: {observable_type_str})")
    
    if "IPBlocklists" in selected_tools and "IPBlocklists" not in tools_to_execute:
        logger.error(f"IPBlocklists was selected but NOT in tools_to_execute for {observable} (type: {observable_type_str}). Selected: {selected_tools}, To execute: {tools_to_execute}")
        tools_to_execute.append("IPBlocklists")
        logger.warning(f"Force-added IPBlocklists to tools_to_execute as safeguard")
    if observable_type_str == "Domain" and "DomainBlocklists" in selected_tools and "DomainBlocklists" not in tools_to_execute:
        logger.error(f"DomainBlocklists was selected but NOT in tools_to_execute for {observable} (type: {observable_type_str}). Selected: {selected_tools}, To execute: {tools_to_execute}")
        tools_to_execute.append("DomainBlocklists")
        logger.warning("Force-added DomainBlocklists to tools_to_execute as safeguard")
    
    if processing_id:
        from utils.modules.interfaces import StreamingResultHandler
        from utils.app_streamer import FlaskResultStreamer
        
        streamer = FlaskResultStreamer(app)
        result_handler = StreamingResultHandler(streamer, processing_id, result)
        
        tool_results = await module_executor.execute_modules(
            module_names=tools_to_execute,
            observable=observable,
            input_type=input_type,
            api_keys=api_keys,
            result_handler=result_handler,
            **tool_kwargs
        )
    else:
        tool_results = await module_executor.execute_modules(
            module_names=tools_to_execute,
            observable=observable,
            input_type=input_type,
            api_keys=api_keys,
            **tool_kwargs
        )
    
    logger.info(f"Tool results for {observable}: {tool_results}")
    logger.info(f"Selected tools: {selected_tools}")
    
    result["data"].update(tool_results)
    
    logger.info(f"Final result.data keys: {list(result['data'].keys())}")
    logger.info(f"Final result.data: {result['data']}")
    
    # Explicit check for IPBlocklists if it was selected
    if "IPBlocklists" in selected_tools and "ipblocklists" not in result["data"]:
        logger.error(f"IPBlocklists was selected but result.data does not contain 'ipblocklists' key! Tool results keys: {list(tool_results.keys())}, Final data keys: {list(result['data'].keys())}")
        # Check if it's in tool_results with a different key
        if "IPBlocklists" in tool_results or "ipblocklists" in tool_results:
            logger.warning(f"IPBlocklists result found in tool_results but not merged properly")
        else:
            logger.warning(f"IPBlocklists result not found in tool_results - module may have failed silently")
    # Explicit check for DomainBlocklists if it was selected
    if observable_type_str == "Domain" and "DomainBlocklists" in selected_tools and "domainblocklists" not in result["data"]:
        logger.error(f"DomainBlocklists was selected but result.data does not contain 'domainblocklists' key! Tool results keys: {list(tool_results.keys())}, Final data keys: {list(result['data'].keys())}")
        if "DomainBlocklists" in tool_results or "domainblocklists" in tool_results:
            logger.warning("DomainBlocklists result found in tool_results but not merged properly")
        else:
            logger.warning("DomainBlocklists result not found in tool_results - module may have failed silently")
    
    # Update storage if streaming
    # Note: When using result_handler, results are already streamed via handler
    # But we still need to ensure final result is in storage
    if processing_id and processing_id in app.processing_storage:
        # Find or create result in storage
        storage = app.processing_storage[processing_id]
        existing_results = storage.get('results', [])
        # Update or add this result
        # Match on both observable AND type to prevent overwriting
        result_observable = result.get('observable', display_observable)
        result_type = result.get('type', observable_type_str)
        found = False
        for i, r in enumerate(existing_results):
            existing_observable = r.get('observable', '')
            existing_type = r.get('type', 'Unknown')
            # Match on both observable and type to allow same observable with different types
            if existing_observable == result_observable and existing_type == result_type:
                existing_results[i] = result
                found = True
                logger.info(f"Updated existing result for {result_observable} (type: {result_type}) in storage")
                break
        if not found:
            existing_results.append(result)
            logger.info(f"Added new result for {result_observable} (type: {result_type}) to storage")
        storage['results'] = existing_results
        logger.info(f"Storage now has {len(existing_results)} results")
    
    # NOTE: IP tools are NEVER merged into domain results
    # If auto_resolve_domain is enabled, the IP will be processed as a separate observable
    # If auto_resolve_domain is disabled, IP tools are simply not executed for domains
    # This keeps the domain and IP results completely separate
    if resolved_ip and observable_type_str == "Domain":
        auto_resolve_enabled = form_data and form_data.get('auto_resolve_domain', False) if form_data else False
        if auto_resolve_enabled:
            logger.info(f"Skipping IP tools merge for {resolved_ip} - will be processed as separate observable")
        else:
            logger.info(f"Skipping IP tools for resolved IP {resolved_ip} - auto_resolve_domain is disabled, IP tools not executed for domains")
    
    return results

@app.route('/settings', methods=['GET', 'POST'])
async def settings():
    """Settings page for managing API keys"""
    # Get all modules dynamically for API key management
    from utils.module_helpers import get_all_modules, get_required_api_keys
    
    if request.method == 'POST':
        # Get API keys from form dynamically
        api_keys = {}
        required_keys = get_required_api_keys()
        
        # Get all API keys from form (format: {key_name}_key)
        for key_name in required_keys:
            form_key = f"{key_name}_key"
            api_keys[key_name] = request.form.get(form_key, '').strip()
        
        # Also handle opencti_url (special case)
        api_keys['opencti_url'] = request.form.get('opencti_url', '').strip()
        
        logger.info("Saving API keys...")
        # Save API keys to api_keys.json
        save_api_keys(api_keys)
        
        # Redirect to index page
        return redirect(url_for('index'))
    
    # Load existing API keys from api_keys.json
    api_keys = load_api_keys()
    logger.info("Loaded API keys from file")
    
    # SECURITY: Never send actual API key values to template - only indicate if they're set
    # This prevents API keys from appearing in HTML source code
    api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
    
    # Don't check API key status on page load - user can check manually via button
    # Initialize all as 'unknown' - will be checked when user clicks "Check API Keys" button
    api_status = {}
    for service in api_keys.keys():
        if service == 'opencti_url':
            continue  # Skip URL fields
        api_status[service] = 'unknown'
    
    # Get all modules for template
    all_modules = get_all_modules()
    
    # Group modules by API key name to avoid duplicates
    # For modules sharing the same API key (like URLHaus and MalwareBazaar), show combined label
    modules_by_key = {}
    for module in all_modules:
        api_key_name = module.get('api_key_name')
        if api_key_name:
            if api_key_name not in modules_by_key:
                modules_by_key[api_key_name] = []
            modules_by_key[api_key_name].append(module)
    
    # Create a list of unique API keys with their modules
    modules = []
    for api_key_name, module_list in modules_by_key.items():
        # Build display label - if multiple modules share the key, show combined label
        if len(module_list) > 1:
            display_names = '/'.join([m.get('display_name', '') for m in module_list])
            display_label = f"Abuse.ch ({display_names})"
        else:
            display_label = module_list[0].get('display_name', '')
        
        modules.append({
            'api_key_name': api_key_name,
            'display_name': module_list[0].get('display_name', ''),
            'display_label': display_label,  # Custom label for display
            'requires_api_key': module_list[0].get('requires_api_key', False),
            'module_list': module_list  # Store all modules sharing this key
        })
    
    return render_template('settings.html', api_keys_set=api_keys_set, api_status=api_status, modules=modules, opencti_url=api_keys.get('opencti_url', ''))

@app.route('/', methods=['GET', 'POST'])
async def index():
    """Main page for submitting observables"""
    # Load API keys
    api_keys = load_api_keys()
    
    # Don't check API key status on page load - user can check manually via button
    # Initialize all as 'unknown' - will be checked when user clicks "Check API Keys" button
    api_status = {}
    for service in api_keys.keys():
        api_status[service] = 'unknown'
    
    # Get all modules dynamically for template
    from utils.module_helpers import get_all_modules, is_module_result_safe
    modules = get_all_modules()
    
    api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
    if request.method == 'GET':
        return render_template('index.html', 
                             api_status=api_status,
                             modules=modules,
                             api_keys=api_keys_set,
                             OPENCTI_URL=api_keys.get('opencti_url', ''),
                             is_module_result_safe=is_module_result_safe)
    
    # Only process on POST requests
    if request.method == 'POST':
        # Get observables from form
        observables = request.form.get('observables', '').strip()
        # Get all modules dynamically for template
        from utils.module_helpers import get_all_modules
        modules = get_all_modules()
        
        api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
        
        if not observables:
            return render_template('index.html', 
                                 error='Please enter at least one observable', 
                                 api_status=api_status,
                                 modules=modules,
                                 api_keys=api_keys_set,
                                 OPENCTI_URL=api_keys.get('opencti_url', ''),
                                 is_module_result_safe=is_module_result_safe)
        
        # Get selected tools
        selected_tools = request.form.getlist('tools')
        if not selected_tools:
            return render_template('index.html', 
                                 error='Please select at least one tool', 
                                 api_status=api_status,
                                 modules=modules,
                                 api_keys=api_keys_set,
                                 OPENCTI_URL=api_keys.get('opencti_url', ''),
                                 is_module_result_safe=is_module_result_safe)
        
        # Start async processing and return streaming endpoint
        processing_id = f"proc_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        session['processing_id'] = processing_id
        session['processing_results'] = []
        session['processing_complete'] = False
        
        # Extract form data before starting background thread (request context won't be available there)
        form_data = {
            'crtsh_exclude_expired': request.form.get('crtsh_exclude_expired') == 'on',
            'auto_resolve_domain': request.form.get('auto_resolve_domain', 'false') == 'true',
            'auto_resolve_url': request.form.get('auto_resolve_url', 'false') == 'true',
            'auto_resolve_url_ip': request.form.get('auto_resolve_url_ip', 'false') == 'true',
        }
        
        # Store session data in a dict that we can update from background thread
        # We'll use a simple in-memory store keyed by processing_id
        if not hasattr(app, 'processing_storage'):
            app.processing_storage = {}
        
        app.processing_storage[processing_id] = {
            'results': [],
            'completed': False
        }
        
        # Get processing options from request (if sent from frontend)
        auto_resolve_domain = request.form.get('auto_resolve_domain', 'false') == 'true'
        auto_resolve_url = request.form.get('auto_resolve_url', 'false') == 'true'
        auto_resolve_url_ip = request.form.get('auto_resolve_url_ip', 'false') == 'true'
        
        # Start background processing
        import threading
        def process_background():
            async def run_processing():
                # Ensure InputType is in scope
                from utils.modules.base import InputType
                
                all_results = []
                processed_observables = set()  # Track processed observables to avoid duplicates
                resolved_ips_tracker = {}  # Track which domains resolved to which IPs
                resolved_domains_tracker = {}  # Track which URLs resolved to which domains
                
                # First pass: collect all observables and their resolved IPs/domains (if any)
                observables_list = []
                seen_observables = set()  # Track normalized observables to avoid duplicates
                for observable in observables.split('\n'):
                    observable = observable.strip()
                    if not observable:
                        continue
                    
                    observable_normalized = observable.lower()  # Normalize to lowercase for comparison
                    
                    # Skip if already in list (duplicate in input)
                    if observable_normalized in seen_observables:
                        logger.info(f"Skipping duplicate observable in input: {observable}")
                        continue
                    
                    seen_observables.add(observable_normalized)
                    observable_original = observable  # Keep original case for processing
                    observable_type_str = detect_input_type(observable_normalized)
                    
                    # If it's a URL, extract domain/IP (always extract, regardless of settings)
                    resolved_domain = None
                    if observable_type_str == "URL":
                        logger.info(f"Extracting host from URL: {observable_normalized}...")
                        # Ensure URL has protocol for extraction (extract_domain_from_url normalizes internally)
                        extracted_domain = extract_domain_from_url(observable_normalized)
                        if extracted_domain:
                            resolved_domain = extracted_domain.lower()  # Normalize domain/IP
                            resolved_domains_tracker[observable_normalized] = resolved_domain
                            logger.info(f"Successfully extracted host {resolved_domain} from URL: {observable_normalized}")
                            # If the host is actually an IP, record it directly as a resolved IP (always)
                            if is_valid_ip(resolved_domain):
                                resolved_ips_tracker[resolved_domain] = resolved_domain
                                logger.info(f"URL host is an IP; recorded resolved IP {resolved_domain} for URL: {observable_normalized}")
                        else:
                            logger.warning(f"Failed to extract host from URL: {observable_normalized} (observable_type_str={observable_type_str})")
                    
                    # If auto-resolve is enabled and it's a domain, resolve it to IP
                    resolved_ip = None
                    if auto_resolve_domain and observable_type_str == "Domain":
                        logger.info(f"Auto-resolve enabled for domain: {observable_normalized}, attempting DNS resolution...")
                        resolved_ips = await resolve_domain_to_ips(observable_normalized)
                        if resolved_ips:
                            resolved_ip = resolved_ips[0].lower()  # Normalize IP
                            resolved_ips_tracker[observable_normalized] = resolved_ip
                            logger.info(f"Successfully resolved domain {observable_normalized} to IP: {resolved_ip}")
                        else:
                            logger.warning(f"Failed to resolve domain {observable_normalized} to IP address")
                    
                    # If auto-resolve is enabled for URL and we extracted a domain, also resolve that domain to IP
                    if auto_resolve_domain and auto_resolve_url and observable_type_str == "URL" and resolved_domain:
                        logger.info(f"Auto-resolve enabled for domain extracted from URL: {resolved_domain}, attempting DNS resolution...")
                        resolved_ips = await resolve_domain_to_ips(resolved_domain)
                        if resolved_ips:
                            resolved_ip_from_url_domain = resolved_ips[0].lower()  # Normalize IP
                            # Store this IP for the resolved domain (not the URL)
                            resolved_ips_tracker[resolved_domain] = resolved_ip_from_url_domain
                            logger.info(f"Successfully resolved domain {resolved_domain} (from URL {observable_normalized}) to IP: {resolved_ip_from_url_domain}")
                        else:
                            logger.warning(f"Failed to resolve domain {resolved_domain} (from URL {observable_normalized}) to IP address")
                    
                    observables_list.append({
                        'original': observable_original,
                        'normalized': observable_normalized,
                        'type': observable_type_str,
                        'resolved_ip': resolved_ip,
                        'resolved_domain': resolved_domain
                    })
                
                # Track all domains (both resolved from URLs and directly entered) to ensure only one domain observable is created
                resolved_domains_from_urls = set()  # Track resolved domains from URLs
                direct_domains = []  # Track directly entered domains separately for logging
                all_domains_set = set()  # Track all domains for deduplication
                
                # First, collect all unique resolved domains from URLs
                if auto_resolve_url:
                    logger.info(f"Collecting resolved domains from URLs (auto_resolve_url is enabled)...")
                    for obs_info in observables_list:
                        if obs_info['type'] == "URL":
                            if obs_info['resolved_domain']:
                                resolved_domain_normalized = obs_info['resolved_domain'].lower()
                                # If host is an IP and auto_resolve_url_ip is enabled, skip adding as domain (will be handled as IP)
                                if auto_resolve_url_ip and is_valid_ip(resolved_domain_normalized):
                                    logger.info(f"URL {obs_info['original']} resolved to IP {resolved_domain_normalized}; skipping domain list (will handle as IP)")
                                    continue
                                if resolved_domain_normalized not in resolved_domains_from_urls:
                                    resolved_domains_from_urls.add(resolved_domain_normalized)
                                    all_domains_set.add(resolved_domain_normalized)
                                    logger.info(f"Collected resolved domain: {resolved_domain_normalized} from URL: {obs_info['original']}")
                                else:
                                    logger.info(f"Skipping duplicate resolved domain: {resolved_domain_normalized} from URL: {obs_info['original']}")
                            else:
                                logger.warning(f"URL {obs_info['original']} has no resolved domain (extraction may have failed)")
                    logger.info(f"Total resolved domains collected from URLs: {len(resolved_domains_from_urls)}")
                else:
                    logger.info("Skipping domain collection from URLs - auto_resolve_url is disabled")
                
                # Then, collect direct domains (but exclude those that are already resolved from URLs)
                for obs_info in observables_list:
                    if obs_info['type'] == "Domain":
                        domain_normalized = obs_info['normalized'].lower()
                        # Only track as direct domain if it's not already a resolved domain from a URL
                        if domain_normalized not in resolved_domains_from_urls:
                            direct_domains.append(domain_normalized)
                            all_domains_set.add(domain_normalized)
                            logger.info(f"Collected direct domain: {domain_normalized}")
                        else:
                            logger.info(f"Skipping domain {domain_normalized} - already resolved from URL, will not be processed as direct domain")
                
                # Track all IPs (both resolved from domains and directly entered) to ensure only one IP observable is created
                resolved_ips_from_domains = set()  # Track resolved IPs from domains
                direct_ips = []  # Track directly entered IPs separately for logging
                all_ips_set = set()  # Track all IPs for deduplication

                # If a URL host is an IP (auto_resolve_url_ip), capture it as a direct IP candidate
                if auto_resolve_url and auto_resolve_url_ip:
                    for obs_info in observables_list:
                        if obs_info['type'] == "URL" and obs_info.get('resolved_domain'):
                            host_val = obs_info['resolved_domain'].lower()
                            if is_valid_ip(host_val):
                                if host_val not in direct_ips and host_val not in resolved_ips_from_domains:
                                    direct_ips.append(host_val)
                                    all_ips_set.add(host_val)
                                    logger.info(f"Captured IP host from URL as direct IP: {host_val} (URL: {obs_info['original']})")
                                else:
                                    logger.info(f"Skipping duplicate IP host from URL: {host_val} (URL: {obs_info['original']})")

                # If a URL host is an IP (auto_resolve_url_ip), capture it as a resolved IP
                if auto_resolve_domain and auto_resolve_url and auto_resolve_url_ip:
                    for obs_info in observables_list:
                        if obs_info['type'] == "URL" and obs_info.get('resolved_domain'):
                            candidate_ip = obs_info['resolved_domain'].lower()
                            if is_valid_ip(candidate_ip):
                                if candidate_ip not in resolved_ips_from_domains:
                                    resolved_ips_from_domains.add(candidate_ip)
                                    all_ips_set.add(candidate_ip)
                                    logger.info(f"Captured IP host from URL for IP processing: {candidate_ip} (URL: {obs_info['original']})")
                                else:
                                    logger.info(f"Skipping duplicate IP host from URL: {candidate_ip} (URL: {obs_info['original']})")
                
                # First, collect all unique resolved IPs from domains
                if auto_resolve_domain:
                    logger.info(f"Collecting resolved IPs from domains (auto_resolve_domain is enabled)...")
                    for obs_info in observables_list:
                        if obs_info['type'] == "Domain":
                            if obs_info['resolved_ip']:
                                resolved_ip_normalized = obs_info['resolved_ip'].lower()
                                if resolved_ip_normalized not in resolved_ips_from_domains:
                                    resolved_ips_from_domains.add(resolved_ip_normalized)
                                    all_ips_set.add(resolved_ip_normalized)
                                    logger.info(f"Collected resolved IP: {resolved_ip_normalized} from domain: {obs_info['original']}")
                                else:
                                    logger.info(f"Skipping duplicate resolved IP: {resolved_ip_normalized} from domain: {obs_info['original']}")
                            else:
                                logger.warning(f"Domain {obs_info['original']} has no resolved IP (resolution may have failed)")
                    
                    # Also collect resolved IPs from domains that were extracted from URLs
                    if auto_resolve_url:
                        logger.info(f"Collecting resolved IPs from domains extracted from URLs...")
                        for obs_info in observables_list:
                            if obs_info['type'] == "URL" and obs_info['resolved_domain']:
                                resolved_domain = obs_info['resolved_domain']
                                # Check if this resolved domain has an IP in the tracker
                                if resolved_domain in resolved_ips_tracker:
                                    resolved_ip_normalized = resolved_ips_tracker[resolved_domain].lower()
                                    if resolved_ip_normalized not in resolved_ips_from_domains:
                                        resolved_ips_from_domains.add(resolved_ip_normalized)
                                        all_ips_set.add(resolved_ip_normalized)
                                        logger.info(f"Collected resolved IP: {resolved_ip_normalized} from domain {resolved_domain} (extracted from URL: {obs_info['original']})")
                                    else:
                                        logger.info(f"Skipping duplicate resolved IP: {resolved_ip_normalized} from domain {resolved_domain} (extracted from URL: {obs_info['original']})")
                    
                    logger.info(f"Total resolved IPs collected from domains: {len(resolved_ips_from_domains)}")
                else:
                    logger.info("Skipping IP collection from domains - auto_resolve_domain is disabled")
                
                # Collect IPs directly from URLs with IP hosts (always)
                logger.info(f"Collecting IPs directly from URLs with IP hosts...")
                urls_checked = 0
                ips_collected_from_urls = 0
                for obs_info in observables_list:
                    if obs_info['type'] == "URL":
                        urls_checked += 1
                        resolved_domain = obs_info.get('resolved_domain')
                        logger.info(f"Checking URL {obs_info['original']} for IP host, resolved_domain={resolved_domain}")
                        if resolved_domain:
                            # Check if the resolved domain is actually an IP
                            if is_valid_ip(resolved_domain):
                                ip_from_url = resolved_domain.lower()
                                # Always add to direct_ips if not already there (regardless of resolved_ips_from_domains)
                                if ip_from_url not in direct_ips:
                                    direct_ips.append(ip_from_url)
                                    all_ips_set.add(ip_from_url)
                                    ips_collected_from_urls += 1
                                    logger.info(f"✓ Collected IP {ip_from_url} directly from URL with IP host: {obs_info['original']}")
                                else:
                                    logger.info(f"IP {ip_from_url} from URL {obs_info['original']} already in direct_ips, skipping duplicate")
                            else:
                                logger.debug(f"URL {obs_info['original']} resolved_domain {resolved_domain} is not an IP, skipping IP collection")
                        else:
                            logger.warning(f"URL {obs_info['original']} has no resolved_domain - extraction may have failed")
                logger.info(f"IP Collection Summary: Checked {urls_checked} URLs, collected {ips_collected_from_urls} IPs. Total direct_ips now: {len(direct_ips)}")
                
                # Then, collect direct IPs (but exclude those that are already resolved from domains)
                for obs_info in observables_list:
                    if obs_info['type'] == "IP":
                        ip_normalized = obs_info['normalized'].lower()
                        # Only track as direct IP if it's not already a resolved IP from a domain
                        if ip_normalized not in resolved_ips_from_domains:
                            if ip_normalized not in direct_ips:  # Avoid duplicates
                                direct_ips.append(ip_normalized)
                                all_ips_set.add(ip_normalized)
                                logger.info(f"Collected direct IP: {ip_normalized}")
                        else:
                            logger.info(f"Skipping IP {ip_normalized} - already resolved from domain, will not be processed as direct IP")
                
                # Determine which domain to process (priority: resolved domains from URLs, then first direct domain)
                # IMPORTANT: Only ONE domain observable should be created, maximum
                # BUT: Only process resolved domains from URLs if auto_resolve_url is enabled
                # Direct domains should always be processed (they are explicitly entered by the user)
                domain_to_process = None
                
                # Log current state for debugging
                logger.info(f"Domain Processing Decision - auto_resolve_url: {auto_resolve_url}, resolved_domains_from_urls: {list(resolved_domains_from_urls)}, direct_domains: {direct_domains}")
                
                if auto_resolve_url and resolved_domains_from_urls and len(resolved_domains_from_urls) > 0:
                    # Use first resolved domain from URL (convert set to sorted list for consistency)
                    # Only if auto_resolve_url is enabled
                    sorted_resolved_domains = sorted(resolved_domains_from_urls)
                    domain_to_process = sorted_resolved_domains[0]
                    logger.info(f"Will process resolved domain from URL: {domain_to_process} (selected from {len(resolved_domains_from_urls)} total resolved domains, auto_resolve_url is enabled)")
                    if len(resolved_domains_from_urls) > 1:
                        skipped_domains = sorted_resolved_domains[1:]
                        logger.info(f"Skipping {len(skipped_domains)} additional resolved domains: {skipped_domains}")
                elif direct_domains and len(direct_domains) > 0:
                    # Use first direct domain if no resolved domains (or auto_resolve_url is disabled)
                    # Direct domains are always processed regardless of auto_resolve_url setting
                    domain_to_process = direct_domains[0]
                    logger.info(f"Will process first direct domain: {domain_to_process} (selected from {len(direct_domains)} total direct domains)")
                    if len(direct_domains) > 1:
                        logger.info(f"Skipping {len(direct_domains) - 1} additional direct domains: {direct_domains[1:]}")
                elif not auto_resolve_url and resolved_domains_from_urls and len(resolved_domains_from_urls) > 0:
                    # If auto_resolve_url is disabled, don't process resolved domains from URLs
                    logger.info(f"Skipping {len(resolved_domains_from_urls)} resolved domains from URLs - auto_resolve_url is disabled")
                
                # Log final decision
                if domain_to_process:
                    logger.info(f"FINAL DECISION: Will process ONLY ONE domain observable: {domain_to_process}")
                else:
                    logger.info(f"FINAL DECISION: No domain observable will be processed (auto_resolve_url={auto_resolve_url}, resolved_domains_count={len(resolved_domains_from_urls)}, direct_domains_count={len(direct_domains)})")
                
                # Determine which IPs to process (allow all unique IPs)
                # Direct IPs should always be processed; resolved IPs from domains require auto_resolve_domain
                ip_candidates = []
                
                # Final safeguard: Double-check URLs for IP hosts and ensure they're in direct_ips
                logger.info(f"[SAFEGUARD] Double-checking URLs for IP hosts before IP processing decision...")
                for obs_info in observables_list:
                    if obs_info['type'] == "URL":
                        url_value = obs_info.get('original', '') or obs_info.get('normalized', '')
                        resolved_domain = obs_info.get('resolved_domain')
                        if not resolved_domain:
                            # Try to extract again
                            extracted = extract_domain_from_url(url_value)
                            if extracted:
                                resolved_domain = extracted.lower()
                                obs_info['resolved_domain'] = resolved_domain
                                logger.info(f"[SAFEGUARD] Re-extracted host {resolved_domain} from URL: {url_value}")
                        if resolved_domain and is_valid_ip(resolved_domain):
                            ip_from_url = resolved_domain.lower()
                            if ip_from_url not in direct_ips:
                                direct_ips.append(ip_from_url)
                                all_ips_set.add(ip_from_url)
                                logger.warning(f"[SAFEGUARD] Added missing IP {ip_from_url} from URL {url_value} to direct_ips")
                
                # Log current state for debugging
                logger.info(f"IP Processing Decision - auto_resolve_domain: {auto_resolve_domain}, auto_resolve_url_ip: {auto_resolve_url_ip}, resolved_ips_from_domains: {list(resolved_ips_from_domains)}, direct_ips: {direct_ips}")
                
                if auto_resolve_domain and resolved_ips_from_domains:
                    sorted_resolved_ips = sorted(resolved_ips_from_domains)
                    ip_candidates.extend(sorted_resolved_ips)
                    if len(sorted_resolved_ips) > 0:
                        logger.info(f"Will process resolved IPs from domains: {sorted_resolved_ips} (auto_resolve_domain is enabled)")
                if direct_ips:
                    for ip in direct_ips:
                        if ip not in ip_candidates:
                            ip_candidates.append(ip)
                    logger.info(f"Will process direct IPs: {direct_ips}")
                if not ip_candidates:
                    logger.warning(f"✗✗✗ FINAL DECISION: No IP observable will be processed (auto_resolve_domain={auto_resolve_domain}, resolved_ips_count={len(resolved_ips_from_domains)}, direct_ips_count={len(direct_ips)}, direct_ips={direct_ips}) ✗✗✗")
                else:
                    logger.info(f"✓✓✓ FINAL DECISION: Will process {len(ip_candidates)} IP observables: {ip_candidates} ✓✓✓")
                
                # Second pass: process observables in parallel, avoiding duplicates
                # Create tasks for all observables that need processing
                processing_tasks = []
                for obs_info in observables_list:
                    observable = obs_info['original']
                    observable_normalized = obs_info['normalized']
                    observable_type_str = obs_info['type']
                    resolved_ip = obs_info['resolved_ip']
                    resolved_domain = obs_info['resolved_domain']
                    
                    # Skip if already processed
                    if observable_normalized in processed_observables:
                        logger.info(f"Skipping already processed observable: {observable}")
                        continue
                    
                    # If it's an IP, ALWAYS skip it in the second pass (will be processed in third pass if selected)
                    if observable_type_str == "IP":
                        logger.info(f"Skipping IP {observable_normalized} - will be processed as single IP observable if selected")
                        processed_observables.add(observable_normalized)  # Mark as processed to prevent duplicate processing
                        continue
                    
                    # If it's a URL, process it with URL-compatible tools only (never run IP-only tools on URLs)
                    if observable_type_str == "URL":
                        # Get URL-only tools (like PhishTank, GoogleSafeBrowsing) that need to run on the URL itself
                        from utils.module_helpers import get_url_only_modules
                        url_only_tools = get_url_only_modules()
                        # Also include tools that support URL (but exclude IP-only tools)
                        url_compatible_tools = []
                        for tool in selected_tools:
                            if tool in url_only_tools:
                                url_compatible_tools.append(tool)
                            else:
                                # Check if tool supports URL (but not if it's IP-only)
                                from utils.module_executor import module_executor
                                module = module_executor.get_module(tool)
                                if module:
                                    # Only include if it supports URL AND doesn't ONLY support IP
                                    if InputType.URL in module.INPUT_TYPES:
                                        # Exclude tools that ONLY support IP (like IP Blocklists)
                                        if not (InputType.IP in module.INPUT_TYPES and len(module.INPUT_TYPES) == 1):
                                            url_compatible_tools.append(tool)
                        
                        if url_compatible_tools:
                            # Process URL with URL-compatible tools first
                            logger.info(f"[SECOND PASS] Processing URL {observable_normalized} with URL-compatible tools: {url_compatible_tools}")
                            task = asyncio.create_task(process_observable_streaming(
                                observable, url_compatible_tools, api_keys, form_data, processing_id
                            ))
                            processing_tasks.append((task, observable, observable_normalized, "url"))
                        else:
                            logger.info(f"Skipping URL {observable_normalized} - no URL-compatible tools selected")
                            # Don't mark as processed - we still want to create IP observable if host is IP
                        continue
                    
                    # Create task for processing this observable (start immediately, don't wait)
                    if auto_resolve_domain and observable_type_str == "Domain" and resolved_ip:
                        # Process domain as separate observable (without IP tools merged - IP will be in separate observable)
                        logger.info(f"[SECOND PASS] Starting parallel task for domain: {observable}")
                        task = asyncio.create_task(process_observable_streaming(
                            observable, selected_tools, api_keys, form_data, processing_id
                        ))
                        processing_tasks.append((task, observable, observable_normalized, "domain"))
                    else:
                        # Normal processing (not a domain with auto-resolve, not an IP, not a URL with auto-resolve)
                        # Filter tools to only those that support this observable type
                        from utils.module_executor import module_executor
                        from utils.modules.base import InputType
                        type_mapping = {
                            "IP": InputType.IP,
                            "Domain": InputType.DOMAIN,
                            "URL": InputType.URL,
                            "Hash": InputType.HASH
                        }
                        input_type = type_mapping.get(observable_type_str)
                        compatible_tools = []
                        for tool in selected_tools:
                            module = module_executor.get_module(tool)
                            if module and input_type and module.validate_input(observable, input_type):
                                compatible_tools.append(tool)
                        
                        if compatible_tools:
                            logger.info(f"[SECOND PASS] Starting parallel task for observable: {observable} (type: {observable_type_str}) with compatible tools: {compatible_tools}")
                            task = asyncio.create_task(process_observable_streaming(
                                observable, compatible_tools, api_keys, form_data, processing_id
                            ))
                            processing_tasks.append((task, observable, observable_normalized, "normal"))
                        else:
                            logger.info(f"[SECOND PASS] No compatible tools for {observable} (type: {observable_type_str}), skipping")
                            processed_observables.add(observable_normalized)
                
                # Execute all tasks concurrently - process results as they complete
                if processing_tasks:
                    # Use gather with return_exceptions to wait for all tasks and handle them
                    # This is more reliable than as_completed for matching tasks
                    task_list = [t[0] for t in processing_tasks]
                    
                    # Wait for all tasks to complete
                    task_results = await asyncio.gather(*task_list, return_exceptions=True)
                    
                    # Process each result
                    for i, (task_result, task_info) in enumerate(zip(task_results, processing_tasks)):
                        task, observable, observable_normalized, task_type = task_info
                        try:
                            if isinstance(task_result, Exception):
                                logger.error(f"[SECOND PASS] Task for {observable} raised exception: {task_result}", exc_info=True)
                                processed_observables.add(observable_normalized)
                                continue
                            
                            results = task_result
                            logger.info(f"[SECOND PASS] Task completed for {observable} (type: {task_type}), results: {results is not None}, result count: {len(results) if results else 0}")
                            if results:
                                logger.info(f"[SECOND PASS] Result details for {observable}: {[r.get('observable', 'N/A') for r in results]}")
                                logger.info(f"[SECOND PASS] Result data keys for {observable}: {[list(r.get('data', {}).keys()) for r in results]}")
                                all_results.extend(results)
                                logger.info(f"[SECOND PASS] Added {task_type} observable results for: {observable}. Total results now: {len(all_results)}")
                                # Update storage immediately for streaming
                                if processing_id and processing_id in app.processing_storage:
                                    storage = app.processing_storage[processing_id]
                                    existing_results = storage.get('results', [])
                                    # Merge new results into storage
                                    # Match on both observable AND type to prevent overwriting
                                    for new_result in results:
                                        found = False
                                        new_observable = new_result.get('observable', '')
                                        new_type = new_result.get('type', 'Unknown')
                                        for j, existing in enumerate(existing_results):
                                            existing_observable = existing.get('observable', '')
                                            existing_type = existing.get('type', 'Unknown')
                                            # Match on both observable and type
                                            if existing_observable == new_observable and existing_type == new_type:
                                                existing_results[j] = new_result
                                                found = True
                                                break
                                        if not found:
                                            existing_results.append(new_result)
                                    storage['results'] = existing_results
                                    logger.info(f"[SECOND PASS] Updated storage for {observable}, storage now has {len(existing_results)} results")
                                processed_observables.add(observable_normalized)
                            else:
                                logger.warning(f"[SECOND PASS] No results returned for {observable} (type: {task_type})")
                                processed_observables.add(observable_normalized)
                        except Exception as e:
                            logger.error(f"Error processing observable {observable}: {e}", exc_info=True)
                            processed_observables.add(observable_normalized)  # Mark as processed even on error
                
                # Third pass: process the selected domain from URLs (only once, maximum 1 domain observable from URLs)
                # This is the ONLY place where a domain observable from URLs should be created
                # domain_to_process is only set if:
                # - auto_resolve_url is enabled AND there are resolved domains from URLs, OR
                # - there are direct domains entered by the user (always processed)
                if domain_to_process:
                    # Ensure domain is normalized
                    domain_to_process_normalized = domain_to_process.lower()
                    
                    # Double-check: this domain should NOT be in processed_observables yet
                    processed_observables.discard(domain_to_process)
                    processed_observables.discard(domain_to_process_normalized)
                    
                    # Final check before processing
                    if domain_to_process_normalized not in processed_observables:
                        logger.info(f"[THIRD PASS] Processing resolved domain from URL: {domain_to_process}")
                        try:
                            # Exclude URL-only tools when processing a domain (they should have been run on the original URL)
                            from utils.module_helpers import get_url_only_modules
                            url_only_tools = get_url_only_modules()
                            domain_tools_to_execute = [tool for tool in selected_tools if tool not in url_only_tools]
                            logger.info(f"[THIRD PASS] Excluding URL-only tools {url_only_tools} from domain processing, using tools: {domain_tools_to_execute}")
                            
                            logger.info(f"[THIRD PASS] Calling process_observable_streaming for domain: {domain_to_process} with tools: {domain_tools_to_execute}")
                            domain_results = await process_observable_streaming(
                                domain_to_process, domain_tools_to_execute, api_keys, form_data, processing_id
                            )
                            logger.info(f"[THIRD PASS] process_observable_streaming returned {len(domain_results) if domain_results else 0} results for domain: {domain_to_process}")
                            if domain_results:
                                logger.info(f"[THIRD PASS] Domain results details: {[r.get('observable', 'N/A') + ' (' + r.get('type', 'N/A') + ')' for r in domain_results]}")
                                all_results.extend(domain_results)
                                logger.info(f"[THIRD PASS] Added domain results for: {domain_to_process}. Total results now: {len(all_results)}")
                                # Update storage immediately for streaming
                                if processing_id and processing_id in app.processing_storage:
                                    storage = app.processing_storage[processing_id]
                                    existing_results = storage.get('results', [])
                                    # Merge new results into storage
                                    for new_result in domain_results:
                                        found = False
                                        for j, existing in enumerate(existing_results):
                                            if existing.get('observable') == new_result.get('observable'):
                                                existing_results[j] = new_result
                                                found = True
                                                break
                                        if not found:
                                            existing_results.append(new_result)
                                    storage['results'] = existing_results
                                    logger.info(f"[THIRD PASS] Updated storage for {domain_to_process}, storage now has {len(existing_results)} results")
                                processed_observables.add(domain_to_process_normalized)
                            else:
                                logger.warning(f"[THIRD PASS] No results returned for domain: {domain_to_process}")
                                processed_observables.add(domain_to_process_normalized)
                        except Exception as e:
                            logger.error(f"Error processing resolved domain {domain_to_process}: {e}", exc_info=True)
                            processed_observables.add(domain_to_process_normalized)
                    else:
                        logger.info(f"[THIRD PASS] Domain {domain_to_process} already processed, skipping")
                else:
                    logger.info(f"[THIRD PASS] No domain to process from URLs")
                
                # Fourth pass: process all IP observables (direct entries and resolved)
                # ip_candidates contains all unique IPs we plan to process
                if ip_candidates:
                    for ip_to_process in ip_candidates:
                        # Ensure IP is normalized
                        ip_to_process_normalized = ip_to_process.lower()
                        
                        # Double-check: this IP should NOT be in processed_observables yet
                        # Remove from processed_observables if it was added during IP skipping (check both normalized and original)
                        processed_observables.discard(ip_to_process)
                        processed_observables.discard(ip_to_process_normalized)
                        
                        # Final check before processing
                        if ip_to_process_normalized in processed_observables:
                            logger.warning(f"[THIRD PASS] SKIPPING IP {ip_to_process_normalized} - already in processed_observables")
                            continue
                        
                        logger.info(f"✓✓✓ [THIRD PASS] Processing IP as separate observable: {ip_to_process_normalized} ✓✓✓")
                        # Only run IP-capable tools to avoid empty results when only URL-only tools are selected
                        from utils.module_executor import module_executor
                        ip_tools = []
                        for tool in selected_tools:
                            module = module_executor.get_module(tool)
                            if module and InputType.IP in module.INPUT_TYPES:
                                ip_tools.append(tool)
                        # Explicit safeguard: Ensure IPBlocklists is included if selected
                        if "IPBlocklists" in selected_tools and "IPBlocklists" not in ip_tools:
                            logger.warning(f"[THIRD PASS] IPBlocklists was selected but missing from ip_tools - adding it explicitly")
                            ip_tools.append("IPBlocklists")
                        if not ip_tools:
                            logger.warning(f"[THIRD PASS] No IP-capable tools selected; adding placeholder IP observable {ip_to_process_normalized}")
                            # Check if IP observable already exists (by type:observable composite key)
                            existing_keys_in_results = {f"{r.get('type', '').lower()}:{r.get('observable', '').lower()}" for r in all_results}
                            ip_key = f"ip:{ip_to_process_normalized}"
                            if ip_key not in existing_keys_in_results:
                                # Still surface an empty IP observable to render a card indicating no IP tools
                                all_results.append({
                                    "observable": ip_to_process_normalized,
                                    "type": "IP",
                                    "data": {
                                        "ip_observable": {
                                            "error": "No IP-capable tools selected"
                                        }
                                    }
                                })
                            else:
                                logger.warning(f"[THIRD PASS] IP observable {ip_key} already exists, skipping placeholder")
                            processed_observables.add(ip_to_process_normalized)
                            continue
                        
                        results = await process_observable_streaming(
                            ip_to_process_normalized, ip_tools, api_keys, form_data, processing_id
                        )
                        # Verify we're not adding duplicate results (check by type:observable composite key)
                        existing_keys_in_results = {f"{r.get('type', '').lower()}:{r.get('observable', '').lower()}" for r in all_results}
                        ip_key = f"ip:{ip_to_process_normalized}"
                        
                        if results:
                            if ip_key not in existing_keys_in_results:
                                all_results.extend(results)
                                logger.info(f"✓✓✓ [THIRD PASS] Added IP observable results for: {ip_to_process_normalized} (count: {len(results)}) ✓✓✓")
                            else:
                                logger.warning(f"[THIRD PASS] SKIPPED adding IP observable - already exists in all_results: {ip_key}")
                        else:
                            # process_observable_streaming should always return at least one result, but if it doesn't, create a placeholder
                            logger.warning(f"[THIRD PASS] process_observable_streaming returned empty results for IP {ip_to_process_normalized}, creating placeholder")
                            if ip_key not in existing_keys_in_results:
                                all_results.append({
                                    "observable": ip_to_process_normalized,
                                    "type": "IP",
                                    "data": {
                                        "ip_observable": {
                                            "error": "No results returned from IP tools"
                                        }
                                    }
                                })
                                logger.info(f"✓✓✓ [THIRD PASS] Added placeholder IP observable for: {ip_to_process_normalized} ✓✓✓")
                            else:
                                logger.warning(f"[THIRD PASS] IP observable {ip_key} already exists, skipping placeholder")
                        
                        # Final verification that IP observable was added
                        final_check_keys = {f"{r.get('type', '').lower()}:{r.get('observable', '').lower()}" for r in all_results}
                        if ip_key not in final_check_keys:
                            logger.error(f"✗✗✗ [THIRD PASS] CRITICAL: IP observable {ip_key} was NOT added to all_results! ✗✗✗")
                        else:
                            logger.info(f"✓✓✓ [THIRD PASS] CONFIRMED: IP observable {ip_key} is in all_results ✓✓✓")
                        processed_observables.add(ip_to_process_normalized)
                        logger.info(f"[THIRD PASS] Successfully processed IP observable: {ip_to_process_normalized}")
                else:
                    logger.info("[THIRD PASS] No IP to process - skipping IP observable creation")
                
                # Mark as completed
                # Before finalizing, ensure no duplicate observables in all_results
                # Allow multiple IP observables; URLs and their resolved domains should BOTH be shown
                seen_observables_final = {}
                deduplicated_results = []
                # Allow multiple IP observables (no single-IP restriction)
                
                logger.info(f"[DEDUP] Starting deduplication with {len(all_results)} results")
                for idx, r in enumerate(all_results):
                    obs_key = r.get('observable', '').lower()
                    obs_type = r.get('type', '').lower()
                    data_keys = list(r.get('data', {}).keys())
                    
                    logger.debug(f"[DEDUP] Processing result {idx}: observable='{r.get('observable')}', type='{obs_type}', data_keys={data_keys}")
                    
                    # Use a composite key: observable + type to allow same observable with different types
                    # This allows URL "webeasyt.com/mVttL7CH" and Domain "webeasyt.com" to both exist
                    composite_key = f"{obs_type}:{obs_key}"
                    
                    if composite_key not in seen_observables_final:
                        seen_observables_final[composite_key] = True
                        deduplicated_results.append(r)
                        logger.debug(f"[DEDUP] Added observable: {r.get('observable')} (type: {obs_type})")
                    else:
                        existing_result = next((res for res in deduplicated_results if f"{res.get('type', '').lower()}:{res.get('observable', '').lower()}" == composite_key), None)
                        existing_data_keys = list(existing_result.get('data', {}).keys()) if existing_result else []
                        logger.warning(f"[DEDUP] Removing duplicate observable from final results: {r.get('observable')} (type: {obs_type})")
                        logger.debug(f"[DEDUP] Existing result has data_keys: {existing_data_keys}, new result has data_keys: {data_keys}")
                        # Merge data from duplicate into existing result
                        if existing_result:
                            existing_result['data'].update(r.get('data', {}))
                            logger.debug(f"[DEDUP] Merged data from duplicate into existing result. New data_keys: {list(existing_result.get('data', {}).keys())}")
                
                if len(deduplicated_results) < len(all_results):
                    logger.info(f"[DEDUP] Removed {len(all_results) - len(deduplicated_results)} duplicate observables from final results")
                    logger.info(f"[DEDUP] Final results count: {len(deduplicated_results)}")
                    final_observables_list = [f"{r.get('observable')} ({r.get('type')})" for r in deduplicated_results]
                    logger.debug(f"[DEDUP] Final observables: {final_observables_list}")
                all_results = deduplicated_results
                
                # Final safeguard: If a URL with an IP host was processed, ensure an IP observable exists
                # Check if any URL in results has an IP host, and if no IP observable exists, create one
                for result in all_results:
                    if result.get('type', '').lower() == 'url':
                        url_observable = result.get('observable', '')
                        # Try to extract IP from URL
                        extracted_host = extract_domain_from_url(url_observable)
                        if extracted_host and is_valid_ip(extracted_host):
                            ip_value = extracted_host.lower()
                            # Check if IP observable already exists
                            ip_exists = any(
                                r.get('type', '').lower() == 'ip' and r.get('observable', '').lower() == ip_value
                                for r in all_results
                            )
                            if not ip_exists:
                                logger.warning(f"[FINAL SAFEGUARD] URL {url_observable} has IP host {ip_value}, but no IP observable exists. Creating placeholder IP observable.")
                                all_results.append({
                                    "observable": ip_value,
                                    "type": "IP",
                                    "data": {
                                        "ip_observable": {
                                            "error": "IP extracted from URL but no IP-capable tools were selected or processing failed"
                                        }
                                    }
                                })
                                logger.info(f"[FINAL SAFEGUARD] Added placeholder IP observable: {ip_value}")
                
                if processing_id in app.processing_storage:
                    app.processing_storage[processing_id]['results'] = all_results
                    app.processing_storage[processing_id]['completed'] = True
            
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                # Run processing and wait for it to complete
                loop.run_until_complete(run_processing())
                
                # Give a small delay to ensure all callbacks and final updates are processed
                import time
                time.sleep(0.1)
                
                # Check for any remaining tasks
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                if pending:
                    logger.info(f"Waiting for {len(pending)} pending tasks to complete")
                    # Wait a bit more for tasks to complete naturally
                    try:
                        loop.run_until_complete(asyncio.wait(pending, timeout=5.0))
                    except Exception as e:
                        logger.warning(f"Error waiting for tasks: {e}")
                    
                    # Check again
                    still_pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                    if still_pending:
                        logger.warning(f"Cancelling {len(still_pending)} tasks that didn't complete")
                        for task in still_pending:
                            task.cancel()
                        # Wait for cancellations to complete
                        try:
                            loop.run_until_complete(asyncio.gather(*still_pending, return_exceptions=True))
                        except Exception as e:
                            logger.warning(f"Error cancelling tasks: {e}")
            finally:
                loop.close()
        
        thread = threading.Thread(target=process_background)
        thread.daemon = True
        thread.start()
        
        # Return page that will use SSE to stream results
        # Get all modules dynamically for template
        from utils.module_helpers import get_all_modules, is_module_result_safe
        modules = get_all_modules()
        
        api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
        
        return render_template('index.html', 
                             results=[], 
                             selected_tools=selected_tools, 
                             api_status=api_status,
                             modules=modules,
                             api_keys=api_keys_set,
                             OPENCTI_URL=api_keys.get('opencti_url', ''),
                             processing_id=processing_id,
                             is_module_result_safe=is_module_result_safe)
    
    # This should never be reached, but just in case
    # Get all modules dynamically for template
    from utils.module_helpers import get_all_modules, is_module_result_safe
    modules = get_all_modules()
    
    # SECURITY: Only pass boolean flags indicating if keys are set, not actual values
    api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
    
    return render_template('index.html', 
                         api_status=api_status,
                         modules=modules,
                         api_keys=api_keys_set,  # Only boolean flags, not actual values
                         OPENCTI_URL=api_keys.get('opencti_url', ''),
                         is_module_result_safe=is_module_result_safe)

@app.route('/test_urlscan', methods=['GET'])
async def test_urlscan():
    """Test endpoint for URLScan API key validation"""
    try:
        api_keys = load_api_keys()
        urlscan_key = api_keys.get('urlscan', '')
        
        if not urlscan_key:
            logger.error("No URLScan API key found")
            return jsonify({'error': 'No URLScan API key found'})
        
        logger.info(f"Testing URLScan API key: {urlscan_key[:5]}...{urlscan_key[-5:]}")
        status = await check_api_key_status(urlscan_key, 'urlscan')
        logger.info(f"URLScan API key status: {status}")
        
        return jsonify({
            'api_key': f"{urlscan_key[:5]}...{urlscan_key[-5:]}",
            'status': status
        })
    except Exception as e:
        logger.error(f"Error in test_urlscan endpoint: {str(e)}")
        # SECURITY: Don't expose internal error details to client
        return jsonify({'error': 'An error occurred while testing URLScan'}), 500

@app.route('/check-api-keys', methods=['POST'])
async def check_api_keys():
    """Check all API keys and return their status"""
    try:
        # Load API keys
        api_keys = load_api_keys()
        
        # Check API key status for all services
        api_status = {}
        for service, key in api_keys.items():
            if service == 'opencti_url':
                continue  # Skip URL fields
            logger.info(f"Checking {service} API key status...")
            api_status[service] = await check_api_key_status(key, service, api_keys)
        
        logger.info("API key check completed")
        return jsonify({'success': True, 'api_status': api_status})
    except Exception as e:
        logger.error(f"Error checking API keys: {str(e)}")
        # SECURITY: Don't expose internal error details to client
        return jsonify({'success': False, 'error': 'An error occurred while checking API keys'}), 500

@app.route('/delete_key', methods=['POST'])
def delete_key():
    """Delete a specific API key from the JSON file"""
    try:
        key_name = request.form.get('key_name')
        if not key_name:
            logger.error("No key name provided for deletion")
            return jsonify({'success': False, 'error': 'No key name provided'})
        
        logger.info(f"Attempting to delete key: {key_name}")
        
        # Load existing keys
        existing_keys = load_api_keys()
        
        # Check if the key exists
        if key_name not in existing_keys:
            logger.error(f"Key {key_name} not found in existing keys")
            return jsonify({'success': False, 'error': f'Key {key_name} not found'})
        
        # Set the specified key to empty string
        existing_keys[key_name] = ""
        logger.info(f"Key {key_name} set to empty string")
        
        # Save updated keys
        with open(API_KEYS_FILE, 'w') as f:
            json.dump(existing_keys, f)
        
        # Invalidate cache - next load will reload from file
        global _api_keys_cache, _api_keys_cache_mtime
        _api_keys_cache = None
        _api_keys_cache_mtime = None
        logger.info(f"Updated keys saved to {API_KEYS_FILE}")
        
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting key: {str(e)}")
        # SECURITY: Don't expose internal error details to client
        return jsonify({'success': False, 'error': 'An error occurred while deleting the key'})

@app.route('/process', methods=['POST'])
async def process_observable_route():
    observable = request.form.get('observable')
    tools = request.form.getlist('tools')
    
    results = {}
    
    if 'DNSRecords' in tools:
        try:
            from utils.modules.dns_records.query import query_dns_records_async
            results['DNSRecords'] = await query_dns_records_async(observable)
        except Exception as e:
            logger.error(f"Error processing DNS records: {str(e)}")
            results['DNSRecords'] = None
    
    return jsonify(results)

@app.route('/resolve_domain', methods=['GET'])
async def resolve_domain():
    """Resolve a domain to its IP address"""
    domain = request.args.get('domain')
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400
    
    try:
        # Try multiple DNS resolution methods
        try:
            # Method 1: Using socket.gethostbyname
            ip = socket.gethostbyname(domain)
            if ip:
                return jsonify({'ip': ip})
        except socket.gaierror:
            logger.warning(f"Socket resolution failed for {domain}, trying alternative methods")
        
        try:
            # Method 2: Using socket.getaddrinfo
            addrinfo = socket.getaddrinfo(domain, None)
            if addrinfo:
                # Get the first IPv4 address
                for addr in addrinfo:
                    if addr[0] == socket.AF_INET:  # IPv4
                        ip = addr[4][0]
                        return jsonify({'ip': ip})
        except socket.gaierror:
            logger.warning(f"getaddrinfo resolution failed for {domain}")
        
        # If all methods fail, try using aiohttp with a public DNS server
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://dns.google/resolve?name={domain}&type=A') as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer['type'] == 1:  # A record
                                    return jsonify({'ip': answer['data']})
        except Exception as e:
            logger.warning(f"Google DNS resolution failed for {domain}: {str(e)}")
        
        # If all methods fail, return a more descriptive error
        return jsonify({'error': 'Could not resolve domain using any available method'}), 404
        
    except Exception as e:
        logger.error(f"Error resolving domain {domain}: {str(e)}")
        # SECURITY: Don't expose internal error details to client
        return jsonify({'error': 'An error occurred while resolving the domain'}), 500

def resolve_dns(domain):
    try:
        url = f"https://dns.quad9.net:5053/dns-query?name={domain}&type=A"
        headers = {
            'Accept': 'application/dns-json'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if 'Answer' in data:
            return [answer['data'] for answer in data['Answer']]
        return []
    except Exception as e:
        return [f"Error resolving DNS: {str(e)}"]

def get_website_info(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        dns_ips = resolve_dns(domain)
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.title.string if soup.title else "No title found"
        
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        description = meta_desc['content'] if meta_desc else "No description found"
        
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        keywords = meta_keywords['content'] if meta_keywords else "No keywords found"
        
        h1_tags = [h1.text.strip() for h1 in soup.find_all('h1')]
        
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        return {
            'url': url,
            'domain': domain,
            'dns_ips': dns_ips,
            'title': title,
            'description': description,
            'keywords': keywords,
            'h1_tags': h1_tags,
            'links': links
        }
    except Exception as e:
        return {
            'url': url,
            'error': str(e)
        }



@app.route('/investigate', methods=['POST'])
def investigate():
    data = request.get_json()
    urls = data.get('urls', [])
    
    results = []
    for url in urls:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        result = get_website_info(url)
        results.append(result)
    
    return jsonify(results)

@app.route('/save', methods=['POST'])
def save():
    data = request.get_json()
    format_type = data.get('format')
    urls = data.get('urls', [])
    
    # Get results from processing storage instead of session to avoid cookie size issues
    processing_id = session.get('processing_id')
    results = []
    if processing_id and hasattr(app, 'processing_storage') and processing_id in app.processing_storage:
        results = app.processing_storage[processing_id].get('results', [])
    
    saved_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Embed timestamp so reloads can show when it was saved
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict):
                r['saved_at'] = saved_at
    
    if not results:
        return jsonify({'error': 'No results found to save'}), 400
    
    if format_type == 'json':
        # Export raw results as JSON so they can be reloaded later
        content = json.dumps(results, ensure_ascii=False, indent=2)
        return send_file(
            io.BytesIO(content.encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'investigation_results_{current_timestamp_ms()}.json'
        )
    else:
        return jsonify({'error': 'Invalid format type. Supported: json'}), 400


@app.route('/api/stream_results/<processing_id>', methods=['GET'])
def stream_results(processing_id):
    """Stream results via Server-Sent Events (SSE)"""
    def generate():
        import time
        import hashlib
        last_count = 0
        last_results_hash = None
        max_wait = 300  # 5 minutes max
        saved_at = None
        
        for i in range(max_wait):
            # Check processing storage for this processing ID
            if not hasattr(app, 'processing_storage') or processing_id not in app.processing_storage:
                yield f"data: {json.dumps({'error': 'Invalid processing ID'})}\n\n"
                break
            
            storage = app.processing_storage[processing_id]
            results = storage.get('results', [])
            completed = storage.get('completed', False)
            # Persist a saved_at timestamp once per processing run so UI can show when it was generated
            if not saved_at:
                saved_at = storage.get('saved_at') or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                storage['saved_at'] = saved_at
            if results and isinstance(results, list):
                for r in results:
                    if isinstance(r, dict) and 'saved_at' not in r:
                        r['saved_at'] = saved_at
            
            # Results are stored in processing_storage, not session (to avoid cookie size limits)
            
            # Create a hash of the results to detect changes (not just count changes)
            results_json = json.dumps(results, sort_keys=True, default=str)
            results_hash = hashlib.md5(results_json.encode()).hexdigest()
            
            # If we have new results OR results have been updated (hash changed), send them
            if len(results) > last_count or results_hash != last_results_hash or (i == 0 and len(results) > 0):
                data = {
                    'results': results,
                    'count': len(results),
                    'completed': completed
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_count = len(results)
                last_results_hash = results_hash
            
            if completed:
                yield f"data: {json.dumps({'completed': True, 'final': True})}\n\n"
                break
            
            time.sleep(0.3)  # Poll every 300ms for faster updates
        
        yield f"data: {json.dumps({'error': 'Timeout'})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/results_status', methods=['GET'])
def results_status():
    """Check if results are available in session (for async display)"""
    processing_id = request.args.get('processing_id')
    if not processing_id or session.get('processing_id') != processing_id:
        return jsonify({'error': 'Invalid or missing processing ID'}), 404
    
    # Get results from processing storage instead of session
    results = []
    completed = False
    if processing_id and hasattr(app, 'processing_storage') and processing_id in app.processing_storage:
        storage = app.processing_storage[processing_id]
        results = storage.get('results', [])
        completed = storage.get('completed', False)
    
    return jsonify({
        'has_results': len(results) > 0,
        'count': len(results),
        'completed': completed,
        'results': results
    })

@app.route('/api/render_results', methods=['POST'])
def render_results():
    """Render results HTML for async display"""
    data = request.get_json()
    results = data.get('results', [])
    selected_tools = data.get('selected_tools', [])
    saved_at = None
    if isinstance(results, list):
        # If results came from streaming, they may already include saved_at
        saved_at = next((r.get('saved_at') for r in results if isinstance(r, dict) and r.get('saved_at')), None)
        if not saved_at:
            saved_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for r in results:
            if isinstance(r, dict) and 'saved_at' not in r:
                r['saved_at'] = saved_at
    
    # Store results in processing storage (not session) to avoid cookie size limits
    processing_id = session.get('processing_id')
    if processing_id and isinstance(results, list) and results:
        if not hasattr(app, 'processing_storage'):
            app.processing_storage = {}
        if processing_id not in app.processing_storage:
            app.processing_storage[processing_id] = {'results': [], 'completed': False}
        app.processing_storage[processing_id]['results'] = results

    # Load API status for template
    api_keys = load_api_keys()
    api_status = {}
    for service, key in api_keys.items():
        if key:
            api_status[service] = 'valid'  # Simplified for async display
        else:
            api_status[service] = 'unknown'
    
    # SECURITY: Only pass boolean flags indicating if keys are set, not actual values
    api_keys_set = {k: bool(v and v.strip()) for k, v in api_keys.items()}
    
    # Get all modules dynamically for template
    from utils.module_helpers import get_all_modules, is_module_result_safe
    modules = get_all_modules()
    
    # Render just the results container HTML using a partial template
    return render_template('index.html',
                         results=results,
                         selected_tools=selected_tools,
                         api_status=api_status,
                         modules=modules,
                         api_keys=api_keys_set,  # Only boolean flags, not actual values
                         OPENCTI_URL=api_keys.get('opencti_url', ''))


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)