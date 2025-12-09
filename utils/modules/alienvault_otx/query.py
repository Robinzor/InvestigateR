"""
AlienVault OTX query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any
import re

logger = logging.getLogger(__name__)


def _detect_observable_type(observable: str) -> str:
    """
    Detect the type of observable to determine the correct OTX API endpoint.
    
    Args:
        observable: The observable to check
        
    Returns:
        'ip', 'domain', 'hash', or 'unknown'
    """
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, observable):
        return 'ip'
    
    # Check if it's a hash (MD5, SHA1, SHA256)
    hash_pattern = r'^[a-fA-F0-9]{32,64}$'
    if re.match(hash_pattern, observable):
        if len(observable) == 32:
            return 'hash'  # MD5
        elif len(observable) == 40:
            return 'hash'  # SHA1
        elif len(observable) == 64:
            return 'hash'  # SHA256
    
    # Otherwise assume it's a domain
    return 'domain'


async def query_otx_async(observable: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query AlienVault OTX API for threat intelligence.
    
    Args:
        observable: The observable to query (IP, domain, or hash)
        api_key: The OTX API key
        
    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    if not api_key:
        logger.warning("AlienVault OTX API key not provided")
        return None
    
    # Detect observable type
    obs_type = _detect_observable_type(observable)
    logger.info(f"Querying AlienVault OTX for {obs_type}: {observable}")
    
    # Map observable type to OTX endpoint type
    endpoint_type_map = {
        'ip': 'IPv4',
        'domain': 'domain',
        'hash': 'file'
    }
    
    endpoint_type = endpoint_type_map.get(obs_type)
    if not endpoint_type:
        logger.warning(f"Unknown observable type for OTX: {obs_type}")
        return None
    
    # Construct API URL
    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint_type}/{observable}/general"
    
    headers = {
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Raw AlienVault OTX response received")
                    return {
                        "raw_data": data,
                        "observable": observable,
                        "type": obs_type
                    }
                elif response.status == 404:
                    logger.info(f"No data found in OTX for {observable}")
                    return {
                        "raw_data": {},
                        "observable": observable,
                        "type": obs_type,
                        "not_found": True
                    }
                else:
                    logger.warning(f"AlienVault OTX API returned status {response.status}")
                    try:
                        error_text = await response.text()
                        logger.warning(f"Error response: {error_text[:200]}")
                    except:
                        pass
                    return None
    
    except aiohttp.ClientError as e:
        logger.error(f"Network error querying AlienVault OTX for {observable}: {e}")
    except Exception as e:
        logger.error(f"Error querying AlienVault OTX for {observable}: {e}", exc_info=True)
    
    return None

