"""
IPInfo query module - handles API communication
"""
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any
import ipaddress

logger = logging.getLogger(__name__)


async def query_ipinfo_async(ip_or_hostname: str, api_key: str, **kwargs) -> Optional[Dict[str, Any]]:
    """
    Queries the IPInfo API for information about an IP address.
    Note: IPInfo API only supports IP addresses, not domains.

    Args:
        ip_or_hostname (str): The IP address to query.
        api_key (str): The IPInfo API key.
        **kwargs: Additional parameters (may include input_type)

    Returns:
        dict: Raw API response data.
        None: If an error occurs or if input is not an IP address.
    """
    if not api_key:
        logger.warning("IPInfo API key not provided")
        return None

    # Check if this is actually an IP address (IPv4 or IPv6, including compressed)
    ip_or_hostname = (ip_or_hostname or "").strip()
    input_type = kwargs.get('input_type')
    observable_type = kwargs.get('observable_type')
    
    # If input_type is provided, check if it's an IP
    if input_type:
        from utils.modules.base import InputType
        if input_type != InputType.IP:
            logger.debug(f"IPInfo: Skipping {ip_or_hostname} - not an IP address (type: {input_type})")
            return None
    
    # Also check observable_type string if provided
    if observable_type and observable_type != "IP":
        logger.debug(f"IPInfo: Skipping {ip_or_hostname} - not an IP address (type: {observable_type})")
        return None
    
    try:
        ipaddress.ip_address(ip_or_hostname)
    except Exception:
        logger.debug(f"IPInfo: Skipping {ip_or_hostname} - invalid IP format")
        return None

    url = f"https://ipinfo.io/{ip_or_hostname}?token={api_key}"
    logger.info(f"Querying IPInfo API for IP: {ip_or_hostname}")
    
    # Simple retry for transient failures/429
    for attempt in range(2):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                        except Exception as json_err:
                            logger.warning(f"IPInfo JSON parse error for {ip_or_hostname}: {json_err}")
                            return None
                        
                        logger.info(f"Raw IPInfo response received")
                        return {
                            "raw_data": data,
                            "observable": ip_or_hostname
                        }
                    
                    error_text = await response.text()
                    logger.warning(f"IPInfo API returned status {response.status}: {error_text[:200]}")
                    
                    # Retry on 429/5xx once
                    if response.status in (429, 500, 502, 503, 504) and attempt == 0:
                        await asyncio.sleep(1)
                        continue
                    
                    return None
        except aiohttp.ClientError as e:
            logger.error(f"Network error querying IPInfo for '{ip_or_hostname}' (attempt {attempt+1}): {e}")
            if attempt == 0:
                await asyncio.sleep(1)
                continue
        except Exception as e:
            logger.error(f"Error querying IPInfo for '{ip_or_hostname}' (attempt {attempt+1}): {e}", exc_info=True)
            if attempt == 0:
                await asyncio.sleep(1)
                continue

    return None

