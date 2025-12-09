"""
crt.sh query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any
from aiohttp import ClientTimeout
import asyncio

logger = logging.getLogger(__name__)


async def query_crtsh_async(domain: str, exclude_expired: bool = False) -> Optional[Dict[str, Any]]:
    """
    Query crt.sh for SSL/TLS certificates associated with a domain.
    
    Args:
        domain (str): The domain to check
        exclude_expired (bool): Whether to exclude expired certificates
        
    Returns:
        dict: Certificate information if successful, None otherwise
    """
    max_retries = 2
    base_delay = 3
    timeout = ClientTimeout(total=10)
    
    all_certificates = []
    
    for attempt in range(max_retries):
        try:
            delay = base_delay * (2 ** attempt)
            url = f"https://crt.sh/?q={domain}&output=json"
            if exclude_expired:
                url += "&exclude=expired"
            logger.info(f"Querying crt.sh for {domain} with exclude_expired={exclude_expired} (attempt {attempt + 1}/{max_retries})")
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            data = await response.json()
                            if not data:
                                logger.info(f"No certificates found for {domain}")
                                return None
                            
                            logger.info(f"Received {len(data)} certificates from crt.sh for {domain}")
                            all_certificates = data
                            break
                            
                        elif response.status == 502:
                            logger.warning(f"crt.sh query failed with status 502 (Bad Gateway) for {domain}")
                            if attempt < max_retries - 1:
                                logger.info(f"Retrying in {delay} seconds...")
                                await asyncio.sleep(delay)
                                continue
                            break
                        else:
                            logger.warning(f"crt.sh query failed with status {response.status} for {domain}")
                            if attempt < max_retries - 1:
                                logger.info(f"Retrying in {delay} seconds...")
                                await asyncio.sleep(delay)
                                continue
                            break
                            
                except asyncio.TimeoutError:
                    logger.warning(f"crt.sh query for {domain} timed out")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying in {delay} seconds...")
                        await asyncio.sleep(delay)
                        continue
                    break
                except aiohttp.ClientError as e:
                    logger.error(f"Network error while querying crt.sh for {domain}: {str(e)}")
                    if attempt < max_retries - 1:
                        logger.info(f"Retrying in {delay} seconds...")
                        await asyncio.sleep(delay)
                        continue
                    break
                    
        except Exception as e:
            logger.error(f"Error querying crt.sh for {domain}: {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {delay} seconds...")
                await asyncio.sleep(delay)
                continue
            break
    
    if not all_certificates:
        logger.info(f"No certificates found for {domain} after {max_retries} attempts")
        return None
    
    return {
        "raw_data": all_certificates,
        "domain": domain,
        "exclude_expired": exclude_expired
    }

