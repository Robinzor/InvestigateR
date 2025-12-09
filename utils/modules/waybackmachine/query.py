"""
WaybackMachine query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_waybackmachine_async(domain: str) -> Optional[Dict[str, Any]]:
    """
    Query Wayback Machine for domain snapshots.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": domain,
            "output": "json",
            "limit": 50  # Reduced limit to speed up response for domains with many snapshots
            # Removed 'fl' parameter to get full response for better compatibility
        }
        logger.info(f"Querying Wayback Machine for domain: {domain}")
        
        async with aiohttp.ClientSession() as session:
            # Increase timeout for domains with many snapshots
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        logger.info(f"Raw Wayback Machine response received, type: {type(data)}, length: {len(data) if isinstance(data, list) else 'N/A'}")
                        if isinstance(data, list) and len(data) > 0:
                            logger.debug(f"First row sample: {data[0][:3] if isinstance(data[0], list) else data[0]}")
                        return {
                            "raw_data": data,
                            "domain": domain
                        }
                    except Exception as e:
                        logger.error(f"Error parsing Wayback Machine JSON response: {e}")
                        # Try to get text response for debugging
                        text = await response.text()
                        logger.debug(f"Response text (first 500 chars): {text[:500]}")
                        return None
                else:
                    logger.warning(f"Wayback Machine API returned status {response.status}")
                    return None

    except aiohttp.ClientError as e:
        logger.error(f"Network error querying Wayback Machine for {domain}: {e}")
    except Exception as e:
        logger.error(f"Error querying Wayback Machine for {domain}: {e}", exc_info=True)

    return None

