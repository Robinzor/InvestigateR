"""
URLScanSearch query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_urlscan_search_async(observable: str) -> Optional[Dict[str, Any]]:
    """
    Search URLScan.io for domain/URL.

    Args:
        observable (str): The domain or URL to search.

    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        url = f"https://urlscan.io/api/v1/search/"
        params = {
            "q": f"domain:{observable} OR page.domain:{observable}"
        }
        logger.info(f"Searching URLScan for: {observable}")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Raw URLScan search response received")
                    return {
                        "raw_data": data,
                        "observable": observable
                    }
                else:
                    logger.warning(f"URLScan search API returned status {response.status}")
                    return None

    except aiohttp.ClientError as e:
        logger.error(f"Network error searching URLScan for {observable}: {e}")
    except Exception as e:
        logger.error(f"Error searching URLScan for {observable}: {e}", exc_info=True)

    return None

