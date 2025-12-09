"""
ShodanInternetDB query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_shodan_internetdb_async(ip: str) -> Optional[Dict[str, Any]]:
    """
    Query Shodan InternetDB API for IP information.

    Args:
        ip (str): The IP address to query.

    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        logger.info(f"Querying Shodan InternetDB for IP: {ip}")
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                text_preview = ""
                try:
                    text_preview = (await response.text())[:300]
                except Exception:
                    text_preview = "<unable to read body>"

                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Raw Shodan InternetDB response received")
                    return {
                        "raw_data": data,
                        "ip": ip
                    }

                logger.warning(f"Shodan InternetDB API returned status {response.status}: {text_preview}")
                return {
                    "error": f"Shodan InternetDB responded with {response.status}",
                    "status": response.status,
                    "body": text_preview,
                    "ip": ip
                }

    except aiohttp.ClientError as e:
        logger.error(f"Network error querying Shodan InternetDB for {ip}: {e}")
    except Exception as e:
        logger.error(f"Error querying Shodan InternetDB for {ip}: {e}", exc_info=True)

    return None

