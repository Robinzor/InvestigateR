"""
GreyNoise query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_greynoise_async(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query the GreyNoise IP intelligence API for a single IP address.

    Args:
        ip: IPv4 address to query.
        api_key: GreyNoise API key (optional for community API).

    Returns:
        Raw API response data.
    """
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {
        "Accept": "application/json",
    }
    # Only add API key header if provided (optional)
    if api_key:
        headers["key"] = api_key

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "raw_data": data,
                        "ip": ip
                    }
                else:
                    text = await resp.text()
                    logger.warning(f"GreyNoise query failed ({resp.status}): {text}")
                    return {
                        "error": f"GreyNoise HTTP {resp.status}",
                        "details": text[:500],
                        "ip": ip
                    }
    except Exception as e:
        logger.error(f"Error querying GreyNoise for {ip}: {e}")
        return {
            "error": f"Error querying GreyNoise: {str(e)}",
            "ip": ip
        }

