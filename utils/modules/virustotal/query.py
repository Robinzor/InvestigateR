"""
VirusTotal query module - handles API communication
"""
import base64
import aiohttp
import logging
from typing import Dict, Any, Optional, Tuple
from utils.modules.base import InputType

logger = logging.getLogger(__name__)

API_BASE = "https://www.virustotal.com/api/v3"


def _get_endpoint(observable: str, input_type: Optional[InputType]) -> Tuple[str, Optional[str]]:
    """Return the best VT endpoint for the observable and a human friendly target description."""
    if input_type == InputType.IP:
        return f"{API_BASE}/ip_addresses/{observable}", f"ip {observable}"
    if input_type == InputType.DOMAIN:
        return f"{API_BASE}/domains/{observable}", f"domain {observable}"
    if input_type == InputType.HASH:
        return f"{API_BASE}/files/{observable}", f"hash {observable}"
    if input_type == InputType.URL:
        # VT requires a url-safe base64 without padding for URL lookups
        url_id = base64.urlsafe_b64encode(observable.encode()).decode().rstrip("=")
        return f"{API_BASE}/urls/{url_id}", f"url {observable}"

    # Fallback to search endpoint when type is unknown
    return f"{API_BASE}/search?query={observable}", f"search {observable}"


async def query_virustotal_async(
    observable: str,
    api_key: str,
    input_type: Optional[InputType] = None
) -> Dict[str, Any]:
    """
    Query VirusTotal API for threat intelligence.
    
    Args:
        observable: IP, domain, URL, or hash to query
        api_key: VirusTotal API key
        input_type: Detected input type to pick the right VT endpoint
        
    Returns:
        Raw API response data
    """
    url, target_desc = _get_endpoint(observable, input_type)
    headers = {"x-apikey": api_key}
    timeout = aiohttp.ClientTimeout(total=20)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                text_preview = ""
                try:
                    text_preview = (await response.text())[:300]
                except Exception:
                    text_preview = "<unable to read body>"

                if response.status == 200:
                    data = await response.json()
                    return {
                        "raw_data": data,
                        "observable": observable,
                        "input_type": input_type.value if input_type else None
                    }

                logger.warning(f"VirusTotal returned {response.status} for {target_desc}: {text_preview}")
                return {
                    "error": f"VirusTotal responded with {response.status}",
                    "status": response.status,
                    "body": text_preview,
                    "observable": observable
                }
    except aiohttp.ClientError as e:
        logger.error(f"VirusTotal query error: {e}")
        return {
            "error": f"VirusTotal query error: {str(e)}",
            "observable": observable
        }
