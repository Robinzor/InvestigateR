"""
URLHaus query module - handles API communication.
"""
import aiohttp
import ssl
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


async def query_urlhaus_async(observable: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Query URLHaus for a URL observable.

    URLHaus uses the same API key as MalwareBazaar (abuse.ch API key).
    """
    if not api_key:
        logger.warning("URLHaus API key is required (uses MalwareBazaar API key)")
        return {
            "error": "API key is required. Get one at https://bazaar.abuse.ch/api/",
            "observable": observable,
        }
    
    data = {"url": observable}
    headers = {
        "User-Agent": "investigateR/1.0",
        "Auth-Key": api_key
    }
    timeout = aiohttp.ClientTimeout(total=20)

    # Create SSL context that doesn't verify certificates
    # Note: abuse.ch services sometimes have certificate chain issues, so we disable
    # verification to ensure connectivity. This is acceptable for threat intelligence APIs.
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.post(API_URL, data=data, headers=headers) as response:
                text_preview = ""
                try:
                    text_preview = (await response.text())[:400]
                except Exception:
                    text_preview = "<unable to read body>"

                if response.status == 200:
                    payload = await response.json()
                    return {
                        "raw_data": payload,
                        "observable": observable,
                        "status": response.status,
                    }

                logger.warning(f"URLHaus returned {response.status}: {text_preview}")
                return {
                    "error": f"URLHaus responded with {response.status}",
                    "body": text_preview,
                    "status": response.status,
                    "observable": observable,
                }
    except aiohttp.ClientConnectorError as exc:
        logger.error(f"URLHaus connection error: {exc}")
        # Check if it's an SSL error
        if "SSL" in str(exc) or "CERTIFICATE" in str(exc):
            return {
                "error": f"SSL certificate verification failed for URLHaus API. This may be a temporary issue with the server's certificate.",
                "observable": observable,
            }
        return {
            "error": f"Could not connect to URLHaus API: {str(exc)}",
            "observable": observable,
        }
    except aiohttp.ClientError as exc:
        logger.error(f"URLHaus query error: {exc}")
        return {
            "error": f"URLHaus query error: {str(exc)}",
            "observable": observable,
        }
    except Exception as exc:
        logger.error(f"Unexpected error in URLHaus query: {exc}", exc_info=True)
        return {
            "error": f"Unexpected error querying URLHaus: {str(exc)}",
            "observable": observable,
        }

