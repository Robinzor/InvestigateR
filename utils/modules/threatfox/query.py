"""
ThreatFox query module - handles API communication
"""
import aiohttp
import json
import ssl
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def query_threatfox_async(observable: str, api_key: str = "") -> Optional[Dict[str, Any]]:
    """
    Query ThreatFox API for IOCs (IP, Domain, Hash).
    
    Args:
        observable: IP address, domain, or hash to query
        api_key: API key (required, uses MalwareBazaar API key)
        
    Returns:
        Raw API response data: {"raw_data": {...}, "observable": "..."}
    """
    if not observable:
        logger.warning("ThreatFox query requires an observable")
        return {
            "raw_data": {},
            "observable": "",
            "found": False,
            "error": "Observable is required"
        }
    
    if not api_key:
        logger.warning("ThreatFox API key is required (uses MalwareBazaar API key)")
        return {
            "raw_data": {},
            "observable": observable,
            "found": False,
            "error": "API key is required. Get one at https://bazaar.abuse.ch/api/"
        }
    
    # Determine IOC type based on observable format
    observable_clean = observable.strip()
    ioc_type = None
    
    # Check if it's an IP address
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, observable_clean):
        ioc_type = "ip"
    # Check if it's a hash (MD5: 32, SHA1: 40, SHA256: 64)
    elif len(observable_clean) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in observable_clean):
        ioc_type = "hash"
        observable_clean = observable_clean.upper()  # ThreatFox expects uppercase hashes
    # Otherwise assume it's a domain
    else:
        ioc_type = "domain"
    
    logger.info(f"Querying ThreatFox for {ioc_type}: {observable_clean[:30]}...")
    
    # Prepare JSON data (ThreatFox API expects JSON in request body)
    json_data = {
        "query": "search_ioc",
        "search_term": observable_clean
    }
    
    # Serialize to JSON string explicitly
    json_string = json.dumps(json_data)
    
    # Prepare headers (API key is required, Content-Type must be set explicitly)
    headers = {
        "User-Agent": "investigateR/1.0",
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    
    timeout = aiohttp.ClientTimeout(total=10, connect=5)

    # Create SSL context that doesn't verify certificates
    # Note: abuse.ch services sometimes have certificate chain issues, so we disable
    # verification to ensure connectivity. This is acceptable for threat intelligence APIs.
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.post(
                THREATFOX_API_URL,
                data=json_string.encode('utf-8'),  # Send JSON string as bytes
                headers=headers
            ) as response:
                if response.status == 200:
                    try:
                        json_response = await response.json()
                        logger.debug(f"ThreatFox API response received: {json_response}")
                        
                        # Check query status
                        query_status = json_response.get("query_status", "unknown")
                        logger.debug(f"ThreatFox query_status: {query_status}")
                        
                        if query_status == "ok":
                            data_list = json_response.get("data", [])
                            logger.debug(f"ThreatFox data list length: {len(data_list) if data_list else 0}")
                            
                            if data_list and len(data_list) > 0:
                                # IOC found in database
                                logger.info(f"IOC found in ThreatFox: {observable_clean[:30]}...")
                                return {
                                    "raw_data": data_list,  # All results
                                    "observable": observable_clean,
                                    "found": True,
                                    "ioc_type": ioc_type
                                }
                            else:
                                # No data returned
                                logger.info(f"No data in response for IOC: {observable_clean[:30]}...")
                                return {
                                    "raw_data": {"query_status": "no_results"},
                                    "observable": observable_clean,
                                    "found": False,
                                    "ioc_type": ioc_type
                                }
                        elif query_status == "no_results":
                            logger.info(f"IOC not found in ThreatFox: {observable_clean[:30]}...")
                            return {
                                "raw_data": {"query_status": "no_results"},
                                "observable": observable_clean,
                                "found": False,
                                "ioc_type": ioc_type
                            }
                        else:
                            logger.warning(f"ThreatFox query status: {query_status}, full response: {json_response}")
                            return {
                                "raw_data": json_response,
                                "observable": observable_clean,
                                "found": False,
                                "query_status": query_status,
                                "ioc_type": ioc_type,
                                "error": f"Unexpected query status: {query_status}"
                            }
                    except Exception as e:
                        logger.error(f"Failed to parse ThreatFox JSON response: {e}", exc_info=True)
                        return {
                            "raw_data": {},
                            "observable": observable_clean,
                            "found": False,
                            "ioc_type": ioc_type,
                            "error": f"Failed to parse response: {str(e)}"
                        }
                elif response.status == 401:
                    response_text = await response.text()
                    logger.warning(f"ThreatFox API returned 401 Unauthorized: {response_text[:200]}")
                    return {
                        "raw_data": {},
                        "observable": observable_clean,
                        "found": False,
                        "ioc_type": ioc_type,
                        "error": f"Unauthorized - invalid or missing API key. Response: {response_text[:100]}"
                    }
                else:
                    logger.warning(f"ThreatFox API returned status {response.status}")
                    try:
                        error_text = await response.text()
                        logger.debug(f"Error response: {error_text}")
                    except Exception:
                        pass
                    return {
                        "raw_data": {},
                        "observable": observable_clean,
                        "found": False,
                        "ioc_type": ioc_type,
                        "error": f"API returned status {response.status}"
                    }
                    
    except aiohttp.ClientConnectorError as e:
        logger.error(f"Connection error while querying ThreatFox: {e}")
        if "SSL" in str(e) or "CERTIFICATE" in str(e):
            return {
                "raw_data": {},
                "observable": observable_clean,
                "found": False,
                "ioc_type": ioc_type,
                "error": "SSL certificate verification failed for ThreatFox API. This may be a temporary certificate issue."
            }
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "ioc_type": ioc_type,
            "error": f"Could not connect to ThreatFox API: {str(e)}"
        }
    except aiohttp.ClientError as e:
        logger.error(f"Network error while querying ThreatFox: {e}")
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "ioc_type": ioc_type,
            "error": f"Network error: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error while querying ThreatFox: {e}", exc_info=True)
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "ioc_type": ioc_type,
            "error": f"Error: {str(e)}"
        }

