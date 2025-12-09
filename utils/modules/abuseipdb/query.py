"""
AbuseIPDB query module - handles API communication
"""
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any
# Import shared utilities - modules can import from utils root
import sys
from pathlib import Path
# Get project root (parent of utils)
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
from utils.ip_resolver import resolve_domain_to_ips

logger = logging.getLogger(__name__)


async def query_abuseipdb_async(ip_or_hostname: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Queries the AbuseIPDB API for information about an IP address or domain.

    Args:
        ip_or_hostname (str): The IP address or domain to query.
        api_key (str): The AbuseIPDB API key.

    Returns:
        dict: A dictionary containing raw API response data.
        None: If an error occurs.
    """
    if not api_key:
        logger.warning("AbuseIPDB API key not provided")
        return {
            "error": "AbuseIPDB API key not provided",
            "ip": ip_or_hostname
        }

    # If the input is a domain, resolve it to an IP first
    target_ip = ip_or_hostname
    if not all(c.isdigit() or c == '.' for c in ip_or_hostname):
        resolved_ips = await resolve_domain_to_ips(ip_or_hostname)
        if not resolved_ips:
            logger.warning(f"Could not resolve domain {ip_or_hostname} to an IP address")
            return {
                "error": f"Could not resolve domain {ip_or_hostname} to an IP address",
                "ip": ip_or_hostname
            }
        target_ip = resolved_ips[0]  # Use the first resolved IP
        logger.info(f"Resolved domain {ip_or_hostname} to IP {target_ip}")

    logger.info(f"Starting AbuseIPDB query for IP: {target_ip}")
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": target_ip}
    
    logger.info(f"Making request to AbuseIPDB API with URL: {url}")

    timeout = aiohttp.ClientTimeout(total=20, connect=10)
    
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers, params=params) as response:
                logger.info(f"Received response with status: {response.status}")
                
                if response.status != 200:
                    logger.warning(f"AbuseIPDB API returned status {response.status}")
                    try:
                        error_text = await response.text()
                        logger.warning(f"Error response text: {error_text}")
                    except Exception as e:
                        logger.warning(f"Could not read error response: {e}")
                    return {
                        "error": f"AbuseIPDB API returned status {response.status}",
                        "status": response.status,
                        "ip": target_ip
                    }

                try:
                    json_response = await response.json()
                    logger.info(f"Raw AbuseIPDB response received, type: {type(json_response)}")
                    logger.debug(f"AbuseIPDB response keys: {list(json_response.keys()) if isinstance(json_response, dict) else 'not a dict'}")
                except Exception as e:
                    logger.error(f"Failed to parse JSON response: {e}", exc_info=True)
                    # Try to read as text for debugging
                    try:
                        text_response = await response.text()
                        logger.error(f"Response text (first 500 chars): {text_response[:500]}")
                    except:
                        pass
                    return {
                        "error": f"Failed to parse JSON response: {str(e)}",
                        "ip": target_ip
                    }

                if not isinstance(json_response, dict):
                    logger.warning(f"AbuseIPDB response is not a dict: {type(json_response)}")
                    return {
                        "error": f"AbuseIPDB response is not a dict: {type(json_response)}",
                        "ip": target_ip,
                        "raw_response": json_response
                    }

                if "data" not in json_response:
                    logger.warning("AbuseIPDB response has no 'data' key")
                    logger.debug(f"AbuseIPDB response keys: {list(json_response.keys())}")
                    logger.debug(f"Full response: {json_response}")
                    return {
                        "error": "AbuseIPDB response has no 'data' key",
                        "ip": target_ip,
                        "raw_response": json_response
                    }

                # Return raw data for normalization
                logger.info(f"AbuseIPDB query successful for {target_ip}, data keys: {list(json_response['data'].keys()) if isinstance(json_response.get('data'), dict) else 'not a dict'}")
                return {
                    "raw_data": json_response["data"],
                    "ip": target_ip
                }

    except asyncio.TimeoutError as e:
        logger.error(f"Timeout while querying AbuseIPDB: {e}", exc_info=True)
        return {
            "error": f"Timeout while querying AbuseIPDB: {str(e)}",
            "ip": target_ip
        }
    except aiohttp.ClientError as e:
        logger.error(f"Network error while querying AbuseIPDB: {e}", exc_info=True)
        return {
            "error": f"Network error while querying AbuseIPDB: {str(e)}",
            "ip": target_ip
        }
    except Exception as e:
        logger.error(f"Unexpected error while querying AbuseIPDB: {e}", exc_info=True)
        return {
            "error": f"Unexpected error while querying AbuseIPDB: {str(e)}",
            "ip": target_ip
        }

