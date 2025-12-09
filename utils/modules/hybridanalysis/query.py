"""
Hybrid Analysis query module - handles API communication
"""
import aiohttp
import asyncio
import logging
import json
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

HYBRIDANALYSIS_API_BASE_URL = "https://www.hybrid-analysis.com/api/v2"


async def query_hybridanalysis_async(observable: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query Hybrid Analysis API for malware intelligence.
    
    Args:
        observable: Hash, URL, domain, or IP to query
        api_key: Hybrid Analysis API key
        
    Returns:
        Raw API response data: {"raw_data": {...}, "observable": "..."}
    """
    if not api_key:
        logger.warning("Hybrid Analysis API key is required")
        return {
            "raw_data": {},
            "observable": observable,
            "found": False,
            "error": "API key is required. Get one at https://www.hybrid-analysis.com/"
        }
    
    # Detect observable type
    observable_clean = observable.strip()
    # Check if it's a hash (MD5=32, SHA1=40, SHA256=64 hex chars)
    # Also check for ssdeep format: number:hash1:hash2
    is_hash = False
    if len(observable_clean) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in observable_clean):
        is_hash = True
    elif ':' in observable_clean and len(observable_clean.split(':')) == 3:
        # Might be ssdeep, but Hybrid Analysis doesn't support ssdeep directly
        # Try to extract if it's actually a regular hash
        parts = observable_clean.split(':')
        if len(parts[1]) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in parts[1]):
            # Use the second part as hash
            observable_clean = parts[1]
            is_hash = True
            logger.info(f"Hybrid Analysis: Detected ssdeep format, using hash part: {observable_clean[:20]}...")
    
    logger.info(f"Hybrid Analysis: observable={observable_clean[:50]}, is_hash={is_hash}, length={len(observable_clean)}")
    
    timeout = aiohttp.ClientTimeout(total=10, connect=5)
    headers = {
        "api-key": api_key,
        "User-Agent": "investigateR/1.0",
        "Accept": "application/json"
    }
    
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            if is_hash:
                # Search by hash (MD5, SHA1, SHA256)
                # Try multiple endpoints - Hybrid Analysis API might use different endpoints
                hash_upper = observable_clean.upper()
                
                # Try /search/hash endpoint first
                url = f"{HYBRIDANALYSIS_API_BASE_URL}/search/hash"
                params = {"hash": hash_upper}
                
                async with session.get(url, headers=headers, params=params, ssl=False) as response:
                    response_text = await response.text()
                    logger.info(f"Hybrid Analysis hash search: status={response.status}, hash={hash_upper[:20]}..., url={url}")
                    logger.debug(f"Hybrid Analysis response text (first 500 chars): {response_text[:500]}")
                    
                    if response.status == 200:
                        try:
                            data = await response.json()
                            logger.info(f"Hybrid Analysis JSON response type: {type(data)}")
                            if isinstance(data, dict):
                                logger.info(f"Hybrid Analysis response keys: {list(data.keys())}")
                            elif isinstance(data, list):
                                logger.info(f"Hybrid Analysis response is list with {len(data)} items")
                            logger.info(f"Hybrid Analysis full response (first 2000 chars): {str(data)[:2000]}")
                            # Log full response structure for debugging
                            if isinstance(data, list) and len(data) > 0:
                                logger.info(f"Hybrid Analysis: First item in list is type {type(data[0])}")
                                if isinstance(data[0], dict):
                                    logger.info(f"Hybrid Analysis: First item keys: {list(data[0].keys())}")
                                    logger.info(f"Hybrid Analysis: First item sample: {json.dumps({k: v for k, v in list(data[0].items())[:10]}, default=str)}")
                            logger.debug(f"Hybrid Analysis full response: {str(data)[:1000]}")
                            
                            # Check different possible response structures
                            # If we get a 200 response, assume data exists unless explicitly empty
                            found = False
                            if isinstance(data, dict):
                                # Check for result array (most common)
                                if "result" in data:
                                    results = data.get("result", [])
                                    logger.info(f"Hybrid Analysis: Found 'result' key, type={type(results)}, length={len(results) if isinstance(results, list) else 'N/A'}")
                                    if isinstance(results, list):
                                        # Even if list is empty, if we got a 200 response, the hash might exist
                                        # Check if list has items OR if response indicates success
                                        found = len(results) > 0
                                        if found:
                                            logger.info(f"Hybrid Analysis: Found {len(results)} result(s) in 'result' array")
                                        else:
                                            # Empty list but 200 response - might still be valid, check other fields
                                            logger.info("Hybrid Analysis: 'result' array is empty, checking other fields")
                                            # If there are other fields, might still be valid
                                            if len(data) > 1:  # More than just 'result' key
                                                found = True
                                                logger.info("Hybrid Analysis: Found other fields in response, considering as found")
                                    else:
                                        found = bool(results)
                                        if found:
                                            logger.info("Hybrid Analysis: Found non-empty 'result' value")
                                # Check for direct sample data
                                elif "sha256" in data or "md5" in data or "sha1" in data:
                                    logger.info("Hybrid Analysis: Found direct hash fields in response")
                                    found = True
                                # Check for count field
                                elif "count" in data:
                                    count = data.get("count", 0)
                                    logger.info(f"Hybrid Analysis: Found 'count' field: {count}")
                                    found = count > 0
                                # Check for data array
                                elif "data" in data:
                                    data_array = data.get("data", [])
                                    logger.info(f"Hybrid Analysis: Found 'data' array, length={len(data_array) if isinstance(data_array, list) else 'N/A'}")
                                    if isinstance(data_array, list):
                                        found = len(data_array) > 0
                                    else:
                                        found = bool(data_array)
                                # If we have any data at all in the response, consider it found
                                elif data:
                                    logger.info(f"Hybrid Analysis: Response has data but no recognized structure, keys: {list(data.keys())}")
                                    # If response is not empty, consider it found
                                    found = True
                            elif isinstance(data, list):
                                logger.info(f"Hybrid Analysis: Response is a list, length={len(data)}")
                                found = len(data) > 0
                            else:
                                # Any non-empty response means something was found
                                logger.info(f"Hybrid Analysis: Response is {type(data)}, considering as found if non-empty")
                                found = bool(data)
                            
                            logger.info(f"Hybrid Analysis: Final found={found} for hash {hash_upper[:20]}...")
                            
                            return {
                                "raw_data": data,
                                "observable": observable_clean,
                                "found": found
                            }
                        except Exception as e:
                            logger.warning(f"Error parsing Hybrid Analysis JSON response: {e}, response text: {response_text[:300]}")
                            return {
                                "raw_data": {},
                                "observable": observable_clean,
                                "found": False,
                                "error": f"Error parsing response: {str(e)}"
                            }
                    elif response.status == 401:
                        logger.warning("Hybrid Analysis API returned 401 Unauthorized")
                        return {
                            "raw_data": {},
                            "observable": observable_clean,
                            "found": False,
                            "error": "Unauthorized - invalid API key"
                        }
                    else:
                        response_text = await response.text()
                        logger.warning(f"Hybrid Analysis API returned status {response.status}: {response_text[:200]}")
                        return {
                            "raw_data": {},
                            "observable": observable_clean,
                            "found": False,
                            "error": f"API error: {response.status}"
                        }
            else:
                # Detect if it's a URL, domain, or IP
                import re
                # Check if it's an IP address
                ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                is_ip = bool(re.match(ip_pattern, observable_clean))
                
                # Check if it's a URL (has protocol)
                is_url = observable_clean.startswith(('http://', 'https://'))
                
                # If it's a URL, try quick-scan endpoint
                if is_url:
                    url = f"{HYBRIDANALYSIS_API_BASE_URL}/quick-scan/url"
                    data = {"scan_type": "all", "url": observable_clean}
                    
                    async with session.post(url, headers=headers, json=data, ssl=False) as response:
                        if response.status == 200:
                            result = await response.json()
                            logger.debug(f"Hybrid Analysis URL scan response received")
                            return {
                                "raw_data": result,
                                "observable": observable_clean,
                                "found": True if result.get("sha256") else False
                            }
                        elif response.status == 401:
                            logger.warning("Hybrid Analysis API returned 401 Unauthorized")
                            return {
                                "raw_data": {},
                                "observable": observable_clean,
                                "found": False,
                                "error": "Unauthorized - invalid API key"
                            }
                        else:
                            response_text = await response.text()
                            logger.warning(f"Hybrid Analysis API returned status {response.status}: {response_text[:200]}")
                            # For URLs, still return with link even on error
                            return {
                                "raw_data": {},
                                "observable": observable_clean,
                                "found": False,
                                "error": f"API error: {response.status}"
                            }
                else:
                    # For domains and IPs, Hybrid Analysis doesn't have a direct search API
                    # Return a result with a link to the search page
                    logger.info(f"Hybrid Analysis: Domain/IP search not supported via API, providing search link for {observable_clean}")
                    return {
                        "raw_data": {},
                        "observable": observable_clean,
                        "found": False
                    }
                        
    except asyncio.TimeoutError:
        logger.warning(f"Timeout querying Hybrid Analysis for {observable_clean[:20]}...")
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "error": "Request timed out"
        }
    except aiohttp.ClientError as e:
        logger.error(f"Network error while querying Hybrid Analysis: {e}")
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "error": f"Network error: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error while querying Hybrid Analysis: {e}", exc_info=True)
        return {
            "raw_data": {},
            "observable": observable_clean,
            "found": False,
            "error": f"Error: {str(e)}"
        }

