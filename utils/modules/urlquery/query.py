"""
URLQuery query module - handles API communication
"""
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any
from urllib.parse import urlparse, quote_plus

logger = logging.getLogger(__name__)


async def query_urlquery_async(observable: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query URLQuery API for URL or domain analysis.
    
    Args:
        observable (str): The URL or domain to analyze.
                          - URLs: will have protocol removed to match database format
                          - Domains: used as-is
        api_key (str): URLQuery API key.
    
    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        # For URLs, try both the full URL (without protocol) and just the domain
        # For domains, use as-is
        query_params_to_try = []
        
        if observable.startswith(('http://', 'https://')):
            # It's a URL - try both the full URL without protocol and just the domain
            parsed = urlparse(observable)
            domain = parsed.netloc
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # First try: full URL without protocol (e.g., "webeasyt.com/mVttL7CH")
            url_without_protocol = domain
            if parsed.path:
                url_without_protocol += parsed.path
            if parsed.query:
                url_without_protocol += '?' + parsed.query
            if parsed.fragment:
                url_without_protocol += '#' + parsed.fragment
            query_params_to_try.append(url_without_protocol)
            
            # Second try: just the domain (e.g., "webeasyt.com")
            query_params_to_try.append(domain)
            
            logger.info(f"URLQuery: For URL '{observable}', will try: {query_params_to_try}")
        else:
            # It's a domain - use as-is
            query_params_to_try.append(observable)
            logger.info(f"URLQuery: Using domain '{observable}' for querying")
        
        # URLQuery API endpoint for searching reports
        # Using GET /public/v1/search/reports/
        api_url = "https://api.urlquery.net/public/v1/search/reports/"
        
        # Prepare the request
        # API key goes in header as 'x-apikey' (lowercase)
        headers = {
            'x-apikey': api_key,
            'accept': 'application/json'
        }
        
        # Try each query parameter until we get results
        async with aiohttp.ClientSession() as session:
            for query_param in query_params_to_try:
                params = {
                    "query": quote_plus(query_param),
                    "limit": 50,
                    "offset": 0
                }
                
                logger.info(f"Querying URLQuery search reports for: {observable} (trying query parameter: {query_param})")
                logger.debug(f"URLQuery API URL: {api_url}, params: {params}")
                
                async with session.get(
                    api_url,
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    logger.debug(f"URLQuery API response status: {response.status}")
                    if response.status == 200:
                        data = await response.json()
                        total_hits = data.get("total_hits") or 0
                        reports = data.get("reports") or []  # Handle None case
                        reports_count = len(reports) if reports else 0
                        logger.info(f"URLQuery response received for {observable}: total_hits={total_hits}, reports_returned={reports_count} (query: {query_param})")
                        logger.debug(f"URLQuery response data keys: {list(data.keys())}")
                        
                        # If we got results, return them
                        if total_hits > 0 or reports_count > 0:
                            return {
                                "raw_data": data,
                                "observable": observable,
                                "query_string": query_param  # Use the query parameter that worked
                            }
                        # If no results but this was the last try, return empty result
                        elif query_param == query_params_to_try[-1]:
                            return {
                                "raw_data": data,
                                "observable": observable,
                                "query_string": query_param
                            }
                        # Otherwise, try next query parameter
                        else:
                            logger.info(f"URLQuery: No results for '{query_param}', trying next query parameter...")
                            continue
                    elif response.status == 401:
                        logger.warning(f"URLQuery API returned status 401: Invalid API key")
                        return {
                            "raw_data": {},
                            "observable": observable,
                            "query_string": query_param,
                            "error": "Invalid API key"
                        }
                    elif response.status == 400:
                        error_text = await response.text()
                        logger.warning(f"URLQuery API returned status 400: {error_text}")
                        return {
                            "raw_data": {},
                            "observable": observable,
                            "query_string": query_param,
                            "error": "Invalid request format"
                        }
                    elif response.status == 404:
                        # For 404, continue to next query parameter if available
                        if query_param != query_params_to_try[-1]:
                            logger.info(f"URLQuery: 404 for '{query_param}', trying next query parameter...")
                            continue
                        else:
                            logger.info(f"URLQuery API returned status 404: Not found in database")
                            return {
                                "raw_data": {},
                                "observable": observable,
                                "query_string": query_param,
                                "error": "Not found in database"
                            }
                    else:
                        logger.warning(f"URLQuery API returned status {response.status}")
                        error_text = await response.text()
                        return {
                            "raw_data": {},
                            "observable": observable,
                            "query_string": query_param,
                            "error": f"API error: {response.status}"
                        }
    
    except aiohttp.ClientError as e:
        logger.error(f"Network error querying URLQuery for {observable}: {e}")
        return {
            "raw_data": {},
            "observable": observable,
            "query_string": observable,
            "error": f"Network error: {str(e)}"
        }
    except asyncio.TimeoutError as e:
        logger.error(f"Timeout error querying URLQuery for {observable}: {e}")
        return {
            "raw_data": {},
            "observable": observable,
            "query_string": observable,
            "error": "Request timed out"
        }
    except Exception as e:
        logger.error(f"Error querying URLQuery for {observable}: {e}", exc_info=True)
        return {
            "raw_data": {},
            "observable": observable,
            "query_string": observable,
            "error": f"Error: {str(e)}"
        }
