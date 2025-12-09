"""
Google Safe Browsing query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)


def _generate_url_variants(url: str) -> List[str]:
    """
    Generate URL variants to check for threats.
    Includes the original URL and variations (with/without www, trailing slash, etc.)
    
    Args:
        url: The original URL to generate variants from
        
    Returns:
        List of URL variants to check
    """
    variants = [url]  # Always include the original URL
    
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme
        netloc = parsed.netloc
        path = parsed.path
        params = parsed.params
        query = parsed.query
        fragment = parsed.fragment
        
        # Extract domain from netloc (remove port if present)
        domain = netloc.split(':')[0] if ':' in netloc else netloc
        
        # Generate variants
        # 1. Original URL (already added)
        
        # 2. With/without trailing slash
        if path and not path.endswith('/'):
            variants.append(urlunparse((scheme, netloc, path + '/', params, query, fragment)))
        elif path.endswith('/') and path != '/':
            variants.append(urlunparse((scheme, netloc, path.rstrip('/'), params, query, fragment)))
        
        # 3. With/without www subdomain
        if not domain.startswith('www.'):
            www_domain = f"www.{domain}"
            www_netloc = www_domain + (':' + netloc.split(':')[1] if ':' in netloc else '')
            variants.append(urlunparse((scheme, www_netloc, path, params, query, fragment)))
        else:
            # Remove www
            no_www_domain = domain[4:]  # Remove 'www.'
            no_www_netloc = no_www_domain + (':' + netloc.split(':')[1] if ':' in netloc else '')
            variants.append(urlunparse((scheme, no_www_netloc, path, params, query, fragment)))
        
        # 4. Root domain (if path exists)
        if path and path != '/':
            variants.append(urlunparse((scheme, netloc, '/', '', '', '')))
            # Also check root with www variant
            if not domain.startswith('www.'):
                www_domain = f"www.{domain}"
                www_netloc = www_domain + (':' + netloc.split(':')[1] if ':' in netloc else '')
                variants.append(urlunparse((scheme, www_netloc, '/', '', '', '')))
        
        # 5. Parent directory (if path has multiple levels)
        if path and path.count('/') > 1:
            parent_path = '/'.join(path.rstrip('/').split('/')[:-1]) + '/'
            variants.append(urlunparse((scheme, netloc, parent_path, params, query, fragment)))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                unique_variants.append(variant)
        
        return unique_variants
    
    except Exception as e:
        logger.warning(f"Error generating URL variants for {url}: {e}")
        return [url]  # Return original URL if variant generation fails


async def query_googlesafebrowsing_async(observable: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query Google Safe Browsing API v4 for threat information.
    
    Args:
        observable (str): The URL or domain to check.
                       - URLs: will be normalized to include protocol
                       - Domains: will be converted to URLs (https://domain)
        api_key (str): Google Safe Browsing API key.
    
    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        # Normalize URL: if it doesn't have a protocol, add https://
        # This handles both URLs without protocol and domains
        normalized_url = observable
        if not observable.startswith(('http://', 'https://')):
            # It's either a URL without protocol (e.g., "example.com/path") or a domain (e.g., "example.com")
            # Add https:// to make it a valid URL
            normalized_url = f"https://{observable}"
            logger.info(f"Google Safe Browsing: Normalizing '{observable}' to '{normalized_url}'")
        
        # Google Safe Browsing API v4 endpoint
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        # Prepare the request payload
        # Generate URL variants (with/without www, trailing slash, parent paths, etc.)
        threat_entries = []
        url_variants = _generate_url_variants(normalized_url)
        for variant_url in url_variants:
            threat_entries.append({"url": variant_url})
        logger.debug(f"Generated {len(url_variants)} URL variants for {observable} (normalized: {normalized_url})")
        
        payload = {
            "client": {
                "clientId": "investigateR",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": threat_entries
            }
        }
        
        logger.info(f"Querying Google Safe Browsing for: {observable} (normalized: {normalized_url})")
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Google Safe Browsing response received for {observable}")
                    logger.debug(f"Google Safe Browsing raw response: {data}")
                    # Log if matches are found
                    matches = data.get("matches", [])
                    if matches:
                        logger.info(f"Google Safe Browsing found {len(matches)} threat(s) for {observable}")
                        for match in matches:
                            logger.info(f"  Threat: {match.get('threatType')} on {match.get('threat', {}).get('url', 'unknown')}")
                    else:
                        logger.info(f"Google Safe Browsing found no threats for {observable} (checked {len(threat_entries)} URL(s))")
                    return {
                        "raw_data": data,
                        "observable": observable,
                        "threat_entries": [entry["url"] for entry in threat_entries]
                    }
                elif response.status == 400:
                    error_text = await response.text()
                    logger.warning(f"Google Safe Browsing API returned status 400: {error_text}")
                    # Return empty result for bad request (invalid format, etc.)
                    return {
                        "raw_data": {},
                        "observable": observable,
                        "threat_entries": [entry["url"] for entry in threat_entries],
                        "error": "Invalid request format"
                    }
                elif response.status == 403:
                    logger.warning(f"Google Safe Browsing API returned status 403: Invalid API key or quota exceeded")
                    return {
                        "raw_data": {},
                        "observable": observable,
                        "threat_entries": [entry["url"] for entry in threat_entries],
                        "error": "Invalid API key or quota exceeded"
                    }
                else:
                    logger.warning(f"Google Safe Browsing API returned status {response.status}")
                    error_text = await response.text()
                    return {
                        "raw_data": {},
                        "observable": observable,
                        "threat_entries": [entry["url"] for entry in threat_entries],
                        "error": f"API error: {response.status}"
                    }
    
    except aiohttp.ClientError as e:
        logger.error(f"Network error querying Google Safe Browsing for {observable}: {e}")
    except Exception as e:
        logger.error(f"Error querying Google Safe Browsing for {observable}: {e}", exc_info=True)
    
    return None

