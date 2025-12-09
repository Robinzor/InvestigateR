"""
OpenCTI query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any
import sys
from pathlib import Path
import os
import json
import ssl

logger = logging.getLogger(__name__)

# Get project root for api_keys.json
project_root = Path(__file__).parent.parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


def get_opencti_url() -> Optional[str]:
    """Get OpenCTI URL from api_keys.json"""
    try:
        api_keys_file = project_root / 'api_keys.json'
        if api_keys_file.exists():
            with open(api_keys_file, 'r') as f:
                keys = json.load(f)
                return keys.get('opencti_url', '')
    except Exception as e:
        logger.error(f"Error loading OpenCTI URL: {e}")
    return None


async def query_opencti_async(observable: str, observable_type: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query OpenCTI for threat intelligence.

    Args:
        observable (str): The observable to query.
        observable_type (str): Type of observable (IP, Domain, URL, Hash).
        api_key (str): OpenCTI API key.

    Returns:
        dict: Raw API response data (merged results if multiple queries).
        None: If an error occurs.
    """
    if not api_key:
        logger.warning("OpenCTI API key not provided")
        return None
    
    opencti_url = get_opencti_url()
    if not opencti_url:
        logger.warning("OpenCTI URL not configured")
        return None
    
    # Sanity check: If observable_type is IP, ensure the observable is actually an IP, not a URL
    if observable_type == "IP":
        from urllib.parse import urlparse
        # Check if observable looks like a URL
        if observable.startswith(('http://', 'https://')):
            logger.warning(f"OpenCTI: IP observable_type but observable is a URL: {observable}. Extracting IP from URL.")
            parsed = urlparse(observable)
            ip_from_url = parsed.netloc.split(':')[0]  # Remove port if present
            # Validate it's an IP
            import re
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if re.match(ip_pattern, ip_from_url):
                logger.info(f"OpenCTI: Using extracted IP {ip_from_url} instead of URL {observable}")
                observable = ip_from_url
            else:
                logger.warning(f"OpenCTI: Could not extract valid IP from URL {observable}, using as-is")
    
    logger.info(f"OpenCTI query for {observable_type}: {observable}")

    # For all types, use single query - each observable type searches for its own value
    # URL observables search for exact URL, Domain observables search for domain
    return await _query_opencti_single(observable, observable_type, api_key, opencti_url)


async def _query_opencti_single(observable: str, observable_type: str, api_key: str, opencti_url: str) -> Optional[Dict[str, Any]]:
    """
    Execute a single OpenCTI query.
    
    Args:
        observable (str): The observable to query.
        observable_type (str): Type of observable (IP, Domain, URL, Hash).
        api_key (str): OpenCTI API key.
        opencti_url (str): OpenCTI base URL.
    
    Returns:
        dict: Raw API response data.
        None: If an error occurs.
    """
    try:
        # Map observable_type to OpenCTI entity types
        # This scopes the search to the correct observable type
        entity_types_map = {
            "IP": ["IPv4-Addr", "IPv6-Addr", "Indicator"],
            "Domain": ["Domain-Name", "Indicator"],
            "URL": ["Url", "Indicator"],  # URLs search for Url entities and Indicators with URL patterns
            "Hash": ["File", "StixFile", "Artifact", "Indicator"]
        }
        
        # Get entity types for this observable type, or use all if unknown
        entity_types = entity_types_map.get(observable_type, [])
        
        # For URLs, remove protocol for matching (OpenCTI might store URLs without protocol)
        # Also remove trailing slash for matching
        observable_for_match = observable
        if observable_type == "URL" and observable.startswith(('http://', 'https://')):
            # Remove protocol from URL for matching
            from urllib.parse import urlparse
            parsed = urlparse(observable)
            observable_for_match = parsed.netloc
            if parsed.path:
                observable_for_match += parsed.path
            if parsed.query:
                observable_for_match += '?' + parsed.query
            if parsed.fragment:
                observable_for_match += '#' + parsed.fragment
            logger.debug(f"OpenCTI: Removed protocol from URL '{observable}' -> '{observable_for_match}'")
        
        # Remove trailing slash for matching (OpenCTI might store domains/URLs without trailing slash)
        observable_for_match = observable_for_match.rstrip('/')
        
        # For hashes, determine the hash type and use appropriate filter key
        hash_filter_keys = []
        if observable_type == "Hash":
            # Determine hash type based on length
            hash_length = len(observable)
            if hash_length == 32:
                # Try different MD5 filter key formats
                hash_filter_keys = ["hashes.MD5", "hashes.md5", "hashes_MD5", "hashes_md5"]
            elif hash_length == 40:
                # Try different SHA1 filter key formats
                hash_filter_keys = ["hashes.SHA-1", "hashes.SHA1", "hashes.sha1", "hashes_SHA-1", "hashes_SHA1", "hashes_sha1"]
            elif hash_length == 64:
                # Try different SHA256 filter key formats
                hash_filter_keys = ["hashes.SHA-256", "hashes.SHA256", "hashes.sha256", "hashes_SHA-256", "hashes_SHA256", "hashes_sha256"]
            else:
                # Unknown hash type, try common hash fields
                hash_filter_keys = ["hashes.SHA-256", "hashes.SHA256", "hashes.sha256", "hashes_SHA-256", "hashes_SHA256", "hashes_sha256"]
            logger.info(f"OpenCTI: Detected hash type for {observable} (length {hash_length}), using filter keys: {hash_filter_keys}")
        
        # Build GraphQL query - use globalSearch for better compatibility
        # This approach is more reliable across different OpenCTI versions
        if entity_types:
            # Use globalSearch query (more compatible with different OpenCTI versions)
            # Only include hash fragments for Hash observables
            if observable_type == "Hash":
                # Include hash fragments for File observables
                query = """
                query SearchStixCoreObjectsLinesPaginationQuery(
                  $types: [String]
                  $search: String
                  $count: Int!
                  $cursor: ID
                  $orderBy: StixCoreObjectsOrdering
                  $orderMode: OrderingMode
                  $filters: FilterGroup
                ) {
                  globalSearch(
                    types: $types,
                    search: $search,
                    first: $count,
                    after: $cursor,
                    orderBy: $orderBy,
                    orderMode: $orderMode,
                    filters: $filters
                  ) {
                    edges {
                      node {
                        id
                        entity_type
                        created_at
                        createdBy {
                          name
                          id
                        }
                        creators {
                          id
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                        }
                        ... on HashedObservable {
                          observable_value
                        }
                        ... on Artifact {
                          observable_value
                        }
                        ... on StixFile {
                          observable_value
                        }
                        ... on X509Certificate {
                          observable_value
                        }
                        ... on Indicator {
                          pattern
                          name
                        }
                        objectLabel {
                          id
                          value
                          color
                        }
                      }
                      cursor
                    }
                    pageInfo {
                      endCursor
                      hasNextPage
                      globalCount
                    }
                  }
                }
                """
            else:
                # For IP, Domain, URL - no need to query hashes
                query = """
                query SearchStixCoreObjectsLinesPaginationQuery(
                  $types: [String]
                  $search: String
                  $count: Int!
                  $cursor: ID
                  $orderBy: StixCoreObjectsOrdering
                  $orderMode: OrderingMode
                  $filters: FilterGroup
                ) {
                  globalSearch(
                    types: $types,
                    search: $search,
                    first: $count,
                    after: $cursor,
                    orderBy: $orderBy,
                    orderMode: $orderMode,
                    filters: $filters
                  ) {
                    edges {
                      node {
                        id
                        entity_type
                        created_at
                        createdBy {
                          name
                          id
                        }
                        creators {
                          id
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                        }
                        ... on Indicator {
                          pattern
                          name
                        }
                        objectLabel {
                          id
                          value
                          color
                        }
                      }
                      cursor
                    }
                    pageInfo {
                      endCursor
                      hasNextPage
                      globalCount
                    }
                  }
                }
                """
            
            # Build variables for globalSearch query
            # For domains and URLs, use exact match filters instead of fuzzy search
            # For other types, use search parameter for flexible matching
            if observable_type in ["Domain", "URL"]:
                # Use exact match filter for domains and URLs
                # Try multiple variations for better matching
                filter_values = [observable_for_match]
                if observable_for_match != observable:
                    filter_values.append(observable)
                
                if observable_type == "URL":
                    # For URLs, try multiple variations to match how OpenCTI might store them
                    from urllib.parse import urlparse
                    parsed = urlparse(observable if observable.startswith(('http://', 'https://')) else f"https://{observable}")
                    
                    # Try with http://
                    if not observable.startswith('http://'):
                        filter_values.append(f"http://{observable_for_match}")
                    # Try with https://
                    if not observable.startswith('https://'):
                        filter_values.append(f"https://{observable_for_match}")
                    # Try with trailing slash
                    if not observable_for_match.endswith('/'):
                        filter_values.append(observable_for_match + '/')
                    # Try original with trailing slash
                    if not observable.endswith('/'):
                        filter_values.append(observable + '/')
                    # Try the path only (without domain)
                    if parsed.path:
                        filter_values.append(parsed.path)
                    # Try full URL variations
                    filter_values.append(observable_for_match)
                    if observable.startswith('http://'):
                        filter_values.append(observable.replace('http://', 'https://', 1))
                    elif observable.startswith('https://'):
                        filter_values.append(observable.replace('https://', 'http://', 1))
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    unique_filter_values = []
                    for val in filter_values:
                        if val not in seen:
                            seen.add(val)
                            unique_filter_values.append(val)
                    filter_values = unique_filter_values
                    logger.info(f"OpenCTI: Trying {len(filter_values)} URL variations: {filter_values[:5]}...")
                elif observable_type == "Domain":
                    # For domains, also try without www prefix
                    if observable.startswith('www.'):
                        filter_values.append(observable[4:])
                    elif not observable.startswith('www.'):
                        filter_values.append('www.' + observable)
                
                # For URLs, use both search parameter and filters for better matching
                # Search parameter does fuzzy matching (including Indicator patterns), filters do exact matching
                if observable_type == "URL":
                    # Use the full URL for search to match Indicator patterns like [url:value = 'http://...']
                    # Also try without protocol for matching stored URLs
                    search_term = observable  # Use full URL to match Indicator patterns
                    search_terms = [observable, observable_for_match]  # Try both full and without protocol
                    # Use the first search term, but the search should match patterns containing the URL
                    variables = {
                        "count": 100,
                        "orderMode": "desc",
                        "orderBy": "created_at",
                        "search": search_term,  # Use search to match both observables and Indicator patterns
                        "types": entity_types,
                        "filters": {
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "entity_type",
                                    "values": entity_types,
                                    "operator": "eq",
                                    "mode": "or"
                                }
                                # Don't filter by value - let search parameter match both observable_value and Indicator patterns
                            ],
                            "filterGroups": []
                        }
                    }
                    logger.info(f"OpenCTI query using globalSearch with search (no value filter) for URL: {observable} (search: {search_term}, entity_types: {entity_types}) - will match both Url observables and Indicator patterns")
                else:
                    # For domains, use only exact match filters
                    variables = {
                        "count": 100,
                        "orderMode": "desc",
                        "orderBy": "created_at",
                        "search": "",  # Empty search, use filters for exact match
                        "types": entity_types,
                        "filters": {
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "entity_type",
                                    "values": entity_types,
                                    "operator": "eq",
                                    "mode": "or"
                                },
                                {
                                    "key": "value",  # Exact match on observable_value
                                    "values": filter_values,
                                    "operator": "eq"
                                }
                            ],
                            "filterGroups": []
                        }
                    }
                    logger.info(f"OpenCTI query using globalSearch with exact match filter for {observable_type.lower()}: {observable} (entity_types: {entity_types}, filter_values: {filter_values})")
            else:
                # For IP, Hash - use search parameter for flexible matching
                variables = {
                    "count": 100,
                    "orderMode": "desc",
                    "orderBy": "created_at",
                    "search": observable,  # Use search parameter for flexible matching
                    "types": entity_types,
                    "filters": {
                        "mode": "and",
                        "filters": [
                            {
                                "key": "entity_type",
                                "values": entity_types,
                                "operator": "eq",
                                "mode": "or"
                            }
                        ],
                        "filterGroups": []
                    }
                }
                logger.info(f"OpenCTI query using globalSearch for {observable} (type: {observable_type}, entity_types: {entity_types})")
        else:
            # Fallback: use globalSearch without type scoping
            # Only include hash fragments for Hash observables
            if observable_type == "Hash":
                # Include hash fragments for File observables
                query = """
                query SearchStixCoreObjectsLinesPaginationQuery(
                  $types: [String]
                  $search: String
                  $count: Int!
                  $cursor: ID
                  $orderBy: StixCoreObjectsOrdering
                  $orderMode: OrderingMode
                  $filters: FilterGroup
                ) {
                  globalSearch(
                    types: $types,
                    search: $search,
                    first: $count,
                    after: $cursor,
                    orderBy: $orderBy,
                    orderMode: $orderMode,
                    filters: $filters
                  ) {
                    edges {
                      node {
                        id
                        entity_type
                        created_at
                        createdBy {
                          name
                          id
                        }
                        creators {
                          id
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                        }
                        ... on HashedObservable {
                          observable_value
                        }
                        ... on Artifact {
                          observable_value
                        }
                        ... on StixFile {
                          observable_value
                        }
                        ... on X509Certificate {
                          observable_value
                        }
                        ... on Indicator {
                          pattern
                          name
                        }
                        objectLabel {
                          id
                          value
                          color
                        }
                      }
                      cursor
                    }
                    pageInfo {
                      endCursor
                      hasNextPage
                      globalCount
                    }
                  }
                }
                """
            else:
                # For IP, Domain, URL - no need to query hashes
                query = """
                query SearchStixCoreObjectsLinesPaginationQuery(
                  $types: [String]
                  $search: String
                  $count: Int!
                  $cursor: ID
                  $orderBy: StixCoreObjectsOrdering
                  $orderMode: OrderingMode
                  $filters: FilterGroup
                ) {
                  globalSearch(
                    types: $types,
                    search: $search,
                    first: $count,
                    after: $cursor,
                    orderBy: $orderBy,
                    orderMode: $orderMode,
                    filters: $filters
                  ) {
                    edges {
                      node {
                        id
                        entity_type
                        created_at
                        createdBy {
                          name
                          id
                        }
                        creators {
                          id
                          name
                        }
                        ... on StixCyberObservable {
                          observable_value
                        }
                        ... on Indicator {
                          pattern
                          name
                        }
                        objectLabel {
                          id
                          value
                          color
                        }
                      }
                      cursor
                    }
                    pageInfo {
                      endCursor
                      hasNextPage
                      globalCount
                    }
                  }
                }
                """
            
            # For domains and URLs, use exact match filter even without type scoping
            if observable_type in ["Domain", "URL"]:
                # Try multiple variations for better matching
                filter_values = [observable_for_match]
                if observable_for_match != observable:
                    filter_values.append(observable)
                
                if observable_type == "URL":
                    # For URLs, try multiple variations to match how OpenCTI might store them
                    from urllib.parse import urlparse
                    parsed = urlparse(observable if observable.startswith(('http://', 'https://')) else f"https://{observable}")
                    
                    # Try with http://
                    if not observable.startswith('http://'):
                        filter_values.append(f"http://{observable_for_match}")
                    # Try with https://
                    if not observable.startswith('https://'):
                        filter_values.append(f"https://{observable_for_match}")
                    # Try with trailing slash
                    if not observable_for_match.endswith('/'):
                        filter_values.append(observable_for_match + '/')
                    # Try original with trailing slash
                    if not observable.endswith('/'):
                        filter_values.append(observable + '/')
                    # Try the path only (without domain)
                    if parsed.path:
                        filter_values.append(parsed.path)
                    # Try full URL variations
                    filter_values.append(observable_for_match)
                    if observable.startswith('http://'):
                        filter_values.append(observable.replace('http://', 'https://', 1))
                    elif observable.startswith('https://'):
                        filter_values.append(observable.replace('https://', 'http://', 1))
                    
                    # Remove duplicates while preserving order
                    seen = set()
                    unique_filter_values = []
                    for val in filter_values:
                        if val not in seen:
                            seen.add(val)
                            unique_filter_values.append(val)
                    filter_values = unique_filter_values
                    logger.info(f"OpenCTI: Trying {len(filter_values)} URL variations (no type scoping): {filter_values[:5]}...")
                    
                    # Use search parameter for fuzzy matching (will match both observables and Indicator patterns)
                    search_term = observable  # Use full URL to match Indicator patterns like [url:value = 'http://...']
                    variables = {
                        "count": 100,
                        "orderMode": "desc",
                        "orderBy": "created_at",
                        "search": search_term,  # Use search to match both observables and Indicator patterns
                        "filters": {
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "entity_type",
                                    "values": ["Stix-Core-Object"],
                                    "operator": "eq",
                                    "mode": "or"
                                }
                                # Don't filter by value - let search parameter match both observable_value and Indicator patterns
                            ],
                            "filterGroups": []
                        }
                    }
                    logger.info(f"OpenCTI query using globalSearch with search (no value filter, no type scoping) for URL: {observable} (search: {search_term}) - will match both Url observables and Indicator patterns")
                elif observable_type == "Domain":
                    # For domains, also try without www prefix
                    if observable.startswith('www.'):
                        filter_values.append(observable[4:])
                    elif not observable.startswith('www.'):
                        filter_values.append('www.' + observable)
                    
                    variables = {
                        "count": 100,
                        "orderMode": "desc",
                        "orderBy": "created_at",
                        "search": "",  # Empty search, use filters for exact match
                        "filters": {
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "entity_type",
                                    "values": ["Stix-Core-Object"],
                                    "operator": "eq",
                                    "mode": "or"
                                },
                                {
                                    "key": "value",  # Exact match on observable_value
                                    "values": filter_values,
                                    "operator": "eq"
                                }
                            ],
                            "filterGroups": []
                        }
                    }
                    logger.info(f"OpenCTI query using globalSearch with exact match filter (no type scoping) for {observable_type.lower()}: {observable} (filter_values: {filter_values})")
            else:
                variables = {
                    "count": 100,
                    "orderMode": "desc",
                    "orderBy": "created_at",
                    "search": observable,
                    "filters": {
                        "mode": "and",
                        "filters": [
                            {
                                "key": "entity_type",
                                "values": ["Stix-Core-Object"],
                                "operator": "eq",
                                "mode": "or"
                            }
                        ],
                        "filterGroups": []
                    }
                }
                logger.info(f"OpenCTI query using globalSearch (no type scoping) for {observable}")
        
        url = f"{opencti_url.rstrip('/')}/graphql"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        
        # Use the same payload structure as the old working code
        payload = {
            "id": "SearchStixCoreObjectsLinesPaginationQuery",
            "query": query,
            "variables": variables
        }
        
        logger.info(f"Querying OpenCTI for {observable_type}: {observable}")
        
        # Create SSL context that ignores certificate verification (for self-signed certs)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create connector with custom SSL context for OpenCTI
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=30)) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Raw OpenCTI response received: {json.dumps(data, indent=2)[:1000]}")
                    
                    # Check for GraphQL errors
                    if "errors" in data:
                        error_messages = [err.get("message", str(err)) for err in data["errors"]]
                        logger.warning(f"OpenCTI GraphQL errors: {error_messages}")
                        # Log full error details for debugging
                        logger.debug(f"Full OpenCTI error details: {json.dumps(data['errors'], indent=2)}")
                    
                    # Log the structure for debugging
                    if "data" in data:
                        logger.info(f"OpenCTI data structure: {list(data['data'].keys())}")
                        if "globalSearch" in data.get("data", {}):
                            edges = data["data"]["globalSearch"].get("edges", [])
                            logger.info(f"OpenCTI found {len(edges)} edges in globalSearch")
                        if "stixCyberObservables" in data.get("data", {}):
                            edges = data["data"]["stixCyberObservables"].get("edges", [])
                            logger.info(f"OpenCTI found {len(edges)} edges in stixCyberObservables")
                        if "stixObservables" in data.get("data", {}):
                            edges = data["data"]["stixObservables"].get("edges", [])
                            logger.info(f"OpenCTI found {len(edges)} edges in stixObservables")
                    
                    return {
                        "raw_data": data,
                        "observable": observable,
                        "observable_type": observable_type
                    }
                else:
                    error_text = await response.text()
                    logger.warning(f"OpenCTI API returned status {response.status}: {error_text[:500]}")
                    return None

    except aiohttp.ClientError as e:
        logger.error(f"Network error querying OpenCTI for {observable}: {e}")
    except Exception as e:
        logger.error(f"Error querying OpenCTI for {observable}: {e}", exc_info=True)

    return None

