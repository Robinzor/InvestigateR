"""
OpenCTI normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_opencti_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize OpenCTI API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_opencti_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "opencti": {
                "error": "No data received from OpenCTI"
            }
        }
    
    data = raw_result["raw_data"]
    observable = raw_result.get("observable", "Unknown")
    
    # Check for GraphQL errors first
    if "errors" in data:
        error_messages = [err.get("message", "Unknown error") for err in data["errors"]]
        logger.warning(f"OpenCTI GraphQL errors: {error_messages}")
        return {
            "opencti": {
                "observable": observable,
                "error": f"GraphQL errors: {', '.join(error_messages)}"
            }
        }
    
    # Extract results from GraphQL response - try globalSearch, stixCyberObservables, stixObservables, and stixCoreObjects
    edges = []
    if "data" in data:
        # Try globalSearch first (used by the new query approach)
        if "globalSearch" in data["data"]:
            edges = data["data"]["globalSearch"].get("edges", [])
            logger.info(f"Found {len(edges)} results in globalSearch")
            if len(edges) == 0:
                logger.debug(f"globalSearch structure: {list(data['data']['globalSearch'].keys())}")
        # Fallback to stixCyberObservables (for cyber observables like IPs, domains, hashes)
        elif "stixCyberObservables" in data["data"]:
            edges = data["data"]["stixCyberObservables"].get("edges", [])
            logger.info(f"Found {len(edges)} results in stixCyberObservables")
            if len(edges) == 0:
                logger.debug(f"stixCyberObservables structure: {list(data['data']['stixCyberObservables'].keys())}")
        # Fallback to stixObservables (for observables)
        elif "stixObservables" in data["data"]:
            edges = data["data"]["stixObservables"].get("edges", [])
            logger.info(f"Found {len(edges)} results in stixObservables")
        # Fallback to stixCoreObjects (for indicators)
        elif "stixCoreObjects" in data["data"]:
            edges = data["data"]["stixCoreObjects"].get("edges", [])
            logger.info(f"Found {len(edges)} results in stixCoreObjects")
    
    # If no results found, log the data structure for debugging
    if len(edges) == 0:
        logger.warning(f"No results found in OpenCTI response for {observable}")
        if "data" in data:
            logger.debug(f"Available data keys: {list(data['data'].keys())}")
            # Log first level of data structure
            for key in data["data"].keys():
                if isinstance(data["data"][key], dict):
                    logger.debug(f"  {key} structure: {list(data['data'][key].keys())}")
    
    # Get the observable type for filtering
    observable_type_str = raw_result.get("observable_type", "")
    
    # Prepare variations of the observable for matching
    def prepare_match_variations(obs, obs_type):
        """Prepare variations of the observable for matching"""
        variations = [obs.lower()]
        
        if obs_type == "URL":
            # Try without protocol
            if obs.startswith(('http://', 'https://')):
                from urllib.parse import urlparse
                parsed = urlparse(obs)
                without_protocol = parsed.netloc
                if parsed.path:
                    without_protocol += parsed.path
                if parsed.query:
                    without_protocol += '?' + parsed.query
                if parsed.fragment:
                    without_protocol += '#' + parsed.fragment
                variations.append(without_protocol.lower())
                variations.append(without_protocol.rstrip('/').lower())
            # Try with different protocols
            if obs.startswith('http://'):
                variations.append(obs.replace('http://', 'https://', 1).lower())
            elif obs.startswith('https://'):
                variations.append(obs.replace('https://', 'http://', 1).lower())
            # Try with/without trailing slash
            if not obs.endswith('/'):
                variations.append((obs + '/').lower())
            variations.append(obs.rstrip('/').lower())
        
        return variations
    
    match_variations = prepare_match_variations(observable, observable_type_str)
    
    def is_match(node, match_variations, obs_type):
        """Check if a node actually matches the observable"""
        entity_type = node.get("entity_type", "")
        
        # For Indicators, check the pattern
        if "Indicator" in entity_type:
            pattern = node.get("pattern", "")
            if pattern:
                pattern_lower = pattern.lower()
                # For URL patterns like [url:value = 'http://...'], check if URL appears in pattern
                # Also check for domain patterns like [domain-name:value = 'domain.com']
                for variation in match_variations:
                    # Check if variation appears in pattern (exact match in quotes or as value)
                    # Patterns are like: [url:value = 'http://example.com/path']
                    if f"'{variation}'" in pattern_lower or f'"{variation}"' in pattern_lower:
                        return True
                    # Also check if variation is contained in the pattern (for partial matches)
                    if variation in pattern_lower:
                        # Make sure it's not a false positive by checking it's in a value assignment
                        if 'value' in pattern_lower and '=' in pattern_lower:
                            return True
            return False
        
        # For observables, check observable_value
        observable_value = node.get("observable_value", "")
        if observable_value:
            observable_value_lower = str(observable_value).lower().strip()
            # For exact matches or if the observable_value contains the variation
            for variation in match_variations:
                variation_clean = variation.strip()
                # Exact match
                if variation_clean == observable_value_lower:
                    return True
                # For URLs, also check if the path/query matches even if domain differs slightly
                if obs_type == "URL" and variation_clean in observable_value_lower:
                    # Make sure it's a meaningful match (not just a substring)
                    # Check if it's at least the path part of the URL
                    if '/' in variation_clean:
                        return True
        
        return False
    
    results = []
    filtered_count = 0
    for edge in edges:
        node = edge.get("node", {})
        
        # Filter: only include results that actually match the observable
        if not is_match(node, match_variations, observable_type_str):
            filtered_count += 1
            logger.debug(f"Filtering out non-matching result: entity_type={node.get('entity_type')}, observable_value={node.get('observable_value')}, pattern={node.get('pattern', '')[:50]}")
            continue
        
        # Determine observable type from entity_type if available
        entity_type = node.get("entity_type", "")
        # Map entity_type to observable_type (e.g., "IPv4-Addr" -> "IPv4")
        observable_type = None
        if entity_type:
            if "IPv4" in entity_type or "IPv6" in entity_type:
                observable_type = "IP"
            elif "Domain" in entity_type:
                observable_type = "Domain"
            elif "Url" in entity_type:
                observable_type = "URL"
            elif "File" in entity_type or "Hash" in entity_type:
                observable_type = "Hash"
        
        # Extract labels
        labels = []
        object_label = node.get("objectLabel")
        # objectLabel can be a list of label objects or a single label object
        if object_label:
            if isinstance(object_label, list):
                # If it's a list, iterate through it
                for label in object_label:
                    label_value = label.get("value") if isinstance(label, dict) else str(label)
                    if label_value:
                        labels.append(label_value)
            elif isinstance(object_label, dict):
                # If it's a single object, get the value
                label_value = object_label.get("value")
                if label_value:
                    labels.append(label_value)
        
        # For File observables, OpenCTI stores hash values in observable_value
        # The hashes object is not available in the GraphQL response structure
        observable_value = node.get("observable_value")
        
        # For hash observables, the observable_value contains the hash
        # No separate hash_info needed since we don't get hashes object from GraphQL
        hash_info = None
        
        results.append({
            "id": node.get("id"),
            "entity_type": entity_type,
            "name": node.get("name"),
            "pattern": node.get("pattern"),
            "observable_value": observable_value,
            "observable_type": observable_type,
            "score": node.get("x_opencti_score"),
            "created_at": node.get("created_at"),
            "updated_at": node.get("updated_at"),
            "created_by": node.get("createdBy", {}).get("name") if node.get("createdBy") else None,
            "labels": labels,
            "hashes": hash_info if hash_info else None
        })
    
    normalized = {
        "opencti": {
            "observable": observable,
            "observable_type": raw_result.get("observable_type", "Unknown"),
            "results": results,
            "total": len(results)
        }
    }
    
    if filtered_count > 0:
        logger.info(f"Normalized OpenCTI result for {observable}: {len(results)} matches (filtered out {filtered_count} non-matching results)")
    else:
        logger.info(f"Normalized OpenCTI result for {observable}: {len(results)} matches")
    return normalized

