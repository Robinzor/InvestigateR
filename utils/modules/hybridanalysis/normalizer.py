"""
Hybrid Analysis normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def normalize_hybridanalysis_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize Hybrid Analysis API response into a standardized format.
    
    Args:
        raw_result: Raw API response from query_hybridanalysis_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        observable = raw_result.get("observable", "Unknown") if raw_result else "Unknown"
        search_link = f"https://hybrid-analysis.com/search?query={observable}"
        return {
            "hybridanalysis": {
                "error": "No data received from Hybrid Analysis",
                "observable": observable,
                "link": search_link
            }
        }
    
    # Check for error in raw_result
    if "error" in raw_result:
        observable = raw_result.get("observable", "Unknown")
        # Even if there's an error, provide a search link
        search_link = f"https://hybrid-analysis.com/search?query={observable}"
        return {
            "hybridanalysis": {
                "error": raw_result["error"],
                "observable": observable,
                "link": search_link
            }
        }
    
    data = raw_result["raw_data"]
    observable = raw_result.get("observable", "Unknown")
    found = raw_result.get("found", False)
    
    # Even if found is False, check if data exists - might be a different response structure
    if not data:
        # Even if no data, provide a search link
        search_link = f"https://hybrid-analysis.com/search?query={observable}"
        return {
            "hybridanalysis": {
                "found": False,
                "status": "No results found in Hybrid Analysis",
                "observable": observable,
                "link": search_link
            }
        }
    
    # If we have data but found is False, re-check the data structure
    if not found and data:
        logger.info("Hybrid Analysis: found=False but data exists, re-checking structure")
        if isinstance(data, dict):
            # Check if there's any meaningful data
            if "result" in data:
                results = data.get("result", [])
                if isinstance(results, list) and len(results) > 0:
                    found = True
                elif results:  # Non-empty but not a list
                    found = True
            elif any(key in data for key in ["sha256", "md5", "sha1", "count", "data"]):
                found = True
        elif isinstance(data, list) and len(data) > 0:
            found = True
    
    if not found:
        # Even if not found, provide a search link
        search_link = f"https://hybrid-analysis.com/search?query={observable}"
        return {
            "hybridanalysis": {
                "found": False,
                "status": "No results found in Hybrid Analysis",
                "observable": observable,
                "link": search_link
            }
        }
    
    # Extract information from response
    # For hash searches, result contains array of samples
    # For URL scans, result contains scan information
    logger.info(f"Hybrid Analysis normalizer: data type={type(data)}")
    if isinstance(data, dict):
        logger.info(f"Hybrid Analysis normalizer: dict keys={list(data.keys())}")
    elif isinstance(data, list):
        logger.info(f"Hybrid Analysis normalizer: list length={len(data)}")
    
    # Hybrid Analysis API returns an array of samples directly for hash searches
    if isinstance(data, list) and len(data) > 0:
        # Response is directly a list of samples (most common for /search/hash endpoint)
        logger.info(f"Hybrid Analysis: Response is a list with {len(data)} items")
        logger.debug(f"Hybrid Analysis: First sample keys: {list(data[0].keys()) if isinstance(data[0], dict) else 'Not a dict'}")
        
        # Get the most recent or most relevant sample (first one, or one with highest threat_score)
        samples = sorted(data, key=lambda x: (
            x.get("threat_score") or 0 if x.get("threat_score") is not None else 0,
            x.get("threat_level") or 0
        ), reverse=True)
        sample = samples[0]
        
        logger.info(f"Hybrid Analysis: Extracting from sample with keys: {list(sample.keys()) if isinstance(sample, dict) else 'Not a dict'}")
        
        sha256 = sample.get("sha256") or sample.get("SHA256", observable)
        threat_score = sample.get("threat_score")
        verdict = sample.get("verdict", "Unknown")
        vx_family = sample.get("vx_family")  # Malware family
        submit_name = sample.get("submit_name", "Unknown")
        av_detect = sample.get("av_detect")  # AV detection percentage (can be None)
        threat_level = sample.get("threat_level")  # 1=whitelisted, 2=suspicious, 3=malicious, 4=highly malicious
        
        logger.info(f"Hybrid Analysis: Extracted - sha256={sha256[:20] if sha256 else 'None'}..., verdict={verdict}, threat_score={threat_score}, av_detect={av_detect}, vx_family={vx_family}, submit_name={submit_name}")
        
        # Build malware family list
        malware_family = []
        if vx_family:
            malware_family = [vx_family] if isinstance(vx_family, str) else vx_family if isinstance(vx_family, list) else []
        
        # Create search link (not sample link, as there can be multiple samples)
        search_link = f"https://hybrid-analysis.com/search?query={sha256}"
        
        result = {
            "hybridanalysis": {
                "found": True,
                "status": "Sample listed in Hybrid Analysis",
                "observable": observable,
                "sha256": sha256,
                "verdict": verdict,
                "submit_name": submit_name,
                "link": search_link,
                "count": len(data)  # Total number of samples found
            }
        }
        
        # Add optional fields if they exist (explicitly check for None to allow 0 values)
        if threat_score is not None:
            result["hybridanalysis"]["threat_score"] = threat_score
            logger.debug(f"Hybrid Analysis: Added threat_score={threat_score}")
        if av_detect is not None:
            result["hybridanalysis"]["av_detect"] = av_detect
            logger.debug(f"Hybrid Analysis: Added av_detect={av_detect}")
        if malware_family:
            result["hybridanalysis"]["malware_family"] = malware_family
            logger.debug(f"Hybrid Analysis: Added malware_family={malware_family}")
        if threat_level is not None:
            result["hybridanalysis"]["threat_level"] = threat_level
            logger.debug(f"Hybrid Analysis: Added threat_level={threat_level}")
        
        logger.info(f"Hybrid Analysis: Final result keys: {list(result['hybridanalysis'].keys())}")
        return result
    
    if isinstance(data, dict):
        # Check for result array (alternative structure)
        if "result" in data:
            results = data.get("result", [])
            logger.debug(f"Hybrid Analysis: Found 'result' key with {len(results) if isinstance(results, list) else 'non-list'} items")
            
            if isinstance(results, list) and len(results) > 0:
                sample = results[0]  # Get first result
                sha256 = sample.get("sha256") or sample.get("SHA256", observable)
                threat_score = sample.get("threat_score")
                verdict = sample.get("verdict", "Unknown")
                vx_family = sample.get("vx_family")
                submit_name = sample.get("submit_name", "Unknown")
                av_detect = sample.get("av_detect", 0)
                
                malware_family = []
                if vx_family:
                    malware_family = [vx_family] if isinstance(vx_family, str) else vx_family if isinstance(vx_family, list) else []
                
                search_link = f"https://hybrid-analysis.com/search?query={sha256}"
                
                result = {
                    "hybridanalysis": {
                        "found": True,
                        "status": "Sample listed in Hybrid Analysis",
                        "observable": observable,
                        "sha256": sha256,
                        "verdict": verdict,
                        "submit_name": submit_name,
                        "link": search_link,
                        "count": len(results)
                    }
                }
                
                if threat_score is not None:
                    result["hybridanalysis"]["threat_score"] = threat_score
                if av_detect is not None:
                    result["hybridanalysis"]["av_detect"] = av_detect
                if malware_family:
                    result["hybridanalysis"]["malware_family"] = malware_family
                
                return result
            elif results and not isinstance(results, list):
                # Result is not a list but has data
                sample = results
                sha256 = sample.get("sha256") or sample.get("SHA256", observable)
                threat_score = sample.get("threat_score")
                verdict = sample.get("verdict", "Unknown")
                vx_family = sample.get("vx_family")
                submit_name = sample.get("submit_name", "Unknown")
                av_detect = sample.get("av_detect", 0)
                
                malware_family = []
                if vx_family:
                    malware_family = [vx_family] if isinstance(vx_family, str) else vx_family if isinstance(vx_family, list) else []
                
                search_link = f"https://hybrid-analysis.com/search?query={sha256}"
                
                result = {
                    "hybridanalysis": {
                        "found": True,
                        "status": "Sample listed in Hybrid Analysis",
                        "observable": observable,
                        "sha256": sha256,
                        "verdict": verdict,
                        "submit_name": submit_name,
                        "link": search_link
                    }
                }
                
                if threat_score is not None:
                    result["hybridanalysis"]["threat_score"] = threat_score
                if av_detect is not None:
                    result["hybridanalysis"]["av_detect"] = av_detect
                if malware_family:
                    result["hybridanalysis"]["malware_family"] = malware_family
                
                return result
        # Check for direct sample data (alternative structure)
        elif "sha256" in data or "md5" in data or "sha1" in data:
            sha256 = data.get("sha256") or data.get("SHA256", observable)
            threat_score = data.get("threat_score")
            verdict = data.get("verdict", "Unknown")
            vx_family = data.get("vx_family")
            submit_name = data.get("submit_name", "Unknown")
            av_detect = data.get("av_detect", 0)
            
            malware_family = []
            if vx_family:
                malware_family = [vx_family] if isinstance(vx_family, str) else vx_family if isinstance(vx_family, list) else []
            
            search_link = f"https://www.hybrid-analysis.com/search?query={sha256}"
            
            result = {
                "hybridanalysis": {
                    "found": True,
                    "status": "Sample listed in Hybrid Analysis",
                    "observable": observable,
                    "sha256": sha256,
                    "verdict": verdict,
                    "submit_name": submit_name,
                    "link": search_link
                }
            }
            
            if threat_score is not None:
                result["hybridanalysis"]["threat_score"] = threat_score
            if av_detect is not None:
                result["hybridanalysis"]["av_detect"] = av_detect
            if malware_family:
                result["hybridanalysis"]["malware_family"] = malware_family
            
            return result
        # Check for count field (indicates results exist)
        elif "count" in data and data.get("count", 0) > 0:
            # Has count but might need to extract from different structure
            logger.debug(f"Hybrid Analysis: Found count={data.get('count')}, checking for sample data")
            # Try to find sample data in response
            if "data" in data:
                samples = data.get("data", [])
                if isinstance(samples, list) and len(samples) > 0:
                    sample = samples[0]
                    sha256 = sample.get("sha256", "Unknown")
                    return {
                        "hybridanalysis": {
                            "found": True,
                            "status": f"Found {data.get('count')} sample(s) in Hybrid Analysis",
                            "observable": observable,
                            "sha256": sha256,
                            "count": data.get("count"),
                            "link": f"https://hybrid-analysis.com/search?query={sha256}" if sha256 != "Unknown" else None
                        }
                    }
    
    # Fallback for unknown format - try to extract any useful information
    logger.warning(f"Hybrid Analysis: Unknown response format, attempting to extract data")
    logger.info(f"Hybrid Analysis: Full response structure: {str(data)[:2000]}")
    
    # Always create search link using the observable (hash)
    search_link = f"https://hybrid-analysis.com/search?query={observable}"
    
    extracted_info = {
        "found": found,
        "status": "Data received from Hybrid Analysis",
        "observable": observable,
        "link": search_link  # Always include the link
    }
    
    # Try to extract common fields from any structure
    def extract_nested_value(obj, keys):
        """Recursively search for a key in nested dict/list structures"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in keys:
                    return value
                if isinstance(value, (dict, list)):
                    result = extract_nested_value(value, keys)
                    if result:
                        return result
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    result = extract_nested_value(item, keys)
                    if result:
                        return result
        return None
    
    # Try to find common fields
    sha256 = extract_nested_value(data, ["sha256", "SHA256", "sha256_hash"])
    if sha256 and sha256 != observable:
        extracted_info["sha256"] = sha256
        # Update link with actual SHA256 if different
        extracted_info["link"] = f"https://hybrid-analysis.com/search?query={sha256}"
    
    threat_score = extract_nested_value(data, ["threat_score", "threatscore", "score"])
    if threat_score is not None:
        extracted_info["threat_score"] = threat_score
    
    verdict = extract_nested_value(data, ["verdict", "verdict_type", "classification"])
    if verdict:
        extracted_info["verdict"] = verdict
    
    vx_family = extract_nested_value(data, ["vx_family", "malware_family", "malwarefamily", "family"])
    if vx_family:
        extracted_info["malware_family"] = vx_family if isinstance(vx_family, list) else [vx_family]
    
    submit_name = extract_nested_value(data, ["submit_name", "submitname", "filename"])
    if submit_name:
        extracted_info["submit_name"] = submit_name
    
    av_detect = extract_nested_value(data, ["av_detect", "avdetect", "av_detection"])
    if av_detect is not None:
        extracted_info["av_detect"] = av_detect
    
    # Always return with at least the link
    return {
        "hybridanalysis": extracted_info
    }

