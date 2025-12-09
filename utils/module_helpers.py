"""
Helper functions for working with modules dynamically.
Provides utilities for filtering, grouping, and accessing modules.
"""
from typing import List, Dict, Set, Any
from utils.module_executor import module_executor
from utils.modules.base import InputType


def get_modules_by_input_type(input_type: InputType) -> List[str]:
    """
    Get module names that support a specific input type.
    
    Args:
        input_type: The input type to filter by
        
    Returns:
        List of module names (MODULE_NAME)
    """
    modules = []
    for module_name, module_instance in module_executor.modules.items():
        if module_instance.validate_input("", input_type):
            modules.append(module_name)
    return modules


def get_ip_only_modules() -> List[str]:
    """Get modules that only support IP input type"""
    ip_modules = get_modules_by_input_type(InputType.IP)
    # Filter out modules that also support other types
    ip_only = []
    for module_name in ip_modules:
        module = module_executor.get_module(module_name)
        if module and InputType.IP in module.INPUT_TYPES:
            # Check if it ONLY supports IP (not DOMAIN, URL, HASH, or ANY)
            other_types = module.INPUT_TYPES - {InputType.IP}
            if not other_types or (len(other_types) == 1 and InputType.ANY in other_types):
                ip_only.append(module_name)
    return ip_only


def get_domain_only_modules() -> List[str]:
    """Get modules that only support DOMAIN input type"""
    domain_modules = get_modules_by_input_type(InputType.DOMAIN)
    # Filter out modules that also support other types
    domain_only = []
    for module_name in domain_modules:
        module = module_executor.get_module(module_name)
        if module and InputType.DOMAIN in module.INPUT_TYPES:
            # Check if it ONLY supports DOMAIN (not IP, URL, HASH, or ANY)
            other_types = module.INPUT_TYPES - {InputType.DOMAIN}
            if not other_types or (len(other_types) == 1 and InputType.ANY in other_types):
                domain_only.append(module_name)
    return domain_only


def get_url_only_modules() -> List[str]:
    """Get modules that only support URL input type"""
    url_modules = get_modules_by_input_type(InputType.URL)
    # Filter out modules that also support other types
    url_only = []
    for module_name in url_modules:
        module = module_executor.get_module(module_name)
        if module and InputType.URL in module.INPUT_TYPES:
            # Check if it ONLY supports URL (not IP, DOMAIN, HASH, or ANY)
            other_types = module.INPUT_TYPES - {InputType.URL}
            if not other_types or (len(other_types) == 1 and InputType.ANY in other_types):
                url_only.append(module_name)
    return url_only


def get_slow_modules() -> List[str]:
    """
    Get modules that are considered slow (should run last).
    Can be extended with module metadata in the future.
    """
    # For now, hardcode known slow modules - could be moved to module metadata
    slow_module_names = ["crt.sh", "WaybackMachine"]
    return [name for name in slow_module_names if module_executor.get_module(name)]


def get_module_icon(module_name: str) -> str:
    """
    Get Font Awesome icon class for a module.
    Defaults to 'fa-cog' if no specific icon is defined.
    """
    icon_map = {
        'AbuseIPDB': 'fa-shield-alt',
        'VirusTotal': 'fa-virus',
        'GreyNoise': 'fa-cloud',
        'IPInfo': 'fa-map-marker-alt',
        'crt.sh': 'fa-certificate',
        'ReverseDNS': 'fa-exchange-alt',
        'ShodanInternetDB': 'fa-database',
        'SANS': 'fa-fire',
        'URLScanSearch': 'fa-search',
        'URLScanScan': 'fa-camera',
        'OpenCTI': 'fa-project-diagram',
        'WHOIS': 'fa-globe',
        'WaybackMachine': 'fa-history',
        'DNSRecords': 'fa-server',
        'AlienVaultOTX': 'fa-shield-alt',
        'AlienVaultIPRep': 'fa-shield-alt',
        'AbuseCh': 'fa-shield-alt',
        'IPBlocklists': 'fa-ban',
        'DomainBlocklists': 'fa-ban',
        'PhishTank': 'fa-fish',
        'OpenPhish': 'fa-shield-virus',
        'GoogleSafeBrowsing': 'fa-shield-alt',
        'URLQuery': 'fa-search',
        'MalwareBazaar': 'fa-bug',
        'HybridAnalysis': 'fa-vial',
        'URLHaus': 'fa-shield-alt',
        'ThreatFox': 'fa-shield-alt',
    }
    return icon_map.get(module_name, 'fa-cog')


def get_all_modules() -> List[Dict[str, any]]:
    """
    Get all modules with their metadata for template rendering.
    
    Returns:
        List of dicts with module info: {
            'name': MODULE_NAME,
            'display_name': DISPLAY_NAME,
            'description': DESCRIPTION,
            'requires_api_key': bool,
            'api_key_name': str or None,
            'data_key': DATA_KEY,
            'input_types': [list of input type strings],
            'icon': Font Awesome icon class
        }
    """
    modules = []
    for module_name, module_instance in module_executor.modules.items():
        config = module_instance.get_config()
        modules.append({
            'name': config.get('name', module_name),
            'display_name': config.get('display_name', module_name),
            'description': config.get('description', ''),
            'requires_api_key': config.get('requires_api_key', False),
            'api_key_name': config.get('api_key_name'),
            'data_key': config.get('data_key', ''),
            'input_types': config.get('input_types', []),
            'icon': get_module_icon(config.get('name', module_name))
        })
    return sorted(modules, key=lambda x: x['display_name'])


def get_required_api_keys() -> Set[str]:
    """
    Get all required API key names from modules.
    
    Returns:
        Set of API key names (e.g., {'abuseipdb', 'virustotal', ...})
    """
    api_keys = set()
    for module_instance in module_executor.modules.values():
        if module_instance.API_KEY_NAME:
            api_keys.add(module_instance.API_KEY_NAME)
    return api_keys


def get_data_key_to_module_name_map() -> Dict[str, str]:
    """
    Get mapping from DATA_KEY to MODULE_NAME.
    Useful for reverse lookups.
    
    Returns:
        Dict mapping DATA_KEY -> MODULE_NAME
    """
    mapping = {}
    for module_name, module_instance in module_executor.modules.items():
        mapping[module_instance.DATA_KEY] = module_name
    # Add special mappings
    mapping['rdap'] = 'WHOIS'  # WHOIS uses 'rdap' as data key
    mapping['wayback_machine'] = 'WaybackMachine'
    return mapping


def is_module_result_safe(module_data: Dict[str, Any], data_key: str) -> bool:
    """
    Determine if a module result is "safe" (should be hidden when hide_safe_results is enabled).
    This is a universal function that works for all modules.
    
    Args:
        module_data: The normalized module data (e.g., result.data.abuseipdb)
        data_key: The module's data key (e.g., "abuseipdb", "virustotal")
        
    Returns:
        True if result is safe (should be hidden), False if it has significant data
    """
    if not module_data or not isinstance(module_data, dict):
        return True  # No data = safe
    
    # Universal check: look for explicit is_safe field FIRST (highest priority)
    # This allows modules to explicitly mark errors as safe to hide (e.g., "no_results")
    if "is_safe" in module_data:
        return module_data["is_safe"]
    
    # Check for errors - errors are not "safe" (they should be shown)
    # But only if is_safe wasn't explicitly set above
    if "error" in module_data:
        return False
    
    # Universal check: look for value field (0 = safe, >0 = has data)
    if "value" in module_data:
        return module_data["value"] == 0
    
    # Universal check: look for safe field
    if "safe" in module_data:
        return module_data["safe"]
    
    # Module-specific checks
    if data_key == "abuseipdb":
        risk_score = module_data.get("risk_score", 0)
        reports = module_data.get("reports", 0)
        return risk_score == 0 and reports == 0
    
    elif data_key == "virustotal":
        def _as_int(val):
            try:
                return int(val)
            except Exception:
                return 0

        malicious = _as_int(module_data.get("malicious_count", module_data.get("malicious", 0)))
        suspicious = _as_int(module_data.get("suspicious_count", module_data.get("suspicious", 0)))
        risk_score = _as_int(module_data.get("risk_score", 0))

        has_context = bool(
            module_data.get("analysis_results")
            or module_data.get("additional_info")
            or module_data.get("categories")
            or module_data.get("tags")
            or module_data.get("dns_records")
            or module_data.get("ssl_certificate")
            or module_data.get("link")
        )

        # Hide only when there are no detections, no risk score, and no contextual data
        return malicious == 0 and suspicious == 0 and risk_score == 0 and not has_context
    
    elif data_key == "greynoise":
        classification = module_data.get("classification", "").lower()
        return classification in ["", "unknown", "benign"]
    
    elif data_key == "phishtank":
        return not module_data.get("in_database", False)
    
    elif data_key == "openphish":
        return not module_data.get("is_phishing", False)
    
    elif data_key == "alienvault_iprep":
        return not module_data.get("in_blacklist", False)
    
    elif data_key == "alienvault_otx":
        pulse_count = module_data.get("pulse_count", 0)
        return pulse_count == 0
    
    elif data_key == "urlquery":
        total_hits = module_data.get("total_hits", 0)
        return total_hits == 0
    
    elif data_key == "urlhaus":
        # Check for error status (no_results, invalid_url, etc.) - these should be hidden
        status = module_data.get("status", "")
        error = module_data.get("error", "")
        
        # If status is "no_results" or error contains "no_results", it's safe to hide
        if status == "no_results" or (error and ("no_results" in str(error).lower() or "not found" in str(error).lower())):
            return True  # Safe to hide
        
        # If there's any error (but not "ok" status), it's safe to hide
        if error and status != "ok":
            return True  # Safe to hide
        
        # Treat as unsafe if there is threat info, non-empty tags/blacklists, or risk_score > 0
        risk_score = module_data.get("risk_score", 0)
        threat = module_data.get("threat")
        tags = module_data.get("tags") or []
        blacklists = module_data.get("blacklists") or []
        return not threat and risk_score == 0 and len(tags) == 0 and len(blacklists) == 0
    
    elif data_key == "threatfox":
        # Check for error status (no_results, etc.) - these should be hidden
        status = module_data.get("status", "")
        error = module_data.get("error", "")
        found = module_data.get("found", False)
        
        # If status is "IOC not found in ThreatFox database" or error contains "no_results", it's safe to hide
        if status == "IOC not found in ThreatFox database" or (error and ("no_results" in str(error).lower() or "not found" in str(error).lower())):
            return True  # Safe to hide
        
        # If there's any error (but not found), it's safe to hide
        if error and not found:
            return True  # Safe to hide
        
        # Treat as unsafe if IOC was found (has results)
        return not found
    
    elif data_key == "shodan_internetdb":
        # Has data if there are ports, vulns, hostnames, etc.
        ports = module_data.get("ports", [])
        vulns = module_data.get("vulns", [])
        hostnames = module_data.get("hostnames", [])
        return len(ports) == 0 and len(vulns) == 0 and len(hostnames) == 0
    
    elif data_key == "sans":
        attacks = module_data.get("attacks", 0)
        threatfeeds = module_data.get("threatfeeds", [])
        return attacks == 0 and len(threatfeeds) == 0
    
    elif data_key == "googlesafebrowsing":
        matches = module_data.get("matches", [])
        return len(matches) == 0
    
    elif data_key == "abusech":
        return not module_data.get("in_blacklist", False)
    
    elif data_key == "ipblocklists":
        return not module_data.get("in_blacklist", False)
    
    elif data_key == "opencti":
        results = module_data.get("results", [])
        return len(results) == 0
    
    elif data_key == "reversedns":
        hostname = module_data.get("hostname", "")
        return not hostname or hostname.strip() == ""
    
    elif data_key == "crtsh":
        certificates = module_data.get("certificates", [])
        total = module_data.get("total_certificates", 0)
        return len(certificates) == 0 and total == 0
    
    elif data_key == "ipinfo":
        # IPInfo always has data (location, ISP, etc.), so it's never "safe" to hide
        return False
    
    elif data_key == "malwarebazaar":
        found = module_data.get("found", False)
        return not found
    
    elif data_key == "hybridanalysis":
        found = module_data.get("found", False)
        return not found
    
    
    elif data_key == "dns_records":
        records = module_data.get("records", [])
        return len(records) == 0
    
    elif data_key == "wayback_machine":
        snapshots = module_data.get("snapshots", [])
        return len(snapshots) == 0
    
    elif data_key == "rdap" or data_key == "whois":
        # WHOIS always has data, so it's never "safe" to hide
        return False
    
    elif data_key == "urlscan_search":
        scan_history = module_data.get("scan_history", [])
        return len(scan_history) == 0
    
    elif data_key == "urlscan_scan":
        # URLScan scan results always have data if successful
        return False
    
    # Default: if we have any non-empty fields (besides standard ones), it's not safe
    standard_fields = {"ip", "domain", "url", "hash", "link", "source", "error"}
    has_data = False
    for key, value in module_data.items():
        if key not in standard_fields and value:
            if isinstance(value, (list, dict)):
                if len(value) > 0:
                    has_data = True
                    break
            elif str(value).strip():
                has_data = True
                break
    
    return not has_data  # If no data found, it's safe
