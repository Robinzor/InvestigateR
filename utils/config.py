"""
Central configuration file for colors and settings only.
Tool metadata is dynamically retrieved from modules.
"""

# Tool colors for UI display
TOOL_COLORS = {
    'abuseipdb': '#4e7e14',
    'virustotal': '#4B9CD3',
    'ipinfo': '#0095E5',  # rgb(0, 149, 229)
    'greynoise': '#808080',  # Gray
    'reversedns': '#fd7e14',
    'crtsh': '#00B373',
    'shodan_internetdb': '#000000',  # Black
    'whois': '#ff7b7b',
    'opencti': '#004085',  # Dark blue
    'urlscan_search': '#2c3e50',
    'urlscan_scan': '#2c3e50',
    'waybackmachine': '#ffc107',
    'dns_records': '#6610f2',
    'sans': '#781400',
    'alienvault_otx': '#0012b3',
    'phishtank': '#dc3545',
    'googlesafebrowsing': '#4285F4',  # Google blue
    'urlquery': '#0e131f',  # Dark blue-gray
    'urlhaus': '#d9534f',  # Red-ish
    'threatfox': '#ff6b35',  # Orange-red
}

# Observable type colors
OBSERVABLE_COLORS = {
    'hash': '#4B9CD3',
    'ip': '#28a745',
    'domain': '#ffc107',
    'url': '#dc3545',
    'loading': '#6c757d',
}

# Risk score thresholds
RISK_THRESHOLDS = {
    'high': 70,
    'medium': 30,
    'low': 0,
}


def get_tool_color(tool_name: str) -> str:
    """Get the color for a tool by name"""
    return TOOL_COLORS.get(tool_name.lower(), '#6c757d')


def get_observable_color(obs_type: str) -> str:
    """Get the color for an observable type"""
    return OBSERVABLE_COLORS.get(obs_type.lower(), '#6c757d')


def get_risk_level(score: int) -> str:
    """Get risk level based on score"""
    if score >= RISK_THRESHOLDS['high']:
        return 'high'
    elif score >= RISK_THRESHOLDS['medium']:
        return 'medium'
    else:
        return 'low'


def get_tool_metadata():
    """
    Get tool metadata dynamically from discovered modules.
    Returns a dictionary mapping DATA_KEY to module metadata.
    Avoids circular import by importing module_executor lazily.
    """
    from utils.module_executor import module_executor
    metadata = {}
    for module_name, module_instance in module_executor.modules.items():
        config = module_instance.get_config()
        data_key = config.get('data_key', module_name.lower())
        metadata[data_key] = {
            'name': config.get('name', module_name),
            'display_name': config.get('display_name', module_name),
            'description': config.get('description', ''),
            'requires_api_key': config.get('requires_api_key', False),
            'api_key_name': config.get('api_key_name'),
        }
    return metadata


def get_module_by_data_key(data_key: str):
    """
    Get a module instance by its DATA_KEY.
    
    Args:
        data_key: The DATA_KEY of the module (e.g., 'abuseipdb', 'virustotal')
        
    Returns:
        Module instance or None
    """
    from utils.module_executor import module_executor
    for module_instance in module_executor.modules.values():
        if module_instance.DATA_KEY == data_key:
            return module_instance
    return None
