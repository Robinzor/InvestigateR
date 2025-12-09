"""
Domain Blocklists normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Friendly names for blacklists
BLACKLIST_NAMES = {
    "oisd_big": "OISD Big",
    "kadhosts": "KADhosts",
    "fademind_spam": "FadeMind Spam",
    "firebog_w3kbl": "Firebog W3KBL",
    "adaway": "AdAway",
    "firebog_adguard": "Firebog AdguardDNS",
    "firebog_admiral": "Firebog Admiral",
    "anudeep_adservers": "Anudeep Adservers",
    "disconnect_simple_ad": "Disconnect Simple Ad",
    "firebog_easylist": "Firebog Easylist",
    "pgl_yoyo": "Peter Lowe's Adservers",
    "fademind_unchecky": "FadeMind UncheckyAds",
    "bigdargon_hosts_vn": "BigDargon Hosts VN",
    "firebog_easyprivacy": "Firebog Easyprivacy",
    "fademind_2o7net": "FadeMind 2o7Net",
    "windows_spyblocker": "Windows SpyBlocker",
    "frogeye_firstparty": "Frogeye Firstparty Trackers",
    "dandelion_antimalware": "Dandelion AntiMalware",
    "disconnect_malvertising": "Disconnect Malvertising",
    "firebog_prigent_crypto": "Firebog Prigent Crypto",
    "fademind_risk": "FadeMind Risk",
    "mandiant_apt1": "Mandiant APT1",
    "phishing_army": "Phishing Army",
    "notrack_malware": "NoTrack Malware",
    "firebog_rpimlist_malware": "Firebog RPiList Malware",
    "firebog_rpimlist_phishing": "Firebog RPiList Phishing",
    "spam404": "Spam404",
    "assoechap_stalkerware": "AssoEchap Stalkerware",
    "urlhaus_hostfile": "URLhaus Hostfile",
    "hagezi_ultimate": "HaGeZi Ultimate",
    "stevenblack_hosts": "StevenBlack Hosts",
}


def normalize_domainblocklists_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize Domain Blocklists lookup result into a standardized format.
    
    Args:
        raw_result: Raw result from query_domainblocklists_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "domainblocklists": {
                "error": "No data received from Domain Blocklists"
            }
        }
    
    data = raw_result["raw_data"]
    domain = raw_result.get("domain", "Unknown")
    
    # Check for errors
    if "error" in data:
        return {
            "domainblocklists": {
                "domain": domain,
                "error": data["error"]
            }
        }
    
    # Extract results
    in_blacklist = data.get("in_blacklist", False)
    found_in = data.get("found_in", [])
    blacklist_results = data.get("blacklist_results", {})
    total_checked = data.get("total_blacklists_checked", 0)
    total_found = data.get("total_blacklists_found", 0)
    total_failed = data.get("total_blacklists_failed", 0)
    
    # Get friendly names
    found_in_names = [BLACKLIST_NAMES.get(name, name) for name in found_in]
    
    # Build result
    result = {
        "domain": domain,
        "in_blacklist": in_blacklist,
        "is_malicious": in_blacklist,  # Alias for consistency
        "found_in": found_in,
        "found_in_names": found_in_names,
        "total_blacklists_checked": total_checked,
        "total_blacklists_found": total_found,
        "total_blacklists_failed": total_failed,
        "blacklist_results": blacklist_results,
        "link": "https://www.abuse.ch" if in_blacklist else None,
        "value": total_found
    }
    
    return {
        "domainblocklists": result
    }

