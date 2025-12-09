"""
IP Blocklists normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Friendly names for blacklists
BLACKLIST_NAMES = {
    "alienvault_reputation": "AlienVault IP Reputation",
    "bds_atif": "Binary Defense ATIF",
    "ciarmy": "CIArmy",
    "spamhaus_drop": "Spamhaus DROP",
    "spamhaus_edrop": "Spamhaus EDROP",
    "et_botcc": "Emerging Threats BotCC",
    "pushing_inertia": "Pushing Inertia",
    "turris_greylist": "Turris Greylist",
    "bbcan177_ms1": "BBcan177 Malicious Threats MS1",
    "bbcan177_ms3": "BBcan177 Malicious Threats MS3",
    "cta_cryptowall": "CTA CryptoWall",
    "cybercrime": "CyberCrime Tracker",
    "feodo": "Abuse.ch Feodo Tracker",
    "feodo_c2": "Abuse.ch Feodo C2",
    "sslbl": "Abuse.ch SSL Blacklist",
    "sslbl_aggressive": "Abuse.ch SSL Blacklist (Aggressive)",
    "urlhaus": "Abuse.ch URLhaus",
    "iblocklist_badpeers": "iBlocklist Bad Peers",
    "iblocklist_ciarmy_malicious": "iBlocklist CIArmy Malicious",
    "iblocklist_level1": "iBlocklist Level 1",
    "iblocklist_level2": "iBlocklist Level 2",
    "iblocklist_level3": "iBlocklist Level 3",
    "iblocklist_spyware": "iBlocklist Spyware",
    "iblocklist_webexploit": "iBlocklist Web Exploit",
    "iblocklist_abuse_palevo": "iBlocklist Abuse Palevo",
    "iblocklist_abuse_spyeye": "iBlocklist Abuse SpyEye",
    "iblocklist_abuse_zeus": "iBlocklist Abuse Zeus",
    "iblocklist_malc0de": "iBlocklist Malc0de",
    "vxvault": "VxVault",
    # FireHOL Blocklists (only level1-4 exist in the repository)
    "firehol_level1": "FireHOL Level 1",
    "firehol_level2": "FireHOL Level 2",
    "firehol_level3": "FireHOL Level 3",
    "firehol_level4": "FireHOL Level 4",
}


def normalize_ipblocklists_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize IP Blocklists lookup result into a standardized format.
    
    Args:
        raw_result: Raw result from query_ipblocklists_async
        
    Returns:
        Normalized dictionary with consistent structure
    """
    if not raw_result or "raw_data" not in raw_result:
        return {
            "ipblocklists": {
                "error": "No data received from IP Blocklists"
            }
        }
    
    data = raw_result["raw_data"]
    ip = raw_result.get("ip", "Unknown")
    
    # Check for errors
    if "error" in data:
        return {
            "ipblocklists": {
                "ip": ip,
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
    
    # Calculate value: 1 if in any blacklist, 0 if safe
    value = 1 if in_blacklist else 0
    
    # Build friendly names for found blacklists
    found_in_names = [BLACKLIST_NAMES.get(name, name) for name in found_in]
    
    # Primary link (use first found blacklist or general link)
    link = "https://www.abuse.ch" if found_in else "https://www.spamhaus.org"
    
    normalized = {
        "ipblocklists": {
            "ip": ip,
            "in_blacklist": in_blacklist,
            "is_malicious": in_blacklist,
            "found_in": found_in,
            "found_in_names": found_in_names,
            "total_blacklists_checked": total_checked,
            "total_blacklists_found": total_found,
            "total_blacklists_failed": total_failed,
            "blacklist_results": blacklist_results,
            "link": link,
            "value": value  # 1 = has data (malicious), 0 = safe (not in blacklist)
        }
    }
    
    logger.info(f"Normalized IP Blocklists result for {ip}: in_blacklist={in_blacklist}, found_in={len(found_in)} blacklists")
    return normalized

