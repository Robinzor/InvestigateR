"""
URLHaus normalizer - standardizes output format.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


def normalize_urlhaus_result(raw_result: Dict[str, Any]) -> Dict[str, Any]:
    if not raw_result:
        return {"urlhaus": {"error": "No data received from URLHaus", "is_safe": True}}

    if "error" in raw_result:
        return {"urlhaus": {"error": raw_result.get("error", "Unknown error"), "is_safe": True}}

    data = raw_result.get("raw_data") or {}
    query_status = data.get("query_status")

    # URLHaus query_status values: "ok", "no_results", "invalid_url"
    if query_status != "ok":
        return {
            "urlhaus": {
                "error": data.get("error", query_status or "Unknown status"),
                "status": query_status,
                "is_safe": True,  # No results means safe to hide
            }
        }

    threat = data.get("threat")
    url_status = data.get("url_status")
    date_added = data.get("date_added")
    reporter = data.get("reporter")
    signature = data.get("signature")
    tags = data.get("tags") or []
    blacklists = data.get("blacklists") or {}
    urlhaus_reference = data.get("urlhaus_reference")

    # Build blacklists list for display
    blacklist_entries = []
    if isinstance(blacklists, dict):
        for provider, state in blacklists.items():
            blacklist_entries.append(f"{provider}: {state}")

    # Risk heuristic: flag as risky when url_status is online or threat is set
    risky = (url_status or "").lower() == "online" or bool(threat)
    risk_score = 80 if risky else 0

    # If query_status is "ok", URLHaus found the URL in database - always show (is_safe = False)
    # Only hide when there are no results (query_status != "ok") which is handled above
    normalized = {
        "urlhaus": {
            "status": url_status,
            "threat": threat,
            "date_added": date_added,
            "reporter": reporter,
            "signature": signature,
            "tags": tags,
            "blacklists": blacklist_entries,
            "link": urlhaus_reference,
            "risk_score": risk_score,
            "is_safe": False,  # Always show when query_status == "ok" (results found)
        }
    }

    logger.info(f"Normalized URLHaus result for {raw_result.get('observable', 'Unknown')}")
    return normalized

