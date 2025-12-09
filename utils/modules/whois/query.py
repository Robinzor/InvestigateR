"""
WHOIS query module - handles WHOIS lookups
"""
import asyncio
import logging
from typing import Optional, Dict, Any
import whois

logger = logging.getLogger(__name__)


async def query_whois_async(domain: str) -> Optional[Dict[str, Any]]:
    """
    Query WHOIS information for a domain.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: Raw WHOIS data.
        None: If an error occurs.
    """
    try:
        logger.info(f"Querying WHOIS for domain: {domain}")
        
        # Run blocking WHOIS lookup in executor with timeout
        # WHOIS queries can be slow, so set a reasonable timeout (5 seconds)
        # This prevents the query from hanging indefinitely
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _query_whois_sync, domain),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            logger.warning(f"WHOIS query for {domain} timed out after 5 seconds")
            return None
        
        if result:
            return {
                "raw_data": result,
                "domain": domain
            }
        return None

    except Exception as e:
        logger.error(f"Error querying WHOIS for {domain}: {e}", exc_info=True)
        return None


def _query_whois_sync(domain: str) -> Optional[Dict[str, Any]]:
    """Synchronous WHOIS query"""
    try:
        whois_data = whois.whois(domain)
        creation_date = whois_data.creation_date[0] if isinstance(whois_data.creation_date, list) else whois_data.creation_date
        expiration_date = whois_data.expiration_date[0] if isinstance(whois_data.expiration_date, list) else whois_data.expiration_date
        name_servers = [ns.lower() for ns in whois_data.name_servers] if whois_data.name_servers else []
        
        return {
            'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else None,
            'expiration_date': expiration_date.strftime('%Y-%m-%d') if expiration_date else None,
            'registrar': whois_data.registrar,
            'registrant': whois_data.registrant,
            'name_servers': name_servers,
            'all_emails': whois_data.emails if whois_data.emails else [],
            'link': f"https://who.is/whois/{domain}"
        }
    except Exception as e:
        logger.error(f"WHOIS error for {domain}: {str(e)}")
        return None

