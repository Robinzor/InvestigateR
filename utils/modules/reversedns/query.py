"""
ReverseDNS query module - handles DNS lookups
"""
import socket
import asyncio
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


async def query_reversedns_async(ip: str) -> Optional[Dict[str, Any]]:
    """
    Perform reverse DNS lookup for an IP address.

    Args:
        ip (str): The IP address to query.

    Returns:
        dict: Raw DNS lookup data.
        None: If an error occurs.
    """
    try:
        logger.info(f"Performing reverse DNS lookup for IP: {ip}")
        
        # Run blocking DNS lookup in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _reverse_dns_sync, ip)
        
        if result:
            return {
                "raw_data": result,
                "ip": ip
            }
        return None

    except Exception as e:
        logger.error(f"Error performing reverse DNS lookup for {ip}: {e}", exc_info=True)
        return None


def _reverse_dns_sync(ip: str) -> Optional[Dict[str, Any]]:
    """Synchronous reverse DNS lookup"""
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return {
            "hostname": hostname,
            "aliases": aliases if aliases else [],
            "addresses": addresses if addresses else []
        }
    except socket.herror:
        logger.debug(f"No reverse DNS record found for {ip}")
        return None
    except Exception as e:
        logger.error(f"Error in reverse DNS lookup: {e}")
        return None

