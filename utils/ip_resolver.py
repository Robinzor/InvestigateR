import logging
import aiohttp
import dns.resolver
from typing import Optional, List

logger = logging.getLogger(__name__)

async def resolve_domain_to_ips(domain: str) -> Optional[List[str]]:
    """
    Resolves a domain name to its IPv4 addresses using multiple methods.
    
    Args:
        domain (str): The domain name to resolve
        
    Returns:
        List[str]: List of IPv4 addresses if successful, None otherwise
    """
    try:
        logger.info(f"Attempting to resolve domain: {domain}")
        ip_addresses = []
        
        # Method 1: Using Google DNS over HTTPS (try this first as it's most reliable)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://dns.google/resolve?name={domain}&type=A') as response:
                    if response.status == 200:
                        data = await response.json()
                        if 'Answer' in data:
                            for answer in data['Answer']:
                                if answer['type'] == 1:  # A record
                                    ip = answer['data']
                                    if ip not in ip_addresses:
                                        ip_addresses.append(ip)
                                        logger.info(f"Found IPv4 address via Google DNS: {ip}")
        except Exception as e:
            logger.warning(f"Error using Google DNS: {str(e)}")
        
        # Method 2: Using dnspython (run in executor to avoid blocking)
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            
            # Run blocking DNS query in executor
            def _resolve_sync():
                try:
                    answers = resolver.resolve(domain, 'A')
                    return [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    logger.warning(f"No A records found for {domain}")
                    return []
                except Exception as e:
                    logger.warning(f"Error resolving A records: {str(e)}")
                    return []
            
            resolved_ips = await loop.run_in_executor(None, _resolve_sync)
            for ip in resolved_ips:
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
                    logger.info(f"Found IPv4 address via dnspython: {ip}")
        except Exception as e:
            logger.warning(f"Error using dnspython: {str(e)}")
        
        if not ip_addresses:
            logger.warning(f"No IPv4 addresses found for domain: {domain}")
            return None
            
        logger.info(f"Successfully resolved domain {domain} to IPv4 addresses: {ip_addresses}")
        return ip_addresses
        
    except Exception as e:
        logger.error(f"Unexpected error resolving domain {domain}: {str(e)}")
        return None 