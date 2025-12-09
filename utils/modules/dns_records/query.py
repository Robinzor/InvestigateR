"""
DNSRecords query module - handles DNS record lookups
"""
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any
import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


async def query_dns_records_async(domain: str) -> Optional[Dict[str, Any]]:
    """
    Query DNS records for a domain.

    Args:
        domain (str): The domain to query.

    Returns:
        dict: Raw DNS records data.
        None: If an error occurs.
    """
    try:
        logger.info(f"Querying DNS records for domain: {domain}")
        
        # Run blocking DNS queries in executor
        loop = asyncio.get_event_loop()
        records = await loop.run_in_executor(None, _query_dns_sync, domain)
        
        if records:
            return {
                "raw_data": records,
                "domain": domain
            }
        return None

    except Exception as e:
        logger.error(f"Error querying DNS records for {domain}: {e}", exc_info=True)
        return None


def _query_dns_sync(domain: str) -> Optional[Dict[str, Any]]:
    """Synchronous DNS record lookup"""
    records = {}
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
    
    for record_type in record_types:
        try:
            # Set timeout for each query
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
            logger.debug(f"Found {len(records[record_type])} {record_type} records for {domain}")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records found for {domain}")
            continue
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
            return None
        except dns.resolver.Timeout:
            logger.warning(f"Timeout querying {record_type} record for {domain}")
            continue
        except dns.resolver.NoNameservers:
            logger.warning(f"No nameservers found for {domain} when querying {record_type}")
            continue
        except Exception as e:
            logger.warning(f"Error querying {record_type} record for {domain}: {e}")
            continue
    
    if records:
        logger.info(f"Successfully queried DNS records for {domain}: {list(records.keys())}")
        return records
    else:
        logger.warning(f"No DNS records found for {domain}")
        return None

