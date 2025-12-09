"""
DNSRecords module - DNS record lookup
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_dns_records_async
from .normalizer import normalize_dns_records_result

logger = logging.getLogger(__name__)


class DNSRecordsModule(BaseModule):
    """
    DNSRecords investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "DNSRecords"
    DISPLAY_NAME = "DNS Records"
    DESCRIPTION = "DNS record lookup"
    INPUT_TYPES = {InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "dns_records"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query DNS Records"""
        return await query_dns_records_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize DNS Records response"""
        return normalize_dns_records_result(raw_result)


# Module instance - automatically discovered
module = DNSRecordsModule()

__all__ = ['module', 'query_dns_records_async', 'normalize_dns_records_result']

