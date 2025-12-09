"""
WHOIS module - Domain WHOIS information
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_whois_async
from .normalizer import normalize_whois_result

logger = logging.getLogger(__name__)


class WHOISModule(BaseModule):
    """
    WHOIS investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "WHOIS"
    DISPLAY_NAME = "WHOIS"
    DESCRIPTION = "Domain WHOIS information"
    INPUT_TYPES = {InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "rdap"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query WHOIS"""
        return await query_whois_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize WHOIS response"""
        return normalize_whois_result(raw_result)


# Module instance - automatically discovered
module = WHOISModule()

__all__ = ['module', 'query_whois_async', 'normalize_whois_result']

