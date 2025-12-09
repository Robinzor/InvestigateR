"""
ReverseDNS module - Reverse DNS lookup
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_reversedns_async
from .normalizer import normalize_reversedns_result

logger = logging.getLogger(__name__)


class ReverseDNSModule(BaseModule):
    """
    ReverseDNS investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "ReverseDNS"
    DISPLAY_NAME = "Reverse DNS"
    DESCRIPTION = "Reverse DNS lookup"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "reversedns"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Reverse DNS"""
        return await query_reversedns_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Reverse DNS response"""
        return normalize_reversedns_result(raw_result)


# Module instance - automatically discovered
module = ReverseDNSModule()

__all__ = ['module', 'query_reversedns_async', 'normalize_reversedns_result']

