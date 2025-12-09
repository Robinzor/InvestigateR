"""
IPInfo module - IP geolocation and network information
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_ipinfo_async
from .normalizer import normalize_ipinfo_result

logger = logging.getLogger(__name__)


class IPInfoModule(BaseModule):
    """
    IPInfo investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "IPInfo"
    DISPLAY_NAME = "IPInfo"
    DESCRIPTION = "IP geolocation and network information"
    INPUT_TYPES = {InputType.IP}  # IPInfo API only supports IP addresses, not domains
    REQUIRES_API_KEY = True
    API_KEY_NAME = "ipinfo"
    DATA_KEY = "ipinfo"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query IPInfo API"""
        return await query_ipinfo_async(observable, api_key or "", **kwargs)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize IPInfo response"""
        return normalize_ipinfo_result(raw_result)


# Module instance - automatically discovered
module = IPInfoModule()

__all__ = ['module', 'query_ipinfo_async', 'normalize_ipinfo_result']

