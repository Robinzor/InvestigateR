"""
ShodanInternetDB module - Shodan InternetDB IP information
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_shodan_internetdb_async
from .normalizer import normalize_shodan_internetdb_result

logger = logging.getLogger(__name__)


class ShodanInternetDBModule(BaseModule):
    """
    ShodanInternetDB investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "ShodanInternetDB"
    DISPLAY_NAME = "Shodan InternetDB"
    DESCRIPTION = "Shodan InternetDB IP information"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "shodan_internetdb"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Shodan InternetDB API"""
        return await query_shodan_internetdb_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Shodan InternetDB response"""
        return normalize_shodan_internetdb_result(raw_result)


# Module instance - automatically discovered
module = ShodanInternetDBModule()

__all__ = ['module', 'query_shodan_internetdb_async', 'normalize_shodan_internetdb_result']

