"""
AbuseIPDB module - IP reputation and abuse reporting
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_abuseipdb_async
from .normalizer import normalize_abuseipdb_result

logger = logging.getLogger(__name__)


class AbuseIPDBModule(BaseModule):
    """
    AbuseIPDB investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "AbuseIPDB"
    DISPLAY_NAME = "AbuseIPDB"
    DESCRIPTION = "IP reputation and abuse reporting"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "abuseipdb"
    DATA_KEY = "abuseipdb"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB API"""
        return await query_abuseipdb_async(observable, api_key or "")
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize AbuseIPDB response"""
        return normalize_abuseipdb_result(raw_result)


# Module instance - automatically discovered
module = AbuseIPDBModule()

__all__ = ['module', 'query_abuseipdb_async', 'normalize_abuseipdb_result']
