"""
ThreatFox module - ThreatFox IOCs lookup
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_threatfox_async
from .normalizer import normalize_threatfox_result

logger = logging.getLogger(__name__)


class ThreatFoxModule(BaseModule):
    """
    ThreatFox investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "ThreatFox"
    DISPLAY_NAME = "ThreatFox"
    DESCRIPTION = "ThreatFox IOCs lookup from abuse.ch"
    INPUT_TYPES = {InputType.IP, InputType.DOMAIN, InputType.HASH}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "malwarebazaar"  # Uses same API key as MalwareBazaar
    DATA_KEY = "threatfox"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query ThreatFox API"""
        if not api_key:
            logger.warning("ThreatFox requires API key (uses MalwareBazaar API key)")
            return None
        return await query_threatfox_async(observable, api_key)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize ThreatFox response"""
        return normalize_threatfox_result(raw_result)


# Module instance - automatically discovered
module = ThreatFoxModule()

__all__ = ['module', 'query_threatfox_async', 'normalize_threatfox_result']

