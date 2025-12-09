"""
SANS module - SANS Internet Storm Center
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_sans_async
from .normalizer import normalize_sans_result

logger = logging.getLogger(__name__)


class SANSModule(BaseModule):
    """
    SANS investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "SANS"
    DISPLAY_NAME = "SANS"
    DESCRIPTION = "SANS Internet Storm Center"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "sans"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query SANS Internet Storm Center"""
        return await query_sans_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize SANS response"""
        return normalize_sans_result(raw_result)


# Module instance - automatically discovered
module = SANSModule()

__all__ = ['module', 'query_sans_async', 'normalize_sans_result']

