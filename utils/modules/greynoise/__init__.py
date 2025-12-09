"""
GreyNoise module - IP noise and background scanning detection
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_greynoise_async
from .normalizer import normalize_greynoise_result

logger = logging.getLogger(__name__)


class GreyNoiseModule(BaseModule):
    """
    GreyNoise investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "GreyNoise"
    DISPLAY_NAME = "GreyNoise"
    DESCRIPTION = "IP noise and background scanning detection"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = False  # Works without API key
    API_KEY_NAME = "greynoise"
    DATA_KEY = "greynoise"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query GreyNoise API"""
        return await query_greynoise_async(observable, api_key or "")
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize GreyNoise response"""
        return normalize_greynoise_result(raw_result)


# Module instance - automatically discovered
module = GreyNoiseModule()

__all__ = ['module', 'query_greynoise_async', 'normalize_greynoise_result']
