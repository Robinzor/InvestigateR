"""
Google Safe Browsing module - Google Safe Browsing threat detection
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_googlesafebrowsing_async
from .normalizer import normalize_googlesafebrowsing_result

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingModule(BaseModule):
    """
    Google Safe Browsing investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "GoogleSafeBrowsing"
    DISPLAY_NAME = "Google Safe Browsing"
    DESCRIPTION = "Google Safe Browsing threat detection for URLs and domains"
    INPUT_TYPES = {InputType.URL, InputType.DOMAIN}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "googlesafebrowsing"
    DATA_KEY = "googlesafebrowsing"
    ICON = "fas fa-shield-alt"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Google Safe Browsing API"""
        if not api_key:
            logger.warning("Google Safe Browsing requires API key")
            return None
        return await query_googlesafebrowsing_async(observable, api_key)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Google Safe Browsing response"""
        return normalize_googlesafebrowsing_result(raw_result)


# Module instance - automatically discovered
module = GoogleSafeBrowsingModule()

__all__ = ['module', 'query_googlesafebrowsing_async', 'normalize_googlesafebrowsing_result']

