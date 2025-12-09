"""
URLQuery module - URLQuery URL analysis and threat detection
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_urlquery_async
from .normalizer import normalize_urlquery_result

logger = logging.getLogger(__name__)


class URLQueryModule(BaseModule):
    """
    URLQuery investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "URLQuery"
    DISPLAY_NAME = "URLQuery"
    DESCRIPTION = "URLQuery URL and domain analysis and threat detection"
    INPUT_TYPES = {InputType.URL, InputType.DOMAIN}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "urlquery"
    DATA_KEY = "urlquery"
    ICON = "fas fa-search"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query URLQuery API"""
        if not api_key:
            logger.warning("URLQuery requires API key")
            return None
        return await query_urlquery_async(observable, api_key)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize URLQuery response"""
        return normalize_urlquery_result(raw_result)


# Module instance - automatically discovered
module = URLQueryModule()

__all__ = ['module', 'query_urlquery_async', 'normalize_urlquery_result']

