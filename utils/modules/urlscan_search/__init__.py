"""
URLScanSearch module - URLScan.io search functionality
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_urlscan_search_async
from .normalizer import normalize_urlscan_search_result

logger = logging.getLogger(__name__)


class URLScanSearchModule(BaseModule):
    """
    URLScanSearch investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "URLScanSearch"
    DISPLAY_NAME = "URLScan Search"
    DESCRIPTION = "URLScan.io search functionality"
    INPUT_TYPES = {InputType.DOMAIN, InputType.URL}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "urlscan_search"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query URLScan Search"""
        return await query_urlscan_search_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize URLScan Search response"""
        return normalize_urlscan_search_result(raw_result)


# Module instance - automatically discovered
module = URLScanSearchModule()

__all__ = ['module', 'query_urlscan_search_async', 'normalize_urlscan_search_result']

