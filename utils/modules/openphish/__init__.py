"""
OpenPhish module - OpenPhish phishing intelligence feed
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_openphish_async
from .normalizer import normalize_openphish_result

logger = logging.getLogger(__name__)


class OpenPhishModule(BaseModule):
    """
    OpenPhish investigation module.
    Checks URLs and domains against OpenPhish phishing intelligence feed.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "OpenPhish"
    DISPLAY_NAME = "OpenPhish"
    DESCRIPTION = "Check URLs and domains against OpenPhish phishing intelligence feed"
    INPUT_TYPES = {InputType.URL, InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "openphish"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query OpenPhish feed"""
        return await query_openphish_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize OpenPhish response"""
        return normalize_openphish_result(raw_result)


# Module instance - automatically discovered
module = OpenPhishModule()

__all__ = ['module', 'query_openphish_async', 'normalize_openphish_result']

