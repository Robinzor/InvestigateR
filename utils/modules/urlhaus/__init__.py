"""
URLHaus module - URL threat intelligence
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_urlhaus_async
from .normalizer import normalize_urlhaus_result

logger = logging.getLogger(__name__)


class URLHausModule(BaseModule):
    MODULE_NAME = "URLHaus"
    DISPLAY_NAME = "URLHaus"
    DESCRIPTION = "URL threat intelligence (abuse.ch URLHaus)"
    INPUT_TYPES = {InputType.URL}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "malwarebazaar"  # Uses same API key as MalwareBazaar
    DATA_KEY = "urlhaus"

    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        return await query_urlhaus_async(observable, api_key)

    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        return normalize_urlhaus_result(raw_result or {})


module = URLHausModule()

__all__ = ["module", "query_urlhaus_async", "normalize_urlhaus_result"]

