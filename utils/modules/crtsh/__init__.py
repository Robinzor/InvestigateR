"""
crt.sh module - CRT.sh certificate transparency
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_crtsh_async
from .normalizer import normalize_crtsh_result

logger = logging.getLogger(__name__)


class CrtshModule(BaseModule):
    """
    crt.sh investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "crt.sh"
    DISPLAY_NAME = "CRT.sh"
    DESCRIPTION = "CRT.sh certificate transparency"
    INPUT_TYPES = {InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "crtsh"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query crt.sh API"""
        exclude_expired = kwargs.get('exclude_expired', False)
        return await query_crtsh_async(observable, exclude_expired)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize crt.sh response"""
        return normalize_crtsh_result(raw_result)


# Module instance - automatically discovered
module = CrtshModule()

__all__ = ['module', 'query_crtsh_async', 'normalize_crtsh_result']

