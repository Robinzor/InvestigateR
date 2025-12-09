"""
AlienVault OTX module - Open Threat Exchange
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_otx_async
from .normalizer import normalize_otx_result

logger = logging.getLogger(__name__)


class AlienVaultOTXModule(BaseModule):
    """
    AlienVault OTX investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "AlienVaultOTX"
    DISPLAY_NAME = "AlienVault OTX"
    DESCRIPTION = "Open Threat Exchange - threat intelligence"
    INPUT_TYPES = {InputType.IP, InputType.DOMAIN, InputType.HASH}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "alienvault_otx"
    DATA_KEY = "alienvault_otx"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX API"""
        return await query_otx_async(observable, api_key or "")
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize AlienVault OTX response"""
        return normalize_otx_result(raw_result)


# Module instance - automatically discovered
module = AlienVaultOTXModule()

__all__ = ['module', 'query_otx_async', 'normalize_otx_result']

