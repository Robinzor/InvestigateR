"""
WaybackMachine module - Internet Archive Wayback Machine
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_waybackmachine_async
from .normalizer import normalize_waybackmachine_result

logger = logging.getLogger(__name__)


class WaybackMachineModule(BaseModule):
    """
    WaybackMachine investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "WaybackMachine"
    DISPLAY_NAME = "Wayback Machine"
    DESCRIPTION = "Internet Archive Wayback Machine"
    INPUT_TYPES = {InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "wayback_machine"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Wayback Machine"""
        return await query_waybackmachine_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Wayback Machine response"""
        return normalize_waybackmachine_result(raw_result)


# Module instance - automatically discovered
module = WaybackMachineModule()

__all__ = ['module', 'query_waybackmachine_async', 'normalize_waybackmachine_result']

