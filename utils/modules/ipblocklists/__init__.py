"""
IP Blocklists module - Multiple IP reputation blacklists
Checks IPs against various threat intelligence blacklists
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_ipblocklists_async
from .normalizer import normalize_ipblocklists_result

logger = logging.getLogger(__name__)


class IPBlocklistsModule(BaseModule):
    """
    IP Blocklists investigation module.
    Checks if an IP address is malicious according to multiple threat intelligence blacklists.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "IPBlocklists"
    DISPLAY_NAME = "IP Blocklists"
    DESCRIPTION = "Check if an IP address is malicious according to multiple threat intelligence blacklists"
    INPUT_TYPES = {InputType.IP}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "ipblocklists"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query IP Blocklists"""
        return await query_ipblocklists_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize IP Blocklists response"""
        return normalize_ipblocklists_result(raw_result)


# Module instance - automatically discovered
module = IPBlocklistsModule()

__all__ = ['module', 'query_ipblocklists_async', 'normalize_ipblocklists_result']

