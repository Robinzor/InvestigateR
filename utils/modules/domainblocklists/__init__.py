"""
Domain Blocklists module - Multiple domain reputation blacklists
Checks domains against various threat intelligence blacklists
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_domainblocklists_async
from .normalizer import normalize_domainblocklists_result

logger = logging.getLogger(__name__)


class DomainBlocklistsModule(BaseModule):
    """
    Domain Blocklists investigation module.
    Checks if a domain is malicious according to multiple threat intelligence blacklists.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "DomainBlocklists"
    DISPLAY_NAME = "Domain Blocklists"
    DESCRIPTION = "Check if a domain is malicious according to multiple threat intelligence blacklists"
    INPUT_TYPES = {InputType.DOMAIN}
    REQUIRES_API_KEY = False
    API_KEY_NAME = None
    DATA_KEY = "domainblocklists"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Domain Blocklists"""
        return await query_domainblocklists_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Domain Blocklists response"""
        return normalize_domainblocklists_result(raw_result)


# Module instance - automatically discovered
module = DomainBlocklistsModule()

__all__ = ['module', 'query_domainblocklists_async', 'normalize_domainblocklists_result']

