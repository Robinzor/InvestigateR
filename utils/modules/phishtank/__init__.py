"""
PhishTank module - PhishTank phishing URL database
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_phishtank_async
from .normalizer import normalize_phishtank_result

logger = logging.getLogger(__name__)


class PhishTankModule(BaseModule):
    """
    PhishTank investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "PhishTank"
    DISPLAY_NAME = "PhishTank"
    DESCRIPTION = "PhishTank phishing URL database"
    INPUT_TYPES = {InputType.URL, InputType.DOMAIN}
    REQUIRES_API_KEY = False  # PhishTank API key is optional but recommended
    API_KEY_NAME = None
    DATA_KEY = "phishtank"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query PhishTank API"""
        return await query_phishtank_async(observable)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize PhishTank response"""
        return normalize_phishtank_result(raw_result)


# Module instance - automatically discovered
module = PhishTankModule()

__all__ = ['module', 'query_phishtank_async', 'normalize_phishtank_result']

