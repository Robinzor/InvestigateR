"""
VirusTotal module - Malware and threat intelligence
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_virustotal_async
from .normalizer import normalize_virustotal_result

logger = logging.getLogger(__name__)


class VirusTotalModule(BaseModule):
    """
    VirusTotal investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "VirusTotal"
    DISPLAY_NAME = "VirusTotal"
    DESCRIPTION = "Malware and threat intelligence"
    INPUT_TYPES = {InputType.IP, InputType.DOMAIN, InputType.URL, InputType.HASH}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "virustotal"
    DATA_KEY = "virustotal"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query VirusTotal API"""
        input_type: Optional[InputType] = kwargs.get("input_type")
        return await query_virustotal_async(observable, api_key or "", input_type=input_type)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize VirusTotal response"""
        return normalize_virustotal_result(raw_result)


# Module instance - automatically discovered
module = VirusTotalModule()

__all__ = ['module', 'query_virustotal_async', 'normalize_virustotal_result']
