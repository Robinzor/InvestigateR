"""
OpenCTI module - OpenCTI threat intelligence platform
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_opencti_async
from .normalizer import normalize_opencti_result

logger = logging.getLogger(__name__)


class OpenCTIModule(BaseModule):
    """
    OpenCTI investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "OpenCTI"
    DISPLAY_NAME = "OpenCTI"
    DESCRIPTION = "OpenCTI threat intelligence platform"
    INPUT_TYPES = {InputType.IP, InputType.DOMAIN, InputType.URL, InputType.HASH}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "opencti"
    DATA_KEY = "opencti"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query OpenCTI"""
        # Get observable type from kwargs (passed by module_executor)
        observable_type = kwargs.get('observable_type')
        input_type = kwargs.get('input_type')  # InputType enum from module_executor
        
        # If not provided, try to detect from observable string
        if not observable_type and not input_type:
            if '.' in observable and not observable.replace('.', '').replace(':', '').isdigit():
                if observable.startswith('http'):
                    observable_type = "URL"
                else:
                    observable_type = "Domain"
            elif len(observable) == 32 or len(observable) == 40 or len(observable) == 64:
                observable_type = "Hash"
            else:
                observable_type = "IP"
        elif input_type:
            # Map InputType enum to string
            type_mapping = {
                InputType.IP: "IP",
                InputType.DOMAIN: "Domain",
                InputType.URL: "URL",
                InputType.HASH: "Hash"
            }
            observable_type = type_mapping.get(input_type, "IP")
        
        return await query_opencti_async(observable, observable_type, api_key or "")
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize OpenCTI response"""
        return normalize_opencti_result(raw_result)


# Module instance - automatically discovered
module = OpenCTIModule()

__all__ = ['module', 'query_opencti_async', 'normalize_opencti_result']

