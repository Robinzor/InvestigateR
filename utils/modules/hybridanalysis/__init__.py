"""
Hybrid Analysis module - Malware analysis and threat intelligence
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_hybridanalysis_async
from .normalizer import normalize_hybridanalysis_result

logger = logging.getLogger(__name__)


class HybridAnalysisModule(BaseModule):
    """
    Hybrid Analysis investigation module.
    Completely self-contained - all logic in this module directory.
    """
    
    MODULE_NAME = "HybridAnalysis"
    DISPLAY_NAME = "Hybrid Analysis"
    DESCRIPTION = "Public search for malware samples, network behavior & signatures"
    # Hybrid Analysis public search supports hash/domain/IP. We exclude URL here
    # to avoid running on raw URLs (should resolve to domain/IP first).
    INPUT_TYPES = {InputType.HASH, InputType.DOMAIN, InputType.IP}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "hybridanalysis"
    DATA_KEY = "hybridanalysis"
    
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Query Hybrid Analysis API"""
        if not api_key:
            logger.warning("Hybrid Analysis requires API key")
            return None
        return await query_hybridanalysis_async(observable, api_key)
    
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize Hybrid Analysis response"""
        return normalize_hybridanalysis_result(raw_result)


# Module instance - automatically discovered
module = HybridAnalysisModule()

__all__ = ['module', 'query_hybridanalysis_async', 'normalize_hybridanalysis_result']

