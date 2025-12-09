"""
Base module class for all investigation tools.
Each module should define its configuration and implement the query/normalize pattern.
"""
from typing import Dict, Any, Optional, Set
from abc import ABC, abstractmethod
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class InputType(Enum):
    """Supported input types for tools"""
    IP = "IP"
    DOMAIN = "Domain"
    URL = "URL"
    HASH = "Hash"
    ANY = "Any"  # Works with any type


class BaseModule(ABC):
    """
    Base class for all investigation tool modules.
    Each module should inherit from this and define its configuration.
    
    Modules are completely self-contained:
    - All configuration in config.py
    - Query logic in query.py
    - Normalization in normalizer.py
    - Module class in module.py
    """
    
    # Module metadata - must be defined by subclasses
    MODULE_NAME: str = ""
    DISPLAY_NAME: str = ""
    DESCRIPTION: str = ""
    INPUT_TYPES: Set[InputType] = set()
    REQUIRES_API_KEY: bool = False
    API_KEY_NAME: Optional[str] = None
    DATA_KEY: str = ""  # Key used in result dict (e.g., "abuseipdb", "virustotal")
    
    @abstractmethod
    async def query(self, observable: str, api_key: Optional[str] = None, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Query the tool's API/service.
        
        Args:
            observable: The observable to query
            api_key: Optional API key
            **kwargs: Additional tool-specific parameters
            
        Returns:
            Raw response data (will be normalized later)
        """
        pass
    
    @abstractmethod
    def normalize(self, raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Normalize the raw API response into a standardized format.
        
        Args:
            raw_result: Raw response from query()
            
        Returns:
            Normalized dict with consistent structure: {DATA_KEY: {...}}
        """
        pass
    
    def validate_input(self, observable: str, input_type: InputType) -> bool:
        """
        Validate if this module can process the given input.
        
        Args:
            observable: The observable to check
            input_type: The detected input type
            
        Returns:
            True if module can process this input
        """
        return InputType.ANY in self.INPUT_TYPES or input_type in self.INPUT_TYPES
    
    def get_config(self) -> Dict[str, Any]:
        """Get module configuration"""
        return {
            "name": self.MODULE_NAME,
            "display_name": self.DISPLAY_NAME,
            "description": self.DESCRIPTION,
            "input_types": [it.value for it in self.INPUT_TYPES],
            "requires_api_key": self.REQUIRES_API_KEY,
            "api_key_name": self.API_KEY_NAME,
            "data_key": self.DATA_KEY,
        }
