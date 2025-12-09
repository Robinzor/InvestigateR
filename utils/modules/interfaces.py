"""
Interfaces for module communication and result streaming.
This keeps modules decoupled from the application layer.
"""
from typing import Dict, Any, Protocol, Optional
from abc import ABC, abstractmethod


class ResultStreamer(Protocol):
    """
    Protocol for streaming results to the frontend.
    Modules don't need to know about Flask app instances.
    """
    
    def stream_result(self, processing_id: str, observable: str, result: Dict[str, Any]) -> None:
        """
        Stream a result update to the frontend.
        
        Args:
            processing_id: Unique ID for this processing session
            observable: The observable being processed
            result: The result data to stream
        """
        ...


class ModuleResultHandler(ABC):
    """
    Abstract base class for handling module results.
    Allows different implementations (streaming, batch, etc.)
    """
    
    @abstractmethod
    def handle_result(
        self,
        module_name: str,
        observable: str,
        result: Dict[str, Any],
        **kwargs
    ) -> None:
        """
        Handle a module result.
        
        Args:
            module_name: Name of the module that produced the result
            observable: The observable that was queried
            result: The normalized result
            **kwargs: Additional context
        """
        pass


class StreamingResultHandler(ModuleResultHandler):
    """Handler that streams results in real-time"""
    
    def __init__(self, streamer: ResultStreamer, processing_id: str, result_dict: Dict[str, Any]):
        self.streamer = streamer
        self.processing_id = processing_id
        self.result_dict = result_dict
    
    def handle_result(
        self,
        module_name: str,
        observable: str,
        result: Dict[str, Any],
        **kwargs
    ) -> None:
        """Handle result by streaming it"""
        import logging
        logger = logging.getLogger(__name__)
        
        # Update result dict
        logger.info(f"[StreamingResultHandler] Handling result from {module_name} for {observable}")
        logger.debug(f"[StreamingResultHandler] Result keys: {list(result.keys()) if result else 'None'}")
        logger.debug(f"[StreamingResultHandler] Result content: {str(result)[:500] if result else 'None'}")
        
        if not result:
            logger.warning(f"[StreamingResultHandler] No result from {module_name} for {observable}")
            return
        
        if not isinstance(result, dict):
            logger.warning(f"[StreamingResultHandler] Result from {module_name} is not a dict: {type(result)}")
            return
        
        # Update result dict
        self.result_dict["data"].update(result)
        logger.info(f"[StreamingResultHandler] Updated result_dict data keys: {list(self.result_dict.get('data', {}).keys())}")
        logger.debug(f"[StreamingResultHandler] Full result_dict: {str(self.result_dict)[:500]}")
        
        # Stream to frontend
        logger.info(f"[StreamingResultHandler] Streaming to frontend via streamer for processing_id: {self.processing_id}")
        self.streamer.stream_result(self.processing_id, observable, self.result_dict)
        logger.info(f"[StreamingResultHandler] Streamed result for {module_name} on {observable}")

