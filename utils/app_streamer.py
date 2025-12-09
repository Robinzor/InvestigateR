"""
Flask app result streamer implementation.
Bridges the gap between module executor and Flask app.
"""
import logging
from typing import Dict, Any
from utils.modules.interfaces import ResultStreamer

logger = logging.getLogger(__name__)


class FlaskResultStreamer(ResultStreamer):
    """
    Streams results to Flask app's processing storage.
    Implements the ResultStreamer protocol.
    """
    
    def __init__(self, app_instance):
        """
        Initialize with Flask app instance.
        
        Args:
            app_instance: Flask application instance
        """
        self.app = app_instance
    
    def stream_result(self, processing_id: str, observable: str, result: Dict[str, Any]) -> None:
        """
        Stream result to Flask app storage.
        
        Args:
            processing_id: Unique ID for this processing session
            observable: The observable being processed
            result: The result data to stream
        """
        if not hasattr(self.app, 'processing_storage'):
            logger.warning("App instance does not have processing_storage")
            return
        
        if processing_id not in self.app.processing_storage:
            logger.warning(f"Processing ID {processing_id} not found in storage")
            return
        
        storage = self.app.processing_storage[processing_id]
        existing_results = storage.get('results', [])
        
        # Update or add this result
        # Match on both observable AND type to prevent URL from being overwritten by Domain
        result_observable = result.get('observable', observable)
        result_type = result.get('type', 'Unknown')
        
        found = False
        for i, r in enumerate(existing_results):
            existing_observable = r.get('observable', '')
            existing_type = r.get('type', 'Unknown')
            # Match on both observable and type to allow same observable with different types
            if existing_observable == result_observable and existing_type == result_type:
                existing_results[i] = result
                found = True
                logger.debug(f"Updated existing result for {result_observable} (type: {result_type})")
                break
        
        if not found:
            existing_results.append(result)
            logger.debug(f"Added new result for {result_observable} (type: {result_type})")
        
        storage['results'] = existing_results
        logger.info(f"Streamed result for {observable} - {len(existing_results)} total results in storage")
        logger.debug(f"Result data keys: {list(result.get('data', {}).keys())}")

