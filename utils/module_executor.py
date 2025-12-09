"""
Module executor - executes investigation modules.
Completely decoupled from application layer using interfaces.
"""
import asyncio
import logging
from typing import Dict, List, Any, Optional
from utils.modules.base import BaseModule, InputType
from utils.modules.interfaces import ModuleResultHandler
from utils.module_discovery import discover_modules

logger = logging.getLogger(__name__)


class ModuleExecutor:
    """
    Executes investigation modules.
    Works with modules through the BaseModule interface.
    Uses result handlers for different execution modes (streaming, batch, etc.)
    """
    
    def __init__(self, modules: Optional[Dict[str, BaseModule]] = None):
        """
        Initialize executor.
        
        Args:
            modules: Optional pre-discovered modules dict. If None, will auto-discover.
        """
        self.modules: Dict[str, BaseModule] = modules or {}
        if not self.modules:
            self._load_modules()
    
    def _load_modules(self):
        """Load all discovered modules"""
        self.modules = discover_modules()
        logger.info(f"Loaded {len(self.modules)} modules")
    
    def get_module(self, name: str) -> Optional[BaseModule]:
        """Get a module by name"""
        return self.modules.get(name)
    
    def get_modules_for_type(self, input_type: InputType) -> List[BaseModule]:
        """Get all modules that support a given input type"""
        return [
            module for module in self.modules.values()
            if module.validate_input("", input_type)
        ]
    
    def _get_api_key(self, module: BaseModule, api_keys: Dict[str, str]) -> Optional[str]:
        """
        Get API key for a module.
        
        Args:
            module: The module needing an API key
            api_keys: Dictionary of available API keys
            
        Returns:
            API key if available and required, None otherwise
        """
        if not module.API_KEY_NAME:
            return None
        
        api_key = api_keys.get(module.API_KEY_NAME, '').strip()
        
        if module.REQUIRES_API_KEY and not api_key:
            logger.warning(f"{module.MODULE_NAME} requires API key but none provided")
            return None
        
        return api_key if api_key else None
    
    async def execute_module(
        self,
        module_name: str,
        observable: str,
        input_type: InputType,
        api_keys: Dict[str, str],
        **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Execute a single module.
        
        Args:
            module_name: Name of the module to execute
            observable: The observable to query
            input_type: Type of the observable
            api_keys: Dictionary of API keys
            **kwargs: Module-specific parameters
            
        Returns:
            Normalized result dict or None if execution failed
        """
        module = self.get_module(module_name)
        if not module:
            logger.warning(f"Module {module_name} not found")
            return None
        
        # Validate input type
        if not module.validate_input(observable, input_type):
            logger.debug(f"Module {module_name} does not support input type {input_type.value}")
            return None
        
        # Get API key
        api_key = self._get_api_key(module, api_keys)
        if module.REQUIRES_API_KEY and api_key is None:
            return None
        
        logger.info(f"Executing {module_name} for {observable} (type: {input_type.value})")
        
        try:
            # Query and normalize
            # Pass input_type to query for modules that need it (e.g., OpenCTI)
            query_kwargs = {**kwargs, 'input_type': input_type}
            # Also pass observable_type as string for backward compatibility
            if input_type:
                type_mapping = {
                    InputType.IP: "IP",
                    InputType.DOMAIN: "Domain",
                    InputType.URL: "URL",
                    InputType.HASH: "Hash"
                }
                query_kwargs['observable_type'] = type_mapping.get(input_type, "IP")
            raw_result = await module.query(observable, api_key, **query_kwargs)
            logger.debug(f"{module_name} raw_result: {raw_result is not None}, type: {type(raw_result)}")
            if raw_result:
                logger.debug(f"{module_name} raw_result sample: {str(raw_result)[:200]}")
            normalized = module.normalize(raw_result)
            logger.info(f"{module_name} normalized result: {normalized is not None}, keys: {list(normalized.keys()) if normalized and isinstance(normalized, dict) else 'None'}")
            if normalized and isinstance(normalized, dict):
                logger.debug(f"{module_name} normalized result content: {str(normalized)[:300]}")
            return normalized
        except Exception as e:
            logger.error(f"Error executing {module_name}: {e}", exc_info=True)
            return None
    
    async def execute_modules(
        self,
        module_names: List[str],
        observable: str,
        input_type: InputType,
        api_keys: Dict[str, str],
        result_handler: Optional[ModuleResultHandler] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute multiple modules concurrently.
        
        Args:
            module_names: List of module names to execute
            observable: The observable to query
            input_type: Type of the observable
            api_keys: Dictionary of API keys
            result_handler: Optional handler for results (for streaming)
            **kwargs: Module-specific parameters
            
        Returns:
            Combined results dictionary
        """
        tasks = []
        task_module_pairs = []  # List of (task, module_name) tuples for tracking
        
        for module_name in module_names:
            task = asyncio.create_task(
                self.execute_module(module_name, observable, input_type, api_keys, **kwargs)
            )
            tasks.append(task)
            task_module_pairs.append((task, module_name))
        
        if not tasks:
            return {}
        
        if result_handler:
            # Streaming mode - process results as they complete
            return await self._execute_with_handler(tasks, task_module_pairs, observable, result_handler)
        else:
            # Batch mode - wait for all results
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return self._combine_results(results, module_names)
    
    async def _execute_with_handler(
        self,
        tasks: List[asyncio.Task],
        task_module_pairs: List[tuple],
        observable: str,
        result_handler: ModuleResultHandler
    ) -> Dict[str, Any]:
        """Execute with result handler for streaming"""
        combined = {}
        # Create a mapping from task to module name for lookup
        # Use task object directly as key (object identity)
        task_to_module = {task: module_name for task, module_name in task_module_pairs}
        
        pending = set(tasks)
        
        while pending:
            # Wait for at least one task to complete
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            
            for task in done:
                # Get module name using task object identity
                module_name = task_to_module.get(task)
                if module_name is None:
                    # Fallback: try to find by task object identity using 'is' operator
                    module_name = next((name for t, name in task_module_pairs if t is task), None)
                    if module_name is None:
                        logger.error(f"Could not identify module for completed task on observable {observable}, skipping result. This should not happen - check task_module_pairs mapping.")
                        try:
                            # Still await the task to prevent it from being left hanging
                            await task
                        except Exception:
                            pass
                        continue
                
            try:
                result = await task
                if result and isinstance(result, dict):
                    combined.update(result)
                    logger.info(f"Streaming result from {module_name} for {observable}, result keys: {list(result.keys())}")
                    result_handler.handle_result(module_name, observable, result)
                else:
                    logger.warning(f"Module {module_name} for {observable} returned no data or invalid format: {result}")
                    # Optionally, handle error for the module if it returned None or an exception
                    result_handler.handle_result(module_name, observable, {module_name.lower(): {"error": "No data returned or invalid format"}})
            except Exception as e:
                logger.error(f"Error in streaming task for module {module_name} on observable {observable}: {e}", exc_info=True)
                result_handler.handle_result(module_name, observable, {module_name.lower(): {"error": str(e)}})
        
        return combined
    
    def _combine_results(self, results: List[Any], module_names: List[str]) -> Dict[str, Any]:
        """Combine results from multiple modules"""
        combined = {}
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Module {module_names[i]} failed: {result}")
                continue
            if result and isinstance(result, dict):
                combined.update(result)
        return combined


# Global executor instance (can be replaced with custom instance)
module_executor = ModuleExecutor()
