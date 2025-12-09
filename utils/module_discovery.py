"""
Automatic module discovery and registration system.
Discovers all modules in utils/modules/ and registers them automatically.
"""
import os
import importlib
import logging
from typing import Dict
from utils.modules.base import BaseModule

logger = logging.getLogger(__name__)


def discover_modules(modules_dir: str = None) -> Dict[str, BaseModule]:
    """
    Automatically discover all modules in the modules directory.
    
    Args:
        modules_dir: Path to modules directory (default: utils/modules)
        
    Returns:
        Dictionary mapping module names to module instances
    """
    if modules_dir is None:
        modules_dir = os.path.join(os.path.dirname(__file__), 'modules')
    
    discovered_modules = {}
    
    if not os.path.exists(modules_dir):
        logger.warning(f"Modules directory not found: {modules_dir}")
        return discovered_modules
    
    # Iterate through all subdirectories in modules/
    for item in os.listdir(modules_dir):
        module_path = os.path.join(modules_dir, item)
        
        # Skip if not a directory or if it's __pycache__
        if not os.path.isdir(module_path) or item.startswith('_'):
            continue
        
        # Try to import the module (now from __init__.py)
        try:
            module_name = f"utils.modules.{item}"
            module = importlib.import_module(module_name)
            
            # Get the module instance from __init__.py
            if hasattr(module, 'module') and isinstance(module.module, BaseModule):
                module_instance = module.module
                tool_name = module_instance.MODULE_NAME
                discovered_modules[tool_name] = module_instance
                logger.info(f"Discovered module: {tool_name}")
            elif hasattr(module, '__all__') and len(module.__all__) == 0:
                # Module is intentionally disabled (has empty __all__)
                logger.debug(f"Module {item} is disabled (empty __all__), skipping")
            else:
                logger.warning(f"Module {item} does not have a valid module instance in __init__.py")
        except ImportError as e:
            logger.debug(f"Could not import module {item}: {e}")
        except Exception as e:
            logger.error(f"Error loading module {item}: {e}", exc_info=True)
    
    return discovered_modules


# Note: Registration is now handled by ModuleExecutor
# This file only handles discovery

