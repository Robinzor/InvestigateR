# Module System

## Overzicht

Het module systeem is volledig modulair opgezet. Elke tool heeft zijn eigen directory met **slechts 3 bestanden**.

## Structuur

```
utils/modules/
├── base.py              # Base class voor alle modules
├── interfaces.py        # Interfaces voor decoupling
├── abuseipdb/
│   ├── __init__.py     # Module class + config
│   ├── query.py         # API query logica
│   └── normalizer.py   # Output normalisatie
└── [andere tools]/
    ├── __init__.py
    ├── query.py
    └── normalizer.py
```

## Module Bestanden

Elke module heeft precies **3 bestanden**:

1. **`__init__.py`** - Module class met configuratie
2. **`query.py`** - API query logica
3. **`normalizer.py`** - Output normalisatie

## Nieuwe Module Toevoegen

1. **Maak directory**: `utils/modules/naam_van_tool/`

2. **Maak `__init__.py`**:
```python
"""
ToolName module - Description
"""
import logging
from typing import Dict, Any, Optional
from utils.modules.base import BaseModule, InputType
from .query import query_tool_async
from .normalizer import normalize_tool_result

logger = logging.getLogger(__name__)

class ToolNameModule(BaseModule):
    MODULE_NAME = "ToolName"
    DISPLAY_NAME = "Tool Name"
    DESCRIPTION = "Tool description"
    INPUT_TYPES = {InputType.IP, InputType.DOMAIN}
    REQUIRES_API_KEY = True
    API_KEY_NAME = "toolname"
    DATA_KEY = "toolname"
    
    async def query(self, observable, api_key=None, **kwargs):
        return await query_tool_async(observable, api_key or "")
    
    def normalize(self, raw_result):
        return normalize_tool_result(raw_result)

# Module instance - automatically discovered
module = ToolNameModule()

__all__ = ['module', 'query_tool_async', 'normalize_tool_result']
```

3. **Maak `query.py`**:
```python
"""
ToolName query module - handles API communication
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

async def query_tool_async(observable: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Query the ToolName API.
    
    Returns:
        Raw response data: {"raw_data": {...}, "observable": "..."}
    """
    # API query logica
    return {"raw_data": {...}, "observable": observable}
```

4. **Maak `normalizer.py`**:
```python
"""
ToolName normalizer - standardizes output format
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def normalize_tool_result(raw_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Normalize ToolName API response.
    
    Returns:
        Normalized dict: {"toolname": {...}}
    """
    if not raw_result or "raw_data" not in raw_result:
        return {"toolname": {"error": "No data received"}}
    
    data = raw_result["raw_data"]
    return {
        "toolname": {
            # Normalized fields
        }
    }
```

De module wordt automatisch ontdekt en geregistreerd!

## Interfaces

- **BaseModule**: Basis interface voor alle modules
- **ResultStreamer**: Protocol voor result streaming
- **ModuleResultHandler**: Handler voor verschillende execution modes

## Voordelen

- ✅ Slechts 3 bestanden per module
- ✅ Volledig modulair - elke tool is zelfstandig
- ✅ Geen hardcoded dependencies
- ✅ Duidelijke scheiding van concerns
- ✅ Makkelijk uitbreidbaar
- ✅ Automatische discovery
