"""Tool adapter registry — maps tool names to their ToolAdapter subclasses."""

from typing import Any

from app.tools.base import ToolAdapter
from app.tools.chainsaw import ChainsawAdapter
from app.tools.chopchopgo import ChopChopGoAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.zircolite import ZircoliteAdapter

_REGISTRY: dict[str, type[ToolAdapter]] = {
    "zircolite": ZircoliteAdapter,
    "chainsaw": ChainsawAdapter,
    "hayabusa": HayabusaAdapter,
    "chopchopgo": ChopChopGoAdapter,
}


def get_adapter(tool_name: str, config: dict[str, Any]) -> ToolAdapter:
    """Look up and instantiate a ToolAdapter by name. Raises ValueError if unknown."""
    cls = _REGISTRY.get(tool_name.lower())
    if cls is None:
        raise ValueError(f"Unknown tool: {tool_name!r}. Available: {list(_REGISTRY)}")
    return cls(config)
