from .base import BaseTool, ToolResult
from .gobuster import GobusterTool
from .dirsearch import DirsearchTool

TOOL_REGISTRY = {
    "gobuster":  GobusterTool,
    "dirsearch": DirsearchTool,
}

__all__ = [
    "BaseTool", "ToolResult",
    "GobusterTool", "DirsearchTool",
    "TOOL_REGISTRY",
]
