from .base import BaseTool, ToolResult
from .gobuster import GobusterTool
from .ffuf import FfufTool
from .feroxbuster import FeroxbusterTool
from .wfuzz import WfuzzTool
from .dirb import DirbTool
from .dirsearch import DirsearchTool

TOOL_REGISTRY = {
    "gobuster":     GobusterTool,
    "ffuf":         FfufTool,
    "feroxbuster":  FeroxbusterTool,
    "wfuzz":        WfuzzTool,
    "dirb":         DirbTool,
    "dirsearch":    DirsearchTool,
}

__all__ = [
    "BaseTool", "ToolResult",
    "GobusterTool", "FfufTool", "FeroxbusterTool", "WfuzzTool", "DirbTool",
    "DirsearchTool",
    "TOOL_REGISTRY",
]
