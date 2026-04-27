"""
TechToolbox.AI.Agent package

This package contains the local agent implementation, including:
- Tool registry (auto-discovery + manifest merge)
- PowerShell execution bridge
- Agent orchestration logic
"""

from .registry import build_tool_registry
from .ps_bridge import run_tool
from .tech_agent import run_agent

__all__ = [
    "build_tool_registry",
    "run_tool",
    "run_agent",
]
