"""
registry.py
Builds the tool registry by combining auto-discovered PowerShell functions
with explicit metadata from manifest.json.
"""

import json
import subprocess
from pathlib import Path


def discover_tools():
    """
    Calls PowerShell to enumerate functions in the TechToolbox module.
    """
    script_path = Path(__file__).parent / "Export-ToolboxFunctions.ps1"

    result = subprocess.run(
        ["pwsh", "-File", str(script_path)],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"Tool discovery failed: {result.stderr}")

    return json.loads(result.stdout)


def load_manifest():
    """
    Loads manifest.json if present.
    """
    manifest_path = Path(__file__).parent / "manifest.json"
    if not manifest_path.exists():
        return {}
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def build_tool_registry():
    """
    Merges auto-discovered tools with manifest overrides.
    """
    discovered = {t["Name"]: t for t in discover_tools()}
    manifest = load_manifest()

    registry = {}

    for name, tool in discovered.items():
        override = manifest.get(name, {})
        registry[name] = {
            "name": name,
            "description": override.get("description") or tool.get("Synopsis") or "",
            "parameters": override.get("parameters") or tool.get("Parameters") or {},
            "module": tool.get("Module"),
            "meta": override
        }

    # Manifest-only tools
    for name, override in manifest.items():
        if name not in registry:
            registry[name] = {
                "name": name,
                "description": override.get("description", ""),
                "parameters": override.get("parameters", {}),
                "module": override.get("module", "TechToolbox"),
                "meta": override
            }

    return registry
