"""
registry.py
Builds the tool registry by combining auto-discovered PowerShell functions
with explicit metadata from manifest.json.
"""

import json
import subprocess
from pathlib import Path


def _module_manifest_path() -> Path:
    """Resolve the module manifest path from the repository layout."""
    return Path(__file__).resolve().parents[2] / "TechToolbox.psd1"


def _parse_json_payload(payload: str):
    """Parse JSON payload while tolerating leading/trailing noise."""
    text = (payload or "").strip()
    if not text:
        return []

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start_candidates = [i for i in (text.find("["), text.find("{")) if i != -1]
        if not start_candidates:
            raise
        start = min(start_candidates)

        end_list = text.rfind("]")
        end_obj = text.rfind("}")
        end = max(end_list, end_obj)
        if end == -1 or end <= start:
            raise

        return json.loads(text[start : end + 1])


def discover_tools():
    """
    Calls PowerShell to enumerate functions in the TechToolbox module.
    """
    script_path = Path(__file__).parent / "Export-ToolboxFunctions.ps1"
    module_manifest = _module_manifest_path()

    if not module_manifest.exists():
        raise RuntimeError(f"Module manifest not found: {module_manifest}")

    result = subprocess.run(
        [
            "pwsh",
            "-NoLogo",
            "-NonInteractive",
            "-File",
            str(script_path),
            "-ModuleName",
            str(module_manifest),
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(f"Tool discovery failed: {result.stderr}")

    discovered = _parse_json_payload(result.stdout)
    if isinstance(discovered, dict):
        return [discovered]
    return discovered


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
