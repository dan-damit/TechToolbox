"""
ps_bridge.py
Executes PowerShell functions from the TechToolbox module and returns JSON.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict


DESTRUCTIVE_VERBS = {
    "clear",
    "disable",
    "remove",
    "restart",
    "stop",
    "uninstall",
}

DESTRUCTIVE_NAME_KEYWORDS = {
    "cleanup",
    "delete",
    "destroy",
    "format",
    "purge",
    "wipe",
}


def _module_manifest_path() -> Path:
    """Resolve the module manifest path from the repository layout."""
    return Path(__file__).resolve().parents[2] / "TechToolbox.psd1"


def _is_destructive_tool(tool_name: str) -> bool:
    """Best-effort destructive action detection from PowerShell function names."""
    normalized = (tool_name or "").strip().lower()
    if not normalized:
        return False

    verb = normalized.split("-", 1)[0]
    if verb in DESTRUCTIVE_VERBS:
        return True

    return any(keyword in normalized for keyword in DESTRUCTIVE_NAME_KEYWORDS)


def _is_confirmation_value(value: Any) -> bool:
    """Accept explicit confirmation values only."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "approved", "confirm"}
    if isinstance(value, int):
        return value == 1
    return False


def _require_destructive_confirmation(tool_name: str, args: Dict[str, Any]) -> None:
    """Block destructive tool execution unless explicit confirmation is present."""
    if not _is_destructive_tool(tool_name):
        return

    if _is_confirmation_value(args.get("__confirm_destructive")):
        return

    raise PermissionError(
        "Destructive tool execution blocked. "
        f"Tool '{tool_name}' requires explicit confirmation via __confirm_destructive=true."
    )


def run_tool(tool_name: str, args: Dict[str, Any]):
    """
    Executes a PowerShell function with the given arguments.
    """
    if not tool_name or not isinstance(tool_name, str):
        raise ValueError("tool_name must be a non-empty string")

    if not isinstance(args, dict):
        raise ValueError("args must be a dictionary")

    _require_destructive_confirmation(tool_name, args)

    # Strip internal agent-control keys before splatting into PowerShell.
    invoke_args = {k: v for k, v in args.items() if not str(k).startswith("__")}

    module_manifest = _module_manifest_path()
    if not module_manifest.exists():
        raise RuntimeError(f"Module manifest not found: {module_manifest}")

    args_json = json.dumps(invoke_args)

    script = r"""
    $ToolName = $env:TT_TOOL_NAME
    $ArgsJson = $env:TT_ARGS_JSON
    $ModuleManifestPath = $env:TT_MODULE_MANIFEST_PATH

    Set-StrictMode -Version Latest

    Import-Module -Name $ModuleManifestPath -ErrorAction Stop

    $invokeArgs = @{}
    if (-not [string]::IsNullOrWhiteSpace($ArgsJson)) {
        $rawArgs = ConvertFrom-Json -InputObject $ArgsJson
        if ($rawArgs -ne $null) {
            foreach ($p in $rawArgs.PSObject.Properties) {
                $invokeArgs[$p.Name] = $p.Value
            }
        }
    }

    $result = & $ToolName @invokeArgs
    if ($null -eq $result) {
        "null"
    }
    else {
        $result | ConvertTo-Json -Depth 8 -Compress
    }
    """

    env = dict(os.environ)
    env["TT_TOOL_NAME"] = tool_name
    env["TT_ARGS_JSON"] = args_json
    env["TT_MODULE_MANIFEST_PATH"] = str(module_manifest)

    completed = subprocess.run(
        [
            "pwsh",
            "-NoLogo",
            "-NonInteractive",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        env=env,
    )

    if completed.returncode != 0:
        raise RuntimeError(f"Tool {tool_name} failed: {completed.stderr}")

    output = completed.stdout.strip()
    if not output:
        return None

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        # Return plain stdout when PowerShell emits non-JSON text.
        return output
