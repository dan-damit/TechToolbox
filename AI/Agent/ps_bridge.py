"""
ps_bridge.py
Executes PowerShell functions from the TechToolbox module and returns JSON.
"""

import json
import subprocess


def run_tool(tool_name: str, args: dict):
    """
    Executes a PowerShell function with the given arguments.
    """
    ps_args = "@{" + "; ".join(f"{k} = '{v}'" for k, v in args.items()) + "}"

    script = """
    param(
        [string]$ToolName,
        [hashtable]$Args
    )

    Import-Module TechToolbox -ErrorAction Stop

    $result = & $ToolName @Args
    $result | ConvertTo-Json -Depth 8
    """

    completed = subprocess.run(
        ["pwsh", "-NoLogo", "-NonInteractive", "-Command", script, "--", tool_name, ps_args],
        capture_output=True,
        text=True
    )

    if completed.returncode != 0:
        raise RuntimeError(f"Tool {tool_name} failed: {completed.stderr}")

    output = completed.stdout.strip()
    return json.loads(output) if output else None
