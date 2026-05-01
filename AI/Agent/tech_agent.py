"""
tech_agent.py
Entry point for the TechToolbox local agent.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from langchain.agents import create_agent
from langchain_core.tools import StructuredTool
from langchain_ollama import ChatOllama


_REPO_ROOT = Path(__file__).resolve().parents[2]
_READ_MAX_BYTES = 50_000  # ~50 KB cap to avoid flooding the context window

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

if __package__ in (None, ""):
    _THIS_DIR = Path(__file__).resolve().parent
    if str(_THIS_DIR) not in sys.path:
        sys.path.insert(0, str(_THIS_DIR))
    from registry import build_tool_registry
    from ps_bridge import run_tool
else:
    from .registry import build_tool_registry
    from .ps_bridge import run_tool


def _is_destructive_tool(tool_name: str) -> bool:
    """Best-effort destructive action detection from PowerShell function names."""
    normalized = (tool_name or "").strip().lower()
    if not normalized:
        return False

    verb = normalized.split("-", 1)[0]
    if verb in DESTRUCTIVE_VERBS:
        return True

    return any(keyword in normalized for keyword in DESTRUCTIVE_NAME_KEYWORDS)


def make_tool(name, spec, destructive_confirmed: bool = False):
    """
    Wrap a PowerShell tool so the agent can call it.
    """
    is_destructive = _is_destructive_tool(name)

    def _func(input_str: str = ""):
        try:
            args = json.loads(input_str) if input_str.strip() else {}
        except json.JSONDecodeError:
            args = {}

        if is_destructive and destructive_confirmed and "__confirm_destructive" not in args:
            args["__confirm_destructive"] = True

        result = run_tool(name, args)
        if isinstance(result, str):
            return result
        return json.dumps(result, ensure_ascii=False)

    description = spec.get("description", f"PowerShell tool {name}.")
    if is_destructive:
        description = (
            f"{description} "
            "Safety policy: destructive action. Requires explicit confirmation before execution."
        )

    return StructuredTool.from_function(
        name=name,
        func=_func,
        description=description,
    )


def _build_goal_prompt(prompt: str) -> str:
    """Bias the model toward iterative execution until completion/conclusion."""
    return (
        "You are a local automation agent. "
        "Work step-by-step, call tools as needed, and continue iterating until the goal is completed "
        "or you can clearly justify why it cannot be completed safely. "
        "Never execute destructive actions without explicit confirmation. "
        "If confirmation is missing, stop and report exactly what confirmation is required. "
        "If blocked, explain the blocker and provide the next best action.\n\n"
        f"Goal: {prompt}"
    )


def _extract_output(result) -> str:
    """Extract final assistant text from LangChain 1.x agent result payload."""
    if isinstance(result, dict):
        messages = result.get("messages")
        if isinstance(messages, list) and messages:
            last_message = messages[-1]
            content = getattr(last_message, "content", None)
            if content is None and isinstance(last_message, dict):
                content = last_message.get("content")

            if isinstance(content, str):
                return content

            if isinstance(content, list):
                parts = []
                for item in content:
                    if isinstance(item, str):
                        parts.append(item)
                    elif isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str):
                            parts.append(text)
                if parts:
                    return "\n".join(parts)

    return str(result)


def _safe_path(path_str: str) -> Path:
    """Resolve path and verify it stays within the repo root (prevent path traversal)."""
    if not path_str or not path_str.strip():
        raise ValueError("path must not be empty")
    p = Path(path_str)
    if not p.is_absolute():
        p = _REPO_ROOT / p
    p = p.resolve()
    try:
        p.relative_to(_REPO_ROOT)
    except ValueError:
        raise PermissionError(
            f"Access denied: '{p}' is outside the TechToolbox workspace ({_REPO_ROOT})."
        )
    return p


def make_read_file_tool():
    """Returns a StructuredTool for reading a file within the workspace."""

    def _read(path: str) -> str:
        try:
            p = _safe_path(path)
        except (ValueError, PermissionError) as exc:
            return f"Error: {exc}"
        if not p.exists():
            return f"Error: file not found: {p}"
        if not p.is_file():
            return f"Error: '{p}' is not a file."
        size = p.stat().st_size
        if size > _READ_MAX_BYTES:
            content = p.read_bytes()[:_READ_MAX_BYTES].decode("utf-8", errors="replace")
            return f"[Content truncated to {_READ_MAX_BYTES} bytes of {size} total]\n{content}"
        return p.read_text(encoding="utf-8", errors="replace")

    return StructuredTool.from_function(
        name="read_file",
        func=_read,
        description=(
            "Read the text content of a file within the TechToolbox workspace. "
            "Accepts a path relative to the workspace root or an absolute path. "
            "Returns the file content as a string. Files larger than 50 KB are truncated."
        ),
    )


def make_write_file_tool(destructive_confirmed: bool = False):
    """Returns a StructuredTool for writing a file within the workspace."""

    def _write(path: str, content: str) -> str:
        try:
            p = _safe_path(path)
        except (ValueError, PermissionError) as exc:
            return f"Error: {exc}"
        exists = p.exists()
        if exists and not destructive_confirmed:
            return (
                f"Safety block: '{p}' already exists and overwriting is not authorized. "
                "The user must re-run with --destructive-confirmed to allow overwriting existing files."
            )
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        action = "overwritten" if exists else "created"
        return f"Success: file {action}: {p}"

    return StructuredTool.from_function(
        name="write_file",
        func=_write,
        description=(
            "Write text content to a file within the TechToolbox workspace. "
            "Requires 'path' (relative or absolute within the workspace) and 'content' (full text to write). "
            "Overwrites existing files only when the session is run with --destructive-confirmed. "
            "Always read the file first with read_file before overwriting to avoid data loss."
        ),
    )


def run_agent(
    prompt: str,
    model: str = "llama3",
    verbose: bool = True,
    max_iterations: int = 15,
    destructive_confirmed: bool = False,
):
    """
    Run the agent with the given prompt.
    """
    registry = build_tool_registry()
    if not registry:
        raise RuntimeError("No tools were discovered. Verify module import and manifest settings.")

    tools = [
        make_tool(name, spec, destructive_confirmed=destructive_confirmed)
        for name, spec in registry.items()
    ]
    tools.append(make_read_file_tool())
    tools.append(make_write_file_tool(destructive_confirmed=destructive_confirmed))

    llm = ChatOllama(model=model)

    agent = create_agent(
        model=llm,
        tools=tools,
        system_prompt=(
            "You are a local automation agent. Work step-by-step, use tools when helpful, "
            "and complete the task safely. Never execute destructive actions without explicit "
            "confirmation. If blocked, explain exactly what is missing and propose the next step."
        ),
        debug=verbose,
        name="techtoolbox-local-agent",
    )

    goal_prompt = _build_goal_prompt(prompt)

    # recursion_limit is the closest 1.x equivalent to capping tool/reasoning loops.
    recursion_limit = max(10, (max_iterations * 3) + 2)
    result = agent.invoke(
        {
            "messages": [
                {"role": "user", "content": goal_prompt}
            ]
        },
        config={"recursion_limit": recursion_limit},
    )
    return _extract_output(result)


def main():
    parser = argparse.ArgumentParser(description="Run the TechToolbox agent.")
    parser.add_argument("--prompt", required=True, help="User prompt for the agent.")
    parser.add_argument(
        "--model",
        default=os.getenv("TECHTOOLBOX_OLLAMA_MODEL", "llama3"),
        help="Ollama model name (default: TECHTOOLBOX_OLLAMA_MODEL or llama3).",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Disable verbose agent traces.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=int(os.getenv("TECHTOOLBOX_AGENT_MAX_ITERATIONS", "15")),
        help="Maximum tool-reasoning iterations before concluding (default: 15).",
    )
    parser.add_argument(
        "--destructive-confirmed",
        action="store_true",
        help="Explicitly authorize destructive operations for this run.",
    )
    args = parser.parse_args()

    if args.max_iterations < 1:
        raise ValueError("--max-iterations must be at least 1")

    output = run_agent(
        args.prompt,
        model=args.model,
        verbose=not args.quiet,
        max_iterations=args.max_iterations,
        destructive_confirmed=args.destructive_confirmed,
    )
    print(output)


if __name__ == "__main__":
    main()
