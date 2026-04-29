"""
tech_agent.py
Entry point for the TechToolbox local agent.
"""

import argparse
import json
import os
import sys
from pathlib import Path

from langchain.agents import Tool, initialize_agent
from langchain_community.llms import Ollama


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

    def _func(input_str: str):
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

    return Tool(
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

    llm = Ollama(model=model)

    agent = initialize_agent(
        tools,
        llm,
        agent="zero-shot-react-description",
        verbose=verbose,
        max_iterations=max_iterations,
        early_stopping_method="generate",
        handle_parsing_errors=True,
    )

    goal_prompt = _build_goal_prompt(prompt)

    if hasattr(agent, "invoke"):
        result = agent.invoke({"input": goal_prompt})
        if isinstance(result, dict) and "output" in result:
            return result["output"]
        return str(result)

    return agent.run(goal_prompt)


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
