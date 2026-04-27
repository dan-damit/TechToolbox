"""
tech_agent.py
Entry point for the TechToolbox local agent.
"""

import argparse
from .registry import build_tool_registry
from .ps_bridge import run_tool
from langchain.agents import Tool, initialize_agent
from langchain_community.llms import Ollama
import json


def make_tool(name, spec):
    """
    Wrap a PowerShell tool so the agent can call it.
    """
    def _func(input_str: str):
        try:
            args = json.loads(input_str) if input_str.strip() else {}
        except json.JSONDecodeError:
            args = {}
        return run_tool(name, args)

    return Tool(
        name=name,
        func=_func,
        description=spec.get("description", f"PowerShell tool {name}.")
    )


def run_agent(prompt: str):
    """
    Run the agent with the given prompt.
    """
    registry = build_tool_registry()
    tools = [make_tool(name, spec) for name, spec in registry.items()]

    llm = Ollama(model="llama3")  # swap to 70B for deep reasoning

    agent = initialize_agent(
        tools,
        llm,
        agent="zero-shot-react-description",
        verbose=True
    )

    return agent.run(prompt)


def main():
    parser = argparse.ArgumentParser(description="Run the TechToolbox agent.")
    parser.add_argument("--prompt", required=True, help="User prompt for the agent.")
    args = parser.parse_args()

    output = run_agent(args.prompt)
    print(output)


if __name__ == "__main__":
    main()
