"""
tech_agent.py
Entry point for the TechToolbox local agent.
"""

import argparse
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from langchain.agents import create_agent
from langchain_core.tools import StructuredTool
from langchain_ollama import ChatOllama


_REPO_ROOT = Path(__file__).resolve().parents[2]
_READ_MAX_BYTES = 50_000  # ~50 KB cap to avoid flooding the context window
_MEMORY_CONTEXT_MAX_CHARS = int(os.getenv("TECHTOOLBOX_MEMORY_CONTEXT_MAX_CHARS", "10000"))
_MEMORY_HISTORY_ITEMS = 8
_MEMORY_HISTORY_MAX_ITEMS = 200
_MEMORY_TEXT_PREVIEW_MAX_CHARS = int(os.getenv("TECHTOOLBOX_MEMORY_TEXT_PREVIEW_MAX_CHARS", "1400"))
_MEMORY_TREND_WINDOW_ITEMS = 30
_MEMORY_HISTORY_FILE_SUFFIX = ".history.json"
_MEMORY_FORMAT_VERSION = 2

_ASCII_MARKDOWN_INSTRUCTION = (
    "Format the final answer as plain Markdown using ASCII characters only. "
    "Do not use emoji, smart quotes, Unicode bullets, box-drawing characters, or arrow glyphs. "
    "Use '-' for bullets, '##'/'###' for headings, and '->' when an arrow is needed."
)

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


def _required_tool_params(spec) -> list[str]:
    """Return required parameter names from registry metadata when available."""
    params = spec.get("parameters") or {}
    if not isinstance(params, dict):
        return []

    required = []
    for name, meta in params.items():
        if isinstance(meta, dict) and meta.get("Mandatory"):
            required.append(str(name))

    return sorted(required)


def make_tool(name, spec, destructive_confirmed: bool = False):
    """
    Wrap a PowerShell tool so the agent can call it.
    """
    is_destructive = _is_destructive_tool(name)
    required_params = _required_tool_params(spec)

    def _func(input_str: str = ""):
        try:
            args = json.loads(input_str) if input_str.strip() else {}
        except json.JSONDecodeError:
            args = {}

        if required_params:
            missing = [param for param in required_params if param not in args or args[param] in (None, "", [])]
            if missing:
                return (
                    f"Missing required parameter(s): {', '.join(missing)}. "
                    f"Retry {name} with a JSON object that includes those fields."
                )

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


def _build_goal_prompt(prompt: str, memory_context: Optional[str] = None) -> str:
    """Bias the model toward iterative execution until completion/conclusion."""
    header = (
        "You are a local automation agent. "
        "Work step-by-step, call tools as needed, and continue iterating until the goal is completed "
        "or you can clearly justify why it cannot be completed safely. "
        "Never execute destructive actions without explicit confirmation. "
        "If confirmation is missing, stop and report exactly what confirmation is required. "
        "If blocked, explain the blocker and provide the next best action. "
        f"{_ASCII_MARKDOWN_INSTRUCTION}\n\n"
    )

    if memory_context:
        return (
            f"{header}"
            "Persistent memory context (advisory):\n"
            f"{memory_context}\n\n"
            f"Goal: {prompt}"
        )

    return f"{header}Goal: {prompt}"


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


def _normalize_ascii_markdown(text: str) -> str:
    """Normalize model output into ASCII-safe markdown for durable Windows logging."""
    if not text:
        return text

    replacements = {
        "\u2013": "-",
        "\u2014": "-",
        "\u2015": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2022": "-",
        "\u2023": "-",
        "\u2043": "-",
        "\u2212": "-",
        "\u2192": "->",
        "\u21d2": "=>",
        "\u2190": "<-",
        "\u2026": "...",
        "\u00a0": " ",
    }

    normalized = text
    for source, replacement in replacements.items():
        normalized = normalized.replace(source, replacement)

    normalized = unicodedata.normalize("NFKD", normalized)
    normalized = normalized.encode("ascii", "ignore").decode("ascii")

    cleaned_lines = []
    for line in normalized.splitlines():
        line = re.sub(r"^(#{1,6})\s+", r"\1 ", line)
        line = re.sub(r"^([*+-])\s+", r"\1 ", line)
        cleaned_lines.append(line.rstrip())

    return "\n".join(cleaned_lines).strip()


def _extract_tool_call_count(result) -> int:
    """Count assistant-issued tool calls from LangChain 1.x agent payload."""
    count = 0
    if not isinstance(result, dict):
        return count

    messages = result.get("messages")
    if not isinstance(messages, list):
        return count

    for message in messages:
        tool_calls = None
        if isinstance(message, dict):
            tool_calls = message.get("tool_calls")
            if not tool_calls:
                additional_kwargs = message.get("additional_kwargs") or {}
                if isinstance(additional_kwargs, dict):
                    tool_calls = additional_kwargs.get("tool_calls")
        else:
            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                additional_kwargs = getattr(message, "additional_kwargs", None) or {}
                if isinstance(additional_kwargs, dict):
                    tool_calls = additional_kwargs.get("tool_calls")

        if isinstance(tool_calls, list):
            count += len(tool_calls)

    return count


def _extract_tool_call_names(result) -> list[str]:
    """Collect ordered tool names invoked by the assistant during a run."""
    names = []
    seen = set()
    if not isinstance(result, dict):
        return names

    messages = result.get("messages")
    if not isinstance(messages, list):
        return names

    for message in messages:
        tool_calls = None
        if isinstance(message, dict):
            tool_calls = message.get("tool_calls")
            if not tool_calls:
                additional_kwargs = message.get("additional_kwargs") or {}
                if isinstance(additional_kwargs, dict):
                    tool_calls = additional_kwargs.get("tool_calls")
        else:
            tool_calls = getattr(message, "tool_calls", None)
            if not tool_calls:
                additional_kwargs = getattr(message, "additional_kwargs", None) or {}
                if isinstance(additional_kwargs, dict):
                    tool_calls = additional_kwargs.get("tool_calls")

        if not isinstance(tool_calls, list):
            continue

        for tool_call in tool_calls:
            name = None
            if isinstance(tool_call, dict):
                name = tool_call.get("name")
            else:
                name = getattr(tool_call, "name", None)

            if isinstance(name, str):
                normalized = name.strip()
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    names.append(normalized)

    return names


def _classify_outcome(output_text: str, status: str) -> str:
    """Classify final run outcome for memory summaries."""
    if status == "error":
        return "error"

    lower = (output_text or "").lower()
    needs_confirmation_markers = [
        "confirmation is required",
        "requires explicit confirmation",
        "requires confirmation",
        "--destructive-confirmed",
        "not authorized",
        "confirm destructive",
    ]
    blocked_markers = [
        "blocked",
        "cannot be completed",
        "cannot complete",
        "can't complete",
        "unable to complete",
        "missing",
        "not available",
    ]

    if any(marker in lower for marker in needs_confirmation_markers):
        return "needs-confirmation"
    if any(marker in lower for marker in blocked_markers):
        return "blocked"
    return "completed"


def _extract_next_step(output_text: str) -> str:
    """Best-effort extraction of the next suggested action from model output."""
    if not output_text:
        return ""

    patterns = [
        r"(?im)^next\s+best\s+action\s*:\s*(.+)$",
        r"(?im)^next\s+step\s*:\s*(.+)$",
        r"(?im)^recommended\s+next\s+step\s*:\s*(.+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, output_text)
        if match:
            return _preview_text(match.group(1), max_chars=180)

    # Fallback: capture the first imperative-style bullet/list item from the end.
    lines = [line.strip() for line in output_text.splitlines() if line.strip()]
    for line in reversed(lines):
        if re.match(r"^(-|\*|\d+\.)\s+", line):
            return _preview_text(re.sub(r"^(-|\*|\d+\.)\s+", "", line), max_chars=180)

    return ""


def _build_run_summary(prompt_text: str, output_text: str, status: str, outcome: str, tool_names: list[str]) -> dict:
    """Create compact, structured per-run memory for better multi-run chaining."""
    summary = {
        "intent": _preview_text(prompt_text, max_chars=220),
        "actionsTaken": tool_names[:12],
        "blockers": "",
        "nextBestStep": "",
    }

    if status == "error":
        summary["blockers"] = _preview_text(output_text, max_chars=220)
        return summary

    if outcome in ("blocked", "needs-confirmation"):
        summary["blockers"] = _preview_text(output_text, max_chars=220)

    summary["nextBestStep"] = _extract_next_step(output_text)
    return summary


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
            if p.is_dir():
                return (
                    f"Error: '{p}' is a directory, not a file. "
                    "Provide a full file path such as 'en-US/Search-User.help.txt'."
                )
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
        if p.exists() and p.is_dir():
            return (
                f"Error: '{p}' is a directory, not a file. "
                "Provide a full file path such as 'en-US/Search-User.help.txt'."
            )
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
    memory_context: Optional[str] = None,
    return_metadata: bool = False,
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
            "confirmation. If blocked, explain exactly what is missing and propose the next step. "
            f"{_ASCII_MARKDOWN_INSTRUCTION}"
        ),
        debug=verbose,
        name="techtoolbox-local-agent",
    )

    goal_prompt = _build_goal_prompt(prompt, memory_context=memory_context)

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
    output_text = _normalize_ascii_markdown(_extract_output(result))

    if return_metadata:
        metadata = {
            "toolCalls": _extract_tool_call_count(result),
            "toolNames": _extract_tool_call_names(result),
        }
        return output_text, metadata

    return output_text


class MemoryStore:
    def __init__(self, path):
        self.path = Path(path)
        self.history_path = self.path.with_name(f"{self.path.stem}{_MEMORY_HISTORY_FILE_SUFFIX}")
        self.data = {"preferences": {}, "facts": {}, "history": []}
        self.history = []
        self._needs_base_migration = False

        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                if loaded.get("_memoryFormatVersion") != _MEMORY_FORMAT_VERSION:
                    self._needs_base_migration = True
                self.data.update(loaded)

        legacy_history = self.data.pop("history", [])
        if isinstance(legacy_history, list):
            legacy_history = [item for item in legacy_history if isinstance(item, dict)]
        else:
            legacy_history = []

        if self.history_path.exists():
            with self.history_path.open("r", encoding="utf-8") as f:
                loaded_history = json.load(f)
            if isinstance(loaded_history, list):
                self.history = [item for item in loaded_history if isinstance(item, dict)]
        else:
            self.history = legacy_history

        self._sync_recent_history()

        if not self.path.exists() or legacy_history or self._needs_base_migration:
            self._write_base_file()
            self._needs_base_migration = False

        if not self.history_path.exists() and self.history:
            self._write_history_file()

    def _atomic_write_text(self, target_path: Path, content: str):
        target_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = target_path.with_name(
            f".{target_path.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp"
        )
        try:
            with temp_path.open("w", encoding="utf-8", newline="\n") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, target_path)
        finally:
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass

    def _sync_recent_history(self):
        self.data["history"] = self.history[-_MEMORY_HISTORY_ITEMS:]

    def _write_base_file(self):
        payload = dict(self.data)
        payload["_memoryFormatVersion"] = _MEMORY_FORMAT_VERSION
        payload["history"] = self.data.get("history", [])
        self._atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=False))

    def _write_history_file(self):
        capped_history = self.history[-_MEMORY_HISTORY_MAX_ITEMS:] if _MEMORY_HISTORY_MAX_ITEMS > 0 else self.history
        self._atomic_write_text(self.history_path, json.dumps(capped_history, indent=2, ensure_ascii=False))

    def save(self):
        self._sync_recent_history()
        self._write_base_file()

    def remember_fact(self, key, value):
        self.data["facts"][key] = value
        self.save()

    def remember_preference(self, key, value):
        self.data["preferences"][key] = value
        self.save()

    def add_history(self, entry, max_items: int = _MEMORY_HISTORY_MAX_ITEMS):
        self.history.append(entry)
        if max_items > 0 and len(self.history) > max_items:
            self.history = self.history[-max_items:]
        self._sync_recent_history()
        self._write_history_file()
        self.save()

    def update_trend_facts(self, window_items: int = _MEMORY_TREND_WINDOW_ITEMS):
        """Compute compact rolling run stats and persist them in facts."""
        history = self.history or []
        recent = history[-window_items:] if window_items > 0 else history

        run_count = len(recent)
        status_counts = {"success": 0, "error": 0}
        outcome_counts = {
            "completed": 0,
            "blocked": 0,
            "needs-confirmation": 0,
            "error": 0,
        }
        duration_values = []
        tool_call_values = []

        for item in recent:
            if not isinstance(item, dict):
                continue

            status = item.get("status")
            if status in status_counts:
                status_counts[status] += 1

            outcome = item.get("outcome")
            if outcome in outcome_counts:
                outcome_counts[outcome] += 1

            duration_ms = item.get("durationMs")
            if isinstance(duration_ms, (int, float)):
                duration_values.append(int(duration_ms))

            tool_calls = item.get("toolCalls")
            if isinstance(tool_calls, (int, float)):
                tool_call_values.append(int(tool_calls))

        avg_duration_ms = int(sum(duration_values) / len(duration_values)) if duration_values else 0
        avg_tool_calls = round(sum(tool_call_values) / len(tool_call_values), 2) if tool_call_values else 0.0
        success_rate = round((status_counts["success"] / run_count), 3) if run_count else 0.0

        last = recent[-1] if recent else {}
        trend_summary = {
            "windowItems": window_items,
            "runCount": run_count,
            "successRate": success_rate,
            "avgDurationMs": avg_duration_ms,
            "avgToolCalls": avg_tool_calls,
            "statusCounts": status_counts,
            "outcomeCounts": outcome_counts,
            "lastStatus": last.get("status") if isinstance(last, dict) else None,
            "lastOutcome": last.get("outcome") if isinstance(last, dict) else None,
            "lastModel": last.get("model") if isinstance(last, dict) else None,
            "lastRunTimestampUtc": last.get("timestampUtc") if isinstance(last, dict) else None,
            "trendLastUpdatedUtc": _utc_now_iso(),
        }

        if "facts" not in self.data or not isinstance(self.data["facts"], dict):
            self.data["facts"] = {}
        self.data["facts"]["trendSummary"] = trend_summary
        self.save()

    def to_prompt_context(
        self,
        max_chars: int = _MEMORY_CONTEXT_MAX_CHARS,
        history_items: int = _MEMORY_HISTORY_ITEMS,
    ) -> str:
        """Render compact memory text suitable for prompt prepending."""
        preferences = self.data.get("preferences") or {}
        facts = self.data.get("facts") or {}
        history = self.history or []

        lines = ["Preferences:"]
        if preferences:
            for key, value in preferences.items():
                lines.append(f"- {key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            lines.append("- (none)")

        lines.append("Facts:")
        if facts:
            for key, value in facts.items():
                lines.append(f"- {key}: {json.dumps(value, ensure_ascii=False)}")
        else:
            lines.append("- (none)")

        lines.append(f"Recent history (last {history_items}):")
        if history:
            for item in history[-history_items:]:
                if not isinstance(item, dict):
                    lines.append(f"- {json.dumps(item, ensure_ascii=False)}")
                    continue

                ts = item.get("timestampUtc") or "unknown-time"
                status = item.get("status") or "unknown-status"
                outcome = item.get("outcome") or "unknown-outcome"
                model = item.get("model") or "unknown-model"
                duration_ms = item.get("durationMs")
                tool_calls = item.get("toolCalls")
                run_summary_raw = item.get("runSummary")
                run_summary = run_summary_raw if isinstance(run_summary_raw, dict) else {}

                intent = run_summary.get("intent") or item.get("prompt") or ""
                actions = run_summary.get("actionsTaken") or []
                blockers = run_summary.get("blockers") or ""
                next_step = run_summary.get("nextBestStep") or ""

                actions_text = ", ".join(str(x) for x in actions[:8]) if isinstance(actions, list) and actions else "(none)"
                duration_text = f"{duration_ms}ms" if isinstance(duration_ms, (int, float)) else "n/a"
                tool_calls_text = str(tool_calls) if isinstance(tool_calls, (int, float)) else "n/a"

                lines.append(
                    f"- {ts} | {status}/{outcome} | model={model} | duration={duration_text} | toolCalls={tool_calls_text}"
                )
                if intent:
                    lines.append(f"  intent: {intent}")
                lines.append(f"  actions: {actions_text}")
                if blockers:
                    lines.append(f"  blockers: {blockers}")
                if next_step:
                    lines.append(f"  next: {next_step}")
        else:
            lines.append("- (none)")

        context = "\n".join(lines)
        if len(context) > max_chars:
            return context[:max_chars] + "\n[Memory context truncated]"
        return context


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _preview_text(value: str, max_chars: int = _MEMORY_TEXT_PREVIEW_MAX_CHARS) -> str:
    text = (value or "").strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "..."


def _module_access_preflight(module_root: Path) -> dict:
    """Check module-root read/write access and return a compact status object."""
    status = {
        "path": str(module_root),
        "readOk": False,
        "writeOk": False,
        "readError": None,
        "writeError": None,
    }

    try:
        if not module_root.exists():
            status["readError"] = "path does not exist"
            status["writeError"] = "path does not exist"
            return status
        if not module_root.is_dir():
            status["readError"] = "path is not a directory"
            status["writeError"] = "path is not a directory"
            return status

        # Trigger an actual directory read to catch ACL/path issues early.
        _ = next(module_root.iterdir(), None)
        status["readOk"] = True
    except OSError as exc:
        status["readError"] = str(exc)
        status["writeError"] = "read preflight failed"
        return status

    probe = module_root / f".tt_access_probe_{os.getpid()}_{int(time.time() * 1000)}.tmp"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        status["writeOk"] = True
    except OSError as exc:
        status["writeError"] = str(exc)
        try:
            if probe.exists():
                probe.unlink()
        except OSError:
            pass

    return status


def _print_preflight_status(module_root: Path) -> dict:
    """Run and print one-line module access preflight status."""
    status = _module_access_preflight(module_root)

    read_part = "ok" if status["readOk"] else f"fail ({status['readError']})"
    write_part = "ok" if status["writeOk"] else f"fail ({status['writeError']})"

    print(
        f"Preflight module access: path='{status['path']}' read={read_part} write={write_part}",
        file=sys.stderr,
    )
    return status


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
    parser.add_argument(
        "--memory-file",
        default=str(Path(__file__).resolve().parent / "memory.json"),
        help="Path to persistent memory JSON file (default: AI/Agent/memory.json).",
    )
    parser.add_argument(
        "--no-memory",
        action="store_true",
        help="Do not prepend persistent memory context to the goal prompt.",
    )
    args = parser.parse_args()

    if args.max_iterations < 1:
        raise ValueError("--max-iterations must be at least 1")

    _print_preflight_status(_REPO_ROOT)

    memory = None
    memory_context = None
    if not args.no_memory:
        try:
            memory = MemoryStore(args.memory_file)
            memory_context = memory.to_prompt_context()
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Warning: failed to load memory file '{args.memory_file}': {exc}", file=sys.stderr)

    started = time.monotonic()
    output = ""
    error = None
    run_metadata: dict[str, object] = {}
    try:
        run_result = run_agent(
            args.prompt,
            model=args.model,
            verbose=not args.quiet,
            max_iterations=args.max_iterations,
            destructive_confirmed=args.destructive_confirmed,
            memory_context=memory_context,
            return_metadata=True,
        )
        if isinstance(run_result, tuple) and len(run_result) == 2:
            output = str(run_result[0])
            metadata_obj = run_result[1]
            run_metadata = metadata_obj if isinstance(metadata_obj, dict) else {}
        else:
            output = str(run_result)
            run_metadata = {}
        print(output)
    except Exception as exc:
        error = exc
    finally:
        if memory is not None:
            duration_ms = int((time.monotonic() - started) * 1000)
            tool_calls_value = run_metadata.get("toolCalls", 0) if isinstance(run_metadata, dict) else 0
            entry = {
                "timestampUtc": _utc_now_iso(),
                "status": "error" if error else "success",
                "outcome": _classify_outcome(output, "error" if error else "success"),
                "prompt": _preview_text(args.prompt),
                "model": args.model,
                "durationMs": duration_ms,
                "maxIterations": args.max_iterations,
                "destructiveConfirmed": args.destructive_confirmed,
                "toolCalls": int(tool_calls_value) if isinstance(tool_calls_value, (int, float)) else 0,
            }
            tool_names = run_metadata.get("toolNames") if isinstance(run_metadata, dict) else []
            if not isinstance(tool_names, list):
                tool_names = []

            if error is None:
                entry["outputPreview"] = _preview_text(output)
                entry["runSummary"] = _build_run_summary(
                    args.prompt,
                    output,
                    status="success",
                    outcome=entry["outcome"],
                    tool_names=tool_names,
                )
            else:
                entry["error"] = _preview_text(str(error))
                entry["runSummary"] = _build_run_summary(
                    args.prompt,
                    str(error),
                    status="error",
                    outcome=entry["outcome"],
                    tool_names=tool_names,
                )
            try:
                memory.add_history(entry)
                memory.update_trend_facts()
            except OSError as save_exc:
                print(f"Warning: failed to update memory history: {save_exc}", file=sys.stderr)

    if error is not None:
        import traceback
        traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
        # Use sys.exit rather than re-raising so the process terminates cleanly even
        # when LangChain/Ollama leaves non-daemon threads alive in the background.
        sys.exit(1)


if __name__ == "__main__":
    main()
