# TechToolbox AI Agent

This folder contains a local Python agent that discovers and executes
PowerShell functions from the TechToolbox module through a controlled bridge.

The agent is designed to:

- Auto-discover available module functions at runtime.
- Merge discovered metadata with curated tool metadata from `manifest.json`.
- Let an Ollama-backed LLM choose and call tools iteratively.
- Enforce a confirmation gate for destructive operations.

---

## Folder Layout

- `tech_agent.py`
	- Main entrypoint and orchestration logic.
	- Builds LangChain tools from the registry.
	- Runs the loop with `zero-shot-react-description`.
	- Applies destructive-action prompt and confirmation behavior.

- `registry.py`
	- Discovers exported TechToolbox functions via PowerShell.
	- Reads `manifest.json` overrides.
	- Produces the merged tool registry.

- `ps_bridge.py`
	- Executes PowerShell tools with JSON args.
	- Imports `TechToolbox.psd1` directly from repo root.
	- Returns JSON output (or plain text fallback).
	- Blocks destructive actions unless explicitly confirmed.

- `Export-ToolboxFunctions.ps1`
	- Enumerates functions exported by the module.
	- Captures parameters and help synopsis.
	- Emits JSON used by `registry.py`.

- `manifest.json`
	- Optional metadata override/augmentation for tools.
	- Can add descriptions, categories, and parameter docs.

- `requirements.txt`
	- Python dependencies used by the agent runtime.

- `__init__.py`
	- Package exports (`build_tool_registry`, `run_tool`, `run_agent`).

---

## How It Works

1. `tech_agent.py` calls `build_tool_registry()`.
2. `registry.py` runs `Export-ToolboxFunctions.ps1` in `pwsh`.
3. Discovered tools are merged with `manifest.json` overrides.
4. Each tool is wrapped as a LangChain `Tool`.
5. Ollama model reasons over the prompt and invokes tools as needed.
6. Tool calls route through `ps_bridge.py` to PowerShell.
7. PowerShell results are serialized back to Python and returned to the agent.

---

## Safety Model

The agent treats likely-destructive operations as protected actions.

### Destructive detection

A tool is considered destructive if either is true:

- Its PowerShell verb is in this set:
	- `clear`, `disable`, `remove`, `restart`, `stop`, `uninstall`
- Its name contains one of these keywords:
	- `cleanup`, `delete`, `destroy`, `format`, `purge`, `wipe`

### Confirmation requirement

- `ps_bridge.py` blocks destructive tools unless `__confirm_destructive=true`
	is present.
- `tech_agent.py` can automatically inject that internal flag only when the
	CLI switch `--destructive-confirmed` is provided.
- Internal keys (starting with `__`) are removed before splatting into the
	PowerShell function.

If confirmation is missing, the action is rejected with a clear error.

---

## Requirements

- PowerShell 7+ (`pwsh`) available in PATH.
- TechToolbox module manifest present at repo root:
	- `TechToolbox.psd1`
- Python 3.10+ recommended.
- Ollama installed and running locally.
- A pulled Ollama model (default is `llama3`, configurable).

---

## Setup

From repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\AI\Agent\requirements.txt
```

Make sure Ollama is available and a model exists:

```powershell
ollama pull llama3
```

---

## Run The Agent

### Option 1: Run as a script

```powershell
python .\AI\Agent\tech_agent.py --prompt "Check system health and summarize findings"
```

### Option 2: Run as a module

```powershell
python -m AI.Agent.tech_agent --prompt "Run network diagnostics for localhost"
```

### Useful options

- `--model <name>`
	- Uses the specified Ollama model.
	- Default: `TECHTOOLBOX_OLLAMA_MODEL` env var, else `llama3`.

- `--max-iterations <n>`
	- Max reasoning/tool-call cycles.
	- Default: `TECHTOOLBOX_AGENT_MAX_ITERATIONS` env var, else `15`.

- `--quiet`
	- Disables verbose LangChain trace output.

- `--destructive-confirmed`
	- Explicitly permits destructive operations for that run.

Example:

```powershell
python .\AI\Agent\tech_agent.py \
	--prompt "Remove temporary artifacts from old diagnostics runs" \
	--model llama3 \
	--max-iterations 20 \
	--destructive-confirmed
```

---

## Tool Metadata (`manifest.json`)

`manifest.json` is optional but recommended for improving agent behavior.

You can:

- Override weak/missing synopsis text with better descriptions.
- Add richer parameter documentation.
- Add manifest-only tools that are not auto-discovered.

Merge rules in `registry.py`:

- Discovered tools are primary.
- Manifest fields override discovered description/parameters.
- Manifest-only entries are included as additional tools.

---

## Troubleshooting

### No tools discovered

- Verify `TechToolbox.psd1` exists in repo root.
- Ensure module imports cleanly in PowerShell:

```powershell
Import-Module .\TechToolbox.psd1 -Force
Get-Command -Module TechToolbox | Select-Object -First 10
```

### Tool discovery failed

- Run discovery script directly:

```powershell
pwsh -NoLogo -NonInteractive -File .\AI\Agent\Export-ToolboxFunctions.ps1 -ModuleName .\TechToolbox.psd1
```

- If this fails, fix module import/function export issues first.

### Tool execution failed

- Validate target function works manually in PowerShell.
- Check parameter names/types in the discovered JSON.
- Confirm the function does not require interactive prompts.

### Destructive tool blocked

- This is expected safety behavior.
- Re-run with explicit authorization:

```powershell
python .\AI\Agent\tech_agent.py --prompt "<your prompt>" --destructive-confirmed
```

### Ollama/model errors

- Confirm Ollama service is running.
- Confirm selected model is pulled and available:

```powershell
ollama list
```

---

## Developer Notes

- `run_tool()` executes PowerShell using a short in-memory command script,
	not temporary files.
- JSON parsing in `registry.py` tolerates noisy stdout around JSON payloads.
- PowerShell output that is not valid JSON is returned as plain text.
- The current agent type is `zero-shot-react-description` with
	`handle_parsing_errors=True`.

---

## Next Improvements (Suggested)

- Add allow/deny lists for tool exposure by category.
- Add per-tool timeout/retry settings in `manifest.json`.
- Add structured audit logging for tool calls and arguments.
- Add integration tests for discovery, safety gates, and bridge I/O.
