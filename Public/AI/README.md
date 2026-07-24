# **TechToolbox AI Agent Commands**
These commands provide **local, offline PowerShell AI workflows** using a locally‑hosted LLM.  
They are designed specifically for **Dan’s personal workstation** and are **not intended for cloud use, shared environments, or production systems**.

The goal is to provide fast, private, technician-grade AI automation with:
 
- prompt-driven agent execution  
- reusable task template workflows  
- local memory-supported iteration  
- zero cloud dependency  
- AI Agent assistance for building and integrating new toolkits

All analysis is performed **entirely on the local machine**.

---

## **Available Commands**

### `Invoke-TechAgent`
Runs the local TechToolbox AI agent for natural-language task execution and guidance.

It supports:

- prompt-driven troubleshooting and task planning  
- optional model selection for local Ollama-compatible models  
- configurable iteration depth for multi-step workflows  
- always-on lightweight memory stored in `AI\memory.json` by default  
- automatic capture of recent run history plus learned preferences/facts  
- optional quiet mode for reduced console verbosity  
- optional single auto-retry on recursion-limit stop conditions  
- explicit destructive-operation confirmation when needed  
- signed-file overwrite policy control for Authenticode-signed PowerShell files  
- built-in `FETCH-URL` support for external documentation and threat-intel retrieval from approved hosts only  

When no `-Prompt` or `-PromptFile` is supplied, `Invoke-TechAgent` now defaults to:

```text
AI\Tasks\CurrentTask.txt
```

This keeps the active task prompt decoupled from the command itself while making
template-driven workflows easier to reuse.

`FETCH-URL` host allowlist is configured in `Config\config.json` under:

```json
"settings": {
	"agent": {
		"fetch": {
			"allowedHosts": [ "learn.microsoft.com", "api.github.com" ]
		}
	}
}
```

**Usage:**
```powershell
Invoke-TechAgent -Prompt "Cleanup the harddrive on localhost"

# Optional examples
Invoke-TechAgent -Prompt "Run system diagnostics and summarize findings" -Model qwen2.5-coder
Invoke-TechAgent -Prompt "Investigate repeated login failures" -MaxIterations 25 -Quiet
Invoke-TechAgent -Prompt "Investigate repeated login failures" -AutoRetryOnRecursion
Invoke-TechAgent -Prompt "Investigate repeated login failures" -DisableAutoRetryOnRecursion
Invoke-TechAgent -Prompt "Update Public/Get/Get-ToolboxHelp.ps1" -ConfirmDestructive -SignedFilePolicy strip

# Use the default active task file (AI\Tasks\CurrentTask.txt)
Invoke-TechAgent

# Explicitly point to a specific task file
Invoke-TechAgent -PromptFile AI\Tasks\CurrentTask.txt
```

**Recursion Auto-Retry Switches**

- `-AutoRetryOnRecursion` enables exactly one automatic retry when the packaged C# agent reaches an iteration limit.
- `-DisableAutoRetryOnRecursion` forces auto-retry off for the current invocation, even if enabled by environment defaults.
- Only one of these switches can be used at a time.

---

### `Use-TechAgentTaskTemplate`
Public wrapper for the TechAgent task template workflow.

It uses the template library under:

```text
AI\Tasks\Templates
```

and can:

- list available templates  
- filter by category  
- show or open a template before use  
- present an interactive picker  
- copy a selected template into `AI\Tasks\CurrentTask.txt` or another destination  

This is the easiest way to stage a structured prompt before running
`Invoke-TechAgent` with the default task file behavior.

**Usage:**
```powershell
# Pick a template interactively and copy it into AI\Tasks\CurrentTask.txt
Use-TechAgentTaskTemplate -Pick

# List only PowerShell-related templates
Use-TechAgentTaskTemplate -List -Category PowerShell

# Preview a template before copying it
Use-TechAgentTaskTemplate -Template CSharp-BugFix-InPlace -Show

# Open a template file directly
Use-TechAgentTaskTemplate -Template PowerShell-BugFix-InPlace -Open
```

Typical workflow:

```powershell
Use-TechAgentTaskTemplate -Pick
Invoke-TechAgent
```

---

## **Available Commands**

---

## **Intended Use**
These tools are meant for:

- personal development  
- code review  
- refactoring  
- learning  
- module cleanup  
- exploratory analysis  

They are **not** intended for:

- production pipelines  
- CI/CD  
- shared environments  
- cloud execution  
