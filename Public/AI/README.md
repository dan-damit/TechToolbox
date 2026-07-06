# **TechToolbox AI Code Analysis Commands**
These commands provide **local, offline PowerShell code analysis** using a locally‑hosted LLM.  
They are designed specifically for **Dan’s personal workstation** and are **not intended for cloud use, shared environments, or production systems**.

The goal is to provide fast, private, technician‑grade code review with:
 
- signature‑safe preprocessing  
- Markdown report generation  
- folder‑level automation  
- zero cloud dependency  
- AI Agent assistance for building and integrating new toolkits

All analysis is performed **entirely on the local machine**.

---

## **Available Commands**

### `Invoke-CodeAssistant`
Core analysis engine.  
Takes raw code text and a filename, streams analysis to the console, and generates a Markdown report in:

```
<TechToolboxModuleRoot>\CodeAnalysis
```

Used internally by all other AI commands.

---

### `Invoke-CodeAssistantFolder`
Analyzes **every `.ps1` file** in a folder (recursively).

**Usage:**
```powershell
Invoke-CodeAssistantFolder -Path (Join-Path (Get-ModuleRoot) 'Public')
```

For each file, it:

- streams analysis  
- generates a Markdown report  
- names the report after the script  

Ideal for reviewing entire modules.

---

### `Invoke-CodeAssistantWrapper`
Simple wrapper script to simplify the CLI inputs for the user

**Usage:**
```powershell
Invoke-CodeAssistantWrapper .\Path\to\your\script
```

---

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
```

**Recursion Auto-Retry Switches**

- `-AutoRetryOnRecursion` enables exactly one automatic retry when the packaged C# agent reaches an iteration limit.
- `-DisableAutoRetryOnRecursion` forces auto-retry off for the current invocation, even if enabled by environment defaults.
- Only one of these switches can be used at a time.

---

## **Local‑Only Design**
These commands are intentionally built for **local analysis only**:

- They rely on a **local LLM** (Ollama or equivalent).  
- No code is sent to cloud services.  
- No external API calls are made.  
- All artifacts are stored locally.  
- All processing happens on your hardware.

This ensures:

- privacy  
- speed  
- offline capability  
- predictable behavior  

---

## **Signature‑Safe Preprocessing**
Before analysis, scripts are automatically cleaned of:

- Authenticode signature blocks  
- PEM certificates  
- RSA keys  
- PKCS7 blobs  

This prevents the model from misinterpreting cryptographic data as code.

---

## **Output Location**
All analysis reports are saved to:

```
<TechToolboxModuleRoot>\CodeAnalysis
```

Each file is named:

```
Analysis-<ScriptName>-<Timestamp>.md
```

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
