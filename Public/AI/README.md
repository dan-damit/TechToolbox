# **TechToolbox AI Agent Commands**
These commands provide **PowerShell AI workflows** with a local-first default (Ollama) and optional cloud LLM support.

The goal is to provide fast, private, technician-grade AI automation with:
 
- prompt-driven agent execution  
- reusable task template workflows  
- local memory-supported iteration  
- optional cloud provider routing (OpenAI-compatible / Azure OpenAI)  
- AI Agent assistance for building and integrating new toolkits

Analysis can run locally or against a configured cloud provider, depending on `settings.agent.provider`.

---

## **Available Commands**

### `Invoke-TechAgent`
Runs the TechToolbox AI agent for natural-language task execution and guidance.

It supports:

- prompt-driven troubleshooting and task planning  
- optional model selection for local Ollama-compatible models  
- provider routing via `-Provider` (`ollama`, `openai`, `openai-compatible`, `azure-openai`)  
- optional provider endpoint/deployment/api-version controls for cloud runs  
- cloud API key retrieval from environment variable or DPAPI-encrypted config secret  
- interactive one-time bootstrap prompt to store missing cloud API key in `config.secrets.json`  
- bare `-ApiKeyEncrypted` switch to force encrypted config-based key usage  
- optional `-ApiKeyEncryptedBlob` override for direct DPAPI blob input  
- configurable iteration depth for multi-step workflows  
- execution mode control for `execute`, `plan`, and `analyze` runs  
- optional strict prompt preflight validation to block low-quality prompts  
- output contract enforcement for `markdown`, `plain-text`, or `json` final responses  
- quality profile tuning for deterministic vs exploratory responses  
- persisted run-quality telemetry (mode, output contract, profile, preflight score) in memory history and trend summaries  
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

### `Test-TechAgentProvider`
Validates provider settings used by `Invoke-TechAgent` and optionally runs a live connectivity/auth test.

It supports:

- provider-aware validation for `ollama`, `openai`, `openai-compatible`, and `azure-openai`
- model/endpoint/deployment requirement checks
- API key presence validation via environment variable or DPAPI-encrypted config secret
- optional interactive prompt to store a missing cloud API key in `config.secrets.json`
- optional `-NoNetwork` mode for safe configuration-only checks
- bare `-ApiKeyEncrypted` switch to force encrypted config-based key usage
- optional `-ApiKeyEncryptedBlob` override for direct DPAPI blob input

### `Set-TechAgentApiKey`
Sets, rotates, or clears the DPAPI-encrypted cloud API key used by TechAgent cloud providers.

It supports:

- secure input via `-ApiKey` (`SecureString`) or interactive secure prompt
- DPAPI-encrypted persistence to `settings.agent.apiKeyEncrypted` in `config.secrets.json`
- explicit key removal using `-Clear`
- no plain-text key storage on disk

**Usage:**
```powershell
# Prompt securely and store encrypted key
Set-TechAgentApiKey

# Provide SecureString directly
$secureKey = Read-Host 'Enter cloud API key' -AsSecureString
Set-TechAgentApiKey -ApiKey $secureKey -Provider openai

# Clear stored encrypted key
Set-TechAgentApiKey -Clear
```

**Usage:**
```powershell
# Validate current config only (no outbound call)
Test-TechAgentProvider -NoNetwork

# Validate and live-test Ollama + model availability
Test-TechAgentProvider -Provider ollama -Model ornith:35b

# Validate and live-test OpenAI
$env:TT_AGENT_LLM_API_KEY = '<your-key>'
Test-TechAgentProvider -Provider openai -Model gpt-4o-mini

# Validate and live-test Azure OpenAI
$env:TT_AGENT_LLM_API_KEY = '<your-key>'
Test-TechAgentProvider -Provider azure-openai -Endpoint https://your-resource.openai.azure.com -Deployment gpt-4o-mini

# Validate DPAPI-backed secret resolution without network activity
Test-TechAgentProvider -Provider openai -Model gpt-4o-mini -NoNetwork
```

### `Get-TechAgentQualitySummary`
Summarizes recent TechAgent quality telemetry from memory history.

It supports:

- configurable analysis window (`-Window`)
- recent run sampling (`-IncludeRecent`)
- structured object output for automation
- optional JSON output (`-AsJson`)

**Usage:**
```powershell
# Default 20-run summary
Get-TechAgentQualitySummary

# Wider trend view
Get-TechAgentQualitySummary -Window 50

# JSON output for pipeline ingestion
Get-TechAgentQualitySummary -Window 30 -IncludeRecent 10 -AsJson
```

### DPAPI Secret Setup
Store cloud API keys in `Config\config.secrets.json` as a DPAPI-encrypted value:

```powershell
# Generate DPAPI blob in current Windows user context
$secure = Read-Host 'Enter cloud API key' -AsSecureString
$blob = ConvertFrom-SecureString $secure

# Save this value to settings.agent.apiKeyEncrypted in Config\config.secrets.json
$blob
```

Notes:

- DPAPI blobs from `ConvertFrom-SecureString` are generally decryptable only by the same user/machine/context.
- Runtime precedence is: environment variable first, then `settings.agent.apiKeyEncrypted`.
- When `-ApiKeyEncrypted` is supplied, the command skips environment variable lookup and uses encrypted config resolution only.
- If neither source is available and session is interactive, commands can prompt once to capture and persist a DPAPI-protected key.
- Use `-DisableApiKeyPrompt` to suppress this behavior in automation.
- Use `Set-TechAgentApiKey` for explicit key rotation/removal workflows.

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
Invoke-TechAgent -Prompt "Explain repeated authentication failures" -ExecutionMode analyze
Invoke-TechAgent -Prompt "Design a remediation approach" -ExecutionMode plan
Invoke-TechAgent -Prompt "Summarize host posture" -OutputContract plain-text
Invoke-TechAgent -Prompt "Return remediation checklist as JSON" -OutputContract json
Invoke-TechAgent -Prompt "Fix AD sync issue" -StrictPromptPreflight
Invoke-TechAgent -Prompt "Draft a migration proposal" -QualityProfile creative

# Cloud examples (API key loaded from env var)
$env:TT_AGENT_LLM_API_KEY = '<your-key>'
Invoke-TechAgent -Prompt "Summarize these logs" -Provider openai -Model gpt-4o-mini
Invoke-TechAgent -Prompt "Plan migration steps" -Provider azure-openai -Endpoint https://your-resource.openai.azure.com -Deployment gpt-4o-mini

# Cloud example (API key loaded from DPAPI secret in config.secrets.json)
Invoke-TechAgent -Prompt "Summarize these logs" -Provider openai -Model gpt-4o-mini

# Use the default active task file (AI\Tasks\CurrentTask.txt)
Invoke-TechAgent

# Explicitly point to a specific task file
Invoke-TechAgent -PromptFile AI\Tasks\CurrentTask.txt
```

**Recursion Auto-Retry Switches**

- `-AutoRetryOnRecursion` enables exactly one automatic retry when the packaged C# agent reaches an iteration limit.
- `-DisableAutoRetryOnRecursion` forces auto-retry off for the current invocation, even if enabled by environment defaults.
- Only one of these switches can be used at a time.

**Execution Mode and Output Contract**

- `-ExecutionMode execute` allows tool invocation and file/system actions.
- `-ExecutionMode plan` disallows tool calls and requires a plan-style final response.
- `-ExecutionMode analyze` disallows tool calls and requires analysis/recommendations only.
- `-OutputContract markdown` allows markdown-style final answers (default).
- `-OutputContract plain-text` rejects markdown constructs in final answers.
- `-OutputContract json` requires final answers to be valid JSON object/array text.
- `-StrictPromptPreflight` blocks execution when prompt quality signals are too weak for reliable action.

**Quality Profile**

- `-QualityProfile precise` lowers randomness for deterministic troubleshooting and implementation.
- `-QualityProfile balanced` is the default profile for general-purpose work.
- `-QualityProfile creative` increases variation for brainstorming and exploratory drafting.

**Persisted Quality Telemetry**

- Each run now records `executionMode`, `outputContract`, `qualityProfile`, and prompt preflight score/counts in `AI\memory.json` and `AI\memory.history.json`.
- `trendSummary` aggregates these values so you can compare quality outcomes over recent runs.
- Default values can be set in `Config\config.json` under `settings.agent`.

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
