<p align="center">
  <img src="assets/DualThemeSupportReadmeHeader.png" alt="TechToolbox" width="100%" style="max-width:900px; opacity:1;" />
</p>

<p align="center">
  <a href="https://www.powershellgallery.com/packages/TechToolbox" target="_blank">
    <img src="assets/badges/techtoolbox-version.svg" />
  </a>
  <a href="https://www.powershellgallery.com/packages/TechToolbox" target="_blank">
    <img src="assets/badges/techtoolbox-downloads.svg" />
  </a>
  <a href="https://github.com/dan-damit/TechToolbox/releases" target="_blank">
    <img src="assets/badges/techtoolbox-release.svg" />
  </a>
  <a href="https://learn.microsoft.com/powershell/scripting/install/installing-powershell" target="_blank">
    <img src="assets/badges/techtoolbox-requires.svg" />
  </a>
  <a href="https://thedamits.com/" target="_blank">
    <img src="assets/badges/powered-by-techtoolbox.svg" />
  </a>
</p>

<p align="center">
  <a href="https://github.com/dan-damit/TechToolbox/actions/workflows/update-badges.yml">
    <img src="https://github.com/dan-damit/TechToolbox/actions/workflows/update-badges.yml/badge.svg" />
  </a>
  <a href="https://github.com/dan-damit/TechToolbox/actions/workflows/publish.yml">
    <img src="https://github.com/dan-damit/TechToolbox/actions/workflows/publish.yml/badge.svg" />
  </a>
</p>

<div align="center">
  <p style="font-size:1.2em; font-weight:600; margin-top:1em;">

  ## _Modular. Worker-Driven. PowerShell Automation at Scale._

  <br>

  TechToolbox unifies practical admin tooling into a single, predictable, portable module with shared configuration, logging, worker patterns, and a clean development model. It targets real-world enterprise operations: Active Directory lifecycle, Exchange Online / Purview workflows, remote diagnostics, browser cleanup, subnet tooling, and AI-assisted automation.
  </p>
</div>

---

## Contents

- [_Modular. Worker-Driven. PowerShell Automation at Scale._](#modular-worker-driven-powershell-automation-at-scale)
- [Contents](#contents)
- [Quick Start](#quick-start)
  - [One-Liner Demos](#one-liner-demos)
- [Architecture Overview](#architecture-overview)
  - [Module Layers](#module-layers)
  - [How the Loader Works](#how-the-loader-works)
  - [Path Tokens](#path-tokens)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Configuring Secrets](#configuring-secrets)
  - [Baseline Settings (config.json)](#baseline-settings-configjson)
- [Invoke-TechAgent Prompt Example](#invoke-techagent-prompt-example)
  - [Preferred prompt workflow](#preferred-prompt-workflow)
  - [Example: stage a task, then run it](#example-stage-a-task-then-run-it)
  - [Example: Creating an Online Help Markdown File](#example-creating-an-online-help-markdown-file)
- [Command Reference](#command-reference)
  - [Active Directory \& Identity Management](#active-directory--identity-management)
  - [Exchange Online \& Compliance](#exchange-online--compliance)
  - [System Diagnostics \& Health](#system-diagnostics--health)
  - [Endpoint \& Infrastructure Operations](#endpoint--infrastructure-operations)
  - [Remote Execution \& Worker Patterns](#remote-execution--worker-patterns)
  - [Browser Cleanup](#browser-cleanup)
  - [Networking \& Connectivity](#networking--connectivity)
  - [Credential Management](#credential-management)
  - [AI-Assisted Workflows](#ai-assisted-workflows)
  - [Export \& Packaging](#export--packaging)
- [Common Workflows](#common-workflows)
  - [Browser profile cleanup](#browser-profile-cleanup)
  - [Remote software inventory](#remote-software-inventory)
  - [Purview purge flow](#purview-purge-flow)
  - [Exchange Online message trace](#exchange-online-message-trace)
  - [AAD Connect remote sync](#aad-connect-remote-sync)
- [Developer \& Contributor Guide](#developer--contributor-guide)
  - [Creating a New Command](#creating-a-new-command)
  - [Module Architecture Rules](#module-architecture-rules)
  - [Testing Conventions](#testing-conventions)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)
- [Metadata](#metadata)
  - [v0.5.0 - "AI \& Metadata Milestone"](#v050---ai--metadata-milestone)
    - [Highlights](#highlights)

## Quick Start

```powershell
# Import the module (PowerShell 7+ recommended)
Install-Module TechToolbox -Force
Import-Module TechToolbox -Force

# Browse all exported commands
Get-Command -Module TechToolbox | Sort-Object Name

# Get the built-in help catalog
Get-ToolboxHelp
Get-ToolboxHelp -List          # Commands grouped by verb
Get-ToolboxHelp Invoke-SubnetScan   # Help for one command
```

### One-Liner Demos

```powershell
Disable-User -Identity 'jdoe' -Credential (Get-Credential)
Clear-BrowserProfileData -WhatIf
Get-SystemSnapshot
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Custodian-01 -WhatIf
```

---

## Architecture Overview

TechToolbox follows a **loader-driven, one-function-per-file** pattern with deep internal helpers.

### Module Layers

```plaintext
TechToolbox/
├── TechToolbox.psd1          # Module manifest (metadata + declared exports)
├── TechToolbox.psm1          # Bootstrap/loader (runtime path resolution, dot-sourcing, export wiring)
├── Public/                   # Exported command scripts + export helper
│   ├── ActiveDirectory/      # AD lifecycle and identity operations
│   ├── AI/                   # AI assistant and agent bridge commands
│   ├── Get/                  # Read/query commands
│   ├── Invoke/               # Action/orchestration commands
│   ├── Set/                  # Configuration/change commands
│   ├── Start_Stop/           # Session/service start-stop commands
│   ├── System/               # Local system and endpoint operations
│   ├── Test/                 # Validation/diagnostic test commands
│   └── Export-ToolboxFunctions.ps1  # Canonical export discovery helper
├── Private/                  # Internal helpers (dot-sourced, not exported)
│   ├── AADSync/              # AAD Connect internals
│   ├── ActiveDirectory/      # AD internal helper functions
│   ├── AI/                   # Agent/prompt helper internals
│   ├── Browser/              # Browser cleanup internals
│   ├── Exchange/             # Exchange helper internals
│   ├── Input/                # Prompt/input utility internals
│   ├── Loader/               # Module home/bootstrap initialization
│   ├── Logging/              # Logging engine internals
│   ├── M365/                 # Microsoft 365 helper internals
│   ├── Network/              # Network helper internals
│   ├── Purview/              # Purview/compliance helper internals
│   ├── Security/             # Security helper internals
│   └── System/               # Shared system helper internals
├── Workers/                  # Remote / background task workers
├── Config/                   # Runtime configuration (config.json, secrets)
│   ├── config.json           # Base settings (git-tracked)
│   └── config.secrets.json   # Tenant secrets (git-ignored)
├── AgentRuntime/             # Packaged C# TechToolbox agent runtime for PSGallery installs
└── commands.md               # Full command catalog with examples
```

### How the Loader Works

1. **Manifest loads first** -- `TechToolbox.psd1` points to `TechToolbox.psm1` and provides module metadata/declared exports.
2. **Bootstrap establishes module state** -- `TechToolbox.psm1` sets module/home paths and resolves runtime roots without first-import home copy.
3. **Private helpers are dot-sourced** -- all `.ps1` files under `Private/` are loaded recursively into module scope.
4. **Public scripts are dot-sourced** -- all `.ps1` files under `Public/` are loaded (excluding `Export-ToolboxFunctions.ps1` in that pass).
5. **Exports are discovered and published** -- at import time, `Export-ToolboxFunctions` discovers public function names, then `Export-ModuleMember` exports those functions.
6. **Runtime init remains lazy** -- `Initialize-TechToolboxRuntime` initializes config/logging/interop/environment only when needed.

### Path Tokens

Portable path tokens replace absolute paths for roaming safety:

| Token              | Resolves To                 | Use For                                       |
| ------------------ | --------------------------- | --------------------------------------------- |
| `%TT_ModuleRoot%`  | `C:\...\TechToolbox\`       | Module-owned files (Config, Workers, Private) |
| `%TT_Home%`        | Module root by default (or override) | Operational data root (logs, exports, prompt templates, history) |
| `%TT_LogsRoot%`    | Resolved logs root          | Log file output paths                         |
| `%TT_ExportsRoot%` | Resolved exports root       | Exported reports / files                      |

---

## Configuration

All configuration flows through `Get-TechToolboxConfig`. The effective config is the deep merge of:

- `Config/config.json` -- base settings (tracked in source control)
- `Config/config.secrets.json` -- tenant-specific and sensitive overrides (git-ignored)

Keep `config.json` limited to portable defaults, placeholders, and non-sensitive behavior settings. Put any environment-specific values there only if they are safe to share across every copy of the repo.

Move anything that identifies your environment into `config.secrets.json`, including:

- Domain controllers and search bases
- Tenant identifiers and org-specific UPN suffixes
- Internal hostnames, servers, and UNC paths
- Credential-related values or other machine-specific overrides

### Environment Variables

| Variable                         | Purpose                            |
| -------------------------------- | ---------------------------------- |
| `TT_ConfigSecretsPath`           | Override the secrets file location |
| `TT_DisableConfigSecretsMerge=1` | Skip merge for troubleshooting     |

### Configuring Secrets

Use the ignored overlay for site-specific values. Start from `Config/config.secrets.example.json`, copy it to `Config/config.secrets.json`, then fill in your local values:

```json
{
  "settings": {
    "tenant": {
      "organizationName": "yourdomain.onmicrosoft.com",
      "upnSuffix": "yourdomain.local",
      "tenantId": "0000-0000-0000-0000"
    },
    "ad": {
      "domainController": "DC01.yourdomain.local",
      "searchBase": "DC=yourdomain,DC=local"
    }
  }
}
```

### Baseline Settings (config.json)

```json
{
  "schemaVersion": 1,
  "settings": {
    "defaults": {
      "promptForHostname": true,
      "promptForCredentials": true,
      "promptForDateRanges": true,
      "showProgress": true,
      "configPath": "%TT_ModuleRoot%\\Config\\config.json"
    },
    "logging": {
      "enableConsole": true,
      "enableFileLogging": true,
      "minimumLevel": "Info",
      "logPath": "%TT_LogsRoot%",
      "logFileNameFormat": "TechToolbox_{yyyyMMdd}.log"
    }
  }
}
```

---

## Invoke-TechAgent Prompt Example

### Preferred prompt workflow
- `Invoke-TechAgent` now defaults to `AI\Tasks\CurrentTask.txt` when no `-Prompt` or `-PromptFile` is supplied.
- `Use-TechAgentTaskTemplate` can stage a reusable prompt template into that file before you run the agent.
- `-Prompt` can still be used for inline prompt text, and `-PromptFile` can still target any other file when needed.

### Example: stage a task, then run it

```powershell
Use-TechAgentTaskTemplate -Pick
Invoke-TechAgent
```

### Example: Creating an Online Help Markdown File

The **TechAgent** uses a _structured JSON decision schema_ and will have an
easier time writing files when the prompt clearly specifies the required
WRITE-FILE action. A new tool has been created for the agent to use when
modifying existing files. REPLACE-IN-FILE should be preferred for localized
edits.

Use a prompt similar to the following for consistent results:

```
Read this file:
C:\repos\TechToolbox\src\TechToolbox.Agent\Agent\AgentOrchestrator.cs

Task: 
Add or improve XML documentation comments for every public type, public
constructor, and public method in this file.

Requirements:
- Modify the existing file in place at this exact path:
  C:\repos\TechToolbox\src\TechToolbox.Agent\Agent\AgentOrchestrator.cs
- Preserve all existing code and behavior.
- Only add or improve XML documentation comments.
- Prefer REPLACE-IN-FILE for localized edits to this existing file.
- Use WRITE-FILE only if a localized replacement is not practical.
- Do not stop after analysis.
- Do not summarize your plan before editing.
- Do not return a final answer until the file update has succeeded.
```

You can place that prompt directly into `AI\Tasks\CurrentTask.txt`, or use a template as a starting point:

```powershell
Use-TechAgentTaskTemplate -List -Category CSharp
Use-TechAgentTaskTemplate -Template CSharp-XmlDocs-InPlace -Show
Use-TechAgentTaskTemplate -Template CSharp-XmlDocs-InPlace
Invoke-TechAgent
```

---

## Command Reference

The full catalog is at [COMMANDS.md](https://github.com/dan-damit/TechToolbox/blob/main/COMMANDS.md). Below is a categorized summary organized by domain.

### Active Directory & Identity Management

| Function                     | Purpose                                         |
| ---------------------------- | ----------------------------------------------- |
| `Disable-User`               | Disables an AD user account (destructive)       |
| `Reset-ADPassword`           | Resets an AD user password                      |
| `New-OnPremUserFromTemplate` | Creates an on-prem user from a template         |
| `Search-User`                | Searches for AD users by criteria               |
| `Get-AllUsers`               | Enumerates all AD users (with filters)          |
| `Get-LocalAdminMembers`      | Lists members of the local Administrators group |
| `Initialize-TTWordList`      | Initializes word list for Password generator    |

### Exchange Online & Compliance

| Function                          | Purpose                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| `Get-MessageTrace`                | Traces an email message through Exchange / EOP             |
| `Invoke-PurviewPurge`             | Purges content via Purview compliance portal (destructive) |
| `Get-AuditSharedMailboxDeletions` | Audits deleted shared mailboxes                            |
| `Get-SharedMailboxPermissions`    | Lists permissions on shared mailboxes                      |
| `Get-AutodiscoverXmlInteractive`  | Interactive Autodiscover XML viewer                        |
| `Set-EmailAlias`                  | Sets or adds an email alias for a mailbox user             |
| `Set-ProxyAddress`                | Sets the proxy address (SMTP) for a mailbox user           |
| `Test-MailHeaderAuth`             | Tests email header authentication results                  |

### System Diagnostics & Health

| Function                    | Purpose                                          |
| --------------------------- | ------------------------------------------------ |
| `Get-SystemSnapshot`        | Captures key system state information            |
| `Get-ErrorEvents`           | Queries Windows Event Logs for errors            |
| `Get-BatteryHealth`         | Reads battery health / cycle count from powercfg |
| `Get-SystemUptime`          | Reports system uptime                            |
| `Get-WindowsProductKey`     | Retrieves the installed Windows product key      |
| `Get-PDQDiagLogs`           | Retrieves PDQ diagnostics logs                   |
| `Get-SystemTrustDiagnostic` | Runs a system trust diagnostic                   |

### Endpoint & Infrastructure Operations

| Function                                    | Purpose                                           |
| ------------------------------------------- | ------------------------------------------------- |
| `Invoke-SystemRepair`                       | Runs Windows system repair / SFC DISM operations  |
| `Reset-WindowsUpdateComponents`             | Resets the Windows Update stack                   |
| `Enable-NetFx3`                             | Enables the .NET Framework 3.5 feature            |
| `Set-PageFileSize`                          | Configures pagefile size (initial and maximum)    |
| `Set-OneTimeReboot`                         | Schedules a one-time reboot at a given time       |
| `Get-InstalledPrinters` / `Remove-Printers` | Manage installed printers (destructive on remove) |

### Remote Execution & Worker Patterns

| Function                                            | Purpose                                                 |
| --------------------------------------------------- | ------------------------------------------------------- |
| `Invoke-AADSyncRemote`                              | Runs an AAD Connect synchronization remotely            |
| `Invoke-SCW`                                        | Executes a remote command via Secure Credential Wrapper |
| `Start-NewPSRemoteSession` / `Stop-PSRemoteSession` | Manage PSRemoting sessions (destructive stop)           |
| `Get-RemoteInstalledSoftware`                       | Inventory software on remote computers                  |
| `Copy-Directory`                                    | Copies directory contents (robocopy wrapper)            |

### Browser Cleanup

| Function                   | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| `Clear-BrowserProfileData` | Deletes browser profile data (destructive) |
| `Invoke-DownloadsCleanup`  | Cleans the Downloads folder (destructive)  |

### Networking & Connectivity

| Function               | Purpose                                    |
| ---------------------- | ------------------------------------------ |
| `Invoke-SubnetScan`    | Scans a subnet for active hosts / services |
| `Start-DnsQueryLogger` | Starts DNS query logging for analysis      |
| `Watch-ISPConnection`  | Monitors ISP connection health over time   |

### Credential Management

| Function                          | Purpose                                                        |
| --------------------------------- | -------------------------------------------------------------- |
| `Get-DomainAdminCredential`       | Retrieves domain admin credentials from secure store           |
| `Initialize-DomainAdminCred`      | Initializes and stores domain admin credential for session use |
| `Get-CUCredentialManagerContents` | Lists entries in the Credential Manager                        |

### AI-Assisted Workflows

| Function                      | Purpose                                                                                      |
| ----------------------------- | -------------------------------------------------------------------------------------------- |
| `Invoke-CodeAssistant`        | Sends a prompt to the local code assistant                                                   |
| `Invoke-CodeAssistantFolder`  | Runs the assistant on an entire folder                                                       |
| `Invoke-CodeAssistantWrapper` | Wrapper for structured AI task execution                                                     |
| `Invoke-TechAgent`            | Orchestrates the agent-driven workflow engine (single recursion auto-retry toggle available) |

### Export & Packaging

| Function                  | Purpose                                                |
| ------------------------- | ------------------------------------------------------ |
| `Export-ToolboxFunctions` | Exports all module functions as metadata for the agent |
| `Get-ToolboxHelp`         | Displays the built-in help catalog                     |
| `Get-TechToolboxConfig`   | Retrieves or updates configuration                     |

---

## Common Workflows

### Browser profile cleanup

```powershell
Clear-BrowserProfileData -WhatIf                          # Dry run
Clear-BrowserProfileData -Browser Chrome                  # Target one browser
Clear-BrowserProfileData -Browser All -IncludeCache:$true  # Full clean
```

### Remote software inventory

```powershell
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated
Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)
```

### Purview purge flow

```powershell
# Always preview first
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf

# Execute when confirmed
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Search-001
```

### Exchange Online message trace

```powershell
Get-MessageTrace -MessageId '<abc123@company.com>'
Get-MessageTrace -MessageId '<abc123@company.com>' -StartDate (Get-Date).AddHours(-12) -EndDate (Get-Date)
```

### AAD Connect remote sync

```powershell
Invoke-AADSyncRemote -ComputerName 'aadconnect01' -PolicyType Delta
Invoke-AADSyncRemote -ComputerName 'aadconnect01' -PolicyType Initial -UseKerberos -WhatIf
```

---

## Developer & Contributor Guide

### Creating a New Command

1. Create a new `.ps1` file in `Public/<Category>/<FunctionName>.ps1`.
2. Use the standard template (see below).
3. Add the function name to `FunctionsToExport` in `TechToolbox.psd1`.
4. Run `Invoke-ScriptAnalyzer -Path .\TechToolbox -Recurse -Severity Error,Warning` to validate.
5. Test with `-WhatIf` and real data.

```powershell
<#
.SYNOPSIS
    Short description.

.DESCRIPTION
    Longer description explaining what the function does and when to use it.

.EXAMPLE
    New-MyCommand -Name 'test'
      Does something useful.

.PARAMETER Name
    Description of the Name parameter.

.INPUTS
    None. You cannot pipe objects to this cmdlet.

.OUTPUTS
    System.String (or whatever is returned).

.NOTES
    Requires: Admin rights, network access, etc.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
)

begin {}
process { Write-Host "$Name" }
end {}
```

### Module Architecture Rules

- **One function per file** -- every `.ps1` in `Public/` maps to one exported command.
- **Private helpers stay private** -- nothing in `Private/` is exported; use them only from other module functions.
- **No side effects on import** -- the `.psm1` bootstrap should not run user-facing code; lazy-init everything.
- **All paths use tokens** -- never hardcode absolute paths; resolve via `%TT_ModuleRoot%` or `%TT_Home%`.
- **Module-root first import** -- by default, first import does not stage/copy module content to a separate home path. Set `TT_Home` only when you intentionally want runtime data outside module root.
- **WhatIf support** -- every destructive function must respect `$PSCmdlet.ShouldProcess()`.

### Testing Conventions

```powershell
# Always run WhatIf before real execution
Clear-BrowserProfileData -WhatIf
Invoke-PurviewPurge -UserPrincipalName you@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf
Get-RemoteInstalledSoftware -ComputerName srv01 -WhatIf

# ScriptAnalyzer on every PR
Invoke-ScriptAnalyzer -Path .\TechToolbox -Recurse -Severity Error,Warning
```

---

## Security Notes

- **Destructive actions** -- functions marked destructive include `Disable-User`, `Clear-BrowserProfileData`, `Invoke-PurviewPurge`, `Remove-EpicorEdgeAgent`, `Remove-Printers`, `Stop-PSRemoteSession`, and others. Always use `-WhatIf` first.
- **Credentials** -- sensitive credentials are stored in secure config files (git-ignored) or the Credential Manager. Never commit secrets.
- **CredSSP / Kerberos** -- remote execution may require CredSSP delegation or Kerberos auth; configure `remoting.credSSPDelegateComputers` accordingly.

---

## Troubleshooting

| Issue                       | Resolution                                                                                                                 |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Module import fails         | Use PowerShell 7+ and `Import-Module .\TechToolbox.psd1 -Force`                                                            |
| Command not found           | Check that it is listed in `FunctionsToExport` in the manifest                                                             |
| Config errors               | Verify both `config.json` and `config.secrets.json` are valid JSON; use `TT_DisableConfigSecretsMerge=1` to isolate issues |
| Path token resolution fails | Run `Test-TTPathRoots -EnsureDirectories` to validate paths                                                                |
| Remoting failures           | Verify WinRM is running, auth method matches server config, and credentials have appropriate privileges                    |
| Purview / EXO errors        | Confirm required roles (Compliance Administrator, etc.) and Exchange Online module installed                               |
| Battery report fails        | Run elevated if `powercfg` is blocked by group policy                                                                      |
| Logging silent              | Ensure log directories exist; check `logging.enableFileLogging` setting                                                    |

---

## Metadata

- **Author:** Dan Damit
- **License:** MIT License
- **Module version:** 0.5.58
- **PowerShell requirement:** 7+ (Core)
- **Repository:** [GitHub](https://github.com/dan-damit/TechToolbox)

---

### v0.5.0 - "AI & Metadata Milestone"

#### Highlights

- AI-assisted workflow improvements (Export-ToolboxFunctions, Invoke-TechAgent enhancements)
- Full help text capture in agent metadata export
- Config system refinements and path token stabilization
- [Release Template](https://github.com/dan-damit/TechToolbox/blob/main/.github/release_template.md)
