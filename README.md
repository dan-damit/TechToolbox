# TechToolbox

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/TechToolbox.svg?style=for-the-badge&logo=powershell)](https://www.powershellgallery.com/packages/TechToolbox)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/TechToolbox.svg?style=for-the-badge&logo=powershell)](https://www.powershellgallery.com/packages/TechToolbox)
[![GitHub Release](https://img.shields.io/github/v/release/dan-damit/TechToolbox?style=for-the-badge&logo=github)](https://github.com/dan-damit/TechToolbox/releases)


#### _A PowerShell 7+ Operator Framework for Enterprise IT Automation._

TechToolbox unifies practical admin tooling into a single, predictable, portable module with shared configuration, logging, worker patterns, and a clean development model. It targets real-world enterprise operations: Active Directory lifecycle, Exchange Online / Purview workflows, remote diagnostics, browser cleanup, subnet tooling, and AI-assisted automation.

---

## Quick Start

```powershell
# Import the module (PowerShell 7+ recommended)
Import-Module .\TechToolbox.psd1 -Force

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

```
TechToolbox/
├── TechToolbox.psd1          # Module manifest (FunctionsToExport, required modules)
├── TechToolbox.psm1          # Loader / bootstrap (sources Public/*.ps1, Private/*, Config)
├── Public/                   # Exported commands (one .ps1 per function)
│   ├── AD/                   # Active Directory user lifecycle
│   ├── AI/                   # AI assistant and agent bridge
│   ├── Browser/              # Browser profile cleanup
│   ├── Compliance/           # Purview / email compliance
│   ├── Config/               # Configuration helpers
│   ├── Credential/           # Credential management (CU, domain admin)
│   ├── Diagnostics/          # System / error diagnostics
│   ├── Exchange/             # Message trace, autodiscover
│   ├── Hardware/             # Battery, product key, uptime
│   ├── Infrastructure/       # NetFx3, pagefile, reboot, printers
│   ├── Networking/           # Subnet scan, DNS logger, ISP watch
│   ├── PSRemoting/           # Session management
│   ├── Search/               # File / large file helpers
│   ├── SharedMailbox/        # Permissions, deletion audit
│   └── Workers/              # Remote worker helpers
├── Private/                  # Internal helpers (not exported)
│   ├── Config/               # Config merge logic, path resolution
│   ├── Logging/              # Console + file logging engine
│   ├── Helpers/              # Shared utility functions
│   └── Validation/           # Input validation wrappers
├── Workers/                  # Remote / background task workers
├── Config/                   # Runtime configuration (config.json, secrets)
│   ├── config.json           # Base settings (git-tracked)
│   └── config.secrets.json   # Tenant secrets (git-ignored)
├── AI/Agent/                 # Python bridge and agent tooling
└── commands.md               # Full command catalog with examples
```

### How the Loader Works

1. **Manifest loads first** -- `TechToolbox.psd1` defines `FunctionsToExport` and required module dependencies.
2. **psm1 bootstrap** -- `TechToolbox.psm1` is invoked after manifest load:
   - Resolves path tokens (`%TT_ModuleRoot%`, `%TT_Home%`) via the config system.
   - Sources all `.ps1` files from `Private/` (internal helpers).
   - Calls `Export-ModuleMember` to expose every function in `FunctionsToExport`.
3. **Config merge** -- On first use, `Get-TechToolboxConfig` deep-merges `config.json` and `config.secrets.json`, caching the result.
4. **Lazy logging init** -- The logging subsystem initializes on first log call, respecting config settings.

### Path Tokens

Portable path tokens replace absolute paths for roaming safety:

| Token | Resolves To | Use For |
|-------|-------------|---------|
| `%TT_ModuleRoot%` | `C:\...\TechToolbox\` | Module-owned files (Config, Workers, Private) |
| `%TT_Home%` | User/machine home directory | Operational data (logs, exports, temp) |
| `%TT_LogsRoot%` | Resolved logs root | Log file output paths |
| `%TT_ExportsRoot%` | Resolved exports root | Exported reports / files |

---

## Configuration

All configuration flows through `Get-TechToolboxConfig`. The effective config is the deep merge of:

- `Config/config.json` -- base settings (tracked in source control)
- `Config/config.secrets.json` -- tenant-specific and sensitive overrides (git-ignored)

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `TT_ConfigSecretsPath` | Override the secrets file location |
| `TT_DisableConfigSecretsMerge=1` | Skip merge for troubleshooting |

### Configuring Secrets

```json
{
  "settings": {
    "tenant": {
      "organizationName": "yourdomain.onmicrosoft.com",
      "upnSuffix": "yourdomain.com",
      "tenantId": "0000-0000-0000-0000"
    },
    "ad": {
      "domainController": "DC-1.yourdomain.com",
      "searchBase": "DC=yourdomain,DC=com"
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

## Command Reference

The full catalog is at [commands.md](commands.md). Below is a categorized summary organized by domain.

### Active Directory & Identity Management

| Function | Purpose |
|----------|---------|
| `Disable-User` | Disables an AD user account (destructive) |
| `Reset-ADPassword` | Resets an AD user password |
| `New-OnPremUserFromTemplate` | Creates an on-prem user from a template |
| `Search-User` | Searches for AD users by criteria |
| `Get-AllUsers` | Enumerates all AD users (with filters) |
| `Get-LocalAdminMembers` | Lists members of the local Administrators group |

### Exchange Online & Compliance

| Function | Purpose |
|----------|---------|
| `Get-MessageTrace` | Traces an email message through Exchange / EOP |
| `Invoke-PurviewPurge` | Purges content via Purview compliance portal (destructive) |
| `Get-AuditSharedMailboxDeletions` | Audits deleted shared mailboxes |
| `Get-SharedMailboxPermissions` | Lists permissions on shared mailboxes |
| `Get-AutodiscoverXmlInteractive` | Interactive Autodiscover XML viewer |
| `Set-EmailAlias` | Sets or adds an email alias for a mailbox user |
| `Set-ProxyAddress` | Sets the proxy address (SMTP) for a mailbox user |
| `Test-MailHeaderAuth` | Tests email header authentication results |

### System Diagnostics & Health

| Function | Purpose |
|----------|---------|
| `Get-SystemSnapshot` | Captures key system state information |
| `Get-ErrorEvents` | Queries Windows Event Logs for errors |
| `Get-BatteryHealth` | Reads battery health / cycle count from powercfg |
| `Get-SystemUptime` | Reports system uptime |
| `Get-WindowsProductKey` | Retrieves the installed Windows product key |
| `Get-PDQDiagLogs` | Retrieves PDQ diagnostics logs |
| `Get-SystemTrustDiagnostic` | Runs a system trust diagnostic |

### Endpoint & Infrastructure Operations

| Function | Purpose |
|----------|---------|
| `Invoke-SystemRepair` | Runs Windows system repair / SFC DISM operations |
| `Reset-WindowsUpdateComponents` | Resets the Windows Update stack |
| `Enable-NetFx3` | Enables the .NET Framework 3.5 feature |
| `Set-PageFileSize` | Configures pagefile size (initial and maximum) |
| `Set-OneTimeReboot` | Schedules a one-time reboot at a given time |
| `Get-InstalledPrinters` / `Remove-Printers` | Manage installed printers (destructive on remove) |

### Remote Execution & Worker Patterns

| Function | Purpose |
|----------|---------|
| `Invoke-AADSyncRemote` | Runs an AAD Connect synchronization remotely |
| `Invoke-SCW` | Executes a remote command via Secure Credential Wrapper |
| `Start-NewPSRemoteSession` / `Stop-PSRemoteSession` | Manage PSRemoting sessions (destructive stop) |
| `Get-RemoteInstalledSoftware` | Inventory software on remote computers |
| `Copy-Directory` | Copies directory contents (robocopy wrapper) |

### Browser Cleanup

| Function | Purpose |
|----------|---------|
| `Clear-BrowserProfileData` | Deletes browser profile data (destructive) |
| `Invoke-DownloadsCleanup` | Cleans the Downloads folder (destructive) |

### Networking & Connectivity

| Function | Purpose |
|----------|---------|
| `Invoke-SubnetScan` | Scans a subnet for active hosts / services |
| `Start-DnsQueryLogger` | Starts DNS query logging for analysis |
| `Watch-ISPConnection` | Monitors ISP connection health over time |

### Credential Management

| Function | Purpose |
|----------|---------|
| `Get-DomainAdminCredential` | Retrieves domain admin credentials from secure store |
| `Initialize-DomainAdminCred` | Initializes and stores domain admin credential for session use |
| `Get-CUCredentialManagerContents` | Lists entries in the Credential Manager |

### AI-Assisted Workflows

| Function | Purpose |
|----------|---------|
| `Invoke-CodeAssistant` | Sends a prompt to the local code assistant |
| `Invoke-CodeAssistantFolder` | Runs the assistant on an entire folder |
| `Invoke-CodeAssistantWrapper` | Wrapper for structured AI task execution |
| `Invoke-TechAgent` | Orchestrates the agent-driven workflow engine (single recursion auto-retry toggle available) |
| `Initialize-TTWordList` | Initializes the AI word list used by the agent |

### Export & Packaging

| Function | Purpose |
|----------|---------|
| `Export-ToolboxFunctions` | Exports all module functions as metadata for the agent |
| `Get-ToolboxHelp` | Displays the built-in help catalog |
| `Get-TechToolboxConfig` | Retrieves or updates configuration |

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
    #> Does something useful.

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

| Issue | Resolution |
|-------|------------|
| Module import fails | Use PowerShell 7+ and `Import-Module .\TechToolbox.psd1 -Force` |
| Command not found | Check that it is listed in `FunctionsToExport` in the manifest |
| Config errors | Verify both `config.json` and `config.secrets.json` are valid JSON; use `TT_DisableConfigSecretsMerge=1` to isolate issues |
| Path token resolution fails | Run `Test-TTPathRoots -EnsureDirectories` to validate paths |
| Remoting failures | Verify WinRM is running, auth method matches server config, and credentials have appropriate privileges |
| Purview / EXO errors | Confirm required roles (Compliance Administrator, etc.) and Exchange Online module installed |
| Battery report fails | Run elevated if `powercfg` is blocked by group policy |
| Logging silent | Ensure log directories exist; check `logging.enableFileLogging` setting |

---

## Metadata

- **Author:** Dan Damit
- **License:** MIT License
- **Module version:** 0.5.16
- **PowerShell requirement:** 7+ (Core)
- **Repository:** [GitHub](https://github.com/dan-damit/TechToolbox)

---

### v0.5.0 - "AI & Metadata Milestone"
#### Highlights
- AI-assisted workflow improvements (Export-ToolboxFunctions, Invoke-TechAgent enhancements)
- Full help text capture in agent metadata export
- Config system refinements and path token stabilization
