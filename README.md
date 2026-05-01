# TechToolbox

TechToolbox is a PowerShell 7 module for day-to-day enterprise IT work:
Active Directory operations, remote inventory and repair, Exchange Online and
Purview workflows, system diagnostics, browser cleanup, and subnet tooling.

This project consolidates practical admin scripts into a single, structured,
maintainable module with shared configuration, logging, and helper utilities.

The local AI assistant work is actively evolving under [Public/AI](https://github.com/dan-damit/TechToolbox/tree/main/Public/AI) and [AI/Agent](https://github.com/dan-damit/TechToolbox/tree/main/AI/Agent).

## Table Of Contents

- [TechToolbox](#techtoolbox)
  - [Table Of Contents](#table-of-contents)
  - [What You Get](#what-you-get)
  - [Quick Start](#quick-start)
  - [Configuration](#configuration)
  - [Command Reference](#command-reference)
  - [Command Discovery](#command-discovery)
  - [Common Workflows](#common-workflows)
    - [Browser profile cleanup](#browser-profile-cleanup)
    - [Remote software inventory](#remote-software-inventory)
    - [Purview purge flow](#purview-purge-flow)
    - [Exchange Online message trace](#exchange-online-message-trace)
    - [AAD Connect remote sync](#aad-connect-remote-sync)
    - [Pagefile tuning](#pagefile-tuning)
  - [Project Layout](#project-layout)
  - [Development And QA](#development-and-qa)
  - [Troubleshooting](#troubleshooting)
  - [Metadata](#metadata)

## What You Get

- Consistent advanced functions with `CmdletBinding`, validation, and `WhatIf` support where appropriate.
- Centralized configuration via `Config/config.json`.
- Centralized logging with console and optional file output.
- A loader-driven module model (`TechToolbox.psm1`) that auto-imports private and public functions.
- Worker-based patterns for heavier remote tasks.

## Quick Start

```powershell
# PowerShell 7+ recommended
Import-Module .\TechToolbox.psd1 -Force

# List exported commands
Get-Command -Module TechToolbox | Sort-Object Name

# Built-in toolbox help
Get-ToolboxHelp
Get-ToolboxHelp -ShowEffectiveConfig
```

## Configuration

Primary configuration lives at `Config/config.json`.

Start with a small baseline and expand only the sections you use:

```json
{
  "schemaVersion": 1,
  "settings": {
    "defaults": {
      "promptForHostname": true,
      "promptForCredentials": true,
      "promptForDateRanges": true,
      "showProgress": true,
      "configPath": "C:\\TechToolbox\\Config\\config.json"
    },
    "logging": {
      "enableConsole": true,
      "enableFileLogging": true,
      "minimumLevel": "Info",
      "logPath": "C:\\TechToolbox_LogsAndExports\\Logs",
      "logFileNameFormat": "TechToolbox_{yyyyMMdd}.log"
    },
    "browserCleanup": {
      "defaultBrowser": "All",
      "includeCache": true,
      "includeCookies": true,
      "skipLocalStorage": false
    },
    "remoteSoftwareInventory": {
      "throttleLimit": 32,
      "includeAppx": false,
      "consolidated": false
    },
    "aadSync": {
      "defaultPolicyType": "Delta",
      "defaultPort": 5985,
      "allowKerberos": true
    }
  }
}
```

Use `Get-TechToolboxConfig` to inspect the effective loaded settings.

## Command Reference

For a categorized command catalog with quick examples, see [commands.md](commands.md).

## Command Discovery

There are many public commands; this is the fastest way to browse them:

```powershell
Get-Command -Module TechToolbox | Sort-Object Name
```

Current exported command set includes tooling in these areas:

- Active Directory user lifecycle and search (`Search-User`, `Disable-User`, `Reset-ADPassword`, `Set-EmailAlias`, `Set-ProxyAddress`, `New-OnPremUserFromTemplate`)
- Messaging and compliance (`Get-MessageTrace`, `Invoke-PurviewPurge`, `Get-AuditSharedMailboxDeletions`, `Get-SharedMailboxPermissions`, `Test-MailHeaderAuth`)
- Endpoint and system operations (`Get-SystemSnapshot`, `Get-SystemUptime`, `Invoke-SystemRepair`, `Set-PageFileSize`, `Enable-NetFx3`, `Reset-WindowsUpdateComponents`, `Set-OneTimeReboot`)
- Network and browser tasks (`Invoke-SubnetScan`, `Start-DnsQueryLogger`, `Clear-BrowserProfileData`, `Watch-ISPConnection`)
- Remote worker utilities and helpers (`Invoke-SCW`, `Start-NewPSRemoteSession`, `Stop-PSRemoteSession`, `Test-PathAs`)
- AI-assisted workflows (`Invoke-CodeAssistant`, `Invoke-CodeAssistantFolder`, `Invoke-CodeAssistantWrapper`, `Invoke-TechAgent`)

## Common Workflows

### Browser profile cleanup

```powershell
# Preview cleanup for all supported browsers
Clear-BrowserProfileData -WhatIf

# Chrome cache only
Clear-BrowserProfileData -Browser Chrome -IncludeCache:$true -IncludeCookies:$false
```

### Remote software inventory

```powershell
# Two hosts, one consolidated export
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated

# Include Appx packages
Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)
```

### Purview purge flow

```powershell
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName "Case-001" -SearchName "CustodianSearch-01"

# Dry run
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName "Case-001" -SearchName "CustodianSearch-01" -WhatIf
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

### Pagefile tuning

```powershell
# Use config defaults
Set-PageFileSize -ComputerName 'Server01.domain.local'

# Explicit values
Set-PageFileSize -ComputerName 'Server01.domain.local' -InitialSize 4096 -MaximumSize 8192 -Path 'C:\pagefile.sys'
```

## Project Layout

- `Private/`: internal helper functions and subsystem implementations.
- `Public/`: exported commands (one function per file by convention).
- `Workers/`: task workers used by remote and background workflows.
- `Config/`: runtime and build configuration files.
- `AI/Agent/`: Python bridge and agent tooling for local AI-assisted operations.
- `TechToolbox.psm1`: module loader/bootstrap.
- `TechToolbox.psd1`: module manifest and export definition.

## Development And QA

```powershell
# ScriptAnalyzer
Invoke-ScriptAnalyzer -Path .\TechToolbox -Recurse -Severity Error,Warning

# Build/sign/package pipeline options
.\Build.ps1 -Analyze -AutoVersionPatch -ExportPublic

# Basic dry-run sanity checks
Clear-BrowserProfileData -WhatIf
Get-RemoteInstalledSoftware -ComputerName srv01 -WhatIf
Invoke-PurviewPurge -UserPrincipalName you@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf
Get-MessageTrace -MessageId '<test@company.com>' -WhatIf
Get-BatteryHealth -WhatIf
Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta -WhatIf
```

## Troubleshooting

- Import issues: ensure PowerShell 7+ and import using `Import-Module .\TechToolbox.psd1 -Force`.
- Missing command: verify the function is listed in `FunctionsToExport` in `TechToolbox.psd1`.
- Remoting failures: confirm WinRM availability, auth method, and privileges on target hosts.
- Purview/EXO issues: confirm required roles/modules and account permissions.
- Battery report issues: run elevated if `powercfg` report generation is blocked.
- Logging issues: ensure configured log directories exist and file logging is enabled.

## Metadata

- Author: Dan Damit
- License: Internal use
- Module version: 0.4.56
