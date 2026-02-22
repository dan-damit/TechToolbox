# TechToolbox

A PowerShell 7+ module for day-to-day IT automation: browser profile cleanup,
remote software inventory, Purview eDiscovery workflows, EXO message trace,
battery health parsing, AAD Connect remote sync, and more.

This is a new project to fold all (okay most) of my scripts into an
enterprise-grade PowerShell module.

Recently I've added a local LLM for cloud-less AI code analysis helper. It is in
its infancy, so there is still a lot of work to do on that front, but the
groudwork has been laid.

---

## Contents

- [TechToolbox](#techtoolbox)
  - [Contents](#contents)
  - [Getting Started](#getting-started)
  - [Configuration](#configuration)
  - [Public Commands](#public-commands)
    - [Get-ToolboxHelp](#get-toolboxhelp)
    - [Clear-BrowserProfileData](#clear-browserprofiledata)
    - [Get-RemoteInstalledSoftware](#get-remoteinstalledsoftware)
    - [Invoke-PurviewPurge](#invoke-purviewpurge)
    - [Get-MessageTrace](#get-messagetrace)
    - [Get-BatteryHealth](#get-batteryhealth)
    - [Invoke-AADSyncRemote](#invoke-aadsyncremote)
    - [Get-TechToolboxConfig](#get-techtoolboxconfig)
    - [Set-PageFileSize](#set-pagefilesize)
  - [Design \& Conventions](#design--conventions)
  - [Troubleshooting](#troubleshooting)
  - [Development \& QA](#development--qa)

**There are many more Public Commands available than listed here. Please use
Get-ToolboxHelp for details on those listed here, as well as those not listed.**

---

## Getting Started

```powershell
# This module is designed for PowerShell 7
# Import module from a local path
Import-Module .\TechToolbox -Force

# See exported commands
Get-Command -Module TechToolbox | Sort-Object Name

# View help for any command
Get-ToolboxHelp Clear-BrowserProfileData -Detailed
```

> The module auto-loads functions from `Private/` (helpers) and `Public/` (exported), and caches configuration via `Get-TechToolboxConfig`.

---

## Configuration

Create `Config\config.json` and tailor to your environment. Below is a **minimal
example** with commonly used sections. Omit any you do not need; defaults will
be applied where sensible. The full config.json is located [here.](https://github.com/dan-damit/TechToolbox/blob/main/Config/config.json)

```json
{
  "paths": {
    "temp": "C:\\Temp\\TechToolbox",
    "logs": "C:\\LogsAndExports\\Logs\\TechToolbox",
    "exportDirectory": "C:\\LogsAndExports\\Exports\\TechToolbox"
  },
  "settings": {
    "defaults": {
      "promptForHostname": true,
      "promptForCredentials": true,
      "promptForDateRanges": true,
      "promptForCaseName": true,
      "promptForSearchName": true,
      "promptForKqlQuery": true
    },
    "logging": {
      "enableConsole": true,
      "enableFileLogging": false,
      "includeTimestamps": true,
      "logFileNameFormat": "TechToolbox_{yyyyMMdd}.log",
      "minimumLevel": "Info"
    },
    "dnsLogging": {
      "enabled": true,
      "autoEnableDiagnostics": true,
      "parseMode": "simple",
      "maxLogSizeMB": 50,
      "logPath": "C:\\LogsAndExports\\TechToolbox\\Logs\\DNS"
    },
    "copyDirectory": {
      "runRemote": true,
      "defaultComputerName": null,
      "logDir": "C:\\LogsAndExports\\TechToolbox\\Logs\\Robocopy",
      "retryCount": 2,
      "waitSeconds": 5,
      "copyFlags": ["/E", "/COPYALL"],
      "mirror": false
    },
    "subnetScan": {
      "pingTimeoutMs": 250,
      "tcpTimeoutMs": 500,
      "httpTimeoutMs": 1000,
      "ewmaAlpha": 0.15,
      "displayAlpha": 0.1,
      "defaultPort": 80,
      "exportCsv": true,
      "resolveNames": true,
      "httpBanner": true
    }
  }
}
```

---

## Public Commands

### Get-ToolboxHelp

A standard help function.

```powershell
Get-ToolboxHelp

# Show Effective Config switch
Get-ToolboxHelp -ShowEffectiveConfig
```

---

### Clear-BrowserProfileData

Deletes cache, cookies, and (optionally) local storage for **Chrome/Edge** profiles. Supports `-WhatIf/-Confirm`.

```powershell
# Preview cleanup for both browsers
Clear-BrowserProfileData -WhatIf

# Target Chrome only and just cache
Clear-BrowserProfileData -Browser Chrome -IncludeCache:$true -IncludeCookies:$false

# Target specific profiles, skip local storage
Clear-BrowserProfileData -Browser Edge -Profiles 'Default','Profile 2' -SkipLocalStorage
```

---

### Get-RemoteInstalledSoftware

Collects installed software from remote Windows hosts via **PSRemoting** (registry uninstall keys; optional Appx/MSIX). Exports per-host or consolidated CSV.

```powershell
# Query two servers, consolidated CSV
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated

# Include Appx packages, prompt for credentials
Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)

# Preview without writing any files
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -WhatIf
```

---

### Invoke-PurviewPurge

End-to-end **Purview HardDelete** workflow: connect, clone/create mailbox-only search, wait for completion, submit purge, optional disconnect.

```powershell
# Normal run
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName "Case-001" -SearchName "CustodianSearch-01"

# Preview purge submission
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName "Case-001" -SearchName "CustodianSearch-01" -WhatIf
```

---

### Get-MessageTrace

Runs **EXO V2** message trace by RFC822 Message-ID, shows summary and per-recipient details, and optionally exports CSVs.

```powershell
# 24-hour lookback window (defaults from config)
Get-MessageTrace -MessageId '<abc123@company.com>'

# Custom date window
Get-MessageTrace -MessageId '<abc123@company.com>' -StartDate (Get-Date).AddHours(-12) -EndDate (Get-Date)

# Auto-export to default folder
Get-MessageTrace -MessageId '<abc123@company.com>' -WhatIf
```

---

### Get-BatteryHealth

Generates `powercfg /batteryreport`, parses the **Installed batteries** table from HTML, computes health metrics, and writes JSON.

```powershell
# Use config defaults
Get-BatteryHealth

# Custom paths, preview only
Get-BatteryHealth -ReportPath 'C:\Temp\battery-report.html' -OutputJson 'C:\Temp\batteries.json' -WhatIf
```

---

### Invoke-AADSyncRemote

Remotely triggers **Azure AD Connect** (`Start-ADSyncSyncCycle`) using PSRemoting. Kerberos or credential-based.

```powershell
# Delta sync using defaults
Invoke-AADSyncRemote -ComputerName 'aadconnect01'

# Initial sync via Kerberos, preview only
Invoke-AADSyncRemote -ComputerName 'aadconnect01' -PolicyType Initial -UseKerberos -WhatIf

# HTTPS WinRM (5986) with transcript in Logs
Invoke-AADSyncRemote -ComputerName 'aadconnect01.company.com' -Port 5986 -EnableTranscript
```

---

### Get-TechToolboxConfig

Loads the configs from config.json manually if needed

```powershell
Get-TechToolboxConfig
```

---

### Set-PageFileSize

Remotely set initial and maximum sizes of the pagefile in MB.

```powershell
# Usage of defaults (grabbed from config.json)
Set-PageFileSize -ComputerName "Server01.domain.local"

# Set via parameters during script call
Set-PageFileSize -ComputerName "Server01.domain.local" -InitialSize 4096 -MaximumSize 8192 -Path "C:\pagefile.sys"
```

---

## Design & Conventions

- **Structure**: `Private/` (helpers), `Public/` (exported), `Config/` (json), `TechToolbox.psm1` (loader), `TechToolbox.psd1` (manifest).
- **One function per file** with matching names for clean auto-export.
- **Advanced Functions**: `[CmdletBinding()]`, validated parameters, `ShouldProcess` for state changes.
- **Logging**: centralized `Write-Log` using streams (`Write-Information`, `Write-Warning`, `Write-Error`) and optional file logging via config.
- **Config cache**: `Get-TechToolboxConfig` returns a cached object; add `Reset-TechToolboxConfig` if you need runtime reloads.
- **Cross-platform**: Target is Windows; Chromium paths, EXO/Purview cmdlets assume Windows/EXO contexts.

---

## Troubleshooting

- **Module import**: Ensure `TechToolbox.psd1` points to `TechToolbox.psm1` and PowerShell 7+.
- **Permissions**:
  - **Remote inventory** / **AADSync** require WinRM and appropriate rights on target hosts.
  - **Purview** workflows require eDiscovery roles and ExchangeOnlineManagement module.
- **Message trace**: V2 retention limits apply; widen the window or verify Message-ID.
- **Battery report**: `powercfg` must be present; run PowerShell as admin if report generation fails.
- **Logging to file**: Confirm `Paths.LogDirectory` exists or `EnableFileLogging` is false.

---

## Development & QA

```powershell
# Analyzer (configurable rules)
Invoke-ScriptAnalyzer -Path .\TechToolbox -Recurse -Severity Error,Warning

# Smoke tests (dry runs)
Clear-BrowserProfileData -WhatIf
Get-RemoteInstalledSoftware -ComputerName srv01 -WhatIf
Invoke-PurviewPurge -UserPrincipalName you@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf
Get-MessageTrace -MessageId '<test@company.com>' -WhatIf
Get-BatteryHealth -WhatIf
Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta -WhatIf
```

---

**Author:** Dan Damit  
**License:** Internal use  
**Version:** 0.7.0
