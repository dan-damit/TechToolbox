# TechToolbox

A PowerShell 7+ module for day-to-day IT automation: browser profile cleanup,
remote software inventory, Purview eDiscovery workflows, EXO message trace,
battery health parsing, AAD Connect remote sync, and more.

This is a new project to fold all (okay most) of my scripts into an
enterprise-grade PowerShell module.

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
    - [Invoke-DownloadsCleanup](#invoke-downloadscleanup)
    - [Invoke-SubnetScan](#invoke-subnetscan)
    - [Test-PathAs](#test-pathas)
    - [Copy-Directory](#copy-directory)
    - [Invoke-SystemRepair](#invoke-systemrepair)
    - [Get-WindowsActivationInfo](#get-windowsactivationinfo)
    - [Reset-WindowsUpdateComponents](#reset-windowsupdatecomponents)
    - [Set-ProxyAddress](#set-proxyaddress)
    - [New-OnPremUserFromTemplate](#new-onpremuserfromtemplate)
    - [Get-SystemSnapshot](#get-systemsnapshot)
    - [Search-User](#search-user)
    - [Disable-User](#disable-user)
    - [Remove-Printers](#remove-printers)
    - [Initialize-DomainAdminCred](#initialize-domainadmincred)
    - [Get-DomainAdminCredential](#get-domainadmincredential)
    - [Enable-NetFx3](#enable-netfx3)
    - [Initialize-TTWordList](#initialize-ttwordlist)
    - [Get-SystemUptime](#get-systemuptime)
    - [Get-AutodiscoverXmlInteractive](#get-autodiscoverxmlinteractive)
  - [Design \& Conventions](#design--conventions)
  - [Troubleshooting](#troubleshooting)
  - [Development \& QA](#development--qa)

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

### Invoke-DownloadsCleanup

Recurses through user folders and removes files older than the cutoffyear

```powershell
# Invokes downloads cleanup on a remote workstation
Invoke-DownloadsCleanup -ComputerName "Workstation01"

# Invoke locally
Invoke-DownloadsCleanup -Local -CutoffYear 2020
```

---

### Invoke-SubnetScan

This function gathers Network related details of a subnet. It can be run locally
or remote via PSRemoting.

```powershell
# Local subnet usage example
Invoke-SubnetScan -CIDR "192.168.1.0/24"

# Remote invocation example
Invoke-SubnetScan -CIDR "10.0.0.0/16" -ComputerName "RemoteHost"
```

---

### Test-PathAs

This will utilize an impersonation helper to test directory or file access
using a supplied set of credentials

```powershell
# Test share access as:
Test-PathAs -Path "\\server\share\installer.msi" -Credential $cred
```

---

### Copy-Directory

Utilizes robocopy to copy data from one dir to another

```powershell
# Auto prompting for source and destination
Copy-Directory

# Usage with params
Copy-Directory -Source "\\File01\Share\HR" -DestinationRoot "\\Mgmt01\Archive"
```

---

### Invoke-SystemRepair

A small collection of commonly used built in system repair tools. These can be
run locally with -Local switch; remote with -ComputerName.

```powershell
# Run locally
Invoke-SystemRepair -RestoreHealth -Local

# Run remote
Invoke-SystemRepair -RestoreHealth -ComputerName "Client01" -Credential (Get-Credential)
```

---

### Get-WindowsActivationInfo

This tool retrieves Windows Activation info either locally or on a remote client

```powershell
# Run locally
Get-WindowsActivationInfo

# Run Remote
Get-WindowsActivationInfo -ComputerName "RemotePC" -Credential (Get-Credential)
```

---

### Reset-WindowsUpdateComponents

A module for resetting windows update components locally or on a remote host

```powershell
# Run locally
Reset-WindowsUpdateComponents

# Reset on a remote host
Reset-WindowsUpdateComponents -ComputerName "RemotePC" -Credential (Get-Credential)
```

---

### Set-ProxyAddress

A simple tool to set SMTP: address for a user's AD Object

```powershell
# Usage:
Set-ProxyAddress -Username "jdoe" -ProxyAddress "jdoe@example.com"
```

---

### New-OnPremUserFromTemplate

Automated ADUser creation with -TemplateIdentity "user_to_copy_from" support

```powershell
# Example:
New-OnPremUserFromTemplate -TemplateIdentity "jdoe" -GivenName "John" -Surname "Smith" -DisplayName "John Smith" -TargetOU "OU=Users,DC=example,DC=com"
```

---

### Get-SystemSnapshot

Gets details about a system, local or remote, and outputs to console and exports
to CSV

```powershell
# Local and remote support
Get-SystemSnapshot -ComputerName SERVER01 -Credential (Get-Credential)
```

---

### Search-User

This grabs several values assigned to a user (input at runtime) and returns to
console

```powershell
# EXAMPLE
Search-User -Identity "user@example.com"
```

---

### Disable-User

This routine will disable -Identity <username> in on-prem AD with some other
tasks

```powershell
# Example usage
Disable-User -Identity 'jdoe' -IncludeEXO -IncludeTeams
```

---

### Remove-Printers

This tool cleans up the spooler and removes installed print queues, optional
params include driver removal and/or ports

```powershell
# Example usage
Remove-Printers -IncludePorts -IncludeDrivers -Force -AllUsers -PassThru
```

---

### Initialize-DomainAdminCred

This function will prompt for and save the domain admin credential in the
config.json. The password will be stored encrypted.

```powershell
# Example
Initialize-DomainAdminCred
```

---

### Get-DomainAdminCredential

This function will dictate how you handle the stored credential. This also
allows for the credential to be stored in a variable for use in the console
session.

```powershell
.EXAMPLE
    # Just get the cred (from memory or disk); prompt only if missing
    $cred = Get-DomainAdminCredential -PassThru
.EXAMPLE
    # Force a new prompt and persist to config.json
    $cred = Get-DomainAdminCredential -ForcePrompt -Persist -PassThru
.EXAMPLE
    # Clear stored username/password in config.json and in-memory cache
    Get-DomainAdminCredential -Clear -Confirm
```

---

### Enable-NetFx3

This tool will enable dotNET 3.5 SP1 either locally, or on a target remote
machine

```powershell
.EXAMPLE
    # Local machine, online
    Enable-NetFx3 -Validate
.EXAMPLE
    # Local machine, offline ISO mounted as D:
    Enable-NetFx3 -Source "D:\sources\sxs" -Validate
.EXAMPLE
    # Remote machine(s) with stored domain admin credential
    $cred = Get-DomainAdminCredential Enable-NetFx3 -ComputerName "PC01","PC02"
    -Credential $cred -Source "\\files\Win11\sources\sxs" -TimeoutMinutes 45
    -Validate
    # Returns per-target objects instead of a hard exit.
```

---

### Initialize-TTWordList

A simple tool to build the Password generator tool's word list

```powershell
Initialize-TTWordList
```

---

### Get-SystemUptime

Another simple tool to grab system uptime. Can be used local or remote

```powershell
# Local example
Get-SystemUptime

# Via PSRemoting (Requires WinRM enabled)
Get-SystemUptime -ComputerName "computerName" -Credential (Get-Credential)
```

---

### Get-AutodiscoverXmlInteractive

This script prompts for inputs, including the autodiscover URI, and retrieves
the content and displays it in console

```powershell
# Example
Get-AutodiscoverXmlInteractive
# No prarams
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
