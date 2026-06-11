# **TechToolbox**  
*A PowerShell 7+ Operator Framework for Enterprise IT Automation*

TechToolbox is a modular, configuration‑driven PowerShell framework for real‑world enterprise operations:  
Active Directory lifecycle, Exchange Online and Purview workflows, remote diagnostics, browser cleanup, subnet tooling, and AI‑assisted automation.

It unifies practical admin tooling into a single, predictable, portable module with shared configuration, logging, worker patterns, and a clean development model.

The local AI assistant and agent system is actively evolving under:  
- **[Public/AI](https://github.com/dan-damit/TechToolbox/tree/main/Public/AI)**  
- **[AI/Agent](https://github.com/dan-damit/TechToolbox/tree/main/AI/Agent)**

---

# **Why TechToolbox?**

TechToolbox exists to solve the problems every IT team eventually hits:

- Scripts scattered across machines  
- Inconsistent logging and error handling  
- Hardcoded paths and environment assumptions  
- Repeated boilerplate for remoting, credentials, and configuration  
- No unified way to run heavier remote tasks  
- No safe way to integrate AI into operational workflows  

TechToolbox provides:

- **A consistent function model** (`CmdletBinding`, validation, WhatIf)  
- **Centralized configuration** with secrets merging  
- **Portable path tokens** for roaming environments  
- **A structured module loader** with automatic import  
- **A worker-based execution model** for remote and long‑running tasks  
- **A unified logging subsystem** (console + file)  
- **AI-assisted workflows** for code, refactoring, and operator tasks  
- **A predictable, maintainable folder structure**  

This is not a script dump — it's an operator framework.

---

# **5‑Minute Demo**

```powershell
# Disable an AD user account
Disable-User -Identity 'jdoe' -Credential (Get-Credential)

# Purge a custodian mailbox
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Custodian-01

# Remote software inventory
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated

# Browser cleanup preview
Clear-BrowserProfileData -WhatIf

# Quick system snapshot
Get-SystemSnapshot
```

---

# **What You Get**

- Advanced functions with `CmdletBinding`, validation, and `WhatIf` support  
- Centralized configuration (`Config/config.json` + secrets merge)  
- Portable path tokens for roaming environments  
- Unified logging (console + optional file output)  
- Worker-based patterns for remote and background tasks  
- A loader-driven module model (`TechToolbox.psm1`)  
- AI-assisted workflows for code and operator automation  
- A clean, predictable folder structure  

---

# **Quick Start**

```powershell
# PowerShell 7+ recommended
Import-Module .\TechToolbox.psd1 -Force

# Browse exported commands
Get-Command -Module TechToolbox | Sort-Object Name

# Built-in toolbox help
Get-ToolboxHelp
Get-ToolboxHelp -ShowEffectiveConfig
```

---

# **Configuration**

Primary configuration lives in:

```
Config/config.json
```

Tenant‑specific or sensitive values belong in:

```
Config/config.secrets.json
```

(secrets file is gitignored)

At module load, `Get-TechToolboxConfig` deep‑merges:

- `settings`  
- `paths`  

from `config.secrets.json` into `config.json`.

### **Example secrets override**

```json
{
  "settings": {
    "tenant": {
      "organizationName": "yourdomain.onmicrosoft.com",
      "upnSuffix": "yourdomain.com",
      "tenantId": "00000000-0000-0000-0000-000000000000"
    },
    "ad": {
      "domainController": "DC-1.yourdomain.com",
      "searchBase": "DC=yourdomain,DC=com"
    },
    "remoting": {
      "credSSPDelegateComputers": "*.yourdomain.com"
    },
    "secureCom": {
      "server": "PC01.yourdomain.com"
    }
  }
}
```

### **Environment Controls**

- `TT_ConfigSecretsPath` — override secrets file path  
- `TT_DisableConfigSecretsMerge=1` — disable merge for troubleshooting  

---

## **Portable Path Tokens**

Use tokens instead of absolute paths for portability:

- `%TT_ModuleRoot%` — module-owned files (Config, Workers, Private, AI)  
- `%TT_Home%` — machine/user-specific operational data  
- `%TT_LogsRoot%` — resolved logs root  
- `%TT_ExportsRoot%` — resolved exports root  

### Example

```json
{
  "settings": {
    "workerPath": {
      "default": "%TT_ModuleRoot%\\Workers"
    },
    "logging": {
      "logPath": "%TT_Home%\\LogsAndExports\\Logs"
    }
  }
}
```

### Baseline config

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

Inspect effective settings:

```powershell
Get-TechToolboxConfig
```

Path troubleshooting:

```powershell
Test-TTPathRoots
Test-TTPathRoots -EnsureDirectories
```

---

# **AI-Assisted Workflows**

TechToolbox includes local AI helpers for:

- Code generation and refactoring  
- Folder-wide transformations  
- Operator task automation  
- Agent-driven workflows via Python bridge  

Commands include:

- `Invoke-CodeAssistant`  
- `Invoke-CodeAssistantFolder`  
- `Invoke-CodeAssistantWrapper`  
- `Invoke-TechAgent`  

This subsystem is evolving rapidly.

---

# **Command Reference**

- A categorized catalog with examples is available in: [commands.md](https://github.com/dan-damit/TechToolbox/blob/main/commands.md)

---

# **Command Discovery**

```powershell
Get-Command -Module TechToolbox | Sort-Object Name
```

### Categories

- **Identity & Directory**  
  `Search-User`, `Disable-User`, `Reset-ADPassword`, `New-OnPremUserFromTemplate`

- **Messaging & Compliance**  
  `Get-MessageTrace`, `Invoke-PurviewPurge`, `Get-AuditSharedMailboxDeletions`

- **Endpoint & OS**  
  `Get-ErrorEvents`, `Get-SystemSnapshot`, `Invoke-SystemRepair`, `Set-PageFileSize`

- **Network & Browser**  
  `Invoke-SubnetScan`, `Clear-BrowserProfileData`, `Watch-ISPConnection`

- **Remote Execution & Workers**  
  `Invoke-SCW`, `Start-NewPSRemoteSession`, `Test-PathAs`

- **AI & Automation**  
  `Invoke-CodeAssistant`, `Invoke-TechAgent`

---

# **Common Workflows**

## Browser profile cleanup

```powershell
Clear-BrowserProfileData -WhatIf
Clear-BrowserProfileData -Browser Chrome -IncludeCache:$true -IncludeCookies:$false
```

## Remote software inventory

```powershell
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated
Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)
```

## Purview purge flow

```powershell
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Search-001
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf
```

## Exchange Online message trace

```powershell
Get-MessageTrace -MessageId '<abc123@company.com>'
Get-MessageTrace -MessageId '<abc123@company.com>' -StartDate (Get-Date).AddHours(-12) -EndDate (Get-Date)
```

## AAD Connect remote sync

```powershell
Invoke-AADSyncRemote -ComputerName 'aadconnect01' -PolicyType Delta
Invoke-AADSyncRemote -ComputerName 'aadconnect01' -PolicyType Initial -UseKerberos -WhatIf
```

## Pagefile tuning

```powershell
Set-PageFileSize -ComputerName 'Server01.domain.local'
Set-PageFileSize -ComputerName 'Server01.domain.local' -InitialSize 4096 -MaximumSize 8192 -Path 'C:\pagefile.sys'
```

## Error event review

```powershell
Get-ErrorEvents -LogName System
Get-ErrorEvents -LogName System -EventId 41,6008 -StartTime (Get-Date).AddDays(-1) -MaxEvents 50
```

---

# **Project Layout**

- `Private/` — internal helpers and subsystems  
- `Public/` — exported commands (one function per file)  
- `Workers/` — remote/background task workers  
- `Config/` — runtime and build configuration  
- `AI/Agent/` — Python bridge and agent tooling  
- `TechToolbox.psm1` — module loader/bootstrap  
- `TechToolbox.psd1` — module manifest  

---

# **Development & QA**

```powershell
# ScriptAnalyzer
Invoke-ScriptAnalyzer -Path .\TechToolbox -Recurse -Severity Error,Warning

# Build/sign/package pipeline
.\Build.ps1 -Analyze -AutoVersionPatch -ExportPublic

# Dry-run sanity checks
Clear-BrowserProfileData -WhatIf
Get-RemoteInstalledSoftware -ComputerName srv01 -WhatIf
Invoke-PurviewPurge -UserPrincipalName you@company.com -CaseName Case-001 -SearchName Search-001 -WhatIf
Get-MessageTrace -MessageId '<test@company.com>' -WhatIf
Get-BatteryHealth -WhatIf
Invoke-AADSyncRemote -ComputerName aadconnect-01 -PolicyType Delta -WhatIf
```

---

# **Troubleshooting**

- **Import issues**: use PowerShell 7+ and `Import-Module .\TechToolbox.psd1 -Force`  
- **Missing command**: ensure it's listed in `FunctionsToExport`  
- **Remoting failures**: verify WinRM, auth method, and privileges  
- **Purview/EXO issues**: confirm required roles/modules  
- **Battery report issues**: run elevated if `powercfg` is blocked  
- **Logging issues**: ensure log directories exist  

---

# **Metadata**

- **Author:** Dan Damit  
- **License:** Internal use  
- **Module version:** 0.4.65
