# TechToolbox Command Reference

Back to project overview: [README.md](https://github.com/dan-damit/TechToolbox/blob/main/README.md)

This is a quick operator index for exported public commands.
Use this file to find the right command quickly, then use help for full usage.

## Getting Full Details

```powershell
Get-Help <Command-Name> -Detailed
Get-Help <Command-Name> -Examples
Get-ToolboxHelp
Get-ToolboxHelp -List
Get-ToolboxHelp <Command-Name>
```

To view the live export set:

```powershell
Import-Module .\TechToolbox.psd1 -Force
Get-Command -Module TechToolbox | Sort-Object Name
```

## Flags

- `WhatIf`: supports `-WhatIf`
- `Risk`: can make impactful changes
- `Elevated`: typically requires admin privileges
- `Remote`: built for remoting or remote targets
- `Interactive`: prompts or runs interactively

---

## Core

| Command | Summary | Flags |
|---|---|---|
| Get-TechToolboxConfig | Return merged runtime config, including secrets overlay. | |
| Get-ToolboxHelp | Show module help, lists, and command summaries. | |
| Test-TTPathRoots | Validate toolbox path roots and optionally create missing directories. | |

## Active Directory and Identity

| Command | Summary | Flags |
|---|---|---|
| Disable-User | Disable an AD user and optionally run lifecycle actions. | WhatIf, Risk |
| Get-AllUsers | Return AD users with optional filters. | |
| Get-DomainAdminCredential | Retrieve stored domain admin credential if initialized. | |
| Initialize-DomainAdminCred | Prompt for and securely store domain admin credential. | Interactive |
| Initialize-TTWordList | Load or generate the password word list. | |
| New-OnPremUserFromTemplate | Create an on-prem AD user from a template identity. | Risk |
| Reset-ADPassword | Reset an AD user password, optionally random. | Risk |
| Search-User | Search AD users by lifecycle, attributes, or stale criteria. | |
| Set-EmailAlias | Add or update AD email alias attributes. | Risk |
| Set-ProxyAddress | Manage proxyAddresses for hybrid identity scenarios. | Risk |

## Exchange, Purview, and Messaging

| Command | Summary | Flags |
|---|---|---|
| Get-AuditSharedMailboxDeletions | Retrieve shared mailbox deletion audit events. | |
| Get-AutodiscoverXmlInteractive | Run interactive Autodiscover XML retrieval for troubleshooting. | Interactive |
| Get-MessageTrace | Run Exchange Online message trace by ID or filter. | |
| Get-SharedMailboxPermissions | Show effective permissions for a shared mailbox. | |
| Invoke-PurviewPurge | Execute Purview purge action against case and search. | WhatIf, Risk |
| Test-MailHeaderAuth | Analyze SPF, DKIM, and DMARC from message headers. | |

## Endpoint and System Operations

| Command | Summary | Flags |
|---|---|---|
| Enable-NetFx3 | Enable .NET Framework 3.5 on Windows systems. | Elevated |
| Find-LargeFiles | Find large files across drives or directories. | |
| Get-BatteryHealth | Generate battery health report via powercfg. | |
| Get-LocalAdminMembers | List members of local Administrators group. | Elevated |
| Get-ErrorEvents | Retrieve recent critical and error event logs. | |
| Get-PDQDiagLogs | Collect PDQ Deploy and Inventory diagnostic logs. | |
| Get-SystemSnapshot | Capture quick system health snapshot. | |
| Get-SystemTrustDiagnostic | Run trust chain and certificate diagnostics. | |
| Get-SystemUptime | Return friendly uptime view. | |
| Get-WindowsProductKey | Read Windows product key from registry. | Elevated |
| Get-FilesUsingKeywords | Search files for keyword matches. | |
| Get-CUCredentialManagerContents | List stored Windows Credential Manager items. | |
| Invoke-DownloadsCleanup | Clean Downloads folder by age and size rules. | WhatIf, Risk |
| Invoke-RestartService | Restart a service with retry and wait logic. | Elevated, Risk |
| Invoke-SystemRepair | Run DISM and SFC repair workflows. | Elevated, Risk |
| Remove-EpicorEdgeAgent | Remove Epicor Edge Agent components. | Elevated, Risk |
| Reset-WindowsUpdateComponents | Safely reset Windows Update components. | Elevated, Risk |
| Set-OneTimeReboot | Schedule one-time reboot locally or remotely. | Remote, Risk |
| Set-PageFileSize | Configure pagefile size locally or remotely. | Elevated, Remote, Risk |
| Start-PDQDiagLocalElevated | Launch local PDQ diagnostics elevated. | Elevated |
| Restart-SecureCrimpStack | Restart SecureCrimp stack service set. | Elevated, Risk |
| Restart-SecureCrimpAuxTasks | Restart SecureCrimp auxiliary task set. | Elevated, Risk |
| Restart-SecureCrimpAll | Restart full SecureCrimp stack and task set. | Elevated, Risk |

## Network, Browser, and File Operations

| Command | Summary | Flags |
|---|---|---|
| Clear-BrowserProfileData | Remove browser cache, cookies, and local storage. | WhatIf, Risk |
| Copy-Directory | Copy directory tree with robust error handling. | |
| Get-InstalledPrinters | List installed printers on the current system. | |
| Invoke-SubnetScan | Scan subnet for active hosts and selected ports. | |
| Remove-Printers | Remove printers matching provided filters. | WhatIf, Risk |
| Start-DnsQueryLogger | Start DNS query logging session to output path. | |
| Watch-ISPConnection | Monitor ISP connectivity and log outages. | |

## Remoting and Worker Orchestration

| Command | Summary | Flags |
|---|---|---|
| Get-RemoteInstalledSoftware | Collect installed software from remote hosts. | Remote |
| Invoke-AADSyncRemote | Trigger remote AAD Connect sync (Delta or Initial). | Remote, Risk |
| Invoke-SCW | Easter egg command. | Interactive |
| Start-NewPSRemoteSession | Start new PowerShell remoting session with defaults. | Remote |
| Stop-PSRemoteSession | Stop active PowerShell remoting session. | Remote |
| Test-PathAs | Test path access under alternate credentials. | Remote |

## AI-Assisted Workflows

| Command | Summary | Flags |
|---|---|---|
| Invoke-CodeAssistant | Run local AI code assistant on one file. | |
| Invoke-CodeAssistantFolder | Run AI-assisted transformation across a folder. | |
| Invoke-CodeAssistantWrapper | Wrap code assistant execution with added context. | |
| Install-TechAgentRuntime | Verify Ollama runtime and optionally pull the Tech agent model. | Risk |
| Invoke-TechAgent | Run local tool-using AI agent prompt workflow (supports single recursion auto-retry toggle). | Interactive |
| Use-TechAgentTaskTemplate | List, filter, preview, pick, open, or copy reusable TechAgent task templates. | Interactive |

---

## Maintainer Note

The authoritative export list lives in `TechToolbox.psd1` under `FunctionsToExport`.
When adding or removing commands, update both `FunctionsToExport` and this file.
