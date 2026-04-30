# TechToolbox Command Reference

Back to project overview: [README.md](README.md)

This file is a quick index of exported public commands.

For full syntax, parameters, and examples:

```powershell
Get-Help <Command-Name> -Detailed
Get-Help <Command-Name> -Examples
```

After module load:
```powershell
Get-ToolboxHelp
Get-ToolboxHelp -list
Get-ToolboxHelp <Command-Name>
```

For a live command list from your current module build:

```powershell
Import-Module .\TechToolbox.psd1 -Force
Get-Command -Module TechToolbox | Sort-Object Name
```

## Core

- Get-TechToolboxConfig
- Get-ToolboxHelp

## Active Directory And Identity

- Disable-User
- Get-AllUsers
- Get-DomainAdminCredential
- Initialize-DomainAdminCred
- Initialize-TTWordList
- New-OnPremUserFromTemplate
- Reset-ADPassword
- Search-User
- Set-EmailAlias
- Set-ProxyAddress

## Exchange, Purview, And Messaging

- Get-AuditSharedMailboxDeletions
- Get-AutodiscoverXmlInteractive
- Get-MessageTrace
- Get-SharedMailboxPermissions
- Invoke-PurviewPurge
- Test-MailHeaderAuth

## Endpoint And System Operations

- Enable-NetFx3
- Find-LargeFiles
- Get-BatteryHealth
- Get-LocalAdminMembers
- Get-PDQDiagLogs
- Get-SystemSnapshot
- Get-SystemTrustDiagnostic
- Get-SystemUptime
- Get-WindowsProductKey
- Invoke-DownloadsCleanup
- Invoke-RestartService
- Invoke-SystemRepair
- Remove-EpicorEdgeAgent
- Reset-WindowsUpdateComponents
- Set-OneTimeReboot
- Set-PageFileSize
- Start-PDQDiagLocalElevated

## Network, Browser, And File Operations

- Clear-BrowserProfileData
- Copy-Directory
- Get-InstalledPrinters
- Invoke-SubnetScan
- Remove-Printers
- Start-DnsQueryLogger
- Watch-ISPConnection

## Remoting And Worker Orchestration

- Get-RemoteInstalledSoftware
- Invoke-AADSyncRemote
- Invoke-SCW
- Start-NewPSRemoteSession
- Stop-PSRemoteSession
- Test-PathAs

## AI-Assisted Workflows

- Invoke-CodeAssistant
- Invoke-CodeAssistantFolder
- Invoke-CodeAssistantWrapper
- Invoke-TechAgent

## Fast Start Examples

```powershell
# Browser cleanup preview
Clear-BrowserProfileData -WhatIf

# Remote software inventory
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated

# Purview purge dry run
Invoke-PurviewPurge -UserPrincipalName admin@company.com -CaseName "Case-001" -SearchName "CustodianSearch-01" -WhatIf

# Exchange Online message trace
Get-MessageTrace -MessageId '<abc123@company.com>'

# AAD Connect sync
Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta

# Pagefile tuning
Set-PageFileSize -ComputerName Server01.domain.local -InitialSize 4096 -MaximumSize 8192
```

## Maintainer Note

The source of truth is `FunctionsToExport` in `TechToolbox.psd1`.
When you add or remove exported functions, update this file in the same change.
