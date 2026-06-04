# **TechToolbox Command Reference**

Back to project overview: **[README.md](https://github.com/dan-damit/TechToolbox/blob/main/README.md)**

This document provides a categorized, operator‑focused reference for all exported public commands in TechToolbox.  
Each entry includes:

- A **one‑sentence description**  
- A **short, practical example**  
- Notes when relevant (WhatIf support, prerequisites, etc.)

For full syntax and parameter details:

```powershell
Get-Help <Command-Name> -Detailed
Get-Help <Command-Name> -Examples
```

To browse commands after module load:

```powershell
Get-ToolboxHelp
Get-ToolboxHelp -List
Get-ToolboxHelp <Command-Name>
```

To view the live exported command set:

```powershell
Import-Module .\TechToolbox.psd1 -Force
Get-Command -Module TechToolbox | Sort-Object Name
```

---

# **Core**

### **Get-TechToolboxConfig**  
Returns the fully merged configuration (config.json + secrets).  
**Example:**  
```powershell
Get-TechToolboxConfig
```

### **Get-ToolboxHelp**  
Displays module help, command lists, and per‑command summaries.  
**Example:**  
```powershell
Get-ToolboxHelp -ShowEffectiveConfig
```

### **Test-TTPathRoots**  
Validates module/logs/exports root paths; can create missing directories.  
**Example:**  
```powershell
Test-TTPathRoots -EnsureDirectories
```

---

# **Active Directory & Identity**

### **Disable-User**  
Disables an AD user and applies optional lifecycle actions.  
**Example:**  
```powershell
Disable-User -Identity jsmith
```

### **Get-AllUsers**  
Returns all AD users with optional filtering.  
**Example:**  
```powershell
Get-AllUsers -EnabledOnly
```

### **Get-DomainAdminCredential**  
Retrieves the stored domain admin credential (if initialized).  
**Example:**  
```powershell
Get-DomainAdminCredential
```

### **Initialize-DomainAdminCred**  
Prompts and stores a domain admin credential securely.  
**Example:**  
```powershell
Initialize-DomainAdminCred
```

### **Initialize-TTWordList**  
Loads or generates a word list for password generation workflows.  
**Example:**  
```powershell
Initialize-TTWordList
```

### **New-OnPremUserFromTemplate**  
Creates a new on‑prem AD user using a template object.  
**Example:**  
```powershell
New-OnPremUserFromTemplate -SamAccountName jdoe -OU "OU=Users,DC=domain,DC=com"
```

### **Reset-ADPassword**  
Resets an AD user password with optional random generation.  
**Example:**  
```powershell
Reset-ADPassword -Identity jdoe -Random
```

### **Search-User**  
Searches AD for users by lifecycle, attributes, or stale criteria.  
**Example:**  
```powershell
Search-User -Stale -Days 90
```

### **Set-EmailAlias**  
Adds or updates an AD user’s email alias attributes.  
**Example:**  
```powershell
Set-EmailAlias -Identity jdoe -Alias "john.doe@domain.com"
```

### **Set-ProxyAddress**  
Manages proxyAddresses for hybrid identity scenarios.  
**Example:**  
```powershell
Set-ProxyAddress -Identity jdoe -Add "smtp:alias@domain.com"
```

---

# **Exchange, Purview & Messaging**

### **Get-AuditSharedMailboxDeletions**  
Retrieves mailbox audit logs for deletion events.  
**Example:**  
```powershell
Get-AuditSharedMailboxDeletions -Mailbox shared@domain.com
```

### **Get-AutodiscoverXmlInteractive**  
Interactive Autodiscover XML retrieval for troubleshooting.  
**Example:**  
```powershell
Get-AutodiscoverXmlInteractive -Mailbox user@domain.com
```

### **Get-MessageTrace**  
Runs an EXO message trace by ID or filters.  
**Example:**  
```powershell
Get-MessageTrace -MessageId '<abc123@domain.com>'
```

### **Get-SharedMailboxPermissions**  
Shows permissions assigned to a shared mailbox.  
**Example:**  
```powershell
Get-SharedMailboxPermissions -Mailbox shared@domain.com
```

### **Invoke-PurviewPurge**  
Executes a Purview purge action against a case/search. Supports WhatIf.  
**Example:**  
```powershell
Invoke-PurviewPurge -UserPrincipalName admin@domain.com -CaseName Case-001 -SearchName Custodian-01
```

### **Test-MailHeaderAuth**  
Analyzes message headers for SPF/DKIM/DMARC authentication.  
**Example:**  
```powershell
Test-MailHeaderAuth -Path .\message.eml
```

---

# **Endpoint & System Operations**

### **Enable-NetFx3**  
Enables .NET Framework 3.5 on Windows systems.  
**Example:**  
```powershell
Enable-NetFx3
```

### **Find-LargeFiles**  
Searches for large files across drives or directories.  
**Example:**  
```powershell
Find-LargeFiles -Path C:\ -MinimumSizeGB 5
```

### **Get-BatteryHealth**  
Generates a battery report using `powercfg`.  
**Example:**  
```powershell
Get-BatteryHealth
```

### **Get-LocalAdminMembers**  
Lists members of the local Administrators group.  
**Example:**  
```powershell
Get-LocalAdminMembers
```

### **Get-ErrorEvents**  
Retrieves recent critical/error events with filtering.  
**Example:**  
```powershell
Get-ErrorEvents -LogName System -EventId 41,6008
```

### **Get-PDQDiagLogs**  
Collects PDQ Deploy/Inventory diagnostic logs.  
**Example:**  
```powershell
Get-PDQDiagLogs -OutputPath C:\Temp
```

### **Get-SystemSnapshot**  
Captures a quick system health snapshot (CPU, RAM, disk, services).  
**Example:**  
```powershell
Get-SystemSnapshot
```

### **Get-SystemTrustDiagnostic**  
Runs trust chain and certificate validation diagnostics.  
**Example:**  
```powershell
Get-SystemTrustDiagnostic
```

### **Get-SystemUptime**  
Returns system uptime in a friendly format.  
**Example:**  
```powershell
Get-SystemUptime
```

### **Get-WindowsProductKey**  
Retrieves the Windows product key from the registry.  
**Example:**  
```powershell
Get-WindowsProductKey
```

### **Get-FilesUsingKeywords**  
Searches files for matching keywords.  
**Example:**  
```powershell
Get-FilesUsingKeywords -Path C:\Logs -Keywords error,failure
```

### **Get-CUCredentialManagerContents**  
Lists stored credentials from Windows Credential Manager.  
**Example:**  
```powershell
Get-CUCredentialManagerContents
```

### **Invoke-DownloadsCleanup**  
Cleans up the Downloads folder based on age/size rules.  
**Example:**  
```powershell
Invoke-DownloadsCleanup -DaysOld 30
```

### **Invoke-RestartService**  
Restarts a service with optional wait and retry logic.  
**Example:**  
```powershell
Invoke-RestartService -Name Spooler
```

### **Invoke-SystemRepair**  
Runs DISM/SFC repair workflows.  
**Example:**  
```powershell
Invoke-SystemRepair -Full
```

### **Remove-EpicorEdgeAgent**  
Removes Epicor Edge Agent components.  
**Example:**  
```powershell
Remove-EpicorEdgeAgent
```

### **Reset-WindowsUpdateComponents**  
Resets Windows Update components safely.  
**Example:**  
```powershell
Reset-WindowsUpdateComponents
```

### **Set-OneTimeReboot**  
Schedules a one‑time reboot with optional delay.  
**Example:**  
```powershell
Set-OneTimeReboot -DelayMinutes 10
```

### **Set-PageFileSize**  
Configures pagefile size locally or remotely.  
**Example:**  
```powershell
Set-PageFileSize -ComputerName Server01 -InitialSize 4096 -MaximumSize 8192
```

### **Start-PDQDiagLocalElevated**  
Runs PDQ diagnostics elevated on the local machine.  
**Example:**  
```powershell
Start-PDQDiagLocalElevated
```

### **Restart-SecureCrimpStack / AuxTasks / All**  
Restarts SecureCrimp components or the full stack.  
**Example:**  
```powershell
Restart-SecureCrimpAll
```

---

# **Network, Browser & File Operations**

### **Clear-BrowserProfileData**  
Cleans browser cache, cookies, and local storage. Supports WhatIf.  
**Example:**  
```powershell
Clear-BrowserProfileData -Browser Chrome -IncludeCache -WhatIf
```

### **Copy-Directory**  
Copies a directory with robust error handling.  
**Example:**  
```powershell
Copy-Directory -Source C:\Data -Destination D:\Backup
```

### **Get-InstalledPrinters**  
Lists installed printers on the system.  
**Example:**  
```powershell
Get-InstalledPrinters
```

### **Invoke-SubnetScan**  
Scans a subnet for active hosts and open ports.  
**Example:**  
```powershell
Invoke-SubnetScan -Subnet 192.168.1.0/24
```

### **Remove-Printers**  
Removes printers matching filters.  
**Example:**  
```powershell
Remove-Printers -Name "*PDF*"
```

### **Start-DnsQueryLogger**  
Starts a DNS query logging session.  
**Example:**  
```powershell
Start-DnsQueryLogger -OutputPath C:\Logs
```

### **Watch-ISPConnection**  
Monitors ISP connectivity and logs outages.  
**Example:**  
```powershell
Watch-ISPConnection
```

---

# **Remoting & Worker Orchestration**

### **Get-RemoteInstalledSoftware**  
Collects installed software from remote hosts; supports consolidation.  
**Example:**  
```powershell
Get-RemoteInstalledSoftware -ComputerName srv01,srv02 -Consolidated
```

### **Invoke-AADSyncRemote**  
Triggers AAD Connect sync remotely (Delta/Initial).  
**Example:**  
```powershell
Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta
```

### **Invoke-SCW**  
Runs a SecureCrimp worker task remotely.  
**Example:**  
```powershell
Invoke-SCW -ComputerName pc01 -TaskName Inventory
```

### **Start-NewPSRemoteSession**  
Starts a new PowerShell remoting session with safe defaults.  
**Example:**  
```powershell
Start-NewPSRemoteSession -ComputerName srv01
```

### **Stop-PSRemoteSession**  
Stops an existing PS remoting session.  
**Example:**  
```powershell
Stop-PSRemoteSession
```

### **Test-PathAs**  
Tests path access under alternate credentials.  
**Example:**  
```powershell
Test-PathAs -Path \\server\share -Credential (Get-Credential)
```

---

# **AI-Assisted Workflows**

### **Invoke-CodeAssistant**  
Runs a local AI code assistant for single-file operations.  
**Example:**  
```powershell
Invoke-CodeAssistant -Path .\script.ps1 -Prompt "Refactor this."
```

### **Invoke-CodeAssistantFolder**  
Runs AI-assisted transformations across a folder.  
**Example:**  
```powershell
Invoke-CodeAssistantFolder -Path .\Public -Prompt "Standardize comment-based help."
```

### **Invoke-CodeAssistantWrapper**  
Wraps code assistant operations with additional context or tooling.  
**Example:**  
```powershell
Invoke-CodeAssistantWrapper -Path .\Module -Prompt "Modernize functions."
```

### **Install-TechAgentRuntime**  
Creates/repairs the Python runtime and installs dependencies.  
**Example:**  
```powershell
Install-TechAgentRuntime -UpgradePackages -PullModel
```

### **Invoke-TechAgent**  
Runs the local tool‑using AI agent.  
**Example:**  
```powershell
Invoke-TechAgent -Prompt "Generate a system health summary."
```

---

# **Maintainer Note**

The authoritative export list lives in:

```
TechToolbox.psd1 → FunctionsToExport
```

When adding or removing commands, update both:

- `FunctionsToExport`
- This `commands.md`