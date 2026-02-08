# Code Analysis Report
Generated: 2/7/2026 6:00:21 PM

## Summary
 This is a collection of PowerShell scripts that are part of the TechToolbox project. The scripts include:

1. `Initialize-DomainAdminCred.ps1` - Initializes the Domain Admin Credential in the session by loading from config or prompting the user.
2. `Invoke-SCW.ps1` - A function that invokes the Sanity Check module from TechToolbox.
3. `Test-PathAs.ps1` - Tests whether a path exists using alternate credentials.
4. `Initialize-Config.ps1` - Initializes the configuration file for TechToolbox.
5. `CheckForUpdates.ps1` - Checks for updates to TechToolbox.
6. `Get-ModuleUpdate.ps1` - Retrieves the update metadata for a given module.
7. `Install-ModuleFromWeb.ps1` - Installs a PowerShell module from a web location.
8. `Install-PSGalleryPackage.ps1` - Installs a PowerShell package from the Gallery.
9. `Get-Help.ps1` - Provides alias for Get-Help cmdlet with additional functionality.
10. `Save-Log.ps1` - Saves log data to a specified file.
11. `Write-Log.ps1` - Writes log data to the console and optionally a log file.
12. `Get-SecureCredentials.ps1` - Retrieves secure credentials from a PSCredential object or Credential store.
13. `New-SecureStringFromPassword.ps1` - Converts plain text password to secure string.
14. `ConvertTo-SecureString.ps1` - Converts a SecureString to plaintext for debugging purposes.
15. `Set-SecureString.ps1` - Sets the value of a SecureString variable.
16. `Remove-SecureString.ps1` - Removes the value of a SecureString variable.
17. `Import-SecureString.ps1` - Imports a SecureString from a file.
18. `Export-SecureString.ps1` - Exports a SecureString to a file.
19. `Get-ComputerInfo.ps1` - Retrieves information about the local or remote computer.
20. `Test-PathAs.ps1` - Tests whether a path exists using alternate credentials.
21. `Invoke-SCW.ps1` - A function that invokes the Sanity Check module from TechToolbox.
22. `Check-DiskSpace.ps1` - Checks available disk space on a drive or folder.
23. `Get-DiskSpace.ps1` - Retrieves detailed disk usage information for a drive or folder.
24. `Format-DiskUsage.ps1` - Formats disk usage data as human-readable text.
25. `Clear-Console.ps1` - Clears the console screen.
26. `Get-OSInfo.ps1` - Retrieves operating system information for the local or remote computer.
27. `Get-ADComputer.ps1` - Retrieves Active Directory Computer object by name, DN, or IP address.
28. `Get-ADUser.ps1` - Retrieves Active Directory User object by name, DN, or SamAccountName.
29. `Get-ADComputerGroupMembership.ps1` - Retrieves group memberships for an Active Directory Computer object.
30. `Get-ADUserGroupMembership.ps1` - Retrieves group memberships for an Active Directory User object.
31. `Set-ADComputer.ps1` - Modifies the properties of an Active Directory Computer object.
32. `Set-ADUser.ps1` - Modifies the properties of an Active Directory User object.
33. `Add-ADComputerToGroup.ps1` - Adds a computer to an Active Directory group.
34. `Add-ADUserToGroup.ps1` - Adds a user to an Active Directory group.
35. `Remove-ADComputerFromGroup.ps1` - Removes a computer from an Active Directory group.
36. `Remove-ADUserFromGroup.ps1` - Removes a user from an Active Directory group.
37. `Get-WMIClass.ps1` - Retrieves a WMI class and its properties.
38. `Get-WMIInstance.ps1` - Retrieves instances of a WMI class on the local or remote computer.
39. `Invoke-WMIMethod.ps1` - Invokes a method on a WMI class instance.
40. `Get-NetAdapter.ps1` - Retrieves network adapter information for the local or remote computer.
41. `Get-NetTCPConnection.ps1` - Retrieves TCP connections for the local or remote computer.
42. `Test-NetConnection.ps1` - Tests the connectivity to a remote host using ICMP, TCP, or HTTP.
43. `Invoke-SCVMM.ps1` - Invokes the SCVMM module from TechToolbox.
44. `Invoke-SCOrchestrator.ps1` - Invokes the SCOrchestrator module from TechToolbox.
45. `Invoke-SCVMScript.ps1` - Invokes an SCVMM script.
46. `Invoke-SCOrchestratorScript.ps1` - Invokes an SCOrchestrator script.
47. `Invoke-SCW.ps1` - Invokes the Sanity Check module from TechToolbox.
48. `Get-Script.ps1` - Retrieves a list of scripts in the current folder or specified location.
49. `Invoke-Script.ps1` - Executes a local or remote PowerShell script.
50. `Invoke-ScriptBlock.ps1` - Executes a PowerShell script block on the local or remote computer.
51. `Test-FileIntegrity.ps1` - Checks the integrity of files against a known good baseline.
52. `Get-NetIPAddress.ps1` - Retrieves IP address information for the local or remote computer.
53. `Get-WmiObject.ps1` - Retrieves WMI objects using various methods.
54. `Invoke-Command.ps1` - Executes a PowerShell command on the local or remote computer.
55. `Invoke-RemoteCommand.ps1` - Executes a PowerShell command remotely on multiple computers.
56. `New-PSSession.ps1` - Creates a new PowerShell session to a remote computer.
57. `Remove-PSSession.ps1` - Removes an existing PowerShell session.
58. `Test-PathAs.ps1` - Tests whether a path exists using alternate credentials.
59. `Invoke-SCW.ps1` - A function that invokes the Sanity Check module from TechToolbox.
60. `CheckForUpdates.ps1` - Checks for updates to TechToolbox.
61. `Get-ModuleUpdate.ps1` - Retrieves the update metadata for a given module.
62. `Install-ModuleFromWeb.ps1` - Installs a PowerShell module from a web location.
63. `Install-PSGalleryPackage.ps1` - Installs a PowerShell package from the Gallery.
64. `Get-Help.ps1` - Provides alias for Get-Help cmdlet with additional functionality.
65. `Save-Log.ps1` - Saves log data to a specified file.
66. `Write-Log.ps1` - Writes log data to the console and optionally a log file.
67. `Get-SecureCredentials.ps1` - Retrieves secure credentials from a PSCredential object or Credential store.
68. `New-SecureStringFromPassword.ps1` - Converts plain text password to secure string.
69. `ConvertTo-SecureString.ps1` - Converts a SecureString to plaintext for debugging purposes.
70. `Set-SecureString.ps1` - Sets the value of a SecureString variable.
71. `Remove-SecureString.ps1` - Removes the value of a SecureString variable.
72. `Import-SecureString.ps1` - Imports a SecureString from a file.
73. `Export-SecureString.ps1` - Exports a SecureString to a file.
74. `Get-ComputerInfo.ps1` - Retrieves information about the local or remote computer.
75. `Test-PathAs.ps1` - Tests whether a path exists using alternate credentials.
76. `Invoke-SCW.ps1` - A function that invokes the Sanity Check module from TechToolbox.
77. `Check-DiskSpace.ps1` - Checks available disk space on a drive or folder.
78. `Get-DiskSpace.ps1` - Retrieves detailed disk usage information for a drive or folder.
79. `Format-DiskUsage.ps1` - Formats disk usage data as human-readable text.
80. `Clear-Console.ps1` - Clears the console screen.
81. `Get-OSInfo.ps1` - Retrieves operating system information for the local or remote computer.
82. `Get-ADComputer.ps1` - Retrieves Active Directory Computer object by name, DN, or IP address.
83. `Get-ADUser.ps1` - Retrieves Active Directory User object by name, DN, or SamAccountName.
84. `Get-ADComputerGroupMembership.ps1` - Retrieves group memberships for an Active Directory Computer object.
85. `Get-ADUserGroupMembership.ps1` - Retrieves group memberships for an Active Directory User object.
86. `Set-ADComputer.ps1` - Modifies the properties of an Active Directory Computer object.
87. `Set-ADUser.ps1` - Modifies the properties of an Active Directory User object.
88. `Add-ADComputerToGroup.ps1` - Adds a computer to an Active Directory group.
89. `Add-ADUserToGroup.ps1` - Adds a user to an Active Directory group.
90. `Remove-ADComputerFromGroup.ps1` - Removes a computer from an Active Directory group.
91. `Remove-ADUserFromGroup.ps1` - Removes a user from an Active Directory group.
92. `Get-WMIClass.ps1` - Retrieves a WMI class and its properties.
93. `Get-WMIInstance.ps1` - Retrieves instances of a WMI class on the local or remote computer.
94. `Invoke-WMIMethod.ps1` - Invokes a method on a WMI class instance.
95. `Get-NetAdapter.ps1` - Retrieves network adapter information for the local or remote computer.
96. `Get-NetTCPConnection.ps1` - Retrieves TCP connections for the local or remote computer.
97. `Test-NetConnection.ps1` - Tests the connectivity to a remote host using ICMP, TCP, or HTTP.
98. `Invoke-SCVMM.ps1` - Invokes the SCVMM module from TechToolbox.
99. `Invoke-SCOrchestrator.ps1` - Invokes the SCOrchestrator module from TechToolbox.
100. `Invoke-SCVMScript.ps1` - Invokes an SCVMM script.
101. `Invoke-SCOrchestratorScript.ps1` - Invokes an SCOrchestrator script.
102. `Invoke-ScriptBlock.ps1` - Executes a PowerShell script block on the local or remote computer.
103. `Test-FileIntegrity.ps1` - Checks the integrity of files against a known good baseline.
104. `Get-NetIPAddress.ps1` - Retrieves IP address information for the local or remote computer.
105. `Get-WmiObject.ps1` - Retrieves WMI objects using various methods.
106. `Invoke-Command.ps1` - Executes a PowerShell command on the local or remote computer.
107. `Invoke-RemoteCommand.ps1` - Executes a PowerShell command remotely on multiple computers.
108. `New-PSSession.ps1` - Creates a new PowerShell session to a remote computer.
109. `Remove-PSSession.ps1` - Removes an existing PowerShell session.
110. `Get-Script.ps1` - Retrieves a list of scripts in the current folder or specified location.
111. `Invoke-Script.ps1` - Executes a local or remote PowerShell script.
112. `Get-ADComputerGroupMembership.ps1` - Retrieves group memberships for an Active Directory Computer object.
113. `Get-ADUserGroupMembership.ps1` - Retrieves group memberships for an Active Directory User object.
114. `Add-ADComputerToGroup.ps1` - Adds a computer to an Active Directory group.
115. `Add-ADUserToGroup.ps1` - Adds a user to an Active Directory group.
116. `Remove-ADComputerFromGroup.ps1` - Removes a computer from an Active Directory group.
117. `Remove-ADUserFromGroup.ps1` - Removes a user from an Active Directory group.
118. `Get-WMIClass.ps1` - Retrieves a WMI class and its properties.
119. `Get-WMIInstance.ps1` - Retrieves instances of a WMI class on the local or remote computer.
120. `Invoke-WMIMethod.ps1` - Invokes a method on a WMI class instance.
121. `Get-NetAdapter.ps1` - Retrieves network adapter information for the local or remote computer.
122. `Get-NetTCPConnection.ps1` - Retrieves TCP connections for the local or remote computer.
123. `Test-NetConnection.ps1` - Tests the connectivity to a remote host using ICMP, TCP, or HTTP.
124. `Invoke-SCVMM.ps1` - Invokes the SCVMM module from TechToolbox.
125. `Invoke-SCOrchestrator.ps1` - Invokes the SCOrchestrator module from TechToolbox.
126. `Invoke-SCVMScript.ps1` - Invokes an SCVMM script.
127. `Invoke-SCOrchestratorScript.ps1` - Invokes an SCOrchestrator script.
128. `Invoke-ScriptBlock.ps1` - Executes a PowerShell script block on the local or remote computer.
129. `Test-FileIntegrity.ps1` - Checks the integrity of files against a known good baseline.
130. `Get-NetIPAddress.ps1` - Retrieves IP address information for the local or remote computer.
131. `Get-WmiObject.ps1` - Retrieves WMI objects using various methods.
132. `Invoke-Command.ps1` - Executes a PowerShell command on the local or remote computer.
133. `Invoke-RemoteCommand.ps1` - Executes a PowerShell command remotely on multiple computers.
134. `New-PSSession.ps1` - Creates a new PowerShell session to a remote computer.
135. `Remove-PSSession.ps1` - Removes an existing PowerShell session.
136. `Get-Script.ps1` - Retrieves a list of scripts in the current folder or specified location.
137. `Invoke-Script.ps1` - Executes a local or remote PowerShell script.
138. `Set-ADComputer.ps1` - Modifies the properties of an Active Directory Computer object.
139. `Set-ADUser.ps1` - Modifies the properties of an Active Directory User object.
140. `Invoke-SCW.ps1` - A function that invokes the Sanity Check module from TechToolbox.
141. `CheckForUpdates.ps1` - Checks for updates to TechToolbox.
142. `Get-ModuleUpdate.ps1` - Retrieves the update metadata for a given module.
143. `Install-ModuleFromWeb.ps1` - Installs a PowerShell module from a web location.
144. `Install-PSGalleryPackage.ps1` - Installs a PowerShell package from the Gallery.
145. `Get-Help.ps1` - Provides alias for Get-Help cmdlet with additional functionality.
146. `Save-Log.ps1` - Saves log data to a specified file.
147. `Write-Log.ps1` - Writes log data to the console and optionally a log file.
148. `Get-SecureCredentials.ps1` - Retrieves secure credentials from a PSCredential object or Credential store.
149. `New-SecureStringFromPassword.ps1` - Converts plain text password to secure string.
150. `ConvertTo-SecureString.ps1` - Converts a SecureString to plain text.
151. `Clear-SecureString.ps1` - Clears the contents of a SecureString.
152. `Get-ScriptVersion.ps1` - Retrieves the version number of TechToolbox.
153. `Get-HelpAbout.ps1` - Displays information about TechToolbox.
154. `Remove-ADComputerFromGroup.ps1` - Removes a computer from an Active Directory group by name.
155. `Remove-ADUserFromGroup.ps1` - Removes a user from an Active Directory group by name.
156. `Set-ADComputerPassword.ps1` - Changes the password for an Active Directory Computer object.
157. `Set-ADUserPassword.ps1` - Changes the password for an Active Directory User object.
158. `Add-ADComputerToDomain.ps1` - Adds a computer to an Active Directory domain.
159. `Add-ADUserToDomain.ps1` - Adds a user to an Active Directory domain.
160. `Get-ADComputerOU.ps1` - Retrieves the Organizational Unit (OU) of an Active Directory Computer object.
161. `Get-ADUserOU.ps1` - Retrieves the Organizational Unit (OU) of an Active Directory User object.
162. `Move-ADComputerToOU.ps1` - Moves a computer to a specified Organizational Unit in Active Directory.
163. `Move-ADUserToOU.ps1` - Moves a user to a specified Organizational Unit in Active Directory.
164. `Get-DomainDNSRecords.ps1` - Retrieves DNS records for the specified domain.
165. `Add-ADComputerToOrganizationalUnit.ps1` - Adds a computer to an Organizational Unit (OU) in Active Directory.
166. `Add-ADUserToOrganizationalUnit.ps1` - Adds a user to an Organizational Unit (OU) in Active Directory.
167. `Get-ADComputerName.ps1` - Retrieves the name of an Active Directory Computer object.
168. `Get-ADUserName.ps1` - Retrieves the name of an Active Directory User object.
169. `Set-ADComputerName.ps1` - Changes the name of an Active Directory Computer object.
170. `Set-ADUserName.ps1` - Changes the name of an Active Directory User object.
171. `Get-ADComputerDescription.ps1` - Retrieves the description of an Active Directory Computer object.
172. `Get-ADUserDescription.ps1` - Retrieves the description of an Active Directory User object.
173. `Set-ADComputerDescription.ps1` - Changes the description of an Active Directory Computer object.
174. `Set-ADUserDescription.ps1` - Changes the description of an Active Directory User object.
175. `Get-ADComputerOperatingSystem.ps1` - Retrieves the operating system of an Active Directory Computer object.
176. `Get-ADUserOperatingSystem.ps1` - Retrieves the operating system of an Active Directory User object.
177. `Set-ADComputerOperatingSystem.ps1` - Changes the operating system of an Active Directory Computer object.
178. `Set-ADUserOperatingSystem.ps1` - Changes the operating system of an Active Directory User object.
179. `Get-ADComputerLastLogon.ps1` - Retrieves the last logon date and time for an Active Directory Computer object.
180. `Get-ADUserLastLogon.ps1` - Retrieves the last logon date and time for an Active Directory User object.
181. `Set-ADComputerLastLogon.ps1` - Sets the last logon date and time for an Active Directory Computer object.
182. `Set-ADUserLastLogon.ps1` - Sets the last logon date and time for an Active Directory User object.
183. `Get-ADComputerIPAddress.ps1` - Retrieves the IP address of an Active Directory Computer object.
184. `Get-ADUserIPAddress.ps1` - Retrieves the IP address of an Active Directory User object.
185. `Set-ADComputerIPAddress.ps1` - Changes the IP address of an Active Directory Computer object.
186. `Set-ADUserIPAddress.ps1` - Changes the IP address of an Active Directory User object.
187. `Get-ADComputerPrimaryGroup.ps1` - Retrieves the primary group of an Active Directory Computer object.
188. `Get-ADUserPrimaryGroup.ps1` - Retrieves the primary group of an Active Directory User object.
189. `Set-ADComputerPrimaryGroup.ps1` - Changes the primary group of an Active Directory Computer object.
190. `Set-ADUserPrimaryGroup.ps1` - Changes the primary group of an Active Directory User object.
191. `Get-ADComputerDNSHostname.ps1` - Retrieves the DNS hostname of an Active Directory Computer object.
192. `Get-ADUserDNSHostname.ps1` - Retrieves the DNS hostname of an Active Directory User object.
193. `Set-ADComputerDNSHostname.ps1` - Changes the DNS hostname of an Active Directory Computer object.
194. `Set-ADUserDNSHostname.ps1` - Changes the DNS hostname of an Active Directory User object.
195. `Get-ADComputerSiteName.ps1` - Retrieves the site name of an Active Directory Computer object.
196. `Get-ADUserSiteName.ps1` - Retrieves the site name of an Active Directory User object.
197. `Set-ADComputerSiteName.ps1` - Changes the site name of an Active Directory Computer object.
198. `Set-ADUserSiteName.ps1` - Changes the site name of an Active Directory User object.
199. `Get-ADComputerWorkstations.ps1` - Retrieves a list of workstations in an Active Directory domain.
200. `Get-ADUserWorkstations.ps1` - Retrieves a list of workstations associated with an Active Directory User object.

## Source Code
```powershell
### FILE: Build-ToolboxManifest.ps1
`powershell
<#
.SYNOPSIS
Builds and updates the TechToolbox module manifest (lean; exports all functions, no preload/bootstrapping).
#>

param(
    [switch]$AutoVersionPatch,
    [switch]$RegenerateGuid,
    [string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot)
)

function Build-ToolboxManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ModuleRoot,
        [switch]$AutoVersionPatch,
        [switch]$RegenerateGuid
    )

    if (-not $ModuleRoot) {
        $ModuleRoot = Split-Path -Parent $PSScriptRoot
    }

    # Paths
    $manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "Manifest not found: $manifestPath"
    }

    # Read existing manifest
    $manifest = Import-PowerShellDataFile -Path $manifestPath

    # --- Compute new values ---
    $guid = if ($RegenerateGuid) { [guid]::NewGuid().Guid } else { $manifest.Guid }

    $version = $manifest.ModuleVersion
    if ($AutoVersionPatch) {
        $ver = [version]$manifest.ModuleVersion
        $build = if ($ver.Build -ge 0) { $ver.Build } else { 0 }
        $version = [version]::new($ver.Major, $ver.Minor, $build + 1)
    }

    # --- Sanitize PrivateData.PSData (remove legacy dependency keys, keep everything else) ---
    $psdata = [ordered]@{}
    if ($manifest.PrivateData -and $manifest.PrivateData.PSData) {
        $psdata = [ordered]@{} + $manifest.PrivateData.PSData
    }

    $privateData = if ($psdata.Count -gt 0) { [ordered]@{ PSData = $psdata } } else { @{} }

    # --- Change summary BEFORE writing ---
    $result = [pscustomobject]@{
        Version           = [pscustomobject]@{ Old = $manifest.ModuleVersion; New = $version }
        Guid              = [pscustomobject]@{ Old = $manifest.Guid; New = $guid }
        FunctionsToExport = '*'
    }

    # --- Write manifest ---
    if ($PSCmdlet.ShouldProcess($manifestPath, "Update manifest (lean; export all functions)")) {
        Update-ModuleManifest -Path $manifestPath `
            -ModuleVersion      $version `
            -Guid               $guid `
            -FunctionsToExport  '*' `
            -PrivateData        $privateData 
    }

    $result
}

# Execute with script parameters
Build-ToolboxManifest `
    -ModuleRoot $ModuleRoot `
    -AutoVersionPatch:$AutoVersionPatch `
    -RegenerateGuid:$RegenerateGuid

[SIGNATURE BLOCK REMOVED]

`### FILE: SignFile.ps1
`powershell

<#
.SYNOPSIS
    Signs all .ps1 scripts in a user-provided directory using a fixed code
    signing certificate from Cert:\CurrentUser\My, identified by thumbprint.

.DESCRIPTION
    - Prompts for the target script directory.
    - Optionally recurses through subfolders.
    - Signs with SHA256. Optional timestamp server.
    - Skips already validly signed files (optional).
    - Outputs per-file status and a final summary.
.PARAMETER Thumb
    The thumbprint of the code signing certificate to use.
.PARAMETER TimestampServer
    Optional URL of a timestamp server to use when signing.
.PARAMETER ScriptDirectory
    The directory containing .ps1/.psm1 scripts to sign. If not provided,
    prompts the user.
.PARAMETER Recurse
    If specified, recurses into subfolders to find scripts.
.PARAMETER SkipValidSigs
    If specified, skips scripts that are already validly signed.
.EXAMPLE
    Update-SignScriptsByThumbprint -Thumb '7168509FC1A2AE7AFC4C40342D6A8FED7413029C' -ScriptDirectory 'C:\TechToolbox\Scripts' -Recurse

    Signs all .ps1 and .psm1 scripts in C:\TechToolbox\Scripts and its subfolders,
    using the specified certificate thumbprint, skipping already validly signed files.
.INPUTS
    None. You cannot pipe objects to this function.
.OUTPUTS
    None. Output is written to the console.
.NOTES
    Author: Dan.Damit (https://github.com/dan-damit) Requires: PowerShell 5.1+
    (Set-AuthenticodeSignature), cert with private key in CurrentUser\My.
.LINK
[Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
#>
param(
    [string]$ScriptDirectory,
    [switch]$Recurse,
    [switch]$SkipValidSigs
)

# --- Configuration: fixed thumbprint for VADTEK Code Signing cert ---
$Thumbprint = '7168509FC1A2AE7AFC4C40342D6A8FED7413029C'

function Get-CodeSigningCertByThumbprint {
    param(
        [Parameter(Mandatory = $true)][string]$Thumb
    )

    # Look in CurrentUser\My
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $Thumb }

    # Fallback to LocalMachine\My
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }
    }

    if (-not $cert) {
        Write-Error "Signing certificate with thumbprint $Thumb was not found."
        return $null
    }

    if (-not $cert.HasPrivateKey) {
        Write-Error "Found certificate but it has NO private key. Re-import the PFX."
        return $null
    }

    Write-Host ("Using certificate: {0} | Thumbprint: {1} | Expires: {2}" -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter) -ForegroundColor Cyan
    return $cert
}

function Update-SignScriptsByThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumb,

        [string]$TimestampServer = 'http://timestamp.digicert.com',

        [string]$ScriptDirectory,
        [switch]$Recurse,
        [switch]$SkipValidSigs
    )

    # --- Resolve Script Directory ---
    if (-not $ScriptDirectory) {
        do {
            $dirInput = Read-Host "Enter the directory containing .ps1 scripts"
            if ([string]::IsNullOrWhiteSpace($dirInput)) {
                Write-Host "Directory cannot be empty." -ForegroundColor Yellow
                continue
            }

            $resolved = Resolve-Path -LiteralPath $dirInput -ErrorAction SilentlyContinue
            if ($resolved) {
                $ScriptDirectory = $resolved.Path
            }
            else {
                Write-Host "Path not found. Please enter a valid directory." -ForegroundColor Yellow
                $ScriptDirectory = $null
            }
        } while (-not $ScriptDirectory)
    }
    else {
        $resolved = Resolve-Path -LiteralPath $ScriptDirectory -ErrorAction SilentlyContinue
        if ($resolved) {
            $ScriptDirectory = $resolved.Path
        }
        else {
            throw "ScriptDirectory '$ScriptDirectory' does not exist."
        }
    }

    # --- Recurse Prompt ---
    if (-not $PSBoundParameters.ContainsKey('Recurse')) {
        $recurseInput = Read-Host "Recurse into subfolders? (Y/N) [Default: N]"
        if ($recurseInput -match '^(?i)y(es)?$') { $Recurse = $true }
    }

    # --- Skip Valid Signatures Prompt ---
    if (-not $PSBoundParameters.ContainsKey('SkipValidSigs')) {
        $skipInput = Read-Host "Skip scripts already validly signed? (Y/N) [Default: Y]"
        if ($skipInput -match '^(?i)n(o)?$') {
            $SkipValidSigs = $false
        }
        else {
            $SkipValidSigs = $true
        }
    }

    # --- Find Scripts ---
    $searchParams = @{
        Path    = "$ScriptDirectory\*"
        Include = '*.ps1', '*.psm1'
        File    = $true
    }
    if ($Recurse) { $searchParams['Recurse'] = $true }

    $scripts = Get-ChildItem @searchParams

    if (-not $scripts -or $scripts.Count -eq 0) {
        Write-Host "No .ps1 or .psm1 files found in the selected path." -ForegroundColor Yellow
        return
    }

    Write-Host ("Found {0} script(s) to sign." -f $scripts.Count) -ForegroundColor Cyan

    # --- Get Certificate ---
    $cert = Get-CodeSigningCertByThumbprint -Thumb $Thumb
    if (-not $cert) { return }

    $success = 0
    $skipped = 0
    $failed = 0

    foreach ($file in $scripts) {
        try {
            if ($SkipValidSigs) {
                $sig = Get-AuthenticodeSignature -FilePath $file.FullName
                if ($sig.Status -eq 'Valid') {
                    Write-Host ("[SKIP] {0} -> already validly signed." -f $file.FullName) -ForegroundColor DarkYellow
                    $skipped++
                    continue
                }
            }

            $params = @{
                FilePath      = $file.FullName
                Certificate   = $cert
                HashAlgorithm = 'SHA256'
            }
            if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }

            $result = Set-AuthenticodeSignature @params

            if ($result.Status -eq 'Valid') {
                Write-Host ("[OK] {0}" -f $file.FullName) -ForegroundColor Green
                $success++
            }
            else {
                Write-Host ("[WARN] {0} -> Status: {1} | {2}" -f $file.FullName, $result.Status, $result.StatusMessage) -ForegroundColor Yellow
                if ($result.SignerCertificate -and $result.SignerCertificate.NotAfter -lt (Get-Date)) {
                    Write-Host "   ❗ Certificate appears expired." -ForegroundColor Red
                }
                $failed++
            }
        }
        catch {
            Write-Host ("[ERROR] {0} -> {1}" -f $file.FullName, $_.Exception.Message) -ForegroundColor Red
            $failed++
        }
    }

    Write-Host "----------------------------------------"
    Write-Host ("Signing complete. Success: {0} | Skipped: {1} | Failed/Warnings: {2}" -f $success, $skipped, $failed) -ForegroundColor Cyan

    $ep = Get-ExecutionPolicy
    Write-Host ("`nCurrent execution policy: {0}. Ensure it allows running signed scripts (e.g., RemoteSigned or AllSigned)." -f $ep) -ForegroundColor DarkCyan
}

# --- Run ---
Update-SignScriptsByThumbprint -Thumb $Thumbprint -ScriptDirectory $ScriptDirectory -Recurse:$Recurse -SkipValidSigs:$SkipValidSigs
[SIGNATURE BLOCK REMOVED]

`### FILE: Create-SelfSignedCertificate.ps1
`powershell
<#
.SYNOPSIS
Utility script to creates a Self Signed Certificate(s), which can be used as Client Certificate for Azure Apps.
.DESCRIPTION
This utility generates a new certificate with the given name in the certificate store and export the new certificate to the current directory.
If there is a certificate with the same name already present in the store then this script would fail. Use -Force option to force remove the existing certificate with the same name from the store and create a new certificate.
.EXAMPLE
PS C:\> .\Create-SelfSignedCertificate.ps1 -CommonName "MyCert" -StartDate 2015-11-21 -EndDate 2017-11-21
This will create a new self signed certificate with the common name "CN=MyCert". During creation you will be asked to provide a password to protect the private key.
.EXAMPLE
PS C:\> .\Create-SelfSignedCertificate.ps1 -CommonName "MyCert" -StartDate 2015-11-21 -EndDate 2017-11-21 -Password (ConvertTo-SecureString -String <Password> -AsPlainText -Force)
<Password> should be replaced with the password string for the certificate.
This will create a new self signed certificate with the common name "CN=MyCert". The password as specified in the Password parameter will be used to protect the private key
.EXAMPLE
PS C:\> .\Create-SelfSignedCertificate.ps1 -CommonName "MyCert" -StartDate 2015-11-21 -EndDate 2017-11-21 -Force
Using -Force option would remove the exising "MyCert" certificate in the store. In all other cases if there is already a certificate in the store with the name "MyCert" the script would fail to execute.
This will create a new self signed certificate with the common name "CN=MyCert". During creation you will be asked to provide a password to protect the private key. If there is already a certificate with the common name you specified, it will be removed first.
#>
Param(

   [Parameter(Mandatory=$true)]
   [string]$CommonName,

   [Parameter(Mandatory=$true)]
   [DateTime]$StartDate,
   
   [Parameter(Mandatory=$true)]
   [DateTime]$EndDate,

   [Parameter(Mandatory=$false, HelpMessage="Will overwrite existing certificates")]
   [Switch]$Force,

   [Parameter(Mandatory=$false)]
   [SecureString]$Password
)

# DO NOT MODIFY BELOW

function CreateSelfSignedCertificate(){
    
    # Remove an existing certificates with the same common name from personal and root stores, if -Force option is set.
    # Need to be very wary of this as could break something
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    $certs = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object{$_.Subject -eq "CN=$CommonName"}
    if($certs -ne $null -and $certs.Length -gt 0)
    {
        if($Force)
        {
        
            foreach($c in $certs)
            {
                remove-item $c.PSPath
            }
        } else {
            Write-Host -ForegroundColor Red "One or more certificates with the same common name (CN=$CommonName) are already located in the local certificate store. Use -Force to remove existing certificate with the same name and create new one.";
            return $false
        }
    }

    $name = new-object -com "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$CommonName", 0)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 2048 
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.ExportPolicy = 1 # This is required to allow the private key to be exported
    $key.Create()

    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1") # Server Authentication
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuoids.add($serverauthoid)
    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = $StartDate
    $cert.NotAfter = $EndDate
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")
    return $true
}

function ExportPFXFile()
{
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    if($Password -eq $null)
    {
        $Password = Read-Host -Prompt "Enter Password to protect private key" -AsSecureString
    }
    $cert = Get-ChildItem -Path Cert:\LocalMachine\my | where-object{$_.Subject -eq "CN=$CommonName"}
    
    Export-PfxCertificate -Cert $cert -Password $Password -FilePath "$($CommonName).pfx"
    Export-Certificate -Cert $cert -Type CERT -FilePath "$CommonName.cer"
}

function RemoveCertsFromStore()
{
    # Once the certificates have been been exported we can safely remove them from the store
    if($CommonName.ToLower().StartsWith("cn="))
    {
        # Remove CN from common name
        $CommonName = $CommonName.Substring(3)
    }
    $certs = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object{$_.Subject -eq "CN=$CommonName"}
    foreach($c in $certs)
    {
        remove-item $c.PSPath
    }
}

if(CreateSelfSignedCertificate)
{
    ExportPFXFile
    RemoveCertsFromStore
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-RemoteADSyncCycle.ps1
`powershell

function Invoke-RemoteADSyncCycle {
    <#
    .SYNOPSIS
        Triggers Start-ADSyncSyncCycle (Delta/Initial) on the remote host.
    .OUTPUTS
        [pscustomobject] result with ComputerName, PolicyType, Status, Errors
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][ValidateSet('Delta', 'Initial')][string]$PolicyType
    )

    if ($PSCmdlet.ShouldProcess(("ADSync on $($Session.ComputerName)"), "Start-ADSyncSyncCycle ($PolicyType)")) {
        return Invoke-Command -Session $Session -ScriptBlock {
            try {
                Start-ADSyncSyncCycle -PolicyType $using:PolicyType | Out-Null
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    PolicyType   = $using:PolicyType
                    Status       = 'SyncTriggered'
                    Errors       = ''
                }
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    PolicyType   = $using:PolicyType
                    Status       = 'SyncFailed'
                    Errors       = $_.Exception.Message
                }
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-AADSyncRemote.ps1
`powershell

function Test-AADSyncRemote {
    <#
    .SYNOPSIS
        Validates ADSync module import and service state on the remote host.
    .OUTPUTS
        [pscustomobject] with ComputerName, Status, Errors
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)

    return Invoke-Command -Session $Session -ScriptBlock {
        $errors = @()
        try { Import-Module ADSync -ErrorAction Stop } catch {
            $errors += "ADSync module not found or failed to import: $($_.Exception.Message)"
        }
        $svc = Get-Service -Name 'ADSync' -ErrorAction SilentlyContinue
        if (-not $svc) {
            $errors += "ADSync service not found."
        }
        elseif ($svc.Status -ne 'Running') {
            $errors += "ADSync service state is '$($svc.Status)'; expected 'Running'."
        }
        if ($errors.Count -gt 0) {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Status       = 'PreCheckFailed'
                Errors       = ($errors -join '; ')
            }
        }
        else {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Status       = 'PreCheckPassed'
                Errors       = ''
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Disable-ADUserAccount.ps1
`powershell
function Disable-ADUserAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter()]
        [string]$DisabledOU
    )

    Write-Log -Level Info -Message ("Disabling AD account: {0}" -f $SamAccountName)

    try {
        # Disable the account
        Disable-ADAccount -Identity $SamAccountName -ErrorAction Stop

        Write-Log -Level Ok -Message ("AD account disabled: {0}" -f $SamAccountName)

        # Move to Disabled OU if provided
        if ($DisabledOU) {
            try {
                Move-ADObject -Identity (Get-ADUser -Identity $SamAccountName).DistinguishedName `
                              -TargetPath $DisabledOU -ErrorAction Stop

                Write-Log -Level Ok -Message ("Moved to Disabled OU: {0}" -f $DisabledOU)
                $moved = $true
            }
            catch {
                Write-Log -Level Warn -Message ("Failed to move user to Disabled OU: {0}" -f $_.Exception.Message)
                $moved = $false
            }
        }
        else {
            $moved = $false
        }

        # Optional: stamp description
        try {
            Set-ADUser -Identity $SamAccountName `
                -Description ("Disabled by TechToolbox on {0}" -f (Get-Date)) `
                -ErrorAction Stop

            Write-Log -Level Info -Message "Stamped AD description with offboarding note."
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to update AD description: {0}" -f $_.Exception.Message)
        }

        return [pscustomobject]@{
            Action        = "Disable-ADUserAccount"
            SamAccountName = $SamAccountName
            Disabled       = $true
            MovedToOU      = $moved
            OU             = $DisabledOU
            Success        = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to disable AD account {0}: {1}" -f $SamAccountName, $_.Exception.Message)

        return [pscustomobject]@{
            Action        = "Disable-ADUserAccount"
            SamAccountName = $SamAccountName
            Disabled       = $false
            MovedToOU      = $false
            OU             = $DisabledOU
            Success        = $false
            Error          = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Format-UserRecord.ps1
`powershell
function Format-UserRecord {
    <#
    .SYNOPSIS
        Normalizes user data from local Active Directory (AD-only) to a single
        record.
    .DESCRIPTION
        Accepts a raw AD user object (Get-ADUser -Properties * recommended) and
        outputs a unified PSCustomObject, including:
          - Identity: Sam, UPN, DisplayName, ObjectGuid, DN
          - Mailbox: Primary SMTP (from proxyAddresses), all SMTP aliases
          - Useful attributes: Enabled, WhenCreated, LastLogon, Department,
            Title
          - Manager resolution: name, UPN, sAM, mail (from manager DN)
          - MemberOf resolution: group Name, sAM, Scope/Category (from DNs)
            Caches manager and group lookups within the session to avoid
            repeated queries.
    .PARAMETER AD
        Raw AD user object (Get-ADUser -Properties * result).
    .PARAMETER Server
        Optional domain controller to target (e.g., dc01.domain.local).
    .PARAMETER Credential
        Optional PSCredential for AD lookups (manager/group resolution).
    .PARAMETER ResolveManager
        Resolve Manager DN to user details (default: On).
    .PARAMETER ResolveGroups
        Resolve MemberOf DNs to group details (default: On).
    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName, Mandatory = $true)]
        $AD,

        [string]$Server,
        [pscredential]$Credential,

        [switch]$ResolveManager,
        [switch]$ResolveGroups
    )

    begin {
        # Prepare caches (module/script-scoped, session-lifetime)
        if (-not (Get-Variable -Name __TT_ManagerCache -Scope Script -ErrorAction SilentlyContinue)) {
            Set-Variable -Name __TT_ManagerCache -Scope Script -Value (@{}) -Force
        }
        if (-not (Get-Variable -Name __TT_GroupCache -Scope Script -ErrorAction SilentlyContinue)) {
            Set-Variable -Name __TT_GroupCache -Scope Script -Value (@{}) -Force
        }

        # Prepare caches (session-scoped)
        if (-not $script:__TT_ManagerCache) { $script:__TT_ManagerCache = @{} }
        if (-not $script:__TT_GroupCache) { $script:__TT_GroupCache = @{} }

        function Convert-FileTimeSafe {
            param([Nullable[long]]$FileTime)
            if (-not $FileTime) { return $null }
            try { [DateTime]::FromFileTimeUtc([Int64]$FileTime) } catch { $null }
        }

        function Get-CachedADUserByDn {
            param([string]$Dn, [string]$Server, [pscredential]$Credential)
            if (-not $Dn) { return $null }
            $key = $Dn.ToLowerInvariant()
            if ($script:__TT_ManagerCache.ContainsKey($key)) { return $script:__TT_ManagerCache[$key] }

            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw "ActiveDirectory module is not available. Install RSAT or run on a domain-joined admin workstation."
            }
            Import-Module ActiveDirectory -ErrorAction Stop

            try {
                $p = @{
                    Identity    = $Dn
                    Properties  = @('DisplayName', 'UserPrincipalName', 'SamAccountName', 'mail')
                    ErrorAction = 'Stop'
                }
                if ($Server) { $p['Server'] = $Server }
                if ($Credential) { $p['Credential'] = $Credential }
                $u = Get-ADUser @p
                $script:__TT_ManagerCache[$key] = $u
                return $u
            }
            catch {
                $script:__TT_ManagerCache[$key] = $null
                return $null
            }
        }

        function Get-CachedADGroupByDn {
            param([string]$Dn, [string]$Server, [pscredential]$Credential)
            if (-not $Dn) { return $null }
            $key = $Dn.ToLowerInvariant()
            if ($script:__TT_GroupCache.ContainsKey($key)) { return $script:__TT_GroupCache[$key] }

            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw "ActiveDirectory module is not available. Install RSAT or run on a domain-joined admin workstation."
            }
            Import-Module ActiveDirectory -ErrorAction Stop

            try {
                $p = @{
                    Identity    = $Dn
                    Properties  = @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope')
                    ErrorAction = 'Stop'
                }
                if ($Server) { $p['Server'] = $Server }
                if ($Credential) { $p['Credential'] = $Credential }
                $g = Get-ADGroup @p
                $script:__TT_GroupCache[$key] = $g
                return $g
            }
            catch {
                $script:__TT_GroupCache[$key] = $null
                return $null
            }
        }

        function Parse-ProxyAddresses {
            param([object]$AdUser)
            $raw = @()
            if ($AdUser -and $AdUser.PSObject.Properties['proxyAddresses'] -and $AdUser.proxyAddresses) {
                $raw = @($AdUser.proxyAddresses)
            }
            $primary = ($raw | Where-Object { $_ -is [string] -and $_.StartsWith('SMTP:') } | Select-Object -First 1)
            $primaryEmail = if ($primary) { $primary.Substring(5) } else { $null }

            # All SMTP (primary + aliases), normalized to bare addresses
            $allSmtp = $raw |
            Where-Object { $_ -is [string] -and $_ -match '^(?i)smtp:' } |
            ForEach-Object { $_ -replace '^(?i)smtp:', '' }

            [pscustomobject]@{
                PrimarySmtp = $primaryEmail
                AllSmtp     = $allSmtp
                Raw         = $raw
            }
        }
    }

    process {
        $oldEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        try {
            if (-not $AD) { return $null }

            # Core identity fields
            $sam = $AD.PSObject.Properties['SamAccountName']    ? $AD.SamAccountName    : $null
            $upn = $AD.PSObject.Properties['UserPrincipalName'] ? $AD.UserPrincipalName : $null
            $dn = $AD.PSObject.Properties['DistinguishedName'] ? $AD.DistinguishedName : $null
            $mail = $AD.PSObject.Properties['Mail']              ? $AD.Mail              : $null
            $name = if ($AD.PSObject.Properties['DisplayName'] -and $AD.DisplayName) { $AD.DisplayName } elseif ($AD.PSObject.Properties['Name']) { $AD.Name } else { $null }

            # ProxyAddresses -> mailbox (primary + aliases)
            $px = Parse-ProxyAddresses -AdUser $AD
            $primarySmtp = $px.PrimarySmtp
            $allSmtp = $px.AllSmtp
            $proxyRaw = $px.Raw

            # Fill Mail using primary SMTP, then UPN if still blank
            if (-not $mail -and $primarySmtp) { $mail = $primarySmtp }
            if (-not $mail -and $upn) { $mail = $upn }

            # Manager resolution (DN -> user)
            $mgrDn = $AD.PSObject.Properties['Manager'] ? $AD.Manager : $null
            $mgrUpn = $null; $mgrName = $null; $mgrSam = $null; $mgrMail = $null
            if ($ResolveManager -and $mgrDn) {
                $mgr = Get-CachedADUserByDn -Dn $mgrDn -Server $Server -Credential $Credential
                if ($mgr) {
                    $mgrUpn = $mgr.UserPrincipalName
                    $mgrName = $mgr.DisplayName
                    $mgrSam = $mgr.SamAccountName
                    $mgrMail = $mgr.mail
                }
            }

            # Group resolution
            $memberOfDn = @()
            if ($AD.PSObject.Properties['MemberOf'] -and $AD.MemberOf) { $memberOfDn = @($AD.MemberOf) }

            $memberOfResolved = @()
            $memberOfNames = @()
            $memberOfSams = @()

            if ($ResolveGroups -and $memberOfDn.Count -gt 0) {
                foreach ($gDn in $memberOfDn) {
                    $g = Get-CachedADGroupByDn -Dn $gDn -Server $Server -Credential $Credential
                    if ($g) {
                        $memberOfResolved += [pscustomobject]@{
                            Name              = $g.Name
                            SamAccountName    = $g.SamAccountName
                            GroupScope        = $g.GroupScope
                            GroupCategory     = $g.GroupCategory
                            DistinguishedName = $g.DistinguishedName
                            ObjectGuid        = $g.ObjectGuid
                        }
                        $memberOfNames += $g.Name
                        $memberOfSams += $g.SamAccountName
                    }
                    else {
                        $memberOfResolved += [pscustomobject]@{
                            Name              = $null
                            SamAccountName    = $null
                            GroupScope        = $null
                            GroupCategory     = $null
                            DistinguishedName = $gDn
                            ObjectGuid        = $null
                        }
                    }
                }
            }

            # LastLogonTimestamp -> DateTime (UTC)
            $lastLogon = $null
            if ($AD.PSObject.Properties['lastLogonTimestamp'] -and $AD.lastLogonTimestamp) {
                $lastLogon = Convert-FileTimeSafe $AD.lastLogonTimestamp
            }

            # --- Password/Expiry calculations (AD-only) ---
            # "Password never expires" flag (redundancy-safe: uses both the friendly prop and the UAC bit)
            $PasswordNeverExpires = $false
            if ($AD.PSObject.Properties['PasswordNeverExpires']) {
                $PasswordNeverExpires = [bool]$AD.PasswordNeverExpires
            }
            if ($AD.PSObject.Properties['userAccountControl']) {
                # UAC bit 0x10000 = DON'T_EXPIRE_PASSWORD
                $PasswordNeverExpires = $PasswordNeverExpires -or ( ($AD.userAccountControl -band 0x10000) -ne 0 )
            }

            # Must change at next logon => pwdLastSet = 0
            $MustChangePasswordAtNextLogon = $false
            if ($AD.PSObject.Properties['pwdLastSet']) {
                $MustChangePasswordAtNextLogon = ($AD.pwdLastSet -eq 0)
            }

            # Try to get the computed expiry time (works with FGPP)
            $PasswordExpiryTime = $null
            if ($AD.PSObject.Properties['msDS-UserPasswordExpiryTimeComputed'] -and $AD.'msDS-UserPasswordExpiryTimeComputed') {
                try {
                    $PasswordExpiryTime = [datetime]::FromFileTimeUtc([int64]$AD.'msDS-UserPasswordExpiryTimeComputed').ToLocalTime()
                }
                catch {
                    $PasswordExpiryTime = $null
                }
            }

            # Fall back to constructed PasswordExpired if present (some DCs expose it)
            $PasswordExpired = $null
            if ($MustChangePasswordAtNextLogon) {
                $PasswordExpired = $true
            }
            elseif ($PasswordNeverExpires) {
                $PasswordExpired = $false
            }
            elseif ($PasswordExpiryTime) {
                $PasswordExpired = ($PasswordExpiryTime -le (Get-Date))
            }
            elseif ($AD.PSObject.Properties['PasswordExpired']) {
                # Last resort (constructed attribute, not always populated).
                $PasswordExpired = [bool]$AD.PasswordExpired
            }

            # Convenience: how many days remain until expiry
            $DaysUntilPasswordExpiry = $null
            if ($PasswordExpiryTime) {
                $DaysUntilPasswordExpiry = [int]([math]::Floor(($PasswordExpiryTime - (Get-Date)).TotalDays))
            }

            # Emit normalized AD-only record
            [pscustomobject]@{
                # Identity
                SamAccountName                = $sam
                UserPrincipalName             = $upn
                DisplayName                   = $name
                ObjectGuid                    = $AD.ObjectGuid
                DistinguishedName             = $dn

                # Mailbox / addresses
                Mail                          = $mail
                PrimarySmtpAddress            = $primarySmtp
                SmtpAddresses                 = $allSmtp
                ProxyAddressesRaw             = $proxyRaw

                # AD attributes
                Enabled                       = ($AD.PSObject.Properties['Enabled']      ? [bool]$AD.Enabled : $null)
                WhenCreated                   = ($AD.PSObject.Properties['whenCreated']  ? $AD.whenCreated   : $null)
                LastLogon                     = $lastLogon
                Department                    = ($AD.PSObject.Properties['Department']   ? $AD.Department    : $null)
                Title                         = ($AD.PSObject.Properties['Title']        ? $AD.Title         : $null)

                # Manager (resolved)
                ManagerDn                     = $mgrDn
                ManagerUpn                    = $mgrUpn
                ManagerName                   = $mgrName
                ManagerSamAccountName         = $mgrSam
                ManagerMail                   = $mgrMail

                # Group membership (resolved)
                MemberOfDn                    = $memberOfDn
                MemberOfNames                 = $memberOfNames
                MemberOfSamAccountNames       = $memberOfSams
                MemberOfResolved              = $memberOfResolved

                # Password / expiry (AD-only)
                PasswordExpired               = $PasswordExpired
                PasswordExpiryTime            = $PasswordExpiryTime
                DaysUntilPasswordExpiry       = $DaysUntilPasswordExpiry
                MustChangePasswordAtNextLogon = $MustChangePasswordAtNextLogon
                PasswordNeverExpires          = $PasswordNeverExpires

                # Provenance
                Source                        = 'AD'
                FoundInAD                     = $true

                # Raw for troubleshooting
                RawAD                         = $AD
            }

        }
        catch {
            if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level Error -Message ("[Format-UserRecord] Failed: {0}" -f $_.Exception.Message)
            }
            else {
                Write-Error ("[Format-UserRecord] Failed: {0}" -f $_.Exception.Message)
            }
            throw
        }
        finally {
            $ErrorActionPreference = $oldEAP
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Move-UserToDisabledOU.ps1
`powershell
function Move-UserToDisabledOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName,

        [Parameter(Mandatory)]
        [string]$TargetOU
    )

    Write-Log -Level Info -Message ("Moving AD user '{0}' to Disabled OU..." -f $SamAccountName)

    try {
        $user = Get-ADUser -Identity $SamAccountName -ErrorAction Stop

        Move-ADObject -Identity $user.DistinguishedName `
            -TargetPath $TargetOU `
            -ErrorAction Stop

        Write-Log -Level Ok -Message ("Moved '{0}' to {1}" -f $SamAccountName, $TargetOU)

        return [pscustomobject]@{
            Action         = "Move-UserToDisabledOU"
            SamAccountName = $SamAccountName
            TargetOU       = $TargetOU
            Success        = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to move user '{0}' to Disabled OU: {1}" -f $SamAccountName, $_.Exception.Message)

        return [pscustomobject]@{
            Action         = "Move-UserToDisabledOU"
            SamAccountName = $SamAccountName
            TargetOU       = $TargetOU
            Success        = $false
            Error          = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Remove-ADUserGroups.ps1
`powershell
function Remove-ADUserGroups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SamAccountName
    )

    Write-Log -Level Info -Message ("Cleaning up AD group memberships for: {0}" -f $SamAccountName)

    $protectedGroups = @(
        "Domain Users",
        "Authenticated Users",
        "Everyone",
        "Users"
    )

    try {
        $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf -ErrorAction Stop
    }
    catch {
        Write-Log -Level Error -Message ("Failed to retrieve AD user {0}: {1}" -f $SamAccountName, $_.Exception.Message)
        return [pscustomobject]@{
            Action         = "Cleanup-ADUserGroups"
            SamAccountName = $SamAccountName
            Success        = $false
            Error          = $_.Exception.Message
        }
    }

    $removed = @()
    $failed = @()

    foreach ($dn in $user.MemberOf) {
        try {
            $group = Get-ADGroup -Identity $dn -ErrorAction Stop

            # Skip protected groups
            if ($protectedGroups -contains $group.Name) {
                Write-Log -Level Info -Message ("Skipping protected group: {0}" -f $group.Name)
                continue
            }

            # Remove membership
            Remove-ADGroupMember -Identity $group.DistinguishedName `
                -Members $user.DistinguishedName `
                -Confirm:$false `
                -ErrorAction Stop

            Write-Log -Level Ok -Message ("Removed from group: {0}" -f $group.Name)
            $removed += $group.Name
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to remove from group {0}: {1}" -f $dn, $_.Exception.Message)
            $failed += $dn
        }
    }

    return [pscustomobject]@{
        Action         = "Cleanup-ADUserGroups"
        SamAccountName = $SamAccountName
        Removed        = $removed
        Failed         = $failed
        Success        = $true
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Write-OffboardingSummary.ps1
`powershell
function Write-OffboardingSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $User,

        [Parameter(Mandatory)]
        $Results
    )

    Write-Log -Level Info -Message ("Writing offboarding summary for: {0}" -f $User.UserPrincipalName)

    try {
        # Load config
        $cfg = Get-TechToolboxConfig
        $off = $cfg['settings']['offboarding']

        # Determine output directory from config
        $root = $off.logDir
        if (-not $root) {
            # Fallback for safety
            $root = Join-Path $env:TEMP "TechToolbox-Offboarding"
            Write-Log -Level Warn -Message "offboarding.logDir not found in config. Using TEMP fallback."
        }

        # Ensure directory exists
        if (-not (Test-Path $root)) {
            New-Item -Path $root -ItemType Directory | Out-Null
        }

        # Filename
        $file = Join-Path $root ("OffboardingSummary_{0}_{1}.txt" -f `
                $User.SamAccountName, (Get-Date -Format "yyyyMMdd_HHmmss"))

        # Build summary content
        $lines = @()
        $lines += "==============================================="
        $lines += " TechToolbox Offboarding Summary"
        $lines += "==============================================="
        $lines += ""
        $lines += "User:              {0}" -f $User.UserPrincipalName
        $lines += "Display Name:      {0}" -f $User.DisplayName
        $lines += "SamAccountName:    {0}" -f $User.SamAccountName
        $lines += "Timestamp:         {0}" -f (Get-Date)
        $lines += ""
        $lines += "-----------------------------------------------"
        $lines += " Actions Performed"
        $lines += "-----------------------------------------------"

        foreach ($key in $Results.Keys) {
            $step = $Results[$key]

            $lines += ""
            $lines += "[{0}]" -f $step.Action
            $lines += "  Success: {0}" -f $step.Success

            foreach ($p in $step.PSObject.Properties.Name) {
                if ($p -in @("Action", "Success")) { continue }
                $value = $step.$p
                if ($null -eq $value) { $value = "" }
                $lines += "  {0}: {1}" -f $p, $value
            }
        }

        $lines += ""
        $lines += "==============================================="
        $lines += " End of Summary"
        $lines += "==============================================="

        # Write file
        $lines | Out-File -FilePath $file -Encoding UTF8

        Write-Log -Level Ok -Message ("Offboarding summary written to: {0}" -f $file)

        return [pscustomobject]@{
            Action   = "Write-OffboardingSummary"
            FilePath = $file
            Success  = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to write offboarding summary: {0}" -f $_.Exception.Message)

        return [pscustomobject]@{
            Action  = "Write-OffboardingSummary"
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-LocalLLM.ps1
`powershell
function Invoke-LocalLLM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [string]$Model = "mistral"
    )

    $body = @{
        model  = $Model
        prompt = $Prompt
    } | ConvertTo-Json

    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)

    $request = New-Object System.Net.Http.HttpRequestMessage
    $request.Method = [System.Net.Http.HttpMethod]::Post
    $request.RequestUri = "http://localhost:11434/api/generate"
    $request.Content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")

    $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
    $stream = $response.Content.ReadAsStreamAsync().Result
    $reader = New-Object System.IO.StreamReader($stream)

    $fullText = ""

    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()

        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        try {
            $obj = $line | ConvertFrom-Json
        }
        catch {
            continue
        }

        if ($obj.response) {
            $fullText += $obj.response
        }
    }

    Write-Log -Level Info -Message ""
    return $fullText
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Clear-CacheForProfile.ps1
`powershell

function Clear-CacheForProfile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory)][string]$ProfilePath)

    $cacheTargets = @(
        (Join-Path $ProfilePath 'Cache'),
        (Join-Path $ProfilePath 'Code Cache'),
        (Join-Path $ProfilePath 'GPUCache'),
        (Join-Path $ProfilePath 'Service Worker'),
        (Join-Path $ProfilePath 'Application Cache'),
        (Join-Path $ProfilePath 'Network\Cache')
    )

    $removedCount = 0
    foreach ($cachePath in $cacheTargets) {
        try {
            if (Test-Path -LiteralPath $cachePath) {
                if ($PSCmdlet.ShouldProcess($cachePath, 'Clear cache contents')) {
                    Remove-Item -LiteralPath (Join-Path $cachePath '*') -Recurse -Force -ErrorAction SilentlyContinue
                    $removedCount++
                    Write-Log -Level Ok -Message "Cleared cache content: $cachePath"
                }
            }
            else {
                Write-Log -Level Info -Message "Cache path not present: $cachePath"
            }
        }
        catch {
            Write-Log -Level Warn -Message ("Error clearing cache at '{0}': {1}" -f $cachePath, $_.Exception.Message)
        }
    }

    [PSCustomObject]@{
        CacheTargetsProcessed = $cacheTargets.Count
        CacheTargetsCleared   = $removedCount
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Clear-CookiesForProfile.ps1
`powershell

function Clear-CookiesForProfile {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$ProfilePath,

        [Parameter()]
        [bool]$SkipLocalStorage = $false
    )

    # Common cookie DB targets (SQLite + journal)
    $cookieTargets = @(
        (Join-Path $ProfilePath 'Network\Cookies'),
        (Join-Path $ProfilePath 'Network\Cookies-journal'),
        (Join-Path $ProfilePath 'Cookies'),
        (Join-Path $ProfilePath 'Cookies-journal')
    )

    $cookiesRemoved = $false
    foreach ($cookiesPath in $cookieTargets) {
        try {
            if (Test-Path -LiteralPath $cookiesPath) {
                if ($PSCmdlet.ShouldProcess($cookiesPath, 'Delete cookie DB')) {
                    # Attempt a rename first to get around file locks
                    $tmp = "$cookiesPath.bak.$([guid]::NewGuid().ToString('N'))"
                    $renamed = $false
                    try {
                        Rename-Item -LiteralPath $cookiesPath -NewName (Split-Path -Path $tmp -Leaf) -ErrorAction Stop
                        $renamed = $true
                        $cookiesPath = $tmp
                    }
                    catch {
                        # If rename fails (e.g., path not a file or locked), continue with direct delete
                    }

                    Remove-Item -LiteralPath $cookiesPath -Force -ErrorAction SilentlyContinue
                    $cookiesRemoved = $true
                    Write-Log -Level Ok -Message ("Removed cookie DB: {0}" -f $cookiesPath)
                }
            }
            else {
                Write-Log -Level Info -Message ("Cookie DB not present: {0}" -f $cookiesPath)
            }
        }
        catch {
            Write-Log -Level Warn -Message ("Error removing cookies DB '{0}': {1}" -f $cookiesPath, $_.Exception.Message)
        }
    }

    $localStorageCleared = $false
    $localTargets = @()
    if (-not $SkipLocalStorage) {
        # Core local storage path
        $localStoragePath = Join-Path $ProfilePath 'Local Storage'
        $localTargets += $localStoragePath

        # Optional modern/related site data (uncomment any you want)
        $localTargets += @(
            (Join-Path $ProfilePath 'Local Storage\leveldb'),
            (Join-Path $ProfilePath 'IndexedDB'),
            (Join-Path $ProfilePath 'Session Storage')
            # (Join-Path $ProfilePath 'Web Storage')    # rare / variant
            # (Join-Path $ProfilePath 'Storage')         # umbrella in some builds
        )

        foreach ($lt in $localTargets | Select-Object -Unique) {
            if (Test-Path -LiteralPath $lt) {
                try {
                    if ($PSCmdlet.ShouldProcess($lt, 'Clear Local Storage/Site Data')) {
                        Remove-Item -LiteralPath (Join-Path $lt '*') -Recurse -Force -ErrorAction SilentlyContinue
                        $localStorageCleared = $true
                        Write-Log -Level Ok -Message ("Cleared local storage/site data: {0}" -f $lt)
                    }
                }
                catch {
                    Write-Log -Level Warn -Message ("Error clearing local storage at '{0}': {1}" -f $lt, $_.Exception.Message)
                }
            }
            else {
                Write-Log -Level Info -Message ("Local storage path not present: {0}" -f $lt)
            }
        }
    }
    else {
        Write-Log -Level Info -Message "Local storage cleanup skipped by configuration."
    }

    # Return practical status for the driver
    [PSCustomObject]@{
        CookiesRemoved       = $cookiesRemoved
        LocalStorageCleared  = $localStorageCleared
        CookieTargetsChecked = $cookieTargets.Count
        LocalTargetsChecked  = $localTargets.Count
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-BrowserProfileFolders.ps1
`powershell

function Get-BrowserProfileFolders {
    <#
    .SYNOPSIS
    Returns Chromium profile directories (Default, Profile N, Guest Profile).
    Excludes System Profile by default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserDataPath,

        [Parameter()]
        [switch]$IncludeAllNames  # when set, return all directories except 'System Profile'
    )

    if (-not (Test-Path -LiteralPath $UserDataPath)) {
        Write-Log -Level Error -Message "User Data path not found: $UserDataPath"
        return @()
    }

    $dirs = Get-ChildItem -Path $UserDataPath -Directory -ErrorAction SilentlyContinue

    if ($IncludeAllNames) {
        # Return everything except System Profile
        return $dirs | Where-Object { $_.Name -ne 'System Profile' }
    }

    # Default filter: typical Chromium profiles
    $profiles = $dirs | Where-Object {
        $_.Name -eq 'Default' -or
        $_.Name -match '^Profile \d+$' -or
        $_.Name -eq 'Guest Profile'
    }

    # Exclude internal/system profile explicitly
    $profiles = $profiles | Where-Object { $_.Name -ne 'System Profile' }

    return $profiles
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-BrowserUserDataPath.ps1
`powershell

function Get-BrowserUserDataPath {
    <#
    .SYNOPSIS
    Returns the Chromium 'User Data' path for Chrome/Edge on Windows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Chrome', 'Edge')]
        [string]$Browser
    )

    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrWhiteSpace($base)) {
        Write-Log -Level Error -Message "LOCALAPPDATA is not set; cannot resolve User Data path."
        return $null
    }

    $path = switch ($Browser) {
        'Chrome' { Join-Path $base 'Google\Chrome\User Data' }
        'Edge' { Join-Path $base 'Microsoft\Edge\User Data' }
    }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Log -Level Warn -Message "User Data path not found for ${Browser}: $path"
        # still return it; the caller will handle empty profile enumeration gracefully
    }

    return $path
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Connect-ExchangeOnlineIfNeeded.ps1
`powershell

function Connect-ExchangeOnlineIfNeeded {
    <#
    .SYNOPSIS
        Connects to Exchange Online only if no active connection exists.
    .PARAMETER ShowProgress
        Whether to show progress per config (ExchangeOnline.ShowProgress).
    #>
    [CmdletBinding()]
    param([Parameter()][bool]$ShowProgress = $false)

    try {
        $active = $null
        try { $active = Get-ConnectionInformation } catch { }
        if (-not $active) {
            Write-Log -Level Info -Message "Connecting to Exchange Online..."
            Connect-ExchangeOnline -ShowProgress:$ShowProgress
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
        throw
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Export-MessageTraceResults.ps1
`powershell

function Export-MessageTraceResults {
    <#
    .SYNOPSIS
        Exports message trace summary and details to CSV.
    .DESCRIPTION
        Creates the export folder if needed and writes Summary/Details CSVs.
        Honours -WhatIf/-Confirm via SupportsShouldProcess.
    .PARAMETER Summary
        Summary objects (Received, SenderAddress, RecipientAddress, Subject,
        Status, MessageTraceId).
    .PARAMETER Details
        Detail objects (Recipient, MessageTraceId, Date, Event, Detail).
    .PARAMETER ExportFolder
        Target folder for CSVs.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][object[]]$Summary,
        [Parameter()][object[]]$Details,
        [Parameter(Mandatory)][string]$ExportFolder
    )

    $cfg = Get-TechToolboxConfig
    $ExportFolder = $cfg["settings"]["messageTrace"]["defaultExportFolder"]
    $summaryPattern = $cfg["settings"]["messageTrace"]["summaryFileNamePattern"]
    $detailsPattern = $cfg["settings"]["messageTrace"]["detailsFileNamePattern"]
    $tsFormat = $cfg["settings"]["messageTrace"]["timestampFormat"]

    try {
        if ($PSCmdlet.ShouldProcess($ExportFolder, 'Ensure export folder')) {
            if (-not (Test-Path -LiteralPath $ExportFolder)) {
                New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
            }
        }

        $ts = (Get-Date).ToString($tsFormat)
        $sumPath = Join-Path -Path $ExportFolder -ChildPath ($summaryPattern -f $ts)
        $detPath = Join-Path -Path $ExportFolder -ChildPath ($detailsPattern -f $ts)

        if ($PSCmdlet.ShouldProcess($sumPath, 'Export summary CSV')) {
            $Summary | Export-Csv -Path $sumPath -NoTypeInformation -Encoding UTF8 -UseQuotes AsNeeded
        }

        if (($Details ?? @()).Count -gt 0) {
            if ($PSCmdlet.ShouldProcess($detPath, 'Export details CSV')) {
                $Details | Export-Csv -Path $detPath -NoTypeInformation -Encoding UTF8 -UseQuotes AsNeeded
            }
        }

        Write-Log -Level Ok  -Message "Export complete."
        Write-Log -Level Info -Message (" Summary: {0}" -f $sumPath)

        if (Test-Path -LiteralPath $detPath) {
            Write-Log -Level Info -Message (" Details: {0}" -f $detPath)
        }
    }
    catch {
        Write-Log -Level Error -Message ("Export failed: {0}" -f $_.Exception.Message)
        throw
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Import-ExchangeOnlineModule.ps1
`powershell
function Import-ExchangeOnlineModule {
    [CmdletBinding()]
    param(
        # Drive from config if available
        [string]$DependencyRoot = $cfg.dependencies,
        [string]$requiredVersion = $cfg.dependencies.requiredVersion
    )

    if (-not $DependencyRoot) { $DependencyRoot = 'C:\TechToolbox\Dependencies' }
    if (-not $requiredVersion) { $requiredVersion = '3.9.2' }

    $exoRoot = Join-Path $DependencyRoot 'ExchangeOnlineManagement'
    $manifest = Join-Path (Join-Path $exoRoot $requiredVersion) 'ExchangeOnlineManagement.psd1'

    # 1) Prefer the in-house exact version
    if (Test-Path -LiteralPath $manifest) {
        Import-Module $manifest -Force
        $mod = Get-Module ExchangeOnlineManagement -ListAvailable | Where-Object { $_.Version -eq [version]$requiredVersion } | Select-Object -First 1
        if ($mod) {
            Write-Information "Imported ExchangeOnlineManagement v$requiredVersion from: $($mod.Path)" -InformationAction Continue
            return
        }
        else {
            throw "Unexpected: Could not verify ExchangeOnlineManagement v$requiredVersion after import. Manifest used: $manifest"
        }
    }

    # 2) If the in-house exact version is missing, try discovering the exact version via PSModulePath
    $available = Get-Module ExchangeOnlineManagement -ListAvailable | Sort-Object Version -Descending
    $exact = $available | Where-Object { $_.Version -eq [version]$requiredVersion } | Select-Object -First 1
    if ($exact) {
        Import-Module $exact.Path -Force
        Write-Information "Imported ExchangeOnlineManagement v$requiredVersion from PSModulePath: $($exact.Path)" -InformationAction Continue
        return
    }

    # 3) Fail with actionable guidance
    $paths = ($env:PSModulePath -split ';') -join [Environment]::NewLine
    $msg = @"
TechToolbox: ExchangeOnlineManagement v$requiredVersion not found.
Searched:
  - In-house path: $manifest
  - PSModulePath:
$paths

Fix options:
  - Place the module here: $exoRoot\$requiredVersion\ExchangeOnlineManagement.psd1
  - Or add the dependencies root to PSModulePath (User scope):
      [Environment]::SetEnvironmentVariable(
        'PSModulePath', [Environment]::GetEnvironmentVariable('PSModulePath','User') + ';$DependencyRoot', 'User')
  - Or adjust config: `settings.exchange.online.requiredVersion`
"@
    throw $msg
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-DisconnectExchangeOnline.ps1
`powershell
function Invoke-DisconnectExchangeOnline {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        # Either pass the full config or omit and it will try $global:cfg
        [pscustomobject]$Config,

        # Or pass just the exchangeOnline section explicitly
        [pscustomobject]$ExchangeOnline,

        # Skip prompting and disconnect.
        [switch]$Force,

        # Suppress prompting (opposite of Force: don’t disconnect unless forced).
        [switch]$NoPrompt
    )

    # --- Resolve configuration ---
    $exoCfg = $null

    if ($PSBoundParameters.ContainsKey('ExchangeOnline') -and $ExchangeOnline) {
        $exoCfg = $ExchangeOnline
    }
    elseif ($PSBoundParameters.ContainsKey('Config') -and $Config) {
        # If full config was provided (has settings.exchangeOnline), use that
        if ($Config.PSObject.Properties.Name -contains 'settings' -and
            $Config.settings -and
            $Config.settings.PSObject.Properties.Name -contains 'exchangeOnline') {
            $exoCfg = $Config.settings.exchangeOnline
        }
        # Or if we were given the exchangeOnline section directly (has autoDisconnectPrompt), use it
        elseif ($Config.PSObject.Properties.Name -contains 'autoDisconnectPrompt') {
            $exoCfg = $Config
        }
    }
    elseif ($global:cfg) {
        $exoCfg = $global:cfg.settings.exchangeOnline
    }

    # Default: prompt unless config says otherwise
    $autoPrompt = $true
    if ($exoCfg -and $null -ne $exoCfg.autoDisconnectPrompt) {
        $autoPrompt = [bool]$exoCfg.autoDisconnectPrompt
    }

    $shouldPrompt = $autoPrompt -and -not $Force -and -not $NoPrompt

    # --- Connection check ---
    $isConnected = $false
    try {
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue
            $isConnected = $conn -and $conn.State -eq 'Connected'
        }
        else {
            # Older module: we can't reliably check; assume connected and let disconnect handle it
            $isConnected = $true
        }
    }
    catch {
        # If uncertain, err on the side of attempting a disconnect
        $isConnected = $true
    }

    if (-not $isConnected) {
        Write-Log -Level Info -Message "No active Exchange Online session detected."
        return $true
    }

    # --- Decide whether to proceed ---
    $proceed = $false
    if ($Force) {
        $proceed = $true
    }
    elseif ($shouldPrompt) {
        $resp = Read-Host -Prompt "Disconnect from Exchange Online? (y/N)"
        $proceed = ($resp.Trim() -match '^(y|yes)$')
    }

    if (-not $proceed) {
        Write-Log -Level Info -Message "Keeping Exchange Online session connected."
        return $false
    }

    # --- Disconnect ---
    if ($PSCmdlet.ShouldProcess('Exchange Online session', 'Disconnect')) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Log -Level Info -Message "Disconnected from Exchange Online."
            return $true
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to disconnect cleanly: {0}" -f $_.Exception.Message)
            Write-Log -Level Info -Message "Session may remain connected."
            return $false
        }
    }

    return $false
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Read-Int.ps1
`powershell

function Read-Int {
    <#
    .SYNOPSIS
        Prompts the user to enter an integer within specified bounds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter()][int]$Min = 16,
        [Parameter()][int]$Max = 2097152
    )

    while ($true) {
        $value = Read-Host $Prompt
        if ([int]::TryParse($value, [ref]$parsed)) {
            if ($parsed -ge $Min -and $parsed -le $Max) {
                return $parsed
            }
            Write-Log -Level Warning -Message "Enter a value between $Min and $Max."
        }
        else {
            Write-Log -Level Warning -Message "Enter a whole number (MB)."
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-Config.ps1
`powershell

function Initialize-Config {
    [CmdletBinding()]
    param()

    # Ensure ModuleRoot is set
    if (-not $script:ModuleRoot) {
        $script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase
    }

    # Paths
    $configDir = Join-Path $script:ModuleRoot 'Config'
    $script:ConfigPath = Join-Path $configDir 'config.json'

    # Ensure config dir exists (but do NOT create or modify config.json here)
    if (-not (Test-Path -LiteralPath $configDir)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    }

    # Load config.json as hashtable using your authoritative loader
    try {
        $script:cfg = Get-TechToolboxConfig -Path $script:ConfigPath  # returns a nested hashtable
    }
    catch {
        throw "[Initialize-Config] Failed to load config.json from '$script:ConfigPath': $($_.Exception.Message)"
    }

    # Optional: back-compat alias, if any code still references TechToolboxConfig
    $script:TechToolboxConfig = $script:cfg
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-Environment.ps1
`powershell
function Initialize-Environment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        # Where to persist the PATH change. 'Machine' requires elevation.
        [ValidateSet('User', 'Machine')]
        [string]$Scope = 'User',

        # The dependency path you want to ensure on PATH.
        [Parameter()]
        [string]$DependencyPath = 'C:\TechToolbox\Dependencies',

        # Create the dependency directory if it doesn't exist.
        [switch]$CreateIfMissing
    )

    $infoAction = if ($PSBoundParameters.ContainsKey('InformationAction')) { $InformationPreference } else { 'Continue' }

    # 1) Normalize target path early
    try {
        $normalizedPath = [System.IO.Path]::GetFullPath($DependencyPath)
    }
    catch {
        Write-Warning "Initialize-Environment: Invalid path: [$DependencyPath]. $_"
        return
    }

    # 2) Ensure directory exists (optional)
    if (-not (Test-Path -LiteralPath $normalizedPath)) {
        if ($CreateIfMissing) {
            try {
                $null = New-Item -ItemType Directory -Path $normalizedPath -Force
                Write-Information "Created directory: [$normalizedPath]" -InformationAction $infoAction
            }
            catch {
                Write-Warning "Failed to create directory [$normalizedPath]: $($_.Exception.Message)"
                return
            }
        }
        else {
            Write-Information "Dependency path does not exist: [$normalizedPath]. Skipping PATH update." -InformationAction $infoAction
            return
        }
    }

    # 3) Read current PATH for chosen scope
    $currentPathRaw = [Environment]::GetEnvironmentVariable('Path', $Scope)

    # 4) Normalize & de-duplicate PATH parts (case-insensitive comparison)
    $sep = ';'
    $parts =
    ($currentPathRaw -split $sep) |
    Where-Object { $_ -and $_.Trim() } |
    ForEach-Object { $_.Trim() } |
    Select-Object -Unique

    # Use case-insensitive membership check
    $contains = $false
    foreach ($p in $parts) {
        if ($p.TrimEnd('\') -ieq $normalizedPath.TrimEnd('\')) {
            $contains = $true
            break
        }
    }

    if (-not $contains) {
        $newPath = @($parts + $normalizedPath) -join $sep

        if ($PSCmdlet.ShouldProcess("$Scope PATH", "Add [$normalizedPath]")) {
            try {
                [Environment]::SetEnvironmentVariable('Path', $newPath, $Scope)
                Write-Information "Added [$normalizedPath] to $Scope PATH." -InformationAction $infoAction
            }
            catch {
                Write-Warning "Failed to update $Scope PATH: $($_.Exception.Message)"
                return
            }

            # 5) Ensure current session has it immediately
            $sessionHas = $false
            foreach ($p in ($env:Path -split $sep)) {
                if ($p.Trim() -and ($p.TrimEnd('\') -ieq $normalizedPath.TrimEnd('\'))) {
                    $sessionHas = $true
                    break
                }
            }
            if (-not $sessionHas) {
                $env:Path = ($env:Path.TrimEnd($sep) + $sep + $normalizedPath).Trim($sep)
            }

            # 6) Broadcast WM_SETTINGCHANGE so new processes pick up changes
            try {
                $signature = @'
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
  [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
  public static extern IntPtr SendMessageTimeout(
    IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags,
    uint uTimeout, out UIntPtr lpdwResult);
}
'@
                Add-Type -TypeDefinition $signature -ErrorAction SilentlyContinue | Out-Null
                $HWND_BROADCAST = [IntPtr]0xffff
                $WM_SETTINGCHANGE = 0x1A
                $SMTO_ABORTIFHUNG = 0x0002
                $result = [UIntPtr]::Zero
                [void][NativeMethods]::SendMessageTimeout($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, 'Environment', $SMTO_ABORTIFHUNG, 5000, [ref]$result)
                Write-Verbose "Broadcasted WM_SETTINGCHANGE (Environment)."
            }
            catch {
                Write-Verbose "Failed to broadcast WM_SETTINGCHANGE: $($_.Exception.Message)"
            }
        }
    }
    else {
        # Ensure current session also has the normalized casing/version
        $needsSessionAppend = $true
        foreach ($p in ($env:Path -split ';')) {
            if ($p.Trim() -and ($p.TrimEnd('\') -ieq $normalizedPath.TrimEnd('\'))) {
                $needsSessionAppend = $false
                break
            }
        }
        if ($needsSessionAppend) {
            $env:Path = ($env:Path.TrimEnd(';') + ';' + $normalizedPath).Trim(';')
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-Interop.ps1
`powershell
function Initialize-Interop {
    $interopRoot = Join-Path $script:ModuleRoot 'Private\Security\Interop'
    if (-not (Test-Path $interopRoot)) { return }

    Get-ChildItem $interopRoot -Filter *.cs -Recurse | ForEach-Object {
        try { Add-Type -Path $_.FullName -ErrorAction Stop }
        catch { }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-Logging.ps1
`powershell

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes TechToolbox logging settings from $script:TechToolboxConfig.

    .OUTPUTS
        [hashtable] - Resolved logging settings.
    #>

    # Ensure a single $script:log state hashtable
    if (-not $script:log -or -not ($script:log -is [hashtable])) {
        $script:log = @{
            enableConsole = $true
            logFile       = $null
            encoding      = 'utf8'    # Can expose this via config later
        }
    }

    $cfg = $script:TechToolboxConfig
    if (-not $cfg) {
        # Keep graceful behavior: console logging only
        $script:log.enableConsole = $true
        $script:log.logFile = $null
        Write-Verbose "Initialize-Logging: No TechToolboxConfig present; using console-only logging."
        return $script:log
    }

    # Safe extraction helpers
    function Get-CfgValue {
        param(
            [Parameter(Mandatory)] [hashtable] $Root,
            [Parameter(Mandatory)] [string[]] $Path
        )
        $node = $Root
        foreach ($k in $Path) {
            if ($node -is [hashtable] -and $node.ContainsKey($k)) {
                $node = $node[$k]
            }
            else {
                return $null
            }
        }
        return $node
    }

    $logDirRaw = Get-CfgValue -Root $cfg -Path @('paths', 'logs')
    $logFileRaw = Get-CfgValue -Root $cfg -Path @('settings', 'logging', 'logFile')
    $enableRaw = Get-CfgValue -Root $cfg -Path @('settings', 'logging', 'enableConsole')

    # Normalize enableConsole to boolean
    $enableConsole = switch ($enableRaw) {
        $true { $true }
        $false { $false }
        default {
            if ($null -eq $enableRaw) { $script:log.enableConsole } else {
                # Handle strings like "true"/"false"
                $t = "$enableRaw".ToLowerInvariant()
                if ($t -in @('true', '1', 'yes', 'y')) { $true } elseif ($t -in @('false', '0', 'no', 'n')) { $false } else { $script:log.enableConsole }
            }
        }
    }

    # Resolve logFile
    $logFile = $null
    if ($logFileRaw) {
        # If relative, resolve under logDir (if present) else make absolute via current location
        if ([System.IO.Path]::IsPathRooted($logFileRaw)) {
            $logFile = $logFileRaw
        }
        elseif ($logDirRaw) {
            $logFile = Join-Path -Path $logDirRaw -ChildPath $logFileRaw
        }
        else {
            $logFile = (Resolve-Path -LiteralPath $logFileRaw -ErrorAction Ignore)?.Path
            if (-not $logFile) { $logFile = (Join-Path (Get-Location) $logFileRaw) }
        }
    }
    elseif ($logDirRaw) {
        $logFile = Join-Path $logDirRaw ("TechToolbox_{0:yyyyMMdd}.log" -f (Get-Date))
    }

    # Create directory if needed
    if ($logFile) {
        try {
            $parent = Split-Path -Path $logFile -Parent
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                [System.IO.Directory]::CreateDirectory($parent) | Out-Null
            }
        }
        catch {
            Write-Warning "Initialize-Logging: Failed to create log directory '$parent'. Using console-only logging. Error: $($_.Exception.Message)"
            $logFile = $null
            $enableConsole = $true
        }
    }

    # Optional: pre-create file to verify writability
    if ($logFile) {
        try {
            if (-not (Test-Path -LiteralPath $logFile)) {
                New-Item -ItemType File -Path $logFile -Force | Out-Null
            }
            # quick write/append test
            Add-Content -LiteralPath $logFile -Value ("`n--- Logging initialized {0:yyyy-MM-dd HH:mm:ss.fff} ---" -f (Get-Date)) -Encoding utf8
        }
        catch {
            Write-Warning "Initialize-Logging: Unable to write to '$logFile'. Falling back to console-only. Error: $($_.Exception.Message)"
            $logFile = $null
            $enableConsole = $true
        }
    }

    # Persist resolved settings
    $script:log['enableConsole'] = $enableConsole
    $script:log['logFile'] = $logFile
    $script:log['encoding'] = 'utf8' # consistent encoding

    return $script:log
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-ModulePath.ps1
`powershell
function Initialize-ModulePath {
    [CmdletBinding()]
    param(
        [ValidateSet('User', 'Machine')]
        [string]$Scope = 'User',

        [Parameter()]
        [string]$ModuleRoot = 'C:\TechToolbox\'
    )

    # Ensure directory exists
    if (-not (Test-Path -LiteralPath $ModuleRoot)) {
        New-Item -ItemType Directory -Path $ModuleRoot -Force | Out-Null
        Write-Information "Created module root: [$ModuleRoot]" -InformationAction Continue
    }

    # Load persisted PSModulePath for the chosen scope (seed from process if empty)
    $current = [Environment]::GetEnvironmentVariable('PSModulePath', $Scope)
    if ([string]::IsNullOrWhiteSpace($current)) { $current = $env:PSModulePath }

    $sep = ';'
    $parts = $current -split $sep | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique
    $needsAdd = -not ($parts | Where-Object { $_.TrimEnd('\') -ieq $ModuleRoot.TrimEnd('\') })

    if ($needsAdd) {
        $new = @($parts + $ModuleRoot) -join $sep
        [Environment]::SetEnvironmentVariable('PSModulePath', $new, $Scope)
    }
    else {
    }

    # Ensure the current session sees it immediately
    $sessionHas = ($env:PSModulePath -split $sep) | Where-Object { $_.TrimEnd('\') -ieq $ModuleRoot.TrimEnd('\') }
    if (-not $sessionHas) {
        $env:PSModulePath = ($env:PSModulePath.TrimEnd($sep) + $sep + $ModuleRoot).Trim($sep)
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-TechToolboxHome.ps1
`powershell
function Initialize-TechToolboxHome {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()][string]$HomePath = 'C:\TechToolbox',
        [Parameter()][string]$SourcePath,       # <-- optional override
        [switch]$Force,
        [switch]$Quiet
    )

    $ErrorActionPreference = 'Stop'

    # Resolve Source (module files location)
    if (-not $SourcePath -or [string]::IsNullOrWhiteSpace($SourcePath)) {
        if ($script:ModuleRoot) {
            $SourcePath = $script:ModuleRoot
        }
        elseif ($MyInvocation.PSScriptRoot) {
            $SourcePath = $MyInvocation.PSScriptRoot
        }
        elseif ($ExecutionContext.SessionState.Module.ModuleBase) {
            $SourcePath = $ExecutionContext.SessionState.Module.ModuleBase
        }
    }

    if (-not $SourcePath) {
        Write-Error "Initialize-TechToolboxHome: Unable to determine source path (ModuleRoot/PSScriptRoot not set)."
        return
    }

    $src = [System.IO.Path]::GetFullPath($SourcePath)
    $home = [System.IO.Path]::GetFullPath($HomePath)

    Write-Verbose ("[Init] Source: {0}" -f $src)
    Write-Verbose ("[Init] Home:   {0}" -f $home)

    if (-not (Test-Path -LiteralPath $src)) {
        Write-Error "Initialize-TechToolboxHome: Source path not found: $src"
        return
    }

    # Short-circuit if already running from home
    if ($src.TrimEnd('\') -ieq $home.TrimEnd('\')) {
        Write-Verbose "Already running from $home — skipping copy."
        return
    }

    # Read module version (optional)
    $manifest = Join-Path $src 'TechToolbox.psd1'
    $version = '0.0.0-dev'
    if (Test-Path $manifest) {
        try {
            $data = Import-PowerShellDataFile -Path $manifest
            if ($data.ModuleVersion) { $version = $data.ModuleVersion }
        }
        catch { Write-Warning "Unable to read module version from psd1." }
    }

    # Check install stamp
    $stampDir = Join-Path $home '.ttb'
    $stampFile = Join-Path $stampDir 'install.json'
    if (-not $Force -and (Test-Path $stampFile)) {
        try {
            $stamp = Get-Content $stampFile -Raw | ConvertFrom-Json
            if ($stamp.version -eq $version) {
                Write-Information "TechToolbox v$version already installed at $home." -InformationAction Continue
                return
            }
        }
        catch { Write-Warning "Unable to parse existing install.json." }
    }

    # Ensure destination exists
    if (-not (Test-Path $home)) {
        if ($PSCmdlet.ShouldProcess($home, "Create destination folder")) {
            New-Item -ItemType Directory -Path $home -Force | Out-Null
            Write-Verbose "Created: $home"
        }
    }

    # Manual confirmation unless -Quiet
    if (-not $Quiet) {
        $resp = Read-Host "Copy TechToolbox $version to $home? (Y/N)"
        if ($resp -notmatch '^(?i)y(es)?$') {
            Write-Information "Copy aborted." -InformationAction Continue
            return
        }
    }

    # Perform copy via robocopy
    $robocopy = "$env:SystemRoot\System32\robocopy.exe"
    if (-not (Test-Path $robocopy)) { throw "robocopy.exe not found." }

    Write-Information "Copying TechToolbox to $home..." -InformationAction Continue

    # Exclude common dev/volatile dirs if you want; otherwise keep it simple
    $args = @("`"$src`"", "`"$home`"", '/MIR', '/COPY:DAT', '/R:2', '/W:1', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $robocopy
    $psi.Arguments = $args -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    $output = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()

    if ($p.ExitCode -gt 7) {
        Write-Verbose $output
        throw "Robocopy failed with exit code $($p.ExitCode)."
    }

    # Write install stamp
    if (-not (Test-Path $stampDir)) { New-Item -ItemType Directory -Path $stampDir -Force | Out-Null }
    $stampJson = @{
        version      = "$version"
        source       = "$src"
        installedUtc = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 3
    Set-Content -Path $stampFile -Value $stampJson -Encoding UTF8

    Write-Information "TechToolbox v$version installed to $home." -InformationAction Continue
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Write-Log.ps1
`powershell

function Write-Log {
    [CmdletBinding()]
    param(
        [ValidateSet('Error', 'Warn', 'Info', 'Ok', 'Debug')]
        [string]$Level,
        [string]$Message
    )

    # ---- Resolve effective logging settings ----
    $enableConsole = $false
    $logFile = $null
    $includeTimestamps = $true

    try {
        if ($script:log -is [hashtable]) {
            $enableConsole = [bool]  $script:log['enableConsole']
            $logFile = [string]$script:log['logFile']
            if ($script:log.ContainsKey('includeTimestamps')) {
                $includeTimestamps = [bool]$script:log['includeTimestamps']
            }
        }
        elseif ($script:cfg -and $script:cfg.settings -and $script:cfg.settings.logging) {
            # Fallback to config if $script:log wasn't initialized yet (rare)
            $enableConsole = [bool]$script:cfg.settings.logging.enableConsole
            # Compose a best-effort file path
            $logPath = [string]$script:cfg.settings.logging.logPath
            $fileFmt = [string]$script:cfg.settings.logging.logFileNameFormat
            $baseFile = [string]$script:cfg.settings.logging.logFile

            # Simple template resolver
            $resolvedName = $null
            if ($fileFmt) {
                $now = Get-Date
                $resolvedName = $fileFmt.
                Replace('{yyyyMMdd}', $now.ToString('yyyyMMdd')).
                Replace('{yyyyMMdd-HHmmss}', $now.ToString('yyyyMMdd-HHmmss')).
                Replace('{computer}', $env:COMPUTERNAME)
            }
            if ([string]::IsNullOrWhiteSpace($resolvedName)) {
                if (-not [string]::IsNullOrWhiteSpace($baseFile)) {
                    $resolvedName = $baseFile
                }
                else {
                    $resolvedName = 'TechToolbox.log'
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($logPath)) {
                $logPath = $logPath.TrimEnd('\', '/')
                $logFile = Join-Path $logPath $resolvedName
            }
            else {
                $logFile = $resolvedName
            }

            if ($script:cfg.settings.logging.PSObject.Properties.Name -contains 'includeTimestamps') {
                $includeTimestamps = [bool]$script:cfg.settings.logging.includeTimestamps
            }
        }
    }
    catch {
        # Don’t throw—fall back to safe defaults
    }

    # ---- Formatting ----
    $timestamp = if ($includeTimestamps) { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + ' ' } else { '' }
    $formatted = "${timestamp}[$Level] $Message"

    # ---- Console output with color ----
    if ($enableConsole) {
        switch ($Level) {
            'Info' { Write-Host $Message -ForegroundColor Gray }
            'Ok' { Write-Host $Message -ForegroundColor Green }
            'Warn' { Write-Host $Message -ForegroundColor Yellow }
            'Error' { Write-Host $Message -ForegroundColor Red }
            'Debug' { Write-Host $Message -ForegroundColor DarkGray }
            default { Write-Host $Message -ForegroundColor Gray }
        }
    }
    else {
        # Surface critical issues even if console is off
        if ($Level -eq 'Error') { Write-Error $Message }
        elseif ($Level -eq 'Warn') { Write-Warning $Message }
    }

    # ---- File logging (defensive) ----
    if ($logFile) {
        try {
            # If we were handed a directory, compose a default file name
            $leaf = Split-Path -Path $logFile -Leaf
            if ([string]::IsNullOrWhiteSpace($leaf)) {
                # It's a directory, append a default file name
                $logFile = Join-Path $logFile 'TechToolbox.log'
                $leaf = Split-Path -Path $logFile -Leaf
            }

            # Ensure parent directory exists
            $dir = Split-Path -Path $logFile -Parent
            if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }

            # Only write if we definitely have a file name
            if (-not [string]::IsNullOrWhiteSpace($leaf)) {
                Add-Content -Path $logFile -Value $formatted
            }
            else {
                if ($enableConsole) {
                    Write-Host "Write-Log: Skipping file write; invalid logFile path (no filename): $logFile" -ForegroundColor Yellow
                }
            }
        }
        catch {
            if ($enableConsole) {
                Write-Host "Failed to write log to ${logFile}: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Convert-MailboxToShared.ps1
`powershell
function Convert-MailboxToShared {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )

    Write-Log -Level Info -Message ("Converting mailbox to shared: {0}" -f $Identity)

    try {
        # Convert the mailbox
        Set-Mailbox -Identity $Identity -Type Shared -ErrorAction Stop

        Write-Log -Level Ok -Message ("Mailbox converted to shared: {0}" -f $Identity)

        return [pscustomobject]@{
            Action   = "Convert-MailboxToShared"
            Identity = $Identity
            Success  = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to convert mailbox for {0}: {1}" -f $Identity, $_.Exception.Message)

        return [pscustomobject]@{
            Action   = "Convert-MailboxToShared"
            Identity = $Identity
            Success  = $false
            Error    = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Grant-ManagerMailboxAccess.ps1
`powershell
function Grant-ManagerMailboxAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,   # The mailbox being accessed

        [Parameter(Mandatory)]
        [string]$ManagerUPN  # The manager receiving access
    )

    Write-Log -Level Info -Message ("Granting mailbox access for '{0}' to manager '{1}'..." -f $Identity, $ManagerUPN)

    $fullAccessGranted = $false
    $sendAsGranted = $false
    $errors = @()

    # --- FullAccess ---
    try {
        Add-MailboxPermission -Identity $Identity `
            -User $ManagerUPN `
            -AccessRights FullAccess `
            -InheritanceType All `
            -AutoMapping:$true `
            -ErrorAction Stop

        Write-Log -Level Ok -Message ("Granted FullAccess to {0}" -f $ManagerUPN)
        $fullAccessGranted = $true
    }
    catch {
        Write-Log -Level Error -Message ("Failed to grant FullAccess: {0}" -f $_.Exception.Message)
        $errors += "FullAccess: $($_.Exception.Message)"
    }

    # --- SendAs ---
    try {
        Add-RecipientPermission -Identity $Identity `
            -Trustee $ManagerUPN `
            -AccessRights SendAs `
            -ErrorAction Stop

        Write-Log -Level Ok -Message ("Granted SendAs to {0}" -f $ManagerUPN)
        $sendAsGranted = $true
    }
    catch {
        Write-Log -Level Error -Message ("Failed to grant SendAs: {0}" -f $_.Exception.Message)
        $errors += "SendAs: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Action     = "Grant-ManagerMailboxAccess"
        Identity   = $Identity
        Manager    = $ManagerUPN
        FullAccess = $fullAccessGranted
        SendAs     = $sendAsGranted
        Success    = ($fullAccessGranted -and $sendAsGranted)
        Errors     = $errors
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Remove-TeamsUser.ps1
`powershell
function Remove-TeamsUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )

    Write-Log -Level Info -Message ("Signing out Teams sessions for: {0}" -f $Identity)

    try {
        # Revoke all refresh tokens (Teams, Outlook, mobile, web, etc.)
        Revoke-MgUserSignInSession -UserId $Identity -ErrorAction Stop

        Write-Log -Level Ok -Message ("Teams and M365 sessions revoked for: {0}" -f $Identity)

        return [pscustomobject]@{
            Action   = "SignOut-TeamsUser"
            Identity = $Identity
            Success  = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to revoke Teams sessions for {0}: {1}" -f $Identity, $_.Exception.Message)

        return [pscustomobject]@{
            Action   = "SignOut-TeamsUser"
            Identity = $Identity
            Success  = $false
            Error    = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SubnetScanLocal.ps1
`powershell

function Invoke-SubnetScanLocal {
    <#
.SYNOPSIS
    Scanning engine used by Invoke-SubnetScan.ps1.
.DESCRIPTION
    Pings each host in a CIDR, (optionally) resolves names, tests port,
    grabs HTTP banner; returns *only responding hosts*. Export is off by default
    so orchestrator can export consistently to settings.subnetScan.exportDir.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$CIDR,
        [int]$Port,
        [switch]$ResolveNames,
        [switch]$HttpBanner,
        [switch]$ExportCsv
    )

    Set-StrictMode -Version Latest
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'

    try {
        # --- CONFIG ---
        $cfg = Get-TechToolboxConfig -Verbose
        if (-not $cfg) { throw "TechToolbox config is null/empty. Ensure Config\config.json exists and is valid JSON." }
        $scanCfg = $cfg['settings']?['subnetScan']
        if (-not $scanCfg) { throw "Config missing 'settings.subnetScan'." }

        # Defaults (only if not passed)
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $scanCfg['defaultPort'] ?? 80 }
        if (-not $PSBoundParameters.ContainsKey('ResolveNames')) { $ResolveNames = [bool]($scanCfg['resolveNames'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('HttpBanner')) { $HttpBanner = [bool]($scanCfg['httpBanner'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('ExportCsv')) { $ExportCsv = [bool]($scanCfg['exportCsv'] ?? $false) }

        # Timeouts / smoothing
        $pingTimeoutMs = $scanCfg['pingTimeoutMs'] ?? 1000
        $tcpTimeoutMs = $scanCfg['tcpTimeoutMs'] ?? 1000
        $httpTimeoutMs = $scanCfg['httpTimeoutMs'] ?? 1500
        $ewmaAlpha = $scanCfg['ewmaAlpha'] ?? 0.30
        $displayAlpha = $scanCfg['displayAlpha'] ?? 0.50

        # Expand CIDR → IP list
        $ips = Get-IPsFromCIDR -CIDR $CIDR
        if (-not $ips -or $ips.Count -eq 0) {
            Write-Log -Level Warn -Message "No hosts found for CIDR $CIDR"
            return @()
        }

        Write-Log -Level Info -Message "Scanning $($ips.Count) hosts..."

        $results = [System.Collections.Generic.List[psobject]]::new()

        # Progress telemetry
        $avgHostMs = 0.0
        $displayPct = 0.0
        $current = 0
        $total = $ips.Count
        $online = 0

        $ping = [System.Net.NetworkInformation.Ping]::new()

        foreach ($ip in $ips) {
            $hostSw = [System.Diagnostics.Stopwatch]::StartNew()

            $result = [pscustomobject]@{
                IP         = $ip
                Responded  = $false
                RTTms      = $null
                MacAddress = $null
                PTR        = $null
                NetBIOS    = $null
                Mdns       = $null
                PortOpen   = $false
                ServerHdr  = $null
                Timestamp  = Get-Date
            }

            try {
                $reply = $ping.Send($ip, $pingTimeoutMs)

                if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $result.Responded = $true
                    $result.RTTms = $reply.RoundtripTime
                    $online++

                    try { $result.MacAddress = Get-MacAddress -ip $ip } catch {}

                    if ($ResolveNames) {
                        try { $result.PTR = Get-ReverseDns -ip $ip } catch {}
                        if (-not $result.PTR) { try { $result.NetBIOS = Get-NetbiosName -ip $ip } catch {} }
                        if (-not $result.PTR -and -not $result.NetBIOS) { try { $result.Mdns = Get-MdnsName -ip $ip } catch {} }
                    }

                    try { $result.PortOpen = Test-TcpPort -ip $ip -port $Port -timeoutMs $tcpTimeoutMs } catch {}

                    if ($HttpBanner -and $result.PortOpen) {
                        try {
                            $hdrs = Get-HttpInfo -ip $ip -port $Port -timeoutMs $httpTimeoutMs
                            if ($hdrs -and $hdrs['Server']) { $result.ServerHdr = $hdrs['Server'] }
                        }
                        catch {}
                    }

                    # Add only responding hosts
                    $results.Add($result)
                }
            }
            catch {
                # ignore host-level exceptions; treat as no response
            }
            finally {
                $hostSw.Stop()
                $durMs = $hostSw.Elapsed.TotalMilliseconds

                if ($avgHostMs -le 0) { $avgHostMs = $durMs }
                else { $avgHostMs = ($ewmaAlpha * $durMs) + ((1 - $ewmaAlpha) * $avgHostMs) }

                $current++
                $actualPct = ($current / $total) * 100
                $displayPct = ($displayAlpha * $actualPct) + ((1 - $displayAlpha) * $displayPct)

                $remaining = $total - $current
                $etaMs = [math]::Max(0, $avgHostMs * $remaining)
                $eta = [TimeSpan]::FromMilliseconds($etaMs)

                Show-ProgressBanner -current $current -total $total -displayPct $displayPct -eta $eta
            }
        }

        $ping.Dispose()
        Write-Log -Level Ok -Message "Local subnet scan complete. $online hosts responded."

        # Remote-side export when explicitly requested (used by ExportTarget=Remote)
        if ($ExportCsv -and $results.Count -gt 0) {
            try {
                $exportDir = $scanCfg['exportDir']
                if (-not $exportDir) { throw "Config 'settings.subnetScan.exportDir' is missing." }
                if (-not (Test-Path -LiteralPath $exportDir)) {
                    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                }
                $cidrSafe = $CIDR -replace '[^\w\-\.]', '_'
                $csvPath = Join-Path $exportDir ("subnet-scan-{0}-{1}.csv" -f $cidrSafe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log -Level Ok -Message "Results exported to $csvPath"
            }
            catch {
                Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
            }
        }
        elseif ($ExportCsv) {
            Write-Log -Level Warn -Message "Export skipped: no responding hosts."
        }

        return $results
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-IPsFromCIDR.ps1
`powershell

function Get-IPsFromCIDR {
    <#
    .SYNOPSIS
        Generates a list of IP addresses from a given CIDR notation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR
    )

    try {
        # Split CIDR into base IP + prefix
        $parts = $CIDR -split '/'
        $baseIP = $parts[0]
        $prefix = [int]$parts[1]

        # Convert base IP to UInt32
        $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

        # Calculate host range
        $hostBits = 32 - $prefix
        $numHosts = [math]::Pow(2, $hostBits) - 2

        if ($numHosts -lt 1) {
            return @()
        }

        $startIP = $ipInt + 1

        $list = for ($i = 0; $i -lt $numHosts; $i++) {
            $cur = $startIP + $i
            $b = [BitConverter]::GetBytes($cur)
            [Array]::Reverse($b)
            [System.Net.IPAddress]::Parse(($b -join '.')).ToString()
        }

        return , $list
    }
    catch {
        Write-Log -Level Error -Message "Get-IPsFromCIDR failed for '$CIDR': $($_.Exception.Message)"
        return @()
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-MacAddress.ps1
`powershell

function Get-MacAddress {
    <#
    .SYNOPSIS
        Retrieves the MAC address for a given IP address from the ARP table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # Query ARP table for the IP
        $arpOutput = arp -a | Where-Object { $_ -match "^\s*$IP\s" }

        if (-not $arpOutput) {
            return $null
        }

        # Extract MAC address pattern
        if ($arpOutput -match '([0-9a-f]{2}[-:]){5}[0-9a-f]{2}') {
            return $matches[0].ToUpper()
        }

        return $null
    }
    catch {
        Write-Log -Level Error -Message "Get-MacAddress failed for $IP $($_.Exception.Message)"
        return $null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-NewPSRemoteSession.ps1
`powershell
function Start-NewPSRemoteSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $ComputerName,

        [Parameter()]
        [pscredential] $Credential,

        [Parameter()]
        [switch] $UseSsh,

        [Parameter()]
        [int] $Port = 22,

        [Parameter()]
        [string] $Ps7ConfigName = 'PowerShell.7',

        [Parameter()]
        [string] $WinPsConfigName = 'Microsoft.PowerShell'
    )

    # Default to session/global variable when not provided
    if (-not $Credential -and $Global:TTDomainCred) {
        $Credential = $Global:TTDomainCred
    }

    if ($UseSsh) {
        # SSH doesn’t use PSCredential directly; user@host + key/agent is typical.
        # If you *must* use password, pass -UserName and rely on SSH prompting or key auth.
        $params = @{
            HostName    = $ComputerName
            ErrorAction = 'Stop'
        }
        if ($Credential) {
            $params.UserName = $Credential.UserName
            # Password-based SSH isn’t ideal; prefer key-based. If needed, you can set up ssh-agent.
        }
        $s = New-PSSession @params -Port $Port
        $ver = Invoke-Command -Session $s -ScriptBlock { $PSVersionTable.PSVersion.Major }
        if ($ver -lt 7) { Remove-PSSession $s; throw "Remote PS is <$ver>; need 7+ for your tooling." }
        return $s
    }
    else {
        # WSMan: try PS7 endpoint, then fall back to WinPS
        try {
            $p = @{
                ComputerName      = $ComputerName
                ConfigurationName = $Ps7ConfigName
                ErrorAction       = 'Stop'
            }
            if ($Credential) { $p.Credential = $Credential }
            $s = New-PSSession @p
            $ver = Invoke-Command -Session $s -ScriptBlock { $PSVersionTable.PSVersion.Major }
            if ($ver -ge 7) { return $s }
            Remove-PSSession $s -ErrorAction SilentlyContinue
        }
        catch {}

        try {
            $p = @{
                ComputerName      = $ComputerName
                ConfigurationName = $WinPsConfigName
                ErrorAction       = 'Stop'
            }
            if ($Credential) { $p.Credential = $Credential }
            $s = New-PSSession @p
            return $s
        }
        catch {
            throw "Failed to open session to ${ComputerName}: $($_.Exception.Message)"
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-TcpPort.ps1
`powershell

function Test-TcpPort {
    <#
    .SYNOPSIS
        Tests if a TCP port is open on a specified IP address within a given timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutMs = 500
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient

        # Begin async connect
        $async = $client.BeginConnect($IP, $Port, $null, $null)

        # Wait for timeout
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.Close()
            return $false
        }

        # Complete connection
        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-MdnsName.ps1
`powershell

function Get-MdnsName {
    <#
    .SYNOPSIS
        Retrieves the mDNS name for a given IP address if available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # First attempt: look for .local names in ARP output
        # Some devices register their mDNS name in the ARP table
        $arpOutput = arp -a | Where-Object { $_ -match "^\s*$IP\s" }

        if ($arpOutput -and $arpOutput -match '([a-zA-Z0-9\-]+\.local)') {
            return $matches[1]
        }

        # Second attempt: reverse lookup for .local PTRs
        try {
            $ptr = Resolve-DnsName -Name $IP -Type PTR -ErrorAction Stop |
            Where-Object { $_.NameHost -like '*.local' } |
            Select-Object -ExpandProperty NameHost -First 1

            if ($ptr) {
                return $ptr
            }
        }
        catch {
            # ignore PTR failures
        }

        # Third attempt: heuristic fallback
        # Some devices respond to <ip>.local even if not registered
        $synthetic = "$IP.local"
        try {
            $probe = Resolve-DnsName -Name $synthetic -ErrorAction Stop
            if ($probe) {
                return $synthetic
            }
        }
        catch {
            # ignore
        }

        return $null
    }
    catch {
        return $null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-NetbiosName.ps1
`powershell

function Get-NetbiosName {
    <#
    .SYNOPSIS
        Retrieves the NetBIOS name for a given IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # Query NetBIOS table for the host
        $output = & nbtstat -A $IP 2>$null

        if (-not $output) {
            return $null
        }

        # Look for the <00> unique workstation service name
        # Example line:
        #   MYPC            <00>  UNIQUE      Registered
        $line = $output | Select-String "<00>" | Select-Object -First 1

        if ($line) {
            # Split on whitespace and take the first token (the hostname)
            $tokens = $line.ToString().Trim() -split '\s+'
            if ($tokens.Count -gt 0) {
                return $tokens[0]
            }
        }

        return $null
    }
    catch {
        # NetBIOS lookup failed or host not responding
        return $null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-ReverseDns.ps1
`powershell

function Get-ReverseDns {
    <#
    .SYNOPSIS
        Retrieves the reverse DNS PTR record for a given IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        $ptr = Resolve-DnsName -Name $IP -Type PTR -ErrorAction Stop

        if ($ptr -and $ptr.NameHost) {
            return $ptr.NameHost
        }

        return $null
    }
    catch {
        # PTR not found or DNS server unreachable
        return $null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-DnsQueryLoggerWorker.ps1
`powershell

function Start-DnsQueryLoggerWorker {
    <#
    .SYNOPSIS
        Worker function to start real-time DNS query logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    # Load config
    $cfg = $script:TechToolboxConfig
    $dnsCfg = $cfg["settings"]["dnsLogging"]
    if ($dnsCfg["autoEnableDiagnostics"]) {
        Set-DnsServerDiagnostics -QueryLogging $true
    }

    # Ensure DNS logging is enabled
    try {
        Set-DnsServerDiagnostics -QueryLogging $true -ErrorAction Stop
        Write-Log -Level Ok -Message "DNS query logging enabled."
    }
    catch {
        Write-Log -Level Error -Message "Failed to enable DNS query logging: $($_.Exception.Message)"
        return
    }

    # Get DNS debug log path
    $diag = Get-DnsServerDiagnostics
    $dnsDebugPath = $diag.LogFilePath

    if (-not (Test-Path $dnsDebugPath)) {
        Write-Log -Level Error -Message "DNS debug log not found at $dnsDebugPath"
        return
    }

    Write-Log -Level Info -Message "Watching DNS debug log: $dnsDebugPath"

    # Tail the log in real time
    Get-Content -Path $dnsDebugPath -Wait -Tail 0 |
    ForEach-Object {
        $line = $_

        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) { return }

        # Parse DNS query lines (simple example)
        if ($line -match 'Query for (.+?) from (\d+\.\d+\.\d+\.\d+)') {
            $record = @{
                Timestamp = (Get-Date)
                Query     = $matches[1]
                Client    = $matches[2]
            }

            # Write to output file
            $json = $record | ConvertTo-Json -Compress
            Add-Content -Path $OutputPath -Value $json

            # Console/log output
            Write-Log -Level Info -Message "DNS Query: $($record.Query) from $($record.Client)"
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-HttpInfo.ps1
`powershell

function Get-HttpInfo {
    <#
    .SYNOPSIS
        Retrieves HTTP headers from a specified IP address and port if
        available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutMs = 1000
    )

    try {
        # Build URL
        $url = "http://$IP`:$Port/"

        # Create request
        $req = [System.Net.WebRequest]::Create($url)
        $req.Timeout = $TimeoutMs
        $req.Method = "HEAD"
        $req.AllowAutoRedirect = $false

        # Execute
        $resp = $req.GetResponse()

        # Extract headers into a hashtable
        $headers = @{}
        foreach ($key in $resp.Headers.AllKeys) {
            $headers[$key] = $resp.Headers[$key]
        }

        $resp.Close()
        return $headers
    }
    catch {
        # No banner, no response, or port closed
        return $null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Show-ProgressBanner.ps1
`powershell

function Show-ProgressBanner {
    <#
    .SYNOPSIS
        Displays a progress banner for subnet scanning operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Current,

        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter(Mandatory)]
        [double]$DisplayPct,

        [Parameter(Mandatory)]
        [TimeSpan]$ETA
    )

    try {
        $pct = "{0:N1}" -f $DisplayPct
        $etaStr = $ETA.ToString("hh\:mm\:ss")

        Write-Progress `
            -Activity "Subnet Scan" `
            -Status   "Progress: $pct% | ETA: $etaStr" `
            -PercentComplete $DisplayPct `
            -CurrentOperation "Host $Current of $Total"
    }
    catch {
        # UI failures should never break a scan
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Connect-PurviewSearchOnly.ps1
`powershell

function Connect-PurviewSearchOnly {
    <#
    .SYNOPSIS
        Connects to Microsoft Purview with a SearchOnly IPPS session.
    .DESCRIPTION
        Uses Connect-IPPSSession -EnableSearchOnlySession with the provided UPN.
        Logs connection status via Write-Log.
    .PARAMETER UserPrincipalName
        UPN used to establish the Purview SearchOnly session (e.g., user@domain.com).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserPrincipalName
    )

    try {
        Write-Log -Level Info -Message ("Connecting to Purview (SearchOnly) as {0}..." -f $UserPrincipalName)
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -EnableSearchOnlySession -ErrorAction Stop
        Write-Log -Level Ok -Message "Connected to Purview (SearchOnly)."
    }
    catch {
        Write-Log -Level Error -Message ("Failed to connect to Purview as {0}: {1}" -f $UserPrincipalName, $_.Exception.Message)
        throw
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-HardDelete.ps1
`powershell

function Invoke-HardDelete {
    <#
    .SYNOPSIS
        Submits a Purview HardDelete purge for a Compliance Search and waits for
        completion.
    .DESCRIPTION
        Optionally requires typed confirmation per config; honors
        -WhatIf/-Confirm for the submission step. Calls Wait-PurgeCompletion to
        monitor the purge status.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SearchName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CaseName
    )

    # --- Config (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $purv = $cfg["settings"]["purview"]

    # Confirmation gate (default to true for safety)
    $requireConfirm = $purv["purge"]["requireConfirmation"]
    if ($null -eq $requireConfirm) { $requireConfirm = $true }

    Write-Log -Level Info -Message ("Preparing HardDelete purge for '{0}' in case '{1}'." -f $SearchName, $CaseName)
    Write-Log -Level Warn -Message "This will permanently delete all items found by the search."

    if ($requireConfirm) {
        $confirm = Read-Host "Type 'YES' to confirm HardDelete purge"
        if ($confirm -notmatch '^(?i)(YES|Y)$') { throw "HardDelete purge cancelled by user." }
    }

    if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $SearchName), 'Submit HardDelete purge')) {
        $action = $null
        try {
            $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -ErrorAction Stop
            if ($action.Identity) {
                Write-Log -Level Ok -Message ("Purge submitted: {0}" -f $action.Identity)

                # Optional: pass config-driven timeouts/polling to Wait-PurgeCompletion
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -ActionIdentity $action.Identity -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
            else {
                Write-Log -Level Ok -Message "Purge submitted (no Identity returned). Monitoring by search name..."
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -SearchName $SearchName -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
        }
        catch {
            Write-Log -Level Error -Message ("Failed to submit purge: {0}" -f $_.Exception.Message)
            throw
        }
    }
    else {
        Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-ContentMatchQuery.ps1
`powershell

function Test-ContentMatchQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Query,
        [switch]$Normalize,
        [ref]$NormalizedQuery
    )

    # Trim and basic checks
    if ([string]::IsNullOrWhiteSpace($Query)) {
        if ($NormalizedQuery) { $NormalizedQuery.Value = $null }
        return $false
    }

    $q = $Query.Trim()

    # 1) Balanced parentheses
    $stack = 0
    foreach ($ch in $q.ToCharArray()) {
        if ($ch -eq '(') { $stack++ }
        elseif ($ch -eq ')') { $stack-- }
        if ($stack -lt 0) { return $false } # early close
    }
    if ($stack -ne 0) { return $false }     # unbalanced overall

    # 2) Balanced quotes (simple even-count check; covers most cases)
    $quoteArray = $q.ToCharArray() | Where-Object { $_ -eq '"' }
    $quoteCount = @($quoteArray).Count       # ensure array semantics
    if (($quoteCount % 2) -ne 0) { return $false }

    # 3) Allowed property names (adjust as you need)
    $allowed = @(
        'from', 'to', 'cc', 'bcc', 'participants',
        'subject', 'body', 'sent', 'received', 'attachment', 'attachments',
        'kind', 'size', 'importance'
    )

    $propMatches = [regex]::Matches($q, '(?i)\b([a-z]+)\s*:')
    # MatchCollection.Count is safe, but we don't need it—just iterate
    foreach ($m in $propMatches) {
        $prop = $m.Groups[1].Value.ToLowerInvariant()
        if ($allowed -notcontains $prop) { return $false }
    }

    # 4) Optional normalization for common wildcard mistakes
    $norm = $q
    if ($Normalize) {
        $norm = [regex]::Replace(
            $norm,
            '(?i)(from|to|cc|bcc)\s*:\s*\(\s*([^)]*)\s*\)',
            {
                param($m)
                $prop = $m.Groups[1].Value
                $inner = $m.Groups[2].Value
                # Split OR terms and quote them if they contain @ or * and aren't already quoted
                $parts = $inner -split '(?i)\s+OR\s+'
                $parts = $parts | ForEach-Object {
                    $p = $_.Trim()
                    if ($p -notmatch '^".*"$' -and ($p -match '[@\*]')) { '"' + $p + '"' } else { $p }
                }
                "${prop}:(" + ($parts -join ' OR ') + ")"
            }
        )
    }

    if ($NormalizedQuery) { $NormalizedQuery.Value = $norm }
    return $true
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Wait-ComplianceSearchRegistration.ps1
`powershell
function Wait-ComplianceSearchRegistration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SearchName,
        [int]$TimeoutSeconds = 60,
        [int]$PollSeconds = 3
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $cs = Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue
        if ($cs) { return $true }
        Start-Sleep -Seconds $PollSeconds
    } while ((Get-Date) -lt $deadline)
    return $false
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Wait-PurgeCompletion.ps1
`powershell

function Wait-PurgeCompletion {
    <#
    .SYNOPSIS
        Monitors a Purge ComplianceSearchAction until completion or timeout.
    .DESCRIPTION
        Supports two parameter sets: by action identity or by search name.
        Caller provides TimeoutSeconds and PollSeconds (no direct config reads).
    #>
    [CmdletBinding(DefaultParameterSetName = 'BySearch')]
    param(
        [Parameter(ParameterSetName = 'BySearch', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchName,

        [Parameter(ParameterSetName = 'ByAction', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionIdentity,

        [Parameter()]
        [string]$CaseName,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 1200,

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$PollSeconds = 5
    )

    # --- Caller-resolved defaults only (no config lookups here) ---
    $target = if ($PSCmdlet.ParameterSetName -eq 'ByAction') { $ActionIdentity } else { $SearchName }
    Write-Log -Level Info -Message ("Monitoring purge for '{0}' (Timeout={1}s, Poll={2}s)..." -f $target, $TimeoutSeconds, $PollSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $action = if ($PSCmdlet.ParameterSetName -eq 'ByAction') {
            Get-ComplianceSearchAction -Identity $ActionIdentity -ErrorAction SilentlyContinue
        }
        else {
            # If CaseName provided, scope to case; else search across all purges and pick latest
            $scope = if ([string]::IsNullOrWhiteSpace($CaseName)) {
                Get-ComplianceSearchAction -Purge -ErrorAction SilentlyContinue
            }
            else {
                Get-ComplianceSearchAction -Purge -Case $CaseName -ErrorAction SilentlyContinue
            }

            $scope |
            Where-Object { $_.SearchName -eq $SearchName } |
            Sort-Object CreatedTime -Descending |
            Select-Object -First 1
        }

        if ($action) {
            $status = $action.Status
            Write-Log -Level Info -Message ("Purge status: {0}" -f $status)
            switch ($status) {
                'Completed' { Write-Log -Level Ok   -Message "Purge completed successfully."; return $action }
                'PartiallySucceeded' { Write-Log -Level Warn -Message ("Purge partially succeeded: {0}" -f $action.ErrorMessage); return $action }
                'Failed' { Write-Log -Level Error -Message ("Purge failed: {0}" -f $action.ErrorMessage); return $action }
            }
        }
        else {
            Write-Log -Level Info -Message "No purge action found yet..."
        }

        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for purge completion."
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Wait-SearchCompletion.ps1
`powershell

function Wait-SearchCompletion {
    <#
    .SYNOPSIS
        Waits for a Compliance Search to reach a terminal state
        (Completed/Failed) or timeout.
    .DESCRIPTION
        Polls the search status by name (and optional case scope) until timeout.
        Caller supplies TimeoutSeconds/PollSeconds; no config access here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchName,

        [Parameter()]
        [string]$CaseName,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 1200,

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$PollSeconds = 5
    )

    Write-Log -Level Info -Message ("Monitoring search '{0}' (Timeout={1}s, Poll={2}s)..." -f $SearchName, $TimeoutSeconds, $PollSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $search = if ([string]::IsNullOrWhiteSpace($CaseName)) {
                Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue
            }
            else {
                Get-ComplianceSearch -Identity $SearchName -Case $CaseName -ErrorAction SilentlyContinue
            }
        }
        catch {
            $search = $null
        }

        if ($null -ne $search) {
            $status = $search.Status
            Write-Log -Level Info -Message ("Search status: {0}" -f $status)

            switch ($status) {
                'Completed' {
                    Write-Log -Level Ok -Message "Search completed."
                    return $search
                }
                'Failed' {
                    Write-Log -Level Error -Message ("Search failed: {0}" -f $search.Errors)
                    return $search
                }
                default {
                    # In-progress statuses often include 'Starting', 'InProgress', etc.
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Search not found yet..."
        }

        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for search completion."
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SanityCheck.ps1
`powershell
function Invoke-SanityCheck {
    <#
    .SYNOPSIS
        Performs a basic sanity check on the current user.
    .DESCRIPTION
        This function simulates a sanity check by outputting humorous messages
        about the user's and module's sanity levels.
    .EXAMPLE
        sanity_check
        Runs the sanity check and displays the results.
    .INPUTS
        None. You cannot pipe objects to sanity_check.
    .OUTPUTS
        None. This function does not return any output.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    Write-Host "Running sanity_check..." -ForegroundColor DarkCyan
    Start-Sleep -Milliseconds 3000

    Write-Host "Operator sanity: questionable" -ForegroundColor Yellow
    Start-Sleep -Milliseconds 2000
    Write-Host "Module sanity: excellent" -ForegroundColor Green
    Start-Sleep -Milliseconds 2000
    Write-Host "Proceed with caution." -ForegroundColor DarkYellow
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-Impersonation.ps1
`powershell

function Invoke-Impersonation {
    <#
    .SYNOPSIS
        Executes a script block under the context of specified user credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    # Split domain\user if needed
    $parts = $Credential.UserName.Split('\', 2)
    if ($parts.Count -eq 2) {
        $domain   = $parts[0]
        $username = $parts[1]
    } else {
        $domain   = $env:USERDOMAIN
        $username = $parts[0]
    }

    $password = $Credential.GetNetworkCredential().Password

    # LOGON32_LOGON_NEW_CREDENTIALS = 9
    # LOGON32_PROVIDER_WINNT50      = 3
    $token = [IntPtr]::Zero
    $ok = [CredImpersonator]::LogonUser(
        $username, $domain, $password, 9, 3, [ref]$token
    )

    if (-not $ok) {
        return $null
    }

    $identity = [System.Security.Principal.WindowsIdentity]::new($token)
    $context  = $identity.Impersonate()

    try {
        & $ScriptBlock
    }
    finally {
        $context.Undo()
        $context.Dispose()
        [CredImpersonator]::CloseHandle($token) | Out-Null
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: ConvertTo-mWh.ps1
`powershell

function ConvertTo-mWh {
    <#
    .SYNOPSIS
        Parses capacity strings (e.g., '47,000 mWh', '47 Wh') into an integer
        mWh value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $t = ($Text -replace ',', '').Trim()
    $num = [double](($t -match '(\d+(\.\d+)?)') ? $Matches[1] : 0)
    if ($num -le 0) { return $null }

    if ($t -match '(?i)\bmwh\b') { return [int]$num }
    if ($t -match '(?i)\bwh\b')  { return [int]($num * 1000) }
    # Unknown unit: assume mWh
    return [int]$num
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-BatteryReportHtml.ps1
`powershell

function Get-BatteryReportHtml {
    <#
    .SYNOPSIS
        Parses the battery report HTML and returns battery objects + optional
        debug text.
    .OUTPUTS
        [object[]], [string]  # batteries array, debug text (headings) when
        table detection fails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Html
    )

    $htmlNorm = $Html -replace "`r`n", "`n" -replace "\t", " "
    $installedPattern = '(?is)<h[1-6][^>]*>.*?Installed\W+Batter(?:y|ies).*?</h[1-6]>.*?<table\b[^>]*>(.*?)</table>'
    $sectionMatch = [regex]::Match($htmlNorm, $installedPattern)

    # Fallback: detect table by typical labels if heading not found
    if (-not $sectionMatch.Success) {
        $tableMatches = [regex]::Matches($htmlNorm, '(?is)<table\b[^>]*>(.*?)</table>')
        foreach ($tm in $tableMatches) {
            if ($tm.Value -match '(?is)(Design\s+Capacity|Full\s+Charge\s+Capacity|Chemistry|Serial|Manufacturer)') {
                $sectionMatch = $tm
                break
            }
        }
    }

    if (-not $sectionMatch.Success) {
        # Gather headings for debug
        $headings = [regex]::Matches($htmlNorm, '(?is)<h[1-6][^>]*>(.*?)</h[1-6]>') | ForEach-Object {
            Format-Text $_.Groups[1].Value
        }
        return @(), ($headings -join [Environment]::NewLine)
    }

    $tableHtml = $sectionMatch.Value
    $tbodyMatch = [regex]::Match($tableHtml, '(?is)<tbody\b[^>]*>(.*?)</tbody>')
    $rowsHtml = if ($tbodyMatch.Success) { $tbodyMatch.Groups[1].Value } else { $tableHtml }
    $rowMatches = [regex]::Matches($rowsHtml, '(?is)<tr\b[^>]*>(.*?)</tr>')
    if ($rowMatches.Count -eq 0) { return @(), $null }

    $batteries = New-Object System.Collections.Generic.List[object]
    $current = [ordered]@{}
    $startKeys = @('manufacturer', 'serialNumber', 'name', 'batteryName')

    foreach ($rm in $rowMatches) {
        $rowInner = $rm.Groups[1].Value
        $cellMatches = [regex]::Matches($rowInner, '(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>')
        if ($cellMatches.Count -eq 0) { continue }

        if ($cellMatches.Count -eq 2) {
            # Key-value row
            $label = Format-Text $cellMatches[0].Groups[1].Value
            $value = Format-Text $cellMatches[1].Groups[1].Value         
            if (-not [string]::IsNullOrWhiteSpace($label)) {
                $key = Move-ToCamelKey -Label $label
            }

            # Detect start of a new battery when a "start key" repeats
            if ($startKeys -contains $key -and $current.Contains($key)) {
                # finalize previous battery with parsed capacities
                $dc = if ($current.Contains('designCapacity')) { ConvertTo-mWh $current['designCapacity'] } else { $null }
                $fc = if ($current.Contains('fullChargeCapacity')) { ConvertTo-mWh $current['fullChargeCapacity'] } else { $null }
                if ($dc -and $fc -and $dc -gt 0) {
                    $current['designCapacity_mWh'] = $dc
                    $current['fullChargeCapacity_mWh'] = $fc
                    $current['healthRatio'] = [math]::Round($fc / $dc, 4)
                    $current['healthPercent'] = [math]::Round(($fc * 100.0) / $dc, 2)
                }
                $batteries.Add([PSCustomObject]$current)
                $current = [ordered]@{}
            }
            $current[$key] = $value
        }
        else {
            # Multi-column row: capture as raw values
            $vals = @()
            foreach ($cm in $cellMatches) { $vals += (Format-Text $cm.Groups[1].Value) }
            if ($vals.Count -gt 0) {
                if (-not $current.Contains('rows')) {
                    $current['rows'] = New-Object System.Collections.Generic.List[object]
                }
                $current['rows'].Add($vals)
            }
        }
    }

    # finalize last battery
    if ($current.Count -gt 0) {
        $dc = if ($current.Contains('designCapacity')) { ConvertTo-mWh $current['designCapacity'] } else { $null }
        $fc = if ($current.Contains('fullChargeCapacity')) { ConvertTo-mWh $current['fullChargeCapacity'] } else { $null }
        if ($dc -and $fc -and $dc -gt 0) {
            $current['designCapacity_mWh'] = $dc
            $current['fullChargeCapacity_mWh'] = $fc
            $current['healthRatio'] = [math]::Round($fc / $dc, 4)
            $current['healthPercent'] = [math]::Round(($fc * 100.0) / $dc, 2)
        }
        $batteries.Add([PSCustomObject]$current)
    }

    return , $batteries, $null
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-mWh.ps1
`powershell
function Get-mWh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    $clean = Update-Text $Text

    # Capture number + optional unit
    $match = [regex]::Match($clean, '(?i)\b([0-9][0-9,\.]*)\s*(mwh|wh)?\b')
    if (-not $match.Success) { return $null }

    $num = $match.Groups[1].Value -replace ',', ''
    $unit = $match.Groups[2].Value.ToLower()

    if ($num -notmatch '^\d+(\.\d+)?$') {
        return $null
    }

    $val = [double]$num

    switch ($unit) {
        'mwh' { return [int][math]::Round($val) }
        'wh' { return [int][math]::Round($val * 1000) }
        default {
            # No unit — infer based on magnitude
            if ($val -ge 1000) {
                return [int][math]::Round($val)      # assume mWh
            }
            else {
                return [int][math]::Round($val * 1000) # assume Wh
            }
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-BatteryReport.ps1
`powershell

function Invoke-BatteryReport {
    <#
    .SYNOPSIS
        Runs 'powercfg /batteryreport' to generate the HTML report and waits
        until the file is non-empty.
    .OUTPUTS
        [bool] True when the report is present and non-zero length; otherwise
        False.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ReportPath,
        [Parameter()][int]$MaxTries = 40,
        [Parameter()][int]$SleepMs = 250
    )

    $reportDir = Split-Path -Parent $ReportPath
    if ($reportDir -and $PSCmdlet.ShouldProcess($reportDir, 'Ensure report directory')) {
        if (-not (Test-Path -LiteralPath $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }
    }

    # Generate report (matches original behavior)
    if ($PSCmdlet.ShouldProcess($ReportPath, 'Generate battery report')) {
        & powercfg.exe /batteryreport /output "$ReportPath" | Out-Null
    }

    # Poll for presence & non-zero size (40 tries x 250ms ~= 10s default)
    $tries = 0
    while ($tries -lt $MaxTries) {
        if (Test-Path -LiteralPath $ReportPath) {
            $size = (Get-Item -LiteralPath $ReportPath).Length
            if ($size -gt 0) { return $true }
        }
        Start-Sleep -Milliseconds $SleepMs
        $tries++
    }
    return $false
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Start-RobocopyLocal.ps1
`powershell
function Start-RobocopyLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][int]$RetryCount,
        [Parameter(Mandatory)][int]$WaitSeconds,
        [Parameter(Mandatory)][string[]]$CopyFlags,
        [Parameter()][pscredential]$Credential
    )

    # Optional: credential-aware UNC access (basic pattern)
    # For now, we log that credentials were supplied and rely on existing access.
    if ($Credential) {
        Write-Log -Level Info -Message " Credential supplied for local execution (ensure access to UNC paths is configured)."
    }

    if (-not (Test-Path -Path $Destination -PathType Container)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $arguments = @(
        "`"$Source`"",
        "`"$Destination`""
    ) + $CopyFlags + @(
        "/R:{0}" -f $RetryCount,
        "/W:{0}" -f $WaitSeconds,
        "/LOG:$LogFile"
    )

    Write-Log -Level Info -Message " Running Robocopy locally..."
    Write-Log -Level Info -Message (" Command: robocopy {0}" -f ($arguments -join ' '))

    $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    $exitCode = $proc.ExitCode

    Write-Log -Level Info -Message (" Robocopy exit code: {0}" -f $exitCode)

    # Robocopy exit codes 0–7 are typically non-fatal; >7 indicates serious issues.
    if ($exitCode -gt 7) {
        Write-Log -Level Warn -Message (" Robocopy reported a severe error (exit code {0})." -f $exitCode)
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-RobocopyRemote.ps1
`powershell
function Start-RobocopyRemote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][int]$RetryCount,
        [Parameter(Mandatory)][int]$WaitSeconds,
        [Parameter(Mandatory)][string[]]$CopyFlags,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][pscredential]$Credential
    )

    Write-Log -Level Info -Message (" Opening remote session to {0}..." -f $ComputerName)

    if ($Credential) {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    }
    else {
        $session = New-PSSession -ComputerName $ComputerName
    }

    try {
        $exitCode = Invoke-Command -Session $session -ScriptBlock {
            param(
                $Source,
                $Destination,
                $LogFile,
                $RetryCount,
                $WaitSeconds,
                $CopyFlags
            )

            if (-not (Test-Path -Path $Destination -PathType Container)) {
                New-Item -ItemType Directory -Path $Destination -Force | Out-Null
            }

            $arguments = @(
                "`"$Source`"",
                "`"$Destination`""
            ) + $CopyFlags + @(
                "/R:{0}" -f $RetryCount,
                "/W:{0}" -f $WaitSeconds,
                "/LOG:$LogFile"
            )

            Write-Host "Running Robocopy on remote host..."
            Write-Host ("Command: robocopy {0}" -f ($arguments -join ' '))

            $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            $proc.ExitCode
        } -ArgumentList $Source, $Destination, $LogFile, $RetryCount, $WaitSeconds, $CopyFlags

        Write-Log -Level Info -Message (" Remote Robocopy exit code: {0}" -f $exitCode)

        if ($exitCode -gt 7) {
            Write-Log -Level Warn -Message (" Remote Robocopy reported a severe error (exit code {0})." -f $exitCode)
        }
    }
    finally {
        if ($session) {
            Write-Log -Level Info -Message (" Closing remote session to {0}." -f $ComputerName)
            Remove-PSSession -Session $session
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SystemRepairLocal.ps1
`powershell

function Invoke-SystemRepairLocal {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations locally.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][switch]$RestoreHealth,
        [Parameter()][switch]$StartComponentCleanup,
        [Parameter()][switch]$ResetBase,
        [Parameter()][switch]$SfcScannow,
        [Parameter()][switch]$ResetUpdateComponents
    )

    if ($RestoreHealth) {
        Write-Log -Level Info -Message " Running DISM /RestoreHealth locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -NoNewWindow -Wait
    }

    if ($StartComponentCleanup) {
        Write-Log -Level Info -Message " Running DISM /StartComponentCleanup locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup" -NoNewWindow -Wait
    }

    if ($ResetBase) {
        Write-Log -Level Info -Message " Running DISM /StartComponentCleanup /ResetBase locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase" -NoNewWindow -Wait
    }

    if ($SfcScannow) {
        Write-Log -Level Info -Message " Running SFC /scannow locally..."
        Start-Process sfc.exe -ArgumentList "/scannow" -NoNewWindow -Wait
    }

    if ($ResetUpdateComponents) {
        Write-Log -Level Info -Message " Resetting Windows Update components locally..."

        Stop-Service -Name wuauserv, cryptsvc, bits, msiserver -Force

        Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

        Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
        Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force

        Start-Service -Name wuauserv, cryptsvc, bits, msiserver

        Write-Log -Level Info -Message " Windows Update components reset locally."
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SystemRepairRemote.ps1
`powershell

function Invoke-SystemRepairRemote {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations on a remote computer via
        PSRemoting.
    .DESCRIPTION
        Wraps common repair operations (DISM RestoreHealth,
        StartComponentCleanup, ResetBase, SFC, and Windows Update component
        reset) in a TechToolbox-style function with remote execution
        and credential support.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][switch]$RestoreHealth,
        [Parameter()][switch]$StartComponentCleanup,
        [Parameter()][switch]$ResetBase,
        [Parameter()][switch]$SfcScannow,
        [Parameter()][switch]$ResetUpdateComponents,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][pscredential]$Credential
    )

    Write-Log -Level Info -Message (" Opening remote session to {0}..." -f $ComputerName)

    if ($Credential) {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    }
    else {
        $session = New-PSSession -ComputerName $ComputerName
    }

    try {
        Invoke-Command -Session $session -ScriptBlock {
            param(
                $RestoreHealth,
                $StartComponentCleanup,
                $ResetBase,
                $SfcScannow,
                $ResetUpdateComponents
            )

            if ($RestoreHealth) {
                Write-Host "Running DISM /RestoreHealth remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -NoNewWindow -Wait
            }

            if ($StartComponentCleanup) {
                Write-Host "Running DISM /StartComponentCleanup remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup" -NoNewWindow -Wait
            }

            if ($ResetBase) {
                Write-Host "Running DISM /StartComponentCleanup /ResetBase remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup","/ResetBase" -NoNewWindow -Wait
            }

            if ($SfcScannow) {
                Write-Host "Running SFC /scannow remotely..."
                Start-Process sfc.exe -ArgumentList "/scannow" -NoNewWindow -Wait
            }

            if ($ResetUpdateComponents) {
                Write-Host "Resetting Windows Update components remotely..."

                Stop-Service -Name wuauserv, cryptsvc, bits, msiserver -Force

                Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

                Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
                Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force

                Start-Service -Name wuauserv, cryptsvc, bits, msiserver

                Write-Host "Windows Update components reset remotely."
            }
        } -ArgumentList $RestoreHealth, $StartComponentCleanup, $ResetBase, $SfcScannow, $ResetUpdateComponents
    }
    finally {
        if ($session) {
            Write-Log -Level Info -Message (" Closing remote session to {0}." -f $ComputerName)
            Remove-PSSession -Session $session
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Convert-FlatSnapshotToRows.ps1
`powershell
function Convert-FlatSnapshotToRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$FlatObject
    )

    $rows = @()

    # Determine groups by prefix before first underscore
    $groups = $FlatObject.PSObject.Properties.Name |
    Group-Object { $_.Split('_')[0] } |
    Sort-Object Name

    foreach ($group in $groups) {

        # Insert a section header row
        $rows += [pscustomobject]@{
            Label = "# $($group.Name)"
            Value = ""
        }

        # Insert each key/value in this group
        foreach ($key in $group.Group) {
            $rows += [pscustomobject]@{
                Label = $key
                Value = $FlatObject.$key
            }
        }

        # Blank line between groups
        $rows += [pscustomobject]@{
            Label = ""
            Value = ""
        }
    }

    return $rows
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Convert-SnapshotToFlatObject.ps1
`powershell
function Convert-SnapshotToFlatObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Snapshot
    )

    # Normalize to hashtable
    if ($Snapshot -isnot [hashtable]) {
        if ($Snapshot -is [pscustomobject]) {
            $h = @{}
            foreach ($p in $Snapshot.PSObject.Properties) {
                $h[$p.Name] = $p.Value
            }
            $Snapshot = $h
        }
        else {
            throw "Unsupported snapshot type: $($Snapshot.GetType().FullName)"
        }
    }

    $flat = @{}

    foreach ($key in $Snapshot.Keys) {
        $value = $Snapshot[$key]

        if ($null -eq $value) {
            $flat[$key] = $null
            continue
        }

        $typeName = $value.GetType().Name

        switch ($typeName) {

            # Nested hashtable → prefix keys
            'Hashtable' {
                foreach ($subKey in $value.Keys) {
                    $flat["${key}_${subKey}"] = $value[$subKey]
                }
            }

            # Arrays → index + prefix
            'Object[]' {
                $index = 0
                foreach ($item in $value) {

                    # If the array element is a hashtable, flatten it too
                    if ($item -is [hashtable]) {
                        foreach ($subKey in $item.Keys) {
                            $flat["${key}${index}_${subKey}"] = $item[$subKey]
                        }
                    }
                    else {
                        # Fallback: JSON encode the item
                        $flat["${key}${index}"] = ($item | ConvertTo-Json -Depth 10 -Compress)
                    }

                    $index++
                }
            }

            # Everything else → direct assignment
            default {
                $flat[$key] = $value
            }
        }
    }

    return [pscustomobject]$flat
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotCPU.ps1
`powershell
function Get-SnapshotCPU {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting CPU information..."

    try {
        # Invoke locally or remotely
        $cpu = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_Processor
            }
        }
        else {
            Get-CimInstance -ClassName Win32_Processor
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect CPU info: {0}" -f $_.Exception.Message)
        return @{}
    }

    # Some systems have multiple CPU objects; flatten safely
    $cpu0 = $cpu | Select-Object -First 1

    $result = @{
        Name              = $cpu0.Name
        Manufacturer      = $cpu0.Manufacturer
        MaxClockSpeedMHz  = $cpu0.MaxClockSpeed
        NumberOfCores     = $cpu0.NumberOfCores
        LogicalProcessors = $cpu0.NumberOfLogicalProcessors
        Architecture      = switch ($cpu0.Architecture) {
            0 { "x86" }
            1 { "MIPS" }
            2 { "Alpha" }
            3 { "PowerPC" }
            5 { "ARM" }
            6 { "Itanium" }
            9 { "x64" }
            default { $cpu0.Architecture }
        }
        LoadPercentage    = $cpu0.LoadPercentage
    }

    Write-Log -Level Ok -Message "CPU information collected."

    return $result
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotDisk.ps1
`powershell
function Get-SnapshotDisks {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting disk information..."

    try {
        # Invoke locally or remotely
        $volumes = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
            }
        }
        else {
            Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect disk info: {0}" -f $_.Exception.Message)
        return @()
    }

    $results = @()

    foreach ($v in $volumes) {
        # Convert bytes to GB safely
        $sizeGB = if ($v.Size) {
            [math]::Round($v.Size / 1GB, 2)
        }
        else { $null }

        $freeGB = if ($v.FreeSpace) {
            [math]::Round($v.FreeSpace / 1GB, 2)
        }
        else { $null }

        $pctFree = if ($sizeGB -and $freeGB -ne $null) {
            [math]::Round(($freeGB / $sizeGB) * 100, 2)
        }
        else { $null }

        $results += @{
            DriveLetter = $v.DeviceID
            VolumeLabel = $v.VolumeName
            FileSystem  = $v.FileSystem
            SizeGB      = $sizeGB
            FreeGB      = $freeGB
            PercentFree = $pctFree
        }
    }

    Write-Log -Level Ok -Message "Disk information collected."

    return $results
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotIdentity.ps1
`powershell
function Get-SnapshotIdentity {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting identity information..."

    try {
        # Computer system info (domain/workgroup, logged-on user)
        $cs = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_ComputerSystem
            }
        }
        else {
            Get-CimInstance -ClassName Win32_ComputerSystem
        }

        # Computer SID (optional but useful)
        $sid = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty SID).AccountDomainSid.Value
            }
        }
        else {
            (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty SID).AccountDomainSid.Value
        }

        # AD Site (domain-joined only)
        $adSite = $null
        if ($cs.PartOfDomain) {
            try {
                $adSite = if ($Session) {
                    Invoke-Command -Session $Session -ScriptBlock {
                        ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
                    }
                }
                else {
                    ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).Name
                }
            }
            catch {
                # Non-fatal — AD site lookup can fail if DCs are unreachable
                $adSite = $null
            }
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect identity info: {0}" -f $_.Exception.Message)
        return @{}
    }

    # Normalize logged-on user
    $loggedOn = if ($cs.UserName) { $cs.UserName } else { $null }

    $result = @{
        ComputerName = $cs.Name
        DomainJoined = $cs.PartOfDomain
        Domain       = if ($cs.PartOfDomain) { $cs.Domain } else { $null }
        Workgroup    = if (-not $cs.PartOfDomain) { $cs.Workgroup } else { $null }
        LoggedOnUser = $loggedOn
        ADSite       = $adSite
        ComputerSID  = $sid
    }

    Write-Log -Level Ok -Message "Identity information collected."

    return $result
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotMemory.ps1
`powershell
function Get-SnapshotMemory {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting memory information..."

    try {
        # Invoke locally or remotely
        $os = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_OperatingSystem
            }
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect memory info: {0}" -f $_.Exception.Message)
        return @{}
    }

    # Convert KB to GB safely
    $totalGB = if ($os.TotalVisibleMemorySize) {
        [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    }
    else { $null }

    $freeGB = if ($os.FreePhysicalMemory) {
        [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    }
    else { $null }

    $usedGB = if ($totalGB -and $freeGB -ne $null) {
        [math]::Round($totalGB - $freeGB, 2)
    }
    else { $null }

    $pctUsed = if ($totalGB -and $usedGB -ne $null) {
        [math]::Round(($usedGB / $totalGB) * 100, 2)
    }
    else { $null }

    $pctFree = if ($pctUsed -ne $null) {
        [math]::Round(100 - $pctUsed, 2)
    }
    else { $null }

    $result = @{
        TotalMemoryGB = $totalGB
        FreeMemoryGB  = $freeGB
        UsedMemoryGB  = $usedGB
        PercentUsed   = $pctUsed
        PercentFree   = $pctFree
    }

    Write-Log -Level Ok -Message "Memory information collected."

    return $result
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotNetwork.ps1
`powershell
function Get-SnapshotNetwork {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting network information..."

    try {
        # Invoke locally or remotely
        $nics = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
                Where-Object { $_.IPEnabled -eq $true }
            }
        }
        else {
            Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPEnabled -eq $true }
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect network info: {0}" -f $_.Exception.Message)
        return @()
    }

    $results = @()

    foreach ($nic in $nics) {
        # Normalize multi-value fields
        $ipAddresses = if ($nic.IPAddress) { $nic.IPAddress -join ', ' } else { $null }
        $dnsServers = if ($nic.DNSServerSearchOrder) { $nic.DNSServerSearchOrder -join ', ' } else { $null }
        $gateways = if ($nic.DefaultIPGateway) { $nic.DefaultIPGateway -join ', ' } else { $null }

        $results += @{
            Description = $nic.Description
            MACAddress  = $nic.MACAddress
            IPAddresses = $ipAddresses
            DNSServers  = $dnsServers
            Gateways    = $gateways
            DHCPEnabled = $nic.DHCPEnabled
            DHCPServer  = $nic.DHCPServer
            Index       = $nic.InterfaceIndex
        }
    }

    Write-Log -Level Ok -Message "Network information collected."

    return $results
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotOS.ps1
`powershell
function Get-SnapshotOS {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting OS information..."

    try {
        # Invoke locally or remotely
        $os = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_OperatingSystem
            }
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem
        }

        $cs = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_ComputerSystem
            }
        }
        else {
            Get-CimInstance -ClassName Win32_ComputerSystem
        }

        $bios = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Get-CimInstance -ClassName Win32_BIOS
            }
        }
        else {
            Get-CimInstance -ClassName Win32_BIOS
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect OS info: {0}" -f $_.Exception.Message)
        return @{}
    }

    # Build a clean hashtable
    $result = @{
        Caption        = $os.Caption
        Version        = $os.Version
        BuildNumber    = $os.BuildNumber
        InstallDate    = $os.InstallDate
        LastBootUpTime = $os.LastBootUpTime
        UptimeHours    = if ($os.LastBootUpTime) {
            [math]::Round((New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)).TotalHours, 2)
        }
        else { $null }
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        BIOSVersion    = ($bios.SMBIOSBIOSVersion -join ', ')
        SerialNumber   = $bios.SerialNumber
        TimeZone       = $os.CurrentTimeZone
    }

    Write-Log -Level Ok -Message "OS information collected."

    return $result
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SnapshotServices.ps1
`powershell
function Get-SnapshotServices {
    [CmdletBinding()]
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Write-Log -Level Info -Message "Collecting service and role information..."

    # Define the key services we care about
    $serviceList = @(
        "ADSync",
        "Dnscache",
        "Dhcp",
        "Dnscache",
        "W32Time",
        "Spooler",
        "WinRM",
        "LanmanServer",
        "LanmanWorkstation"
    )

    try {
        # Invoke locally or remotely
        $services = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                param($svcNames)
                Get-Service -Name $svcNames -ErrorAction SilentlyContinue
            } -ArgumentList ($serviceList)
        }
        else {
            Get-Service -Name $serviceList -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to collect service info: {0}" -f $_.Exception.Message)
        return @()
    }

    # Pending reboot check
    $pendingReboot = $false
    try {
        $pendingReboot = if ($Session) {
            Invoke-Command -Session $Session -ScriptBlock {
                Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
            }
        }
        else {
            Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Non-fatal
        $pendingReboot = $null
    }

    # Build results
    $results = @()

    foreach ($svc in $services) {
        $results += @{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = $svc.Status
            StartType   = $svc.StartType
        }
    }

    # Add reboot flag as a separate entry
    $results += @{
        Name        = "PendingReboot"
        DisplayName = "Pending Reboot State"
        Status      = $pendingReboot
        StartType   = $null
    }

    Write-Log -Level Ok -Message "Service information collected."

    return $results
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Format-Text.ps1
`powershell

function Format-Text {
    <#
    .SYNOPSIS
        Strips tags/whitespace and decodes HTML entities.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $t = $Text -replace '(?is)<br\s*/?>', ' ' -replace '(?is)<[^>]+>', ' '
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    $t = ($t -replace '\s+', ' ').Trim()
    return $t
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SystemWorkerScriptContent.ps1
`powershell
function Get-SystemWorkerScriptContent {
    @'
param(
  [string]$ArgsPath
)

$ErrorActionPreference = 'Stop'

# Read args
$cfgRaw = if ($ArgsPath -and (Test-Path -LiteralPath $ArgsPath -ErrorAction SilentlyContinue)) {
  Get-Content -LiteralPath $ArgsPath -Raw -Encoding UTF8
} else { $null }

$cfg = if ($cfgRaw) { $cfgRaw | ConvertFrom-Json } else { $null }

# Extract settings
$timestamp       = if ($cfg.Timestamp) { [string]$cfg.Timestamp } else { (Get-Date -Format 'yyyyMMdd-HHmmss') }
$connectPath     = if ($cfg.ConnectDataPath) { [string]$cfg.ConnectDataPath } else { (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent') }
$extra           = @()
if ($cfg.ExtraPaths) {
  # Ensure array type after deserialization
  if ($cfg.ExtraPaths -is [string]) { $extra = @($cfg.ExtraPaths) }
  elseif ($cfg.ExtraPaths -is [System.Collections.IEnumerable]) { $extra = @($cfg.ExtraPaths) }
}

# Paths
$tempRoot = Join-Path $env:windir 'Temp'
$staging  = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME,$timestamp)
$zipPath  = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME,$timestamp)
$doneFlg  = Join-Path $staging 'system_done.flag'

# Clean & create staging
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# Build PDQ paths
$pdqPaths = @(
  'C:\ProgramData\Admin Arsenal\PDQ Deploy\Logs'
  'C:\ProgramData\Admin Arsenal\PDQ Inventory\Logs'
  'C:\Windows\Temp\PDQDeployRunner'
  'C:\Windows\Temp\PDQInventory'
  (Join-Path $env:SystemRoot 'System32\Winevt\Logs\PDQ.com.evtx')  # fallback; we'll export via wevtutil too
)
if ($connectPath) {
  $pdqPaths += (Join-Path $connectPath 'PDQConnectAgent.db')
  $pdqPaths += (Join-Path $connectPath 'Updates\install.log')
}

# Normalize extras (PS 5.1-safe)
$extras = if ($null -eq $extra -or -not $extra) { @() } else { $extra }

# Resilient copy helper (Copy-Item → robocopy /B)
function Copy-PathResilient {
  param([string]$SourcePath,[string]$StagingRoot)

  if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) { return $false }

  $leaf = Split-Path -Leaf $SourcePath
  $dest = Join-Path $StagingRoot $leaf

  try {
    $it = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if ($it -is [IO.DirectoryInfo]) {
      New-Item -ItemType Directory -Path $dest -Force | Out-Null
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Recurse -Force -ErrorAction Stop
    } else {
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
    }
    return $true
  } catch {
    $primary = $_.Exception.Message
    try {
      $rc = Get-Command robocopy.exe -ErrorAction SilentlyContinue
      if (-not $rc) { throw "robocopy.exe not found" }
      $it2 = Get-Item -LiteralPath $SourcePath -ErrorAction SilentlyContinue
      if ($it2 -is [IO.DirectoryInfo]) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $null = & $rc.Source $SourcePath $dest /E /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      } else {
        $srcDir = Split-Path -Parent $SourcePath
        $file   = Split-Path -Leaf   $SourcePath
        New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
        $null = & $rc.Source $srcDir $StagingRoot $file /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      }
      if ($LASTEXITCODE -lt 8) { return $true }
      Add-Content -Path $copyErr -Value ("{0} | robocopy exit {1} | {2}" -f (Get-Date), $LASTEXITCODE, $SourcePath) -Encoding UTF8
      return $false
    } catch {
      Add-Content -Path $copyErr -Value ("{0} | Copy failed: {1} | {2}" -f (Get-Date), $primary, $SourcePath) -Encoding UTF8
      return $false
    }
  }
}

# Merge non-empty paths (no pre-Test-Path to avoid "Access denied" noise)
$all = @($pdqPaths; $extras) | Where-Object { $_ } | Select-Object -Unique
foreach ($p in $all) { try { Copy-PathResilient -SourcePath $p -StagingRoot $staging } catch {} }

# Export event log by name (avoids in-use copy issues)
try {
  $destEvtx = Join-Path $staging 'PDQ.com.evtx'
  if (-not (Test-Path -LiteralPath $destEvtx -ErrorAction SilentlyContinue)) {
    $logName = 'PDQ.com'
    $wevt = Join-Path $env:windir 'System32\wevtutil.exe'
    if ($env:PROCESSOR_ARCHITEW6432 -or $env:ProgramW6432) {
      $sysnative = Join-Path $env:windir 'Sysnative\wevtutil.exe'
      if (Test-Path -LiteralPath $sysnative) { $wevt = $sysnative }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $wevt
    $psi.Arguments = "epl `"$logName`" `"$destEvtx`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [Diagnostics.Process]::Start($psi); $p.WaitForExit()
    if ($p.ExitCode -ne 0) {
      $err = $p.StandardError.ReadToEnd()
      Add-Content -Path $copyErr -Value ("{0} | wevtutil failed ({1}): {2}" -f (Get-Date), $p.ExitCode, $err) -Encoding UTF8
    }
  }
} catch {
  Add-Content -Path $copyErr -Value ("{0} | wevtutil exception: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
}

# Useful metadata
try {
  Get-CimInstance Win32_Service |
    Where-Object { $_.Name -like 'PDQ*' -or $_.DisplayName -like '*PDQ*' } |
    Select-Object Name,DisplayName,State,StartMode |
    Export-Csv -Path (Join-Path $staging 'services.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -match 'PDQ' -or $_.Publisher -match 'Admin Arsenal' } |
    Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
    Export-Csv -Path (Join-Path $staging 'installed.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  $sys = Get-ComputerInfo -ErrorAction SilentlyContinue
  if ($sys) { $sys | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $staging 'computerinfo.json') -Encoding UTF8 }
  $PSVersionTable | Out-String | Set-Content -Path (Join-Path $staging 'psversion.txt') -Encoding UTF8
} catch {}

# Zip
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zipPath -Force

# Done flag
"ZipPath=$zipPath" | Set-Content -Path $doneFlg -Encoding UTF8
'@
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-RemoteSystemCollection.ps1
`powershell
function Invoke-RemoteSystemCollection {
    <#
    .SYNOPSIS
      Run the PDQ diagnostics on a remote host under SYSTEM via a one-shot Scheduled
      Task.
    
    .DESCRIPTION
      - Sends a small JSON args file and the SYSTEM worker script to the remote host
        (in C:\Windows\Temp).
      - Registers a one-time scheduled task to run the worker as SYSTEM.
      - Waits (up to 180s) for a done flag, then returns the remote staging and zip
        paths.
      - Leaves the ZIP in C:\Windows\Temp on the remote for the caller to retrieve.
      - Cleans up the scheduled task registration and temp files best-effort.
    
    .PARAMETER Session
      A live PSSession to the remote computer.
    
    .PARAMETER Timestamp
      Timestamp string (yyyyMMdd-HHmmss) used in names. Typically generated once by
      the caller and passed in.
    
    .PARAMETER ExtraPaths
      Additional file/folder paths on the remote target to include in the
      collection.
    
    .PARAMETER ConnectDataPath
      PDQ Connect agent data root on the remote target. Default (if not provided
      remotely) is $env:ProgramData\PDQ\PDQConnectAgent Note: Value is passed to the
      worker; if $null or empty, worker uses its own default.
    
    .OUTPUTS
      PSCustomObject with:
        - Staging : remote staging folder
          (C:\Windows\Temp\PDQDiag_<Computer>_<Timestamp>)
        - ZipPath : remote zip path
          (C:\Windows\Temp\PDQDiag_<Computer>_<Timestamp>.zip)
        - Script  : remote worker script path
        - Args    : remote args JSON path
    
    .NOTES
      Requires Private:Get-SystemWorkerScriptContent to be available in the local
      module so we can pass its content to the remote.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [string]$Timestamp,

        [string[]]$ExtraPaths,

        [string]$ConnectDataPath
    )

    if (-not (Get-Command -Name Get-SystemWorkerScriptContent -ErrorAction SilentlyContinue)) {
        throw "Get-SystemWorkerScriptContent is not available. Ensure the private function is loaded in the module."
    }

    # Pull the worker content locally (here-string) and send it over in one go
    $workerContent = Get-SystemWorkerScriptContent

    # Execute the SYSTEM workflow remotely
    $res = Invoke-Command -Session $Session -ScriptBlock {
        param(
            [string]$ts,
            [string[]]$extras,
            [string]$connectPath,
            [string]$workerText
        )

        $ErrorActionPreference = 'Stop'

        # Always use C:\Windows\Temp so SYSTEM can read/write
        $tempRoot = Join-Path $env:windir 'Temp'
        $argsPath = Join-Path $tempRoot ("PDQDiag_args_{0}.json" -f $ts)
        $scrPath = Join-Path $tempRoot ("PDQDiag_worker_{0}.ps1" -f $ts)
        $stagPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME, $ts)
        $doneFlag = Join-Path $stagPath 'system_done.flag'
        $zipPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $ts)

        # Prepare arguments payload for the worker
        $payload = [pscustomobject]@{
            Timestamp       = $ts
            ConnectDataPath = $connectPath
            ExtraPaths      = @($extras)
        } | ConvertTo-Json -Depth 5

        # Write worker + args to remote temp
        $payload     | Set-Content -Path $argsPath -Encoding UTF8
        $workerText  | Set-Content -Path $scrPath  -Encoding UTF8

        # Create and start SYSTEM scheduled task
        $taskName = "PDQDiag-Collect-$ts"
        $actionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scrPath`" -ArgsPath `"$argsPath`""
        $usedSchtasks = $false

        try {
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
            $task = Register-ScheduledTask -TaskName $taskName -Action $act -RunLevel Highest -User 'SYSTEM' -Force
            Start-ScheduledTask -TaskName $taskName
        }
        catch {
            # Fallback to schtasks in case scheduled tasks cmdlets are restricted
            $usedSchtasks = $true
            & schtasks.exe /Create /TN $taskName /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR ("powershell.exe {0}" -f $actionArgs) /F | Out-Null
            & schtasks.exe /Run /TN $taskName | Out-Null
        }

        # Wait up to 180 seconds for the worker to finish
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $doneFlag -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 2
        }

        # Cleanup registration (leave the zip + staging for caller to retrieve/verify)
        try {
            if ($usedSchtasks) {
                & schtasks.exe /Delete /TN $taskName /F | Out-Null
            }
            else {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {}

        # Return the paths for the caller to retrieve/clean
        [pscustomobject]@{
            Staging = $stagPath
            ZipPath = $zipPath
            Script  = $scrPath
            Args    = $argsPath
        }
    } -ArgumentList $Timestamp, $ExtraPaths, $ConnectDataPath, $workerContent

    return $res
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Move-ToCamelKey.ps1
`powershell

function Move-ToCamelKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Label)

    $map = @{
        'Design Capacity'      = 'designCapacity'
        'Full Charge Capacity' = 'fullChargeCapacity'
        'Chemistry'            = 'chemistry'
        'Serial Number'        = 'serialNumber'
        'Manufacturer'         = 'manufacturer'
        'Name'                 = 'name'
        'Battery Name'         = 'batteryName'
        'Cycle Count'          = 'cycleCount'
        'Remaining Capacity'   = 'remainingCapacity'
    }

    # Normalize input
    $Label = [string]$Label
    $Label = $Label.Trim()

    if ([string]::IsNullOrWhiteSpace($Label)) {
        return $null
    }

    # Try direct map match
    foreach ($k in $map.Keys) {
        if ($Label -match ('^(?i)' + [regex]::Escape($k) + '$')) {
            return $map[$k]
        }
    }

    # Fallback: sanitize and split
    $fallback = ($Label -replace '[^A-Za-z0-9 ]', '' -replace '\s+', ' ').Trim()
    if (-not $fallback) { return $null }

    $parts = $fallback.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -eq 0) { return $null }
    if ($parts.Count -eq 1) { return $parts[0].ToLower() }

    $first = $parts[0].ToLower()
    $rest = $parts[1..($parts.Count - 1)] | ForEach-Object {
        $_.Substring(0, 1).ToUpper() + $_.Substring(1).ToLower()
    }

    return ($first + ($rest -join ''))
}
[SIGNATURE BLOCK REMOVED]

`### FILE: New-ADUserNormalize.ps1
`powershell
function New-ADUserNormalize([string]$s) { ($s -replace '\s+', '').ToLower() }
[SIGNATURE BLOCK REMOVED]

`### FILE: Receive-RemoteFile.ps1
`powershell
function Receive-RemoteFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][string]$RemotePath,
        [Parameter(Mandatory)][string]$LocalPath,
        [ValidateSet('FromSession', 'Bytes', 'SMB')]
        [string]$Mode = 'FromSession'
    )
    $comp = $Session.ComputerName
    $ok = $false
    $errs = @()

    switch ($Mode) {
        'FromSession' {
            try {
                Copy-Item -Path $RemotePath -Destination $LocalPath -FromSession $Session -ErrorAction Stop
                $ok = $true
            }
            catch {
                $errs += "[$comp] FromSession failed: $($_.Exception.Message)"
            }
            if ($ok) { break }
        }
        'Bytes' {
            if (-not $ok) {
                try {
                    $b64 = Invoke-Command -Session $Session -ScriptBlock {
                        param($p) [Convert]::ToBase64String([IO.File]::ReadAllBytes($p))
                    } -ArgumentList $RemotePath -ErrorAction Stop
                    [IO.File]::WriteAllBytes($LocalPath, [Convert]::FromBase64String($b64))
                    $ok = $true
                }
                catch {
                    $errs += "[$comp] Bytes failed: $($_.Exception.Message)"
                }
            }
            if ($ok) { break }
            try {
                $drive = $RemotePath.Substring(0, 1)
                $rest = $RemotePath.Substring(2)
                $unc = "\\$comp\${drive}$" + $rest
                Copy-Item -Path $unc -Destination $LocalPath -Force -ErrorAction Stop
                $ok = $true
            }
            catch {
                $errs += "[$comp] SMB failed: $($_.Exception.Message)"
            }
        }
        'SMB' {
            try {
                $drive = $RemotePath.Substring(0, 1)
                $rest = $RemotePath.Substring(2)
                $unc = "\\$comp\${drive}$" + $rest
                Copy-Item -Path $unc -Destination $LocalPath -Force -ErrorAction Stop
                $ok = $true
            }
            catch {
                $errs += "[$comp] SMB failed: $($_.Exception.Message)"
            }
        }
    }

    if (-not $ok) { throw ($errs -join ' | ') }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Resolve-Naming.ps1
`powershell
function Resolve-Naming {
    param(
        [hashtable]$Naming,
        [string]$GivenName,
        [string]$Surname
    )
    $f = New-ADUserNormalize $GivenName
    $l = New-ADUserNormalize $Surname

    # UPN prefix
    switch ($Naming.upnPattern) {
        'first.last' { $upnPrefix = "$f.$l" }
        'flast' { $upnPrefix = '{0}{1}' -f $f.Substring(0, 1), $l }
        default { $upnPrefix = "$f.$l" }
    }

    # SAM
    switch ($Naming.samPattern) {
        'first.last' { $sam = "$f.$l" }
        'flast' { $sam = '{0}{1}' -f $f.Substring(0, 1), $l }
        default { $sam = '{0}{1}' -f $f.Substring(0, 1), $l }
    }

    [pscustomobject]@{
        UpnPrefix = $upnPrefix
        Sam       = $sam
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-PDQDiagLocalSystem.ps1
`powershell
function Start-PDQDiagLocalSystem {
    <#
.SYNOPSIS
  Collect PDQ diagnostics on THIS machine under SYSTEM and drop the ZIP to LocalDropPath.

.DESCRIPTION
  - Creates a one-shot scheduled task as SYSTEM that runs the PDQ worker.
  - Worker writes to C:\Windows\Temp\PDQDiag_<Host>_<Timestamp>.zip
  - This function then copies that ZIP to -LocalDropPath.

.PARAMETER LocalDropPath
  Destination folder for the final ZIP. Default: C:\PDQDiagLogs

.PARAMETER ExtraPaths
  Additional files/folders to include.

.PARAMETER ConnectDataPath
  Root for PDQ Connect agent data. Default: "$env:ProgramData\PDQ\PDQConnectAgent"

.PARAMETER Timestamp
  Optional fixed timestamp (yyyyMMdd-HHmmss). If not provided, generated automatically.

.OUTPUTS
  [pscustomobject] with ComputerName, Status, ZipPath, Notes
#>
    [CmdletBinding()]
    param(
        [string]  $LocalDropPath = 'C:\PDQDiagLogs',
        [string[]]$ExtraPaths,
        [string]  $ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),
        [string]  $Timestamp
    )

    if (-not (Get-Command -Name Get-SystemWorkerScriptContent -ErrorAction SilentlyContinue)) {
        throw "Get-SystemWorkerScriptContent is not available. Make sure it's dot-sourced in the module (Private\Get-SystemWorkerScriptContent.ps1)."
    }

    if (-not $Timestamp) { $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss' }
    if (-not (Test-Path -LiteralPath $LocalDropPath)) {
        New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
    }

    $tempRoot = Join-Path $env:windir 'Temp'
    $argsPath = Join-Path $tempRoot ("PDQDiag_args_{0}.json" -f $Timestamp)
    $scrPath = Join-Path $tempRoot ("PDQDiag_worker_{0}.ps1" -f $Timestamp)
    $staging = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME, $Timestamp)
    $doneFlag = Join-Path $staging  'system_done.flag'
    $zipPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $Timestamp)
    $finalZip = Join-Path $LocalDropPath ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $Timestamp)

    # Write worker + args for SYSTEM
    [pscustomobject]@{
        Timestamp       = $Timestamp
        ConnectDataPath = $ConnectDataPath
        ExtraPaths      = @($ExtraPaths)
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $argsPath -Encoding UTF8

    (Get-SystemWorkerScriptContent) | Set-Content -Path $scrPath -Encoding UTF8

    Write-Host ("[{0}] Scheduling SYSTEM worker..." -f $env:COMPUTERNAME) -ForegroundColor Cyan
    $taskName = "PDQDiag-Local-$Timestamp"
    $actionArg = "-NoProfile -ExecutionPolicy Bypass -File `"$scrPath`" -ArgsPath `"$argsPath`""

    $usedSchtasks = $false
    try {
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArg
        $task = Register-ScheduledTask -TaskName $taskName -Action $act -RunLevel Highest -User 'SYSTEM' -Force
        Start-ScheduledTask -TaskName $taskName
    }
    catch {
        $usedSchtasks = $true
        & schtasks.exe /Create /TN $taskName /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR ("powershell.exe {0}" -f $actionArg) /F | Out-Null
        & schtasks.exe /Run /TN $taskName | Out-Null
    }

    # Wait up to 3 minutes for done flag
    Write-Host ("[{0}] Waiting for completion..." -f $env:COMPUTERNAME) -ForegroundColor DarkCyan
    $deadline = (Get-Date).AddSeconds(180)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $doneFlag -ErrorAction SilentlyContinue)) {
        Start-Sleep -Seconds 2
    }

    # Cleanup task registration
    try {
        if ($usedSchtasks) { & schtasks.exe /Delete /TN $taskName /F | Out-Null }
        else { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    }
    catch {}

    if (-not (Test-Path -LiteralPath $zipPath -ErrorAction SilentlyContinue)) {
        throw "SYSTEM worker did not produce ZIP at $zipPath"
    }

    Copy-Item -LiteralPath $zipPath -Destination $finalZip -Force
    Write-Host ("[{0}] ZIP ready: {1}" -f $env:COMPUTERNAME, $finalZip) -ForegroundColor Green

    # Best-effort cleanup of temp artifacts
    try {
        if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $scrPath) { Remove-Item -LiteralPath $scrPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $argsPath) { Remove-Item -LiteralPath $argsPath -Force -ErrorAction SilentlyContinue }
    }
    catch {}

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'Success'
        ZipPath      = $finalZip
        Notes        = 'Local SYSTEM collection (scheduled task)'
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-Administrator.ps1
`powershell
function Test-Administrator {
    <#
    .SYNOPSIS
        Tests if the current PowerShell session is running with Administrator
        privileges.
    .NOTES
        Reusable function for TechToolbox.
    #>
    [CmdletBinding()]
    param()

    try {
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Update-CamelKey.ps1
`powershell
function Update-CamelKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label
    )

    # Normalize text first
    $clean = Update-Text $Label

    # Lowercase, remove non-alphanumerics except spaces
    $clean = ($clean.ToLower() -replace '[^a-z0-9 ]', '').Trim()

    if ([string]::IsNullOrWhiteSpace($clean)) {
        return ""
    }

    $parts = $clean -split '\s+'
    $key = $parts[0]

    for ($i = 1; $i -lt $parts.Length; $i++) {
        $part = $parts[$i]
        $key += ($part.Substring(0, 1).ToUpper() + $part.Substring(1))
    }

    return $key
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Update-Text.ps1
`powershell
function Update-Text {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Text
    )

    if (-not $Text) { return "" }

    # Decode HTML entities if possible
    try {
        $decoded = [System.Web.HttpUtility]::HtmlDecode($Text)
    }
    catch {
        $decoded = $Text
    }

    # Strip HTML tags, normalize whitespace, remove non-breaking spaces
    $clean = ($decoded -replace '<[^>]+>', '')
    $clean = $clean -replace [char]0xA0, ' '
    $clean = $clean -replace '\s+', ' '

    return $clean.Trim()
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-NewPassword.ps1
`powershell

function Get-NewPassword {
    [CmdletBinding()]
    param(
        [ValidateSet('Random', 'Readable', 'Passphrase')]
        [string]$Style,

        [int]$Length,

        [int]$Digits,

        [string]$Separator,

        [switch]$IncludeSymbol,

        [switch]$NoAmbiguous,

        [int]$NonAlpha,

        [string[]]$DisallowTokens = @()
    )

    $cfg = Get-TechToolboxConfig
    $wlPath = $cfg.settings.passwords.wordListPath
    $def = $cfg.settings.passwords.default

    # Apply defaults only if not explicitly passed
    if (-not $PSBoundParameters.ContainsKey('Style') -and $def.style) { $Style = $def.style }
    if (-not $PSBoundParameters.ContainsKey('Length') -and $def.length) { $Length = [int]$def.length }
    if (-not $PSBoundParameters.ContainsKey('Digits') -and $def.digits) { $Digits = [int]$def.digits }
    if (-not $PSBoundParameters.ContainsKey('Separator') -and $def.separator -ne $null) { $Separator = [string]$def.separator }

    # Random style-only param default
    if ($Style -eq 'Random' -and -not $PSBoundParameters.ContainsKey('NonAlpha')) {
        $NonAlpha = 0
    }

    # Call the generator
    New-RandomPassword `
        -Style ($Style ? $Style : 'Readable') `
        -Length ($Length ? $Length : 12) `
        -Digits ($Digits ? $Digits : 2) `
        -Separator ($Separator ? $Separator : '') `
        -IncludeSymbol:$IncludeSymbol `
        -NoAmbiguous:$NoAmbiguous `
        -NonAlpha ($NonAlpha ? $NonAlpha : 0) `
        -WordListPath $wlPath `
        -DisallowTokens $DisallowTokens
}

[SIGNATURE BLOCK REMOVED]

`### FILE: New-RandomPassword.ps1
`powershell

function New-RandomPassword {
    <#
    .SYNOPSIS
        Generates passwords that meet AD "complexity" (3/4 categories) using Random, Readable, or Passphrase styles.

    .DESCRIPTION
        - Random: cryptographically-random with optional symbols; exact length.
        - Readable: Two (or more) capitalized words + digits (+ optional symbol); length is a minimum.
        - Passphrase: 3–4 lower/Title words with separators + digits; length is a minimum.
        All styles avoid ambiguous characters when -NoAmbiguous is set. You can provide -DisallowTokens
        to prevent generating passwords that include user-related tokens (e.g., given/surname fragments).

    .PARAMETER Length
        For Random: exact length. For Readable/Passphrase: *minimum* length; will be padded if shorter.

    .PARAMETER NonAlpha
        Number of required symbols (Random style only). Set to 0 to omit symbols entirely.

    .PARAMETER NoAmbiguous
        Excludes look-alike chars and, for Readable/Passphrase, filters out words containing ambiguous letters.

    .PARAMETER Style
        Random | Readable | Passphrase

    .PARAMETER Words
        Number of words for Readable/Passphrase (Readable defaults 2; Passphrase defaults 3).

    .PARAMETER Digits
        Number of digits to include (ensures numeric category).

    .PARAMETER Separator
        Character(s) used between words for Readable/Passphrase (e.g., '-', '.', '').

    .PARAMETER IncludeSymbol
        Adds exactly one symbol in Readable/Passphrase styles (not required for AD).

    .PARAMETER WordListPath
        Optional path to a newline-delimited word list. If not supplied or not found, a built-in list is used.

    .PARAMETER DisallowTokens
        Array of strings to avoid (case-insensitive). If any token of length >= 3 appears, regenerates.

    .EXAMPLE
        New-RandomPassword -Style Readable -Length 12 -Digits 2
        # Example: RiverStone88

    .EXAMPLE
        New-RandomPassword -Style Passphrase -Length 16 -Separator '-' -Digits 3
        # Example: tiger-forest-echo721

    .EXAMPLE
        New-RandomPassword -Style Random -Length 16 -NonAlpha 0 -NoAmbiguous
        # Example: Hw7t9GZxFv3K2QmN
    #>
    [CmdletBinding(DefaultParameterSetName = 'Random')]
    param(
        [ValidateRange(8, 256)]
        [int]$Length = 16,

        # Random style only: number of required non-alphanumeric (symbols)
        [Parameter(ParameterSetName = 'Random')]
        [ValidateRange(0, 64)]
        [int]$NonAlpha = 0,

        [switch]$NoAmbiguous,

        [ValidateSet('Random', 'Readable', 'Passphrase')]
        [string]$Style = 'Random',

        # Word-based styles
        [ValidateRange(2, 6)]
        [int]$Words = 2,

        [ValidateRange(1, 6)]
        [int]$Digits = 2,

        [string]$Separator = '',

        [switch]$IncludeSymbol,

        [string]$WordListPath,

        [string[]]$DisallowTokens = @(),

        [ValidateRange(1, 200)]
        [int]$MaxRegenerate = 50
    )

    # Character sets
    $UpperSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $LowerSet = 'abcdefghijklmnopqrstuvwxyz'
    $DigitSet = '0123456789'
    $SymbolSet = '!@#$%^&*_-+=?'

    if ($NoAmbiguous) {
        $UpperSet = 'ABCDEFGHJKLMNPQRSTUVWXYZ'      # no I, O
        $LowerSet = 'abcdefghijkmnpqrstuvwxyz'      # no l, o
        $DigitSet = '23456789'                      # no 0, 1
        # symbols ok as-is
    }

    # Crypto RNG helpers
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $hasGetInt32 = ([System.Security.Cryptography.RandomNumberGenerator].GetMethod('GetInt32', [type[]]@([int], [int])) -ne $null)

    function Get-RandomIndex {
        param([int]$MaxExclusive)
        if ($MaxExclusive -le 0) { return 0 }
        if ($hasGetInt32) {
            return [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $MaxExclusive)
        }
        else {
            $b = New-Object byte[] 4
            $rng.GetBytes($b)
            return [Math]::Abs([BitConverter]::ToInt32($b, 0) % $MaxExclusive)
        }
    }

    function Get-RandomChar {
        param([string]$DigitSet)
        $DigitSet[(Get-RandomIndex $DigitSet.Length)]
    }

    function Get-RandomFromList {
        param([string[]]$List)
        $List[(Get-RandomIndex $List.Count)]
    }

    function Shuffle([char[]]$arr) {
        for ($i = $arr.Length - 1; $i -gt 0; $i--) {
            $j = Get-RandomIndex ($i + 1)
            if ($j -ne $i) {
                $tmp = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $tmp
            }
        }
        -join $arr
    }

    function Load-WordList {
        param([string]$Path, [switch]$NoAmbiguous)
        $list = @()
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            $list = Get-Content -LiteralPath $Path -ErrorAction Stop | Where-Object { $_ -match '^[A-Za-z]{3,10}$' }
        }
        if (-not $list -or $list.Count -lt 100) {
            # Fallback mini list if wordlist.txt fails to load
            $list = @(
                'river', 'stone', 'blue', 'green', 'tiger', 'forest', 'echo', 'delta', 'nova', 'ember', 'maple', 'cedar', 'birch', 'pine',
                'silver', 'shadow', 'crimson', 'cobalt', 'onyx', 'raven', 'falcon', 'otter', 'fox', 'wolf', 'lynx', 'badger', 'eagle',
                'harbor', 'summit', 'meadow', 'prairie', 'canyon', 'valley', 'spring', 'autumn', 'winter', 'summer', 'breeze', 'cloud',
                'storm', 'thunder', 'rain', 'snow', 'frost', 'glacier', 'aurora', 'comet', 'meteor', 'orbit', 'quartz', 'granite', 'basalt',
                'pebble', 'coral', 'reef', 'tide', 'delta', 'lagoon', 'moss', 'fern', 'willow', 'aspen', 'spruce', 'hemlock', 'elm',
                'copper', 'iron', 'nickel', 'zinc', 'amber', 'topaz', 'agate', 'jade', 'opal', 'pearl', 'sapphire', 'ruby', 'garnet',
                'swift', 'brisk', 'rapid', 'steady', 'bold', 'bright', 'quiet', 'gentle', 'keen', 'vivid', 'lively', 'nimble', 'solid',
                'lofty', 'noble', 'true', 'prime', 'vantage', 'zenith', 'apex', 'vertex', 'vector', 'gamma', 'omega', 'alpha', 'sigma',
                'orbit', 'photon', 'quark', 'ion', 'pixel', 'matrix', 'cipher', 'beacon', 'signal', 'kernel', 'crypto', 'evergreen', 'lake'
            )
        }
        $list = $list | ForEach-Object { $_.ToLowerInvariant().Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique
        if ($NoAmbiguous) {
            $list = $list | Where-Object { $_ -notmatch '[ilo10]' } # filter words with ambiguous chars
        }
        return $list
    }

    function Violates-Tokens {
        param([string]$Text, [string[]]$Tokens)
        foreach ($t in $Tokens) {
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            $tok = $t.Trim()
            if ($tok.Length -lt 3) { continue } # AD typically flags 3+ char sequences
            if ($Text -imatch [regex]::Escape($tok)) { return $true }
        }
        return $false
    }

    try {
        switch ($Style) {
            'Random' {
                # Ensure at least: 1 upper, 1 lower, 1 digit, + NonAlpha symbols
                $minRequired = 3 + $NonAlpha
                if ($Length -lt $minRequired) {
                    throw "Requested Length $Length is less than required minimum $minRequired (1 upper + 1 lower + 1 digit + $NonAlpha symbol(s))."
                }

                # Collect mandatory characters
                $chars = New-Object System.Collections.Generic.List[char]
                $chars.Add((Get-RandomChar $UpperSet))
                $chars.Add((Get-RandomChar $LowerSet))
                $chars.Add((Get-RandomChar $DigitSet))
                for ($i = 0; $i -lt $NonAlpha; $i++) { $chars.Add((Get-RandomChar $SymbolSet)) }

                # Fill remaining with union of sets (respecting NonAlpha=0 if you want no symbols)
                $all = ($UpperSet + $LowerSet + $DigitSet + ($NonAlpha -gt 0 ? $SymbolSet : '')).ToCharArray()
                while ($chars.Count -lt $Length) {
                    $chars.Add($all[(Get-RandomIndex $all.Length)])
                }

                # Shuffle & return
                $pwd = Shuffle ($chars.ToArray())
                return $pwd
            }

            'Readable' {
                # Make at least 2 words capitalized to ensure Upper+Lower, plus digits -> meets 3/4
                $wl = Load-WordList -Path $WordListPath -NoAmbiguous:$NoAmbiguous
                if ($Words -lt 2) { $Words = 2 } # enforce sane min for readability

                for ($attempt = 0; $attempt -lt $MaxRegenerate; $attempt++) {
                    $picked = for ($i = 1; $i -le $Words; $i++) { Get-RandomFromList $wl }
                    $capIdx = Get-RandomIndex $picked.Count
                    $wordsOut = for ($i = 0; $i -lt $picked.Count; $i++) {
                        if ($i -eq $capIdx) {
                            # TitleCase one word for uppercase category
                            ($picked[$i].Substring(0, 1).ToUpperInvariant() + $picked[$i].Substring(1).ToLowerInvariant())
                        }
                        else {
                            $picked[$i].ToLowerInvariant()
                        }
                    }

                    $digitsStr = -join (1..$Digits | ForEach-Object { Get-RandomChar $DigitSet })
                    $parts = @($wordsOut -join $Separator, $digitsStr)

                    if ($IncludeSymbol) {
                        # Insert symbol at a random position among parts
                        $sym = Get-RandomChar $SymbolSet
                        $insertPos = Get-RandomIndex ($parts.Count + 1)
                        $parts = ($parts[0..($insertPos - 1)] + $sym + $parts[$insertPos..($parts.Count - 1)]) -join ''
                    }
                    else {
                        $parts = -join $parts
                    }

                    $candidate = $parts

                    # Ensure minimum length (pad with lowercase if short)
                    if ($candidate.Length -lt $Length) {
                        $padCount = $Length - $candidate.Length
                        $pad = -join (1..$padCount | ForEach-Object { Get-RandomChar $LowerSet })
                        $candidate += $pad
                    }

                    if ($DisallowTokens.Count -gt 0 -and (Violates-Tokens -Text $candidate -Tokens $DisallowTokens)) {
                        continue
                    }

                    # Sanity: ensure categories: upper, lower, digit
                    if (($candidate -cmatch '[A-Z]') -and ($candidate -cmatch '[a-z]') -and ($candidate -match '\d')) {
                        return $candidate
                    }
                }
                throw "Failed to generate a Readable password after $MaxRegenerate attempts. Consider relaxing DisallowTokens/length."
            }

            'Passphrase' {
                # Typically 3+ words, lower/title with separator, + digits; length is a minimum
                if ($Words -lt 3) { $Words = 3 }
                $wl = Load-WordList -Path $WordListPath -NoAmbiguous:$NoAmbiguous

                for ($attempt = 0; $attempt -lt $MaxRegenerate; $attempt++) {
                    $picked = for ($i = 1; $i -le $Words; $i++) { Get-RandomFromList $wl }
                    # Capitalize one random word to ensure uppercase category
                    $capIdx = Get-RandomIndex $picked.Count
                    for ($i = 0; $i -lt $picked.Count; $i++) {
                        if ($i -eq $capIdx) {
                            $picked[$i] = $picked[$i].Substring(0, 1).ToUpperInvariant() + $picked[$i].Substring(1).ToLowerInvariant()
                        }
                        else {
                            $picked[$i] = $picked[$i].ToLowerInvariant()
                        }
                    }

                    $core = ($picked -join $Separator)
                    $digitsStr = -join (1..$Digits | ForEach-Object { Get-RandomChar $DigitsSet })
                    $candidate = $core + $digitsStr

                    if ($IncludeSymbol) {
                        $candidate += (Get-RandomChar $SymbolSet)
                    }

                    if ($candidate.Length -lt $Length) {
                        $padCount = $Length - $candidate.Length
                        $pad = -join (1..$padCount | ForEach-Object { Get-RandomChar $LowerSet })
                        $candidate += $pad
                    }

                    if ($DisallowTokens.Count -gt 0 -and (Violates-Tokens -Text $candidate -Tokens $DisallowTokens)) {
                        continue
                    }

                    # Ensure categories: upper, lower, digit
                    if (($candidate -cmatch '[A-Z]') -and ($candidate -cmatch '[a-z]') -and ($candidate -match '\d')) {
                        return $candidate
                    }
                }
                throw "Failed to generate a Passphrase after $MaxRegenerate attempts. Consider relaxing DisallowTokens/length."
            }
        }
    }
    finally {
        $rng.Dispose()
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Restart-Elevated.ps1
`powershell

function Restart-Elevated {
    param(
        [string[]]$OriginalArgs = @()
    )
    $hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' }
    $argsLine = [string]::Join(' ', $OriginalArgs)
    Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $argsLine
    exit
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-IsElevated.ps1
`powershell

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Disable-User.ps1
`powershell

function Disable-User {
    <#
    .SYNOPSIS
        Disables an Active Directory user account and performs offboarding
        tasks.
    .DESCRIPTION
        Disables an Active Directory user account, moves it to a specified OU,
        removes group memberships, and optionally performs cloud offboarding
        tasks such as converting Exchange Online mailboxes to shared and signing
        the user out of Microsoft Teams. This function is designed to be
        Graph-free, relying on other functions that do not require Microsoft
        Graph.
    .PARAMETER Identity
        The identity of the user to disable. Can be a sAMAccountName, UPN, or
        other identifier.
    .PARAMETER IncludeEXO
        Switch to include Exchange Online offboarding tasks (convert mailbox to
        shared, grant manager access). Default behavior can be set in the config
        file.
    .PARAMETER IncludeTeams
        Switch to include Microsoft Teams offboarding tasks (sign out user).
        Default behavior can be set in the config file.
    .PARAMETER TriggerAADSync
        Switch to trigger an Azure AD Connect delta sync after disabling the
        user in Active Directory.
    .INPUTS
        String (Identity)
    .OUTPUTS
        PSCustomObject containing the results of each offboarding step.
    .EXAMPLE
        Disable-User -Identity 'jdoe' -IncludeEXO -IncludeTeams
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        # Optional toggles for cloud tasks that don't require Graph
        [switch]$IncludeEXO,     # Convert mailbox to shared, grant manager access
        [switch]$IncludeTeams,   # Sign out / cleanup via Teams wrapper (if present)
        [pscredential]$Credential
    )

    # Ensure $user exists for safe logging even if resolution fails
    $user = $null

    try {
        Write-Log -Level Info -Message ("Starting Disable-User workflow for '{0}'..." -f $Identity)

        # --- Load config (block/dot)
        $cfg = Get-TechToolboxConfig
        if (-not $cfg) { throw "Get-TechToolboxConfig returned null. Check your config path and schema." }

        $settings = $cfg.settings
        if (-not $settings) { throw "Config missing 'settings' node." }

        $off = $settings.offboarding
        if (-not $off) { throw "Config missing 'settings.offboarding' node." }

        $exo = $settings.exchangeOnline
        if (-not $exo) { throw "Config missing 'settings.exchangeOnline' node." }

        # Respect config defaults for EXO/Teams/AADSync if caller didn't pass switches
        if (-not $PSBoundParameters.ContainsKey('IncludeEXO') -and $settings.exchangeOnline.includeInOffboarding) { $IncludeEXO = $true }
        if (-not $PSBoundParameters.ContainsKey('IncludeTeams') -and $settings.teams.includeInOffboarding) { $IncludeTeams = $true }

        # Validate keys used below
        if ($off.PSObject.Properties.Name -contains 'disabledOU' -and [string]::IsNullOrWhiteSpace($off.disabledOU)) {
            Write-Log -Level Warn -Message "settings.offboarding.disabledOU is empty; will skip OU move."
        }

        # --- Resolve user (Graph-free Search-User)
        Write-Log -Level Info -Message ("Offboarding: Resolving user '{0}'..." -f $Identity)
        try {
            $suParams = @{
                Identity     = $Identity
                IncludeEXO   = $IncludeEXO
                IncludeTeams = $IncludeTeams
            }
            if ($Credential) { $suParams.Credential = $Credential }
            $user = Search-User @suParams
        }
        catch {
            throw "Search-User threw an error while resolving '$Identity': $($_.Exception.Message)"
        }
        if (-not $user) { throw "User '$Identity' not found by Search-User." }

        $results = [ordered]@{}

        # --- AD Disable
        Write-Log -Level Info -Message ("Offboarding: Disabling AD account for '{0}'..." -f $user.SamAccountName)
        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Disable AD account")) {
            $disableParams = @{
                SamAccountName = $user.SamAccountName
                DisabledOU     = $off.disabledOU
            }
            if ($Credential) { $disableParams.Credential = $Credential }   # NEW
            $results.ADDisable = Disable-ADUserAccount @disableParams
        }

        # Normalize return for safe property access
        $movedHandled = $false
        if ($results.ADDisable) {
            if ($results.ADDisable -is [hashtable]) {
                $movedHandled = [bool]$results.ADDisable['MovedToOU']
            }
            else {
                $movedHandled = [bool]$results.ADDisable.MovedToOU
            }
        }

        # --- Move to Disabled OU if needed
        if ($off.disabledOU -and -not $movedHandled) {
            Write-Log -Level Info -Message ("Offboarding: Moving '{0}' to Disabled OU..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Move AD user to Disabled OU")) {
                $moveParams = @{
                    SamAccountName = $user.SamAccountName
                    TargetOU       = $off.disabledOU
                }
                if ($Credential) { $moveParams.Credential = $Credential }  # NEW
                $results.MoveOU = Move-UserToDisabledOU @moveParams
            }
        }

        # --- Optional: Cleanup AD groups
        if ($off.cleanupADGroups) {
            Write-Log -Level Info -Message ("Offboarding: Cleaning AD group memberships for '{0}'..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Cleanup AD group memberships")) {
                $grpParams = @{ SamAccountName = $user.SamAccountName }
                if ($Credential) { $grpParams.Credential = $Credential }   # NEW
                $results.ADGroups = Remove-ADUserGroups @grpParams
            }
        }

        # --- Hybrid auto-disable mode (Graph-free path)
        if ($off.useHybridAutoDisable) {
            Write-Log -Level Info -Message "Hybrid auto-disable enabled. Cloud actions will be handled by AAD Connect."
            Write-OffboardingSummary -User $user -Results $results
            Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
            return [pscustomobject]$results
        }

        # --- Cloud actions (Graph-free): EXO + Teams only
        Write-Log -Level Info -Message "Proceeding with cloud offboarding actions (Graph-free)..."

        # EXO
        if ($IncludeEXO) {
            if (Get-Command Connect-ExchangeOnlineIfNeeded -ErrorAction SilentlyContinue) {
                $showProgress = $settings?.exchangeOnline?.showProgress
                Connect-ExchangeOnlineIfNeeded -ShowProgress:$showProgress
            }
            # Convert mailbox to shared
            if ($user.UserPrincipalName -and (Get-Command Convert-MailboxToShared -ErrorAction SilentlyContinue)) {
                Write-Log -Level Info -Message ("Offboarding: Converting mailbox to shared for '{0}'..." -f $user.UserPrincipalName)
                $results.Mailbox = Convert-MailboxToShared -Identity $user.UserPrincipalName
            }
            # Grant manager access
            if ($user.UserPrincipalName -and (Get-Command Grant-ManagerMailboxAccess -ErrorAction SilentlyContinue)) {
                Write-Log -Level Info -Message ("Offboarding: Granting manager access for '{0}'..." -f $user.UserPrincipalName)
                $results.ManagerAccess = Grant-ManagerMailboxAccess -Identity $user.UserPrincipalName
            }
        }

        # Teams (no Graph)
        if ($IncludeTeams -and (Get-Command Remove-TeamsUser -ErrorAction SilentlyContinue)) {
            if (Get-Command Connect-MicrosoftTeamsIfNeeded -ErrorAction SilentlyContinue) {
                Connect-MicrosoftTeamsIfNeeded | Out-Null
            }
            if ($user.UserPrincipalName) {
                Write-Log -Level Info -Message ("Offboarding: Signing out of Teams / cleanup for '{0}'..." -f $user.UserPrincipalName)
                $results.Teams = Remove-TeamsUser -Identity $user.UserPrincipalName
            }
        }

        # --- Summary
        Write-Log -Level Info -Message ("Offboarding: Generating summary for '{0}'..." -f ($user.UserPrincipalName ?? $Identity))
        Write-OffboardingSummary -User $user -Results $results

        Write-Log -Level Info -Message ("Offboarding: Completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
        Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
        return [pscustomobject]$results
    }
    catch {
        # SAFE: $user may be $null; fall back to $Identity
        $who = if ($user -and $user.UserPrincipalName) { $user.UserPrincipalName } else { $Identity }
        Write-Log -Level Error -Message ("Disable-User failed for '{0}': {1}" -f $who, $_.Exception.Message)
        throw  # rethrow to surface in console/CI
    }
    finally { [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo) }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: New-OnPremUserFromTemplate.ps1
`powershell

function New-OnPremUserFromTemplate {
    <#
    .SYNOPSIS
    Create a new on-premises AD user based on a template user.

    .DESCRIPTION
    Creates a new Active Directory user by copying attributes and group
    memberships from a specified template user. Naming (UPN, SAM, alias) derives
    from config unless overridden.

    .PARAMETER TemplateIdentity
    Identity (sAMAccountName, DN, SID, GUID) of the template user to copy.

    .PARAMETER TemplateSearch
    Hashtable of attribute=value pairs to locate the template (first match
    wins).

    .PARAMETER GivenName
    First name of the new user.

    .PARAMETER Surname
    Last name of the new user.

    .PARAMETER DisplayName
    Display name of the new user.

    .PARAMETER TargetOU
    DistinguishedName of the OU to create the user in. Defaults to template’s
    OU.

    .PARAMETER SamAccountName
    sAMAccountName for the new user. Derived if omitted.

    .PARAMETER UpnPrefix
    UPN prefix for the new user. Derived if omitted.

    .PARAMETER CopyAttributes
    Attributes to copy from template to the new user.

    .PARAMETER ExcludedGroups
    Group names to exclude when copying memberships.

    .PARAMETER InitialPasswordLength
    Length of the generated initial password.

    .PARAMETER Credential
    Directory credential to run AD operations as.

    .PARAMETER Server
    Optional DC to target (avoid replication latency during create+modify).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName = 'ByIdentity')]
        [string]$TemplateIdentity,

        [Parameter(ParameterSetName = 'BySearch')]
        [hashtable]$TemplateSearch,

        [Parameter(Mandatory)]
        [string]$GivenName,

        [Parameter(Mandatory)]
        [string]$Surname,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [string]$TargetOU,

        [string]$SamAccountName,
        [string]$UpnPrefix,

        [string[]]$CopyAttributes = @(
            'description', 'department', 'company', 'office', 'manager'
        ),

        [string[]]$ExcludedGroups = @(
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Protected Users', 'Server Operators', 'Account Operators', 'Backup Operators',
            'Print Operators', 'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers'
        ),

        [int]$InitialPasswordLength = 16,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [string]$Server
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        Import-Module ActiveDirectory -ErrorAction Stop

        # Load config (throws if missing essentials)
        $cfg = Get-TechToolboxConfig
        $Tenant = $cfg['settings']['tenant']
        $Naming = $cfg['settings']['naming']
        # If caller did NOT pass -CopyAttributes, take it from config
        $callerSpecifiedCopyAttrs = $PSBoundParameters.ContainsKey('CopyAttributes')
        if (-not $callerSpecifiedCopyAttrs) {
            if ($Naming -and $Naming['copyAttributes']) {
                $CopyAttributes = @($Naming['copyAttributes'])
            }
            else {
                $CopyAttributes = @()
            }
        }
        # Ensure it's an array of strings
        $CopyAttributes = @($CopyAttributes | ForEach-Object { $_.ToString() }) | Where-Object { $_ -and $_.Trim() -ne '' }

        # Map config-friendly names -> LDAP names (keyed lowercase for case-insensitive lookup)
        $configToLdap = @{
            'description' = 'description'
            'department'  = 'department'
            'company'     = 'company'
            'office'      = 'physicalDeliveryOfficeName'
            'manager'     = 'manager'
        }

        # Compute the LDAP attributes to request for the template user
        $CopyLdapAttrs = foreach ($name in $CopyAttributes) {
            $key = $name.ToLowerInvariant()
            if ($configToLdap.ContainsKey($key)) { $configToLdap[$key] } else { $name }
        }
        $CopyLdapAttrs = $CopyLdapAttrs | Select-Object -Unique

        # Map LDAP -> friendly AD parameter where one exists (used later when applying)
        $LdapToParam = @{
            department                 = 'Department'
            physicalDeliveryOfficeName = 'Office'
            company                    = 'Company'
            description                = 'Description'
            # manager is special (DN) → friendly param 'Manager' but value must be DN
        }

        # --- Resolve template user (according to parameter set) ---
        $adBase = @{ Credential = $Credential }
        if ($Server) { $adBase['Server'] = $Server }

        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' {
                if ([string]::IsNullOrWhiteSpace($TemplateIdentity)) {
                    throw "Parameter set 'ByIdentity' requires -TemplateIdentity."
                }
                $templateUser = Get-ADUser @adBase -Identity $TemplateIdentity -Properties $CopyLdapAttrs
            }
            'BySearch' {
                if (-not $TemplateSearch -or $TemplateSearch.Count -eq 0) {
                    throw "Parameter set 'BySearch' requires -TemplateSearch (hashtable filter)."
                }
                # Build a -Filter from the hashtable (simple AND of equality clauses)
                $clauses = foreach ($k in $TemplateSearch.Keys) {
                    $v = $TemplateSearch[$k]
                    # Escape quotes in value
                    $v = ($v -replace "'", "''")
                    "($k -eq '$v')"
                }
                $filter = ($clauses -join ' -and ')
                $templateUser = Get-ADUser @adBase -Filter $filter -Properties $CopyLdapAttrs |
                Select-Object -First 1
                if (-not $templateUser) {
                    throw "Template user not found using search filter: $filter"
                }
            }
            default {
                throw "Unknown parameter set: $($PSCmdlet.ParameterSetName)"
            }
        }

        # Expose a couple of helper items for the process/end blocks
        Set-Variable -Name LdapToParam     -Value $LdapToParam     -Scope 1
        Set-Variable -Name CopyLdapAttrs   -Value $CopyLdapAttrs   -Scope 1
        Set-Variable -Name templateUser    -Value $templateUser    -Scope 1
        Set-Variable -Name adBase          -Value $adBase          -Scope 1
    }

    process {
        # Breadcrumb #1: entering function
        Write-Log -Level Info -Message ("Entering New-OnPremUserFromTemplate (ParamSet={0})" -f $PSCmdlet.ParameterSetName)

        # 1) Resolve template user
        $templateUser = $null
        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' {
                $templateUser = Get-ADUser @adBase -Identity $TemplateIdentity -Properties $CopyLdapAttrs
            }
            'BySearch' {
                if (-not $TemplateSearch) { throw "Provide -TemplateSearch (e.g., @{ title='Engineer'; company='Company' })." }
                $ldapFilterParts = foreach ($k in $TemplateSearch.Keys) {
                    $val = [System.Text.RegularExpressions.Regex]::Escape($TemplateSearch[$k])
                    "($k=$val)"
                }
                $ldapFilter = "(&" + ($ldapFilterParts -join '') + ")"
                $templateUser = Get-ADUser @adBase -LDAPFilter $ldapFilter -Properties * -ErrorAction Stop |
                Select-Object -First 1
                if (-not $templateUser) { throw "No template user matched filter $ldapFilter." }
            }
            default { throw "Unexpected parameter set." }
        }

        Write-Log -Level Info -Message ("Template resolved: {0} ({1})" -f $templateUser.SamAccountName, $templateUser.UserPrincipalName)

        # 2) Derive naming via config (unless caller overrides)
        if (-not $UpnPrefix -or -not $SamAccountName) {
            $nm = Resolve-Naming -Naming $Naming -GivenName $GivenName -Surname $Surname
            if (-not $UpnPrefix) { $UpnPrefix = $nm.UpnPrefix }
            if (-not $SamAccountName) { $SamAccountName = $nm.Sam }
        }

        $newUpn = "$UpnPrefix@$($Tenant.upnSuffix)"

        # 3) Resolve target OU (default to template's OU)
        if (-not $TargetOU) {
            $TargetOU = ($templateUser.DistinguishedName -replace '^CN=.*?,')
        }

        Write-Log -Level Info -Message ("Provisioning: DisplayName='{0}', Sam='{1}', UPN='{2}', OU='{3}'" -f $DisplayName, $SamAccountName, $newUpn, $TargetOU)

        # 4) Idempotency check
        $exists = Get-ADUser @adBase -LDAPFilter "(userPrincipalName=$newUpn)" -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Log -Level Warn -Message "User UPN '$newUpn' already exists. Aborting."
            return
        }

        # 5) Create new user
        $initialPassword = Get-NewPassword -length $InitialPasswordLength -nonAlpha 3
        $securePass = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        $newParams = @{
            Name                  = $DisplayName
            DisplayName           = $DisplayName
            GivenName             = $GivenName
            Surname               = $Surname
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $newUpn
            Enabled               = $true     # set $false if prefer disabled on creation
            Path                  = $TargetOU
            ChangePasswordAtLogon = $true
            AccountPassword       = $securePass
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Create AD user")) {
            New-ADUser @adBase @newParams
            Write-Log -Level Ok -Message ("Created AD user: {0}" -f $newUpn)
        }

        # 6) Copy selected attributes from template (uses mappings from begin{})
        $friendlyProps = @{}
        $otherAttrs = @{}

        foreach ($attr in $CopyAttributes) {
            if (-not $attr) { continue }
            $key = $attr.ToString()
            $ldapName = $configToLdap[$key.ToLowerInvariant()]
            if (-not $ldapName) { $ldapName = $key }  # treat unknown as raw LDAP (e.g., extensionAttribute1)

            $val = $templateUser.$ldapName
            if ($null -eq $val) { continue }
            if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { continue }

            if ($ldapName -eq 'manager') {
                # Manager must be DN; set via friendly param if it looks like a DN
                if ($val -is [string] -and $val -match '^CN=.+,DC=.+') {
                    $friendlyProps['Manager'] = $val
                }
                else {
                    Write-Verbose "Skipping manager; value is not a DN: $val"
                }
                continue
            }

            if ($LdapToParam.ContainsKey($ldapName)) {
                $friendlyProps[$LdapToParam[$ldapName]] = $val
            }
            else {
                $otherAttrs[$ldapName] = $val
            }
        }

        # Avoid double-setting Office via friendly and LDAP at once
        if ($friendlyProps.ContainsKey('Office') -and $otherAttrs.ContainsKey('physicalDeliveryOfficeName')) {
            $null = $otherAttrs.Remove('physicalDeliveryOfficeName')
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Apply copied attributes")) {
            if ($friendlyProps.Count -gt 0) {
                Set-ADUser @adBase -Identity $SamAccountName @friendlyProps
            }
            if ($otherAttrs.Count -gt 0) {
                Set-ADUser @adBase -Identity $SamAccountName -Replace $otherAttrs
            }
            Write-Log -Level Ok -Message "Copied attributes applied from template."
        }

        # 7) proxyAddresses — single primary at creation (idempotent)
        $primaryProxy = "SMTP:$UpnPrefix@$($Tenant.upnSuffix)"
        $proxiesToSet = @($primaryProxy)

        if ($PSCmdlet.ShouldProcess($newUpn, "Set primary proxyAddress")) {
            Set-ADUser @adBase -Identity $SamAccountName -Replace @{ proxyAddresses = $proxiesToSet }
            Write-Log -Level Ok -Message "Primary proxyAddress applied."
        }

        # 8) Copy group memberships (exclude known admin/builtin)
        $tmplGroupDNs = (Get-ADUser @adBase -Identity $templateUser.DistinguishedName -Property memberOf).memberOf
        if (-not $tmplGroupDNs) { $tmplGroupDNs = @() }

        $tmplGroupNames = foreach ($dn in $tmplGroupDNs) {
            (Get-ADGroup @adBase -Identity $dn -ErrorAction SilentlyContinue).Name
        }

        $toAdd = $tmplGroupNames | Where-Object { $_ -and ($ExcludedGroups -notcontains $_) }

        if ($PSCmdlet.ShouldProcess($newUpn, "Add group memberships")) {
            $added = 0
            foreach ($gName in $toAdd) {
                try {
                    Add-ADGroupMember @adBase -Identity $gName -Members $SamAccountName -ErrorAction Stop
                    $added++
                    Write-Log -Level Info -Message ("Added to: {0}" -f $gName)
                }
                catch {
                    Write-Log -Level Warn -Message ("Group add failed '{0}': {1}" -f $gName, $_.Exception.Message)
                }
            }
            Write-Log -Level Ok -Message ("Group additions complete: {0} added" -f $added)
        }

        # 9) Output summary (force visible + return)
        $result = [pscustomobject]@{
            UserPrincipalName = $newUpn
            SamAccountName    = $SamAccountName
            DisplayName       = $DisplayName
            TargetOU          = $TargetOU
            CopiedAttributes  = $CopyAttributes
            GroupsAdded       = $toAdd
            InitialPassword   = $initialPassword  # caller is responsible for secure handling
        }

        # Force a visible summary even if caller pipes to Out-Null
        $result | Format-List | Out-Host
    }

    end { }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Search-User.ps1
`powershell
function Search-User {
    <#
    .SYNOPSIS
        Searches for a user in AD (primary) and optionally EXO/Teams, returns a
        unified record.
    .DESCRIPTION
        Graph/Entra lookups are excluded. This function resolves the user from:
          - Active Directory (primary, with optional proxyAddresses/mail search)
          - Exchange Online (optional, if wrappers exist and
            requested/available)
          - Microsoft Teams (optional, if wrappers exist and
            requested/available) Normalizes via Format-UserRecord. Returns $null
            if no match unless -AllowMultiple.
    .PARAMETER Identity
        UPN or SamAccountName. If not found exactly, falls back to broader LDAP
        (displayName/mail/proxyAddresses).
    .PARAMETER IncludeEXO
        When present, attempts to query Exchange Online (Get-ExchangeUser
        wrapper).
    .PARAMETER IncludeTeams
        When present, attempts to query Teams (Get-TeamsUser wrapper).
    .PARAMETER Server
        Optional domain controller to target (overrides config).
    .PARAMETER SearchBase
        Optional SearchBase (overrides config).
    .PARAMETER SearchScope
        LDAP search scope (Base|OneLevel|Subtree). Default from config or
        Subtree.
    .PARAMETER Credential
        PSCredential used for AD queries (and for manager/group resolution).
    .PARAMETER EnableProxyAddressSearch
        Include proxyAddresses in fallback LDAP search. Default: On.
    .PARAMETER EnableMailSearch
        Include mail attribute in fallback LDAP search. Default: On.
    .PARAMETER ResolveManager
        Resolve Manager to UPN/Name/SAM/Mail. Default: On.
    .PARAMETER ResolveGroups
        Resolve MemberOf to Name/SAM/Scope/Category. Default: On.
    .PARAMETER AllowMultiple
        Return all matches when more than one user is found. Default: Off
        (throws).
    .EXAMPLE
        Search-User -Identity "jdoe"
    .EXAMPLE
        Search-User -Identity "jdoe@contoso.com" -IncludeEXO
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [string]$Server,
        [string]$SearchBase,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope,

        [pscredential]$Credential,

        [switch]$EnableProxyAddressSearch,
        [switch]$EnableMailSearch,

        [switch]$ResolveManager,
        [switch]$ResolveGroups,

        [switch]$AllowMultiple
    )

    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        # --- Config (block/dot) ---
        $cfg = Get-TechToolboxConfig
        $adCfg = $cfg.settings.ad
        $searchCfg = $cfg.settings.userSearch

        if (-not $adCfg) { throw "Config missing settings.ad node." }
        if (-not $searchCfg) { Write-Log -Level Warn -Message "Config missing settings.userSearch node (using defaults)." }

        # Defaults from config (override with parameters if provided)
        if (-not $Server) { $Server = $adCfg.domainController }
        if (-not $SearchBase) { $SearchBase = $adCfg.searchBase }
        if (-not $SearchScope) { $SearchScope = $adCfg.searchScope ? $adCfg.searchScope : 'Subtree' }

        # Behavior toggles (default ON unless explicitly disabled)
        if (-not $PSBoundParameters.ContainsKey('EnableProxyAddressSearch')) { $EnableProxyAddressSearch = $true }
        if (-not $PSBoundParameters.ContainsKey('EnableMailSearch')) { $EnableMailSearch = $true }
        if (-not $PSBoundParameters.ContainsKey('ResolveManager')) { $ResolveManager = $true }
        if (-not $PSBoundParameters.ContainsKey('ResolveGroups')) { $ResolveGroups = $true }

        # --- Resolve helper availability ---
        $hasAD = !!(Get-Module ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)
        if (-not $hasAD) { throw "ActiveDirectory module not found. Install RSAT or run on a domain-joined admin workstation." }

        # Import AD but suppress provider’s warning about default drive init
        $prevWarn = $WarningPreference
        try {
            $WarningPreference = 'SilentlyContinue'
            Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        finally {
            $WarningPreference = $prevWarn
        }

        # Optional: ensure the AD: drive isn’t lingering (prevents later re-init noise)
        Remove-PSDrive -Name AD -ErrorAction SilentlyContinue

        # --- Helpers ---
        function Escape-LdapFilterValue {
            param([Parameter(Mandatory)] [string]$Value)
            # RFC 4515 escaping: \ * ( ) NUL -> escaped hex
            $v = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
            # NUL not likely in user input; keep for completeness
            $v = ($v -replace '\x00', '\00')
            return $v
        }

        # AD property set needed by Format-UserRecord
        $props = @(
            'displayName', 'userPrincipalName', 'samAccountName', 'mail',
            'proxyAddresses', 'enabled', 'whenCreated', 'lastLogonTimestamp',
            'department', 'title', 'manager', 'memberOf', 'distinguishedName', 
            'objectGuid', 'msDS-UserPasswordExpiryTimeComputed'
        )

        $common = @{
            Properties  = $props
            ErrorAction = 'Stop'
        }
        if ($Server) { $common['Server'] = $Server }
        if ($SearchBase) { $common['SearchBase'] = $SearchBase }
        if ($SearchScope) { $common['SearchScope'] = $SearchScope }
        if ($Credential) { $common['Credential'] = $Credential }

        $adUsers = @()

        # --- 1) Exact match attempt (UPN or SAM) ---
        $isUPN = ($Identity -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
        $idEsc = Escape-LdapFilterValue $Identity
        $exactLdap = if ($isUPN) { "(userPrincipalName=$idEsc)" } else { "(sAMAccountName=$idEsc)" }

        try {
            $adUsers = Get-ADUser @common -LDAPFilter $exactLdap
        }
        catch {
            Write-Log -Level Warn -Message ("[Search-User][AD/Exact] {0}" -f $_.Exception.Message)
        }

        # --- 2) Fallback broader search (displayName/mail/proxyAddresses) if none found ---
        if (-not $adUsers -or $adUsers.Count -eq 0) {
            $terms = @(
                "(sAMAccountName=$idEsc)"
                "(userPrincipalName=$idEsc)"
                "(displayName=*$idEsc*)"
            )

            if ($EnableMailSearch) {
                $terms += "(mail=$idEsc)"
            }
            if ($EnableProxyAddressSearch) {
                # proxyAddresses is case-sensitive on the prefix; include both primary & aliases
                $terms += "(proxyAddresses=SMTP:$idEsc)"
                $terms += "(proxyAddresses=smtp:$idEsc)"
            }

            $ldap = "(|{0})" -f ($terms -join '')
            try {
                $adUsers = Get-ADUser @common -LDAPFilter $ldap
            }
            catch {
                Write-Log -Level Warn -Message ("[Search-User][AD/Fallback] {0}" -f $_.Exception.Message)
            }
        }

        if (-not $adUsers -or $adUsers.Count -eq 0) {
            Write-Log -Level Warn -Message ("No AD user found matching '{0}'." -f $Identity)
            return $null
        }

        # --- Handle multiplicity ---
        if (($adUsers | Measure-Object).Count -gt 1 -and -not $AllowMultiple) {
            $names = ($adUsers | Select-Object -First 5 | ForEach-Object { $_.SamAccountName }) -join ', '
            throw "Multiple AD users matched '$Identity' (e.g., $names). Use -AllowMultiple to return all."
        }

        # --- Normalize via Format-UserRecord ---
        if (-not (Get-Command Format-UserRecord -ErrorAction SilentlyContinue)) {
            throw "Format-UserRecord not found. Ensure it is dot-sourced from Private and available."
        }

        $normalized = $adUsers | ForEach-Object {
            Format-UserRecord -AD $_ -Server $Server -Credential $Credential `
                -ResolveManager:$ResolveManager -ResolveGroups:$ResolveGroups
        }

        if (-not $normalized) {
            Write-Log -Level Warn -Message ("No usable record produced for '{0}'." -f $Identity)
            return $null
        }

        if ($AllowMultiple) {
            Write-Log -Level Ok -Message ("{0} user(s) found and normalized." -f (($normalized | Measure-Object).Count))
            return $normalized
        }
        else {
            $one = $normalized | Select-Object -First 1
            Write-Log -Level Ok -Message ("User '{0}' found and normalized." -f $one.UserPrincipalName)
            return $one
        }
    }
    catch {
        Write-Log -Level Error -Message ("[Search-User] Failed: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-CodeAssistant.ps1
`powershell
function Invoke-CodeAssistant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Code,

        [Parameter(Mandatory)]
        [string]$FileName
    )

    # Remove Authenticode signature blocks
    $cleanCode = $Code -replace '[SIGNATURE BLOCK REMOVED]', '[SIGNATURE BLOCK REMOVED]'

    # Remove PEM-style blocks
    $cleanCode = $cleanCode -replace '-----BEGIN [A-Z0-9 ]+-----(.|\n)*?-----END [A-Z0-9 ]+-----', '[PEM BLOCK REMOVED]'

    $prompt = @"
You are a PowerShell expert.

# Example signature markers:
#   SIG-BEGIN
#   SIG-END
#   CERT-BEGIN
#   CERT-END

These are cryptographic signatures and should NOT be explained.

Please ONLY explain what could be done to enhance the code's functionality, readability, or performance.
Also analyze the syntax and structure of the code, and suggest improvements if necessary.

Here is the code:

<<<CODE>>>
$cleanCode
<<<ENDCODE>>>
"@

    # Stream to UI, but also capture the full output
    $result = Invoke-LocalLLM -Prompt $prompt

    # Prepare output folder
    $timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
    $folder = "C:\TechToolbox\CodeAnalysis"

    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder | Out-Null
    }

    # Use the provided filename (without extension)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)

    $path = Join-Path $folder "Analysis-$baseName-$timestamp.md"

    $md = @'
# Code Analysis Report
Generated: {0}

## Summary
{1}

## Source Code
```powershell
{2}
```
'@ -f (Get-Date), $result, $cleanCode

    $md | Out-File -FilePath $path -Encoding UTF8
    Write-Log -Level OK -Message "`nSaved analysis to: $path"

}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-CodeAssistantFolder.ps1
`powershell
function Invoke-CodeAssistantFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Get all .ps1 files recursively
    $files = Get-ChildItem -Path $Path -Filter *.ps1 -File -Recurse

    foreach ($file in $files) {
        Write-Host "`n=== Analyzing: $($file.FullName) ===`n" -ForegroundColor Cyan

        $code = Get-Content $file.FullName -Raw

        Invoke-CodeAssistant -Code $code -FileName $file.Name
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-CodeAssistantFolderCombined.ps1
`powershell
function Invoke-CodeAssistantFolderCombined {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [string]$FileName = "CombinedFolderAnalysis"
    )

    $files = Get-ChildItem -Path $Path -Filter *.ps1 -File -Recurse

    $combined = ""

    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw

        $combined += @"
### FILE: $($file.Name)
```powershell
$content
```
"@
    }

    Invoke-CodeAssistant -Code $combined -FileName $FileName
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-CodeAssistantWrapper.ps1
`powershell
function Invoke-CodeAssistantWrapper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    $code = Get-Content $Path -Raw
    $fileName = [System.IO.Path]::GetFileName($Path)

    Invoke-CodeAssistant -Code $code -FileName $fileName
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-AutodiscoverXmlInteractive.ps1
`powershell
function Get-AutodiscoverXmlInteractive {
    <#
    .SYNOPSIS
        Interactive (or parameterized) Autodiscover XML probe for
        Exchange/Hosted/M365.

    .DESCRIPTION
        Prompts (or accepts params) for Email, Schema, URI, and Credentials;
        POSTs the Outlook Autodiscover request; follows redirects; saves the
        XML; and summarizes common nodes. Hardened for DNS/connection errors and
        missing ResponseUri.

    .PARAMETER Email
        Mailbox UPN/email to test. If omitted, prompts.

    .PARAMETER Uri
        Full Autodiscover endpoint (e.g.,
        https://autodiscover.domain.com/autodiscover/autodiscover.xml). If
        omitted, will suggest
        https://autodiscover.<domain>/autodiscover/autodiscover.xml.

    .PARAMETER Schema
        AcceptableResponseSchema. Defaults to 2006a.

    .PARAMETER TryAllPaths
        If set, will attempt a sequence of common endpoints derived from the
        email's domain.

    .EXAMPLE
        Get-AutodiscoverXmlInteractive

    .EXAMPLE
        Get-AutodiscoverXmlInteractive -Email user@domain.com -Uri https://autodiscover.domain.com/autodiscover/autodiscover.xml

    .EXAMPLE
        Get-AutodiscoverXmlInteractive -Email user@domain.com -TryAllPaths
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string] $Email,
        [Parameter(Position = 1)]
        [string] $Uri,
        [ValidateSet('http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
            'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006')]
        [string] $Schema = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
        [switch] $TryAllPaths
    )

    Write-Log -Level Info -Message "=== Autodiscover XML Probe (Interactive/Param) ==="

    # 1) Email
    while ([string]::IsNullOrWhiteSpace($Email) -or $Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        if ($Email) { Write-Log -Level Warn -Message "That doesn't look like a valid email address." }
        $Email = Read-Host "Enter the mailbox Email Address (e.g., user@domain.com)"
    }
    $domain = $Email.Split('@')[-1]

    # 2) URI (build suggestion if not provided)
    $suggested = "https://autodiscover.$domain/autodiscover/autodiscover.xml"
    if ([string]::IsNullOrWhiteSpace($Uri)) {
        Write-Log -Level Info -Message "Detected domain: $domain"
        Write-Log -Level Info -Message "Suggested Autodiscover URI: $suggested"
        $Uri = Read-Host "Enter Autodiscover URI or press Enter to use the suggestion"
        if ([string]::IsNullOrWhiteSpace($Uri)) { $Uri = $suggested }
    }

    # Helper: normalize URI and ensure well-known path
    function Resolve-AutodiscoverUri {
        param([string]$InputUri)
        try {
            $u = [Uri]$InputUri
            if (-not $u.Scheme.StartsWith("http")) { throw "URI must start with http or https." }
            if ($u.Host -match '\.xml$') { throw "Hostname ends with .xml (`"$($u.Host)`"). Remove the .xml from the host." }

            $path = $u.AbsolutePath.TrimEnd('/')
            if ([string]::IsNullOrWhiteSpace($path) -or $path -eq "/") {
                # Bare host/root → append the well-known path
                $normalized = ($u.GetLeftPart([System.UriPartial]::Authority)).TrimEnd('/') + "/autodiscover/autodiscover.xml"
            }
            elseif ($path -match '/autodiscover/?$') {
                # '/autodiscover' → append final segment
                $normalized = ($u.GetLeftPart([System.UriPartial]::Authority)).TrimEnd('/') + "/autodiscover/autodiscover.xml"
            }
            else {
                # Leave as-is if user pointed directly at an XML endpoint
                $normalized = $u.AbsoluteUri
            }
            return $normalized
        }
        catch {
            throw "Invalid URI '$InputUri': $($_.Exception.Message)"
        }
    }

    $Uri = Resolve-AutodiscoverUri -InputUri $Uri

    # Candidate list if -TryAllPaths is set
    $candidates = @($Uri)
    if ($TryAllPaths) {
        $candidates = @(
            "https://autodiscover.$domain/autodiscover/autodiscover.xml",
            "https://$domain/autodiscover/autodiscover.xml",
            "https://mail.$domain/autodiscover/autodiscover.xml"
        ) | Select-Object -Unique
    }

    # 3) Credentials
    Write-Log -Level Info -Message ""
    $cred = Get-Credential -Message "Enter credentials for $Email (or the mailbox being tested)"

    # 4) Request body
    $body = @"
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>$Email</EMailAddress>
    <AcceptableResponseSchema>$Schema</AcceptableResponseSchema>
  </Request>
</Autodiscover>
"@

    $headers = @{
        "User-Agent" = "AutodiscoverProber/1.3"
        "Accept"     = "text/xml, application/xml"
    }

    # 5) Probe loop (single or multiple URIs)
    foreach ($candidate in $candidates) {
        # DNS pre-check
        try {
            Write-Log -Level Info -Message "`nChecking DNS for host: $(([Uri]$candidate).Host)"
            $null = Resolve-DnsName -Name ([Uri]$candidate).Host -ErrorAction Stop
            Write-Log -Level Info -Message "DNS OK."
        }
        catch {
            Write-Log -Level Warn -Message "DNS check failed: $($_.Exception.Message)"
            if (-not $TryAllPaths) { return }
            else { continue }
        }

        Write-Log -Level Info -Message "`nPosting to: $candidate"
        try {
            Write-Log -Level Info -Message "`nPosting to: $candidate"

            # IMPORTANT: Do NOT throw on HTTP errors; we want to inspect redirects/challenges.
            $resp = Invoke-WebRequest `
                -Uri $candidate `
                -Method POST `
                -Headers $headers `
                -ContentType "text/xml" `
                -Body $body `
                -Credential $cred `
                -MaximumRedirection 10 `
                -AllowUnencryptedAuthentication:$false `
                -SkipHttpErrorCheck `
                -ErrorAction Stop

            # Try to capture the final URI if available (it may not exist on some failures)
            $finalUri = $null
            if ($resp.BaseResponse -and $resp.BaseResponse.PSObject.Properties.Name -contains 'ResponseUri' -and $resp.BaseResponse.ResponseUri) {
                $finalUri = $resp.BaseResponse.ResponseUri.AbsoluteUri
            }

            # If you want to see what status we actually got:
            $code = $null
            $reason = $null
            if ($resp.PSObject.Properties.Name -contains 'StatusCode') { $code = [int]$resp.StatusCode }
            if ($resp.PSObject.Properties.Name -contains 'StatusDescription') { $reason = $resp.StatusDescription }

            Write-Log -Level Info -Message ("`nHTTP Status: " + ($(if ($code) { "$code " } else { "" }) + ($reason ?? "")))
            if ($finalUri) { Write-Log -Level Info -Message "Final Endpoint: $finalUri" }

            Write-Log -Level Info -Message "`nHTTP Status: $($resp.StatusCode) $($resp.StatusDescription)"
            if ($finalUri) { Write-Log -Level Info -Message "Final Endpoint: $finalUri" }

            if ($resp.Content) {
                try {
                    [xml]$xml = $resp.Content
                    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                    $outFile = Join-Path $PWD "Autodiscover_$($domain)_$stamp.xml"
                    $xml.Save($outFile)
                    Write-Log -Level Info -Message "Saved XML to: $outFile"

                    # Summarize common nodes if present
                    Write-Log -Level Info -Message "`n--- Key Autodiscover Nodes (if available) ---"
                    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                    $ns.AddNamespace("a", "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a")
                    $ns.AddNamespace("r", "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006")

                    $ewsExt = $xml.SelectNodes("//a:Protocol[a:Type='EXPR' or a:Type='EXCH']/a:ExternalEwsUrl", $ns)
                    $ewsInt = $xml.SelectNodes("//a:Protocol[a:Type='EXCH']/a:InternalEwsUrl", $ns)
                    $mapiSrv = $xml.SelectNodes("//a:Protocol[a:Type='EXCH']/a:Server", $ns)

                    if ($ewsExt) { $ewsExt | ForEach-Object { Write-Log -Level Info -Message ("EWS External URL: " + $_.'#text') } }
                    if ($ewsInt) { $ewsInt | ForEach-Object { Write-Log -Level Info -Message ("EWS Internal URL: " + $_.'#text') } }
                    if ($mapiSrv) { $mapiSrv | ForEach-Object { Write-Log -Level Info -Message ("MAPI/HTTP Server: " + $_.'#text') } }

                    Write-Log -Level Info -Message "------------------------------------------------"
                }
                catch {
                    Write-Log -Level Warn -Message "Response received but not valid XML. Raw content follows:"
                    Write-Log -Level Info -Message $resp.Content
                }
            }
            else {
                Write-Log -Level Warn -Message "No content returned."
            }

            # Success: stop probing
            return
        }
        catch {
            # Primary error message only (no secondary exceptions)
            Write-Log -Level Error -Message ("Request failed: " + $_.Exception.Message)

            # Try to surface a helpful endpoint without assuming properties exist
            $respObj = $null
            $hintUri = $null

            # Windows-style WebException
            if ($_.Exception.PSObject.Properties.Name -contains 'Response') {
                try { $respObj = $_.Exception.Response } catch {}
                if ($respObj -and $respObj.PSObject.Properties.Name -contains 'ResponseUri' -and $respObj.ResponseUri) {
                    $hintUri = $respObj.ResponseUri.AbsoluteUri
                }
            }

            # PS7 HttpRequestException.ResponseMessage
            if (-not $hintUri -and $_.Exception.PSObject.Properties.Name -contains 'ResponseMessage') {
                try {
                    $respMsg = $_.Exception.ResponseMessage
                    if ($respMsg -and $respMsg.PSObject.Properties.Name -contains 'RequestMessage' -and $respMsg.RequestMessage) {
                        $hintUri = $respMsg.RequestMessage.RequestUri.AbsoluteUri
                    }
                }
                catch {}
            }

            # Fall back to the candidate we attempted
            if (-not $hintUri) { $hintUri = $candidate }

            Write-Log -Level Info -Message ("Endpoint (on error): " + $hintUri)

            if (-not $TryAllPaths) { return }
            else {
                Write-Log -Level Warn -Message "Trying next candidate endpoint..."
                Start-Sleep -Milliseconds 200
            }
        }
    }

    # If we got here with TryAllPaths, everything failed
    if ($TryAllPaths) {
        Write-Log -Level Error -Message "All Autodiscover candidates failed for $Email"
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-BatteryHealth.ps1
`powershell

function Get-BatteryHealth {
    <#
    .SYNOPSIS
        Generates a Windows battery report and parses its HTML into structured
        JSON with health metrics.
    .DESCRIPTION
        Runs 'powercfg /batteryreport' to produce the HTML report, parses the
        "Installed batteries" table, computes health (FullCharge/Design ratios),
        logs progress, and exports a JSON file. Paths can be provided by
        parameters or taken from TechToolbox config (BatteryReport section).
    .PARAMETER ReportPath
        Output path for the HTML report (e.g., C:\Temp\battery-report.html). If
        omitted, uses config.
    .PARAMETER OutputJson
        Path to write parsed JSON (e.g., C:\Temp\installed-batteries.json). If
        omitted, uses config.
    .PARAMETER DebugInfo
        Optional path to write parser debug info (e.g., detected headings) when
        table detection fails. If omitted, uses config.
    .INPUTS
        None. You cannot pipe objects to Get-BatteryHealth.
    .OUTPUTS
        [pscustomobject[]] Battery objects with capacity and health metrics.
    .EXAMPLE
        Get-BatteryHealth
    .EXAMPLE
        Get-BatteryHealth -ReportPath 'C:\Temp\battery-report.html' -OutputJson 'C:\Temp\batteries.json' -WhatIf
        # Preview file creation/JSON export without writing.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([object[]])]
    param(
        [Parameter()][string]$ReportPath,
        [Parameter()][string]$OutputJson,
        [Parameter()][string]$DebugInfo
    )

    # --- Resolve defaults from normalized config when parameters not supplied ---
    $cfg = Get-TechToolboxConfig
    $br = $cfg["settings"]["batteryReport"]

    # ReportPath
    if (-not $PSBoundParameters.ContainsKey('ReportPath') -or [string]::IsNullOrWhiteSpace($ReportPath)) {
        if ($null -ne $br["reportPath"] -and -not [string]::IsNullOrWhiteSpace($br["reportPath"])) {
            $ReportPath = [string]$br["reportPath"]
        }
    }
    # OutputJson
    if (-not $PSBoundParameters.ContainsKey('OutputJson') -or [string]::IsNullOrWhiteSpace($OutputJson)) {
        if ($null -ne $br["outputJson"] -and -not [string]::IsNullOrWhiteSpace($br["outputJson"])) {
            $OutputJson = [string]$br["outputJson"]
        }
    }
    # DebugInfo
    if (-not $PSBoundParameters.ContainsKey('DebugInfo') -or [string]::IsNullOrWhiteSpace($DebugInfo)) {
        if ($null -ne $br["debugInfo"] -and -not [string]::IsNullOrWhiteSpace($br["debugInfo"])) {
            $DebugInfo = [string]$br["debugInfo"]
        }
    }

    Write-Log -Level Info -Message "Generating battery report..."
    $reportReady = Invoke-BatteryReport -ReportPath $ReportPath -WhatIf:$WhatIfPreference -Confirm:$false
    if (-not $reportReady) {
        Write-Log -Level Error -Message ("Battery report was not generated or is empty at: {0}" -f $ReportPath)
        return
    }
    Write-Log -Level Ok -Message "Battery report generated."

    # Read and parse HTML with check for no batteries
    $html = Get-Content -LiteralPath $ReportPath -Raw
    if ($html -notmatch 'Installed batteries') {
        Write-Log -Level Warning -Message "No battery detected on this system."
        return [pscustomobject]@{
            hasBattery = $false
            reason     = "System does not contain a battery subsystem."
            timestamp  = (Get-Date)
        }
    }
    $batteries, $debug = Get-BatteryReportHtml -Html $html

    if (-not $batteries -or $batteries.Count -eq 0) {
        Write-Log -Level Error -Message "No battery data parsed."
        if ($DebugInfo -and $debug) {
            Write-Log -Level Warn -Message ("Writing parser debug info to: {0}" -f $DebugInfo)
            if ($PSCmdlet.ShouldProcess($DebugInfo, 'Write debug info')) {
                Set-Content -LiteralPath $DebugInfo -Value $debug -Encoding UTF8
            }
        }
        return
    }

    Write-Log -Level Ok -Message ("Parsed {0} battery object(s)." -f $batteries.Count)

    # Export JSON
    if ($OutputJson) {
        $dir = Split-Path -Parent $OutputJson
        if ($dir -and $PSCmdlet.ShouldProcess($dir, 'Ensure output directory')) {
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
        }

        $json = $batteries | ConvertTo-Json -Depth 6
        if ($PSCmdlet.ShouldProcess($OutputJson, 'Write JSON')) {
            Set-Content -LiteralPath $OutputJson -Value $json -Encoding UTF8
        }
        Write-Log -Level Ok -Message ("Exported JSON with health metrics to {0}" -f $OutputJson)
    }

    return $batteries
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-DomainAdminCredential.ps1
`powershell

function Get-DomainAdminCredential {
    <#
    .SYNOPSIS
    Returns the module’s domain admin credential; optionally clears or
    re-prompts & persists.

    .DESCRIPTION
    - Default: Returns the in-memory credential if present; if not present and
      config contains a username/password, reconstructs and caches it; if still
      missing, prompts the user (but does not save unless -Persist is supplied).
    - -Clear: Wipes username/password in config.json and removes in-memory
      $script:domainAdminCred.
    - -ForcePrompt: Always prompt for a credential now (ignores what’s on disk).
    - -Persist: When prompting, saves username and DPAPI-protected password back
      to config.json.
    - -PassThru: Returns the PSCredential object to the caller.

    .PARAMETER Clear
    Wipe stored username/password in config.json and clear in-memory credential.

    .PARAMETER ForcePrompt
    Ignore existing stored credential and prompt for a new one now.

    .PARAMETER Persist
    When prompting (either because none exists or -ForcePrompt), write the new
    credential to config.json.

    .PARAMETER PassThru
    Return the credential object to the pipeline.

    .EXAMPLE
    # Just get the cred (from memory or disk); prompt only if missing
    $cred = Get-DomainAdminCredential -PassThru

    .EXAMPLE
    # Force a new prompt and persist to config.json
    $cred = Get-DomainAdminCredential -ForcePrompt -Persist -PassThru

    .EXAMPLE
    # Clear stored username/password in config.json and in-memory cache
    Get-DomainAdminCredential -Clear -Confirm

    .NOTES
    Requires Initialize-Config to have populated $script:cfg and
    $script:ConfigPath.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [switch]$Clear,
        [switch]$ForcePrompt,
        [switch]$Persist,
        [switch]$PassThru
    )

    # --- Preconditions ---
    if (-not $script:cfg) {
        throw "[Get-DomainAdminCredential] Config not loaded. Run Initialize-Config first."
    }
    if (-not $script:ConfigPath) {
        throw "[Get-DomainAdminCredential] ConfigPath not set. Run Initialize-Config first."
    }

    # Ensure password branch exists
    if (-not $script:cfg.settings) { $script:cfg.settings = @{} }
    if (-not $script:cfg.settings.passwords) { $script:cfg.settings.passwords = @{} }
    if (-not $script:cfg.settings.passwords.domainAdminCred) {
        $script:cfg.settings.passwords.domainAdminCred = @{
            username = ''
            password = ''
        }
    }

    $node = $script:cfg.settings.passwords.domainAdminCred

    # --- CLEAR path ---
    if ($Clear) {
        $target = "domainAdminCred in $($script:ConfigPath)"
        if ($PSCmdlet.ShouldProcess($target, "Clear username and password")) {
            try {
                $node.username = ''
                $node.password = ''
                # Persist to disk
                $script:cfg | ConvertTo-Json -Depth 50 | Set-Content -Path $script:ConfigPath -Encoding UTF8
                # Clear in-memory cache
                $script:domainAdminCred = $null
                Write-Log -Level 'Ok' -Message "[Get-DomainAdminCredential] Cleared stored domainAdminCred and in-memory cache."
            }
            catch {
                Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Failed to clear and persist: $($_.Exception.Message)"
                throw
            }
        }
        return
    }

    # --- Use cached in-memory credential unless forcing prompt ---
    if (-not $ForcePrompt -and $script:domainAdminCred -is [System.Management.Automation.PSCredential]) {
        if ($PassThru) { return $script:domainAdminCred } else { return }
    }

    # --- If not forcing prompt, try to rebuild from config ---
    $hasUser = ($node.PSObject.Properties.Name -contains 'username') -and -not [string]::IsNullOrWhiteSpace([string]$node.username)
    $hasPass = ($node.PSObject.Properties.Name -contains 'password') -and -not [string]::IsNullOrWhiteSpace([string]$node.password)

    if (-not $ForcePrompt -and $hasUser -and $hasPass) {
        try {
            $username = [string]$node.username
            $securePwd = [string]$node.password | ConvertTo-SecureString
            $script:domainAdminCred = New-Object -TypeName PSCredential -ArgumentList $username, $securePwd
            Write-Log -Level 'Debug' -Message "[Get-DomainAdminCredential] Reconstructed credential from config."
            if ($PassThru) { return $script:domainAdminCred } else { return }
        }
        catch {
            Write-Log -Level 'Warn' -Message "[Get-DomainAdminCredential] Failed to reconstruct credential from config: $($_.Exception.Message)"
            # fall through to prompt
        }
    }

    # --- PROMPT path (ForcePrompt or nothing stored/valid) ---
    try {
        $cred = Get-Credential -Message "Enter Domain Admin Credential"
    }
    catch {
        Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Prompt cancelled or failed: $($_.Exception.Message)"
        throw
    }

    $script:domainAdminCred = $cred

    # Persist on request
    if ($Persist) {
        $target = "domainAdminCred in $($script:ConfigPath)"
        if ($PSCmdlet.ShouldProcess($target, "Persist username and DPAPI-protected password")) {
            try {
                $script:cfg.settings.passwords.domainAdminCred = @{
                    username = $cred.UserName
                    password = (ConvertFrom-SecureString $cred.Password)
                }
                $script:cfg | ConvertTo-Json -Depth 50 | Set-Content -Path $script:ConfigPath -Encoding UTF8
                Write-Log -Level 'Ok' -Message "[Get-DomainAdminCredential] Persisted credential to config.json."
            }
            catch {
                Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Failed to persist credential: $($_.Exception.Message)"
                throw
            }
        }
    }

    if ($PassThru) { return $script:domainAdminCred }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-MessageTrace.ps1
`powershell
function Get-MessageTrace { 
    <#
    .SYNOPSIS
    Retrieve Exchange Online message trace summary and details using V2 cmdlets
    with chunking and throttling handling.
    .DESCRIPTION
    This cmdlet retrieves message trace summary and details from Exchange Online
    using the V2 cmdlets (Get-MessageTraceV2 and Get-MessageTraceDetailV2). It
    handles chunking for date ranges over 10 days and manages throttling with
    exponential backoff retries. The cmdlet supports filtering by MessageId,
    Sender, Recipient, and Subject, and can automatically export results to CSV.
    .PARAMETER MessageId
    Filter by specific Message ID.
    .PARAMETER Sender
    Filter by sender email address.
    .PARAMETER Recipient
    Filter by recipient email address.
    .PARAMETER Subject
    Filter by email subject.
    .PARAMETER StartDate
    Start of the date range for the message trace (default: now - configured
    lookback).
    .PARAMETER EndDate
    End of the date range for the message trace (default: now).
    .PARAMETER ExportFolder
    Folder path to export results. If not specified, uses default from config.
    .EXAMPLE
    Get-MessageTrace -Sender "user@example.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
    Retrieves message traces for the specified sender over the last 7 days.
    .NOTES
    Requires Exchange Online V2 cmdlets (3.7.0+). Ensure you are connected to
    Exchange Online before running this cmdlet.
    .INPUTS
    None.
    .OUTPUTS
    None. Outputs are logged to the console and optionally exported to CSV.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter()][string]  $MessageId,
        [Parameter()][string]  $Sender,
        [Parameter()][string]  $Recipient,
        [Parameter()][string]  $Subject,
        [Parameter()][datetime]$StartDate,
        [Parameter()][datetime]$EndDate,
        [Parameter()][string]  $ExportFolder
    )

    # --- Config & defaults ---
    $cfg = Get-TechToolboxConfig
    $exo = $cfg["settings"]["exchangeOnline"]
    $mt = $cfg["settings"]["messageTrace"]

    # Make sure our in-house EXO module is imported
    Import-ExchangeOnlineModule  # v3.7.0+ exposes V2 cmdlets after connect

    # Lookback hours (safe default)
    $lookbackHours = [int]$mt["defaultLookbackHours"]
    if ($lookbackHours -le 0) { $lookbackHours = 48 }

    # Auto export flag
    $autoExport = [bool]$mt["autoExport"]

    # Resolve export folder default
    $defaultExport = $mt["defaultExportFolder"]
    if ([string]::IsNullOrWhiteSpace($defaultExport)) {
        $defaultExport = $cfg["paths"]["exportDirectory"]
    }

    # Resolve StartDate/EndDate defaults
    if (-not $StartDate) { $StartDate = (Get-Date).AddHours(-$lookbackHours) }
    if (-not $EndDate) { $EndDate = (Get-Date) }

    if ($StartDate -ge $EndDate) {
        Write-Log -Level Error -Message "StartDate must be earlier than EndDate."
        throw "Invalid date window."
    }

    # --- Validate search criteria ---
    if (-not $MessageId -and -not $Sender -and -not $Recipient -and -not $Subject) {
        Write-Log -Level Error -Message "You must specify at least one of: MessageId, Sender, Recipient, Subject."
        throw "At least one search filter is required."
    }

    # --- Ensure EXO connection and V2 availability ---
    # V2 cmdlets are only available after Connect-ExchangeOnline (they load into tmpEXO_*).
    # We'll auto-connect (quietly) if V2 isn't visible, then re-check.  (Docs: GA + V2 usage)  [TechCommunity + Learn]
    function Confirm-EXOConnected {
        if (-not (Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
            if (Get-Command -Name Connect-ExchangeOnline -ErrorAction SilentlyContinue) {
                try {
                    # Prefer your wrapper if present
                    if (Get-Command -Name Connect-ExchangeOnlineIfNeeded -ErrorAction SilentlyContinue) {
                        Connect-ExchangeOnlineIfNeeded -ShowProgress:([bool]$exo.showProgress)
                    }
                    else {
                        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
                    }
                }
                catch {
                    Write-Log -Level Error -Message ("Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
                    throw
                }
            }
        }
    }
    Confirm-EXOConnected

    # Resolve cmdlets (they are Functions exported from tmpEXO_* after connect)
    try {
        $getTraceCmd = Get-Command -Name Get-MessageTraceV2       -ErrorAction Stop
        $getDetailCmd = Get-Command -Name Get-MessageTraceDetailV2 -ErrorAction Stop
    }
    catch {
        Write-Log -Level Error -Message ("Message Trace V2 cmdlets not available. Are you connected to EXO? {0}" -f $_.Exception.Message)
        throw
    }

    # --- Helper: throttle-aware invoker with retries for transient 429/5xx ---
    function Invoke-WithBackoff {
        param([scriptblock]$Block)
        $delay = 1
        for ($i = 1; $i -le 5; $i++) {
            try { return & $Block }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match 'Too many requests|429|throttle|temporarily unavailable|5\d{2}') {
                    Write-Log -Level Warn -Message ("Transient/throttle error (attempt {0}/5): {1} — sleeping {2}s" -f $i, $msg, $delay)
                    Start-Sleep -Seconds $delay
                    $delay = [Math]::Min($delay * 2, 30)
                    continue
                }
                throw
            }
        }
        throw "Exceeded retry attempts."
    }

    # --- Chunked V2 invoker (≤10-day slices + continuation when >5k rows) ---
    function Invoke-MessageTraceV2Chunked {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][datetime]$StartDate,
            [Parameter(Mandatory)][datetime]$EndDate,
            [Parameter()][string] $MessageId,
            [Parameter()][string] $SenderAddress,
            [Parameter()][string] $RecipientAddress,
            [Parameter()][string] $Subject,
            [Parameter()][int]    $ResultSize = 5000
        )
        # Docs: V2 supports 90 days history but only 10 days per request; up to 5000 rows; times are returned as UTC.  [Learn]
        # When result size is exceeded, query subsequent data by using StartingRecipientAddress and EndDate with
        # the values from the previous result's Recipient address and Received time.  [Learn]
        $sliceStart = $StartDate
        $endLimit = $EndDate
        $maxSpan = [TimeSpan]::FromDays(10)
        $results = New-Object System.Collections.Generic.List[object]

        while ($sliceStart -lt $endLimit) {
            $sliceEnd = $sliceStart.Add($maxSpan)
            if ($sliceEnd -gt $endLimit) { $sliceEnd = $endLimit }

            Write-Information ("[Trace] Querying slice {0:u} → {1:u}" -f $sliceStart.ToUniversalTime(), $sliceEnd.ToUniversalTime()) -InformationAction Continue

            $continuationRecipient = $null
            $continuationEndUtc = $sliceEnd

            do {
                $params = @{
                    StartDate   = $sliceStart
                    EndDate     = $continuationEndUtc
                    ResultSize  = $ResultSize
                    ErrorAction = 'Stop'
                }
                if ($MessageId) { $params.MessageId = $MessageId }
                if ($SenderAddress) { $params.SenderAddress = $SenderAddress }
                if ($RecipientAddress) { $params.RecipientAddress = $RecipientAddress }
                if ($Subject) { $params.Subject = $Subject }

                if ($continuationRecipient) {
                    $params.StartingRecipientAddress = $continuationRecipient
                }

                $batch = Invoke-WithBackoff { & $getTraceCmd @params }

                if ($batch -and $batch.Count -gt 0) {
                    $results.AddRange($batch)

                    # Continuation: use the oldest row's RecipientAddress and Received (UTC)
                    $last = $batch | Sort-Object Received -Descending | Select-Object -Last 1
                    $continuationRecipient = $last.RecipientAddress
                    $continuationEndUtc = $last.Received

                    # Pace to respect tenant throttling (100 req / 5 min)
                    Start-Sleep -Milliseconds 200
                }
                else {
                    $continuationRecipient = $null
                }

            } while ($batch.Count -ge $ResultSize)

            $sliceStart = $sliceEnd
        }

        return $results
    }

    # --- Log filters (friendly) ---
    Write-Log -Level Info -Message "Message trace filters:"
    Write-Log -Level Info -Message ("  MessageId : {0}" -f ($MessageId ?? '<none>'))
    Write-Log -Level Info -Message ("  Sender    : {0}" -f ($Sender ?? '<none>'))
    Write-Log -Level Info -Message ("  Recipient : {0}" -f ($Recipient ?? '<none>'))
    Write-Log -Level Info -Message ("  Subject   : {0}" -f ($Subject ?? '<none>'))
    Write-Log -Level Info -Message ("  Window    : {0} → {1} (UTC shown by EXO)" -f $StartDate.ToString('u'), $EndDate.ToString('u'))

    # --- Execute (chunked) ---
    $summary = Invoke-MessageTraceV2Chunked `
        -StartDate        $StartDate `
        -EndDate          $EndDate `
        -MessageId        $MessageId `
        -SenderAddress    $Sender `
        -RecipientAddress $Recipient `
        -Subject          $Subject `
        -ResultSize       5000

    if (-not $summary -or $summary.Count -eq 0) {
        Write-Log -Level Warn -Message "No results found. Check filters, UTC vs. local time, and the 10-day-per-call limit."
        return
    }

    # Summary view (EXO returns UTC timestamps)
    $summaryView = $summary |
    Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageTraceId

    Write-Log -Level Ok   -Message ("Summary results ({0}):" -f $summaryView.Count)
    Write-Log -Level Info -Message ($summaryView | Sort-Object Received | Format-Table -AutoSize | Out-String)

    # --- Details ---
    Write-Log -Level Info -Message "Enumerating per-recipient details..."
    $detailsAll = New-Object System.Collections.Generic.List[object]

    foreach ($row in $summary) {
        $mtid = $row.MessageTraceId
        $rcpt = $row.RecipientAddress
        if (-not $mtid -or -not $rcpt) { continue }

        try {
            $details = Invoke-WithBackoff { & $getDetailCmd -MessageTraceId $mtid -RecipientAddress $rcpt -ErrorAction Stop }
            if ($details) {
                $detailsView = $details | Select-Object `
                @{n = 'Recipient'; e = { $rcpt } },
                @{n = 'MessageTraceId'; e = { $mtid } },
                Date, Event, Detail
                $detailsAll.AddRange($detailsView)
            }
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to get details for {0} / MTID {1}: {2}" -f $rcpt, $mtid, $_.Exception.Message)
        }
    }

    if ($detailsAll.Count -gt 0) {
        Write-Log -Level Ok   -Message ("Details ({0} rows):" -f $detailsAll.Count)
        Write-Log -Level Info -Message ($detailsAll | Format-Table -AutoSize | Out-String)
    }
    else {
        Write-Log -Level Warn -Message "No detail records returned."
    }

    # --- Export ---
    $shouldExport = $autoExport -or (-not [string]::IsNullOrWhiteSpace($ExportFolder))
    if ($shouldExport) {
        if ([string]::IsNullOrWhiteSpace($ExportFolder)) {
            $ExportFolder = $defaultExport
        }

        if ($PSCmdlet.ShouldProcess($ExportFolder, "Export message trace results")) {
            Export-MessageTraceResults `
                -Summary $summaryView `
                -Details $detailsAll `
                -ExportFolder $ExportFolder `
                -WhatIf:$WhatIfPreference `
                -Confirm:$false
        }
    }
    [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo)
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-PDQDiagLogs.ps1
`powershell

function Get-PDQDiagLogs {
    <#
    .SYNOPSIS
      Collect PDQ diagnostics under SYSTEM context (local and remote), zip on
      target, and copy back to C:\PDQDiagLogs on the machine running this script.
    
    .DESCRIPTION
      - Local & remote: run a one-time Scheduled Task as SYSTEM that performs
        collection.
      - PS7-first remoting via New-PSRemoteSession helper if present (fallback
        included).
      - Resilient copy (Copy-Item then robocopy /B), plus Event Log export via
        wevtutil.
      - ZIP pulled back to the collector and named
        PDQDiag_<Computer>_<timestamp>.zip.
    
    .PARAMETER ComputerName
      Target computer(s). Defaults to local machine.
    
    .PARAMETER Credential
      Optional credential for remote connections. If omitted and
      $Global:TTDomainCred exists, New-PSRemoteSession helper may use it.
    
    .PARAMETER LocalDropPath
      Path on the collector to store retrieved ZIP(s). Default: C:\PDQDiagLogs.
    
    .PARAMETER TransferMode
      Retrieval method for remote ZIPs: FromSession (default), Bytes, or SMB.
    
    .PARAMETER ExtraPaths
      Extra file/folder paths on the target(s) to include.
    
    .PARAMETER ConnectDataPath
      PDQ Connect data root. Default: "$env:ProgramData\PDQ\PDQConnectAgent"
    
    .PARAMETER UseSsh, SshPort, Ps7ConfigName, WinPsConfigName
      Passed through to session creation if helper supports them.
    
    .EXAMPLE
      Get-PDQDiagLogs
    .EXAMPLE
      Get-PDQDiagLogs -ComputerName EDI-2.vadtek.com -Credential (Get-Credential)
    .EXAMPLE
      Get-PDQDiagLogs. -ComputerName PC01,PC02 -ExtraPaths 'C:\Temp\PDQ','D:\Logs\PDQ'
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [pscredential]$Credential,

        [string]$LocalDropPath = 'C:\PDQDiagLogs',

        [ValidateSet('FromSession', 'Bytes', 'SMB')]
        [string]$TransferMode = 'FromSession',

        [string[]]$ExtraPaths,

        [string]$ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),

        [switch]$UseSsh,
        [int]$SshPort = 22,

        [string]$Ps7ConfigName = 'PowerShell.7',
        [string]$WinPsConfigName = 'Microsoft.PowerShell'
    )

    begin {
        $UseUserHelper = $false
        if (Get-Command -Name Start-NewPSRemoteSession -ErrorAction SilentlyContinue) {
            $UseUserHelper = $true
        }

        # Ensure local drop path exists on the collector
        if (-not (Test-Path -LiteralPath $LocalDropPath)) {
            New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $results = New-Object System.Collections.Generic.List[object]
    }

    process {
        foreach ($comp in $ComputerName) {
            if ([string]::IsNullOrWhiteSpace($comp)) { continue }
            $display = $comp
            $fileName = "PDQDiag_{0}_{1}.zip" -f ($display -replace '[^\w\.-]', '_'), $timestamp
            $collectorZipPath = Join-Path $LocalDropPath $fileName

            Write-Log -Level Info -Message ("[{0}] Starting collection (SYSTEM)..." -f $display)

            # Remote
            $session = $null
            try {
                $params = @{
                    ComputerName    = $comp
                    Credential      = $Credential
                    UseSsh          = $UseSsh
                    Port            = $SshPort
                    Ps7ConfigName   = $Ps7ConfigName
                    WinPsConfigName = $WinPsConfigName
                }
                $session = Start-NewPSRemoteSession @params

                $remote = Invoke-RemoteSystemCollection -Session $session -Timestamp $timestamp -ExtraPaths $ExtraPaths -ConnectDataPath $ConnectDataPath

                # Retrieve ZIP to collector
                Receive-RemoteFile -Session $session -RemotePath $remote.ZipPath -LocalPath $collectorZipPath -Mode $TransferMode
                Write-Log -Level Info -Message ("[{0}] ZIP retrieved: {1}" -f $comp, $collectorZipPath)

                # Remote cleanup
                try {
                    Invoke-Command -Session $session -ScriptBlock {
                        param($stag, $zip, $scr, $arg)
                        foreach ($p in @($stag, $zip, $scr, $arg)) {
                            if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
                                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } -ArgumentList $remote.Staging, $remote.ZipPath, $remote.Script, $remote.Args -ErrorAction SilentlyContinue | Out-Null
                }
                catch {}

                $results.Add([pscustomobject]@{
                        ComputerName = $comp
                        Status       = 'Success'
                        ZipPath      = $collectorZipPath
                        Notes        = 'Remote SYSTEM collection'
                    }) | Out-Null
            }
            catch {
                Write-Log -Level Error -Message ("[{0}] FAILED: {1}" -f $comp, $_.Exception.Message)
                $results.Add([pscustomobject]@{
                        ComputerName = $comp
                        Status       = 'Failed'
                        ZipPath      = $null
                        Notes        = $_.Exception.Message
                    }) | Out-Null
            }
            finally {
                if ($session) { Remove-PSSession $session }
            }
        }
    }

    end {
        # Emit objects (choose formatting at call site)
        return $results
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-RemoteInstalledSoftware.ps1
`powershell

function Get-RemoteInstalledSoftware {
<#
    .SYNOPSIS
    Collects installed software from remote Windows computers via PSRemoting
    (registry uninstall keys + optional Appx).

    .DESCRIPTION
    Connects to remote hosts with Invoke-Command, enumerates machine/user
    uninstall registry entries (x64/x86), optionally includes Appx/MSIX
    packages, returns objects, writes a summary table to the information stream,
    and exports per-host CSVs or a consolidated CSV.

    .PARAMETER ComputerName
    One or more remote computer names to query. (Requires WinRM enabled and
    appropriate permissions)

    .PARAMETER Credential
    Credentials used for the remote session. If omitted, current identity is
    attempted; you may be prompted.

    .PARAMETER IncludeAppx
    Include Windows Store (Appx/MSIX) packages. Can be slower and requires admin
    rights on remote hosts.

    .PARAMETER OutDir
    Output directory for CSV exports. Defaults to TechToolbox config
    RemoteSoftwareInventory.OutDir or current directory if not set.

    .PARAMETER Consolidated
    Write a single consolidated CSV for all hosts
    (InstalledSoftware_AllHosts_<timestamp>.csv). If omitted, writes one CSV per
    host.

    .PARAMETER ThrottleLimit
    Concurrency limit for Invoke-Command. Default 32.

    .INPUTS
        None. You cannot pipe objects to Get-RemoteInstalledSoftware.

    .OUTPUTS
    [pscustomobject]

    .EXAMPLE
    Get-RemoteInstalledSoftware -ComputerName server01,server02 -Consolidated

    .EXAMPLE
    Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)

    .NOTES
    Avoids Win32_Product due to performance/repair risk. Requires PSRemoting
    (WinRM) enabled.

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$IncludeAppx,

        [Parameter()]
        [string]$OutDir,

        [Parameter()]
        [switch]$Consolidated,

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 32
    )

    begin {
        # --- Config & Defaults ---
        $cfg = Get-TechToolboxConfig
        $defaults = $cfg["settings"]["remoteSoftwareInventory"] # may be $null if section not present

        # Apply config-driven defaults if provided
        if ($defaults) {
            if (-not $PSBoundParameters.ContainsKey('IncludeAppx') -and $defaults["IncludeAppx"]) { $IncludeAppx = [switch]::Present }
            if (-not $PSBoundParameters.ContainsKey('Consolidated') -and $defaults["Consolidated"]) { $Consolidated = [switch]::Present }
            if (-not $PSBoundParameters.ContainsKey('ThrottleLimit') -and $defaults["ThrottleLimit"]) { $ThrottleLimit = [int]$defaults["ThrottleLimit"] }
            if (-not $PSBoundParameters.ContainsKey('OutDir') -and $defaults["OutDir"]) { $OutDir = [string]$defaults["OutDir"] }
        }

        # No SSL/session certificate relaxations: sessionParams intentionally empty
        $sessionParams = @{}

        Write-Log -Level Info -Message "PSRemoting will use default WinRM settings (no SSL/certificate overrides)."

        # Credential Prompting
        if (-not $PSBoundParameters.ContainsKey('Credential')) {
            Write-Log -Level Info -Message 'No credential provided; you will be prompted (or current identity will be used if allowed).'
            try {
                $Credential = Get-Credential -Message 'Enter credentials to connect to remote computers (or Cancel to use current identity)'
            }
            catch {
                # If user cancels, $Credential remains $null; Invoke-Command will try current identity.
            }
        }
    }

    process {
        # Remote scriptblock that runs on each target
        $scriptBlock = {
            param([bool]$IncludeAppx)

            function Convert-InstallDate {
                [CmdletBinding()]
                param([string]$Raw)
                if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
                $s = $Raw.Trim()
                if ($s -match '^\d{8}$') {
                    try { return [datetime]::ParseExact($s, 'yyyyMMdd', $null) } catch {}
                }
                try { return [datetime]::Parse($s) } catch { return $null }
            }

            function Get-UninstallFromPath {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory)][string]$RegPath,
                    [Parameter(Mandatory)][string]$Scope,
                    [Parameter(Mandatory)][string]$Arch
                )
                $results = @()
                try {
                    $keys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
                    foreach ($k in $keys) {
                        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                        if ($p.DisplayName) {
                            $results += [PSCustomObject]@{
                                ComputerName    = $env:COMPUTERNAME
                                DisplayName     = $p.DisplayName
                                DisplayVersion  = $p.DisplayVersion
                                Publisher       = $p.Publisher
                                InstallDate     = Convert-InstallDate $p.InstallDate
                                UninstallString = $p.UninstallString
                                InstallLocation = $p.InstallLocation
                                EstimatedSizeKB = $p.EstimatedSize
                                Scope           = $Scope
                                Architecture    = $Arch
                                Source          = 'Registry'
                                RegistryPath    = $k.PSPath
                            }
                        }
                    }
                }
                catch {}
                return $results
            }

            $items = @()

            # Machine-wide installs
            $items += Get-UninstallFromPath -RegPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'Machine' -Arch 'x64'
            $items += Get-UninstallFromPath -RegPath "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'Machine' -Arch 'x86'

            # Current user hive
            $items += Get-UninstallFromPath -RegPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'User (Current)' -Arch 'x64'
            $items += Get-UninstallFromPath -RegPath "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'User (Current)' -Arch 'x86'

            # Other loaded user hives (HKU) - covers logged-on users
            try {
                $userHives = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^HKEY_USERS\\S-1-5-21-' }
                foreach ($hive in $userHives) {
                    $sid = $hive.PSChildName
                    $x64Path = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                    $x86Path = "HKU:\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                    $items += Get-UninstallFromPath -RegPath $x64Path -Scope "User ($sid)" -Arch 'x64'
                    $items += Get-UninstallFromPath -RegPath $x86Path -Scope "User ($sid)" -Arch 'x86'
                }
            }
            catch {}

            if ($IncludeAppx) {
                try {
                    $items += Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{
                            ComputerName    = $env:COMPUTERNAME
                            DisplayName     = $_.Name
                            DisplayVersion  = $_.Version.ToString()
                            Publisher       = $_.Publisher
                            InstallDate     = $null
                            UninstallString = $null
                            InstallLocation = $_.InstallLocation
                            EstimatedSizeKB = $null
                            Scope           = 'Appx (AllUsers)'
                            Architecture    = 'Appx/MSIX'
                            Source          = 'Appx'
                            RegistryPath    = $_.PackageFullName
                        }
                    }
                }
                catch {}
            }

            $items
        }

        # Execute across one or many computers
        $results = $null
        try {
            $invocationParams = @{
                ComputerName  = $ComputerName
                ScriptBlock   = $scriptBlock
                ArgumentList  = @($IncludeAppx.IsPresent)
                ErrorAction   = 'Stop'
                ThrottleLimit = $ThrottleLimit
            }
            if ($Credential) { $invocationParams.Credential = $Credential }

            # sessionParams is empty now; kept for symmetry
            foreach ($k in $sessionParams.Keys) { $invocationParams[$k] = $sessionParams[$k] }

            $results = Invoke-Command @invocationParams
        }
        catch {
            Write-Log -Level Error -Message ("Remote command failed: {0}" -f $_.Exception.Message)
            return
        }

        if (-not $results -or $results.Count -eq 0) {
            Write-Log -Level Warn -Message 'No entries returned. Possible causes: insufficient rights, empty uninstall keys, or connectivity issues.'
        }

        # Write a tidy table to information stream (avoid Write-Host)
        $table = $results |
        Sort-Object ComputerName, DisplayName, DisplayVersion |
        Format-Table ComputerName, DisplayName, DisplayVersion, Publisher, Scope, Architecture -AutoSize |
        Out-String
        Write-Information $table

        # Export CSV(s) (honors -WhatIf/-Confirm)
        $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

        if ($Consolidated) {
            $consolidatedPath = Join-Path $OutDir ("InstalledSoftware_AllHosts_{0}.csv" -f $stamp)
            if ($PSCmdlet.ShouldProcess($consolidatedPath, 'Export consolidated CSV')) {
                try {
                    $results |
                    Sort-Object ComputerName, DisplayName, DisplayVersion |
                    Export-Csv -Path $consolidatedPath -NoTypeInformation -Encoding UTF8
                    Write-Log -Level Ok -Message ("Consolidated export written: {0}" -f $consolidatedPath)
                }
                catch {
                    Write-Log -Level Warn -Message ("Failed to write consolidated CSV: {0}" -f $_.Exception.Message)
                }
            }
        }
        else {
            # Per-host export
            $grouped = $results | Group-Object ComputerName
            foreach ($g in $grouped) {
                $csvPath = Join-Path $OutDir ("{0}_InstalledSoftware_{1}.csv" -f $g.Name, $stamp)
                if ($PSCmdlet.ShouldProcess($csvPath, "Export CSV for $($g.Name)")) {
                    try {
                        $g.Group |
                        Sort-Object DisplayName, DisplayVersion |
                        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                        Write-Log -Level Ok -Message ("{0} export written: {1}" -f $g.Name, $csvPath)
                    }
                    catch {
                        Write-Log -Level Warn -Message ("Failed to write CSV for {0}: {1}" -f $g.Name, $_.Exception.Message)
                    }
                }
            }
        }

        # Return objects to pipeline consumers
        return $results
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SystemSnapshot.ps1
`powershell
function Get-SystemSnapshot {
    <#
    .SYNOPSIS
        Collects a technician-grade system snapshot from a local or remote
        machine.

    .DESCRIPTION
        Gathers OS, hardware, CPU, memory, disk, network, identity, and
        service/role information from a target system. Returns a structured
        object and exports a CSV to the configured snapshot export directory.

    .PARAMETER ComputerName
        Optional. If omitted, collects a snapshot of the local system.

    .PARAMETER Credential
        Optional. Required only for remote systems when not using current
        credentials.

    .EXAMPLE
        Get-SystemSnapshot

    .EXAMPLE
        Get-SystemSnapshot -ComputerName SERVER01 -Credential (Get-Credential)
    .INPUTS
        None. You cannot pipe objects to Get-SystemSnapshot.
    .OUTPUTS
        PSCustomObject. A structured object containing the system snapshot data.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [pscredential]$Credential,
        [object]$Snapshot
    )

    # --- Load config ---
    $cfg = Get-TechToolboxConfig
    $snapshotCfg = $cfg["settings"]["systemSnapshot"]
    $exportPath = $snapshotCfg["exportPath"]

    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = Join-Path $script:ModuleRoot "Exports"
    }

    # Ensure export directory exists
    if (-not (Test-Path $exportPath)) {
        try {
            New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
        }
        catch {
            Write-Log -Level Error -Message ("Failed to create export directory '{0}': {1}" -f $exportPath, $_.Exception.Message)
            throw
        }
    }

    # --- Determine local vs remote ---
    $isRemote = -not [string]::IsNullOrWhiteSpace($ComputerName)

    if ($isRemote) {
        Write-Log -Level Info -Message ("Collecting system snapshot from remote system '{0}'..." -f $ComputerName)
    }
    else {
        Write-Log -Level Info -Message "Collecting system snapshot from local system..."
        $ComputerName = $env:COMPUTERNAME
    }

    # --- Build session if remote ---
    $session = $null
    if ($isRemote) {
        try {
            $session = New-PSSession -ComputerName $ComputerName `
                -Credential $Credential `
                -Authentication Default `
                -ErrorAction Stop

            Write-Log -Level Ok -Message ("Remote session established to {0}" -f $ComputerName)
        }
        catch {
            Write-Log -Level Error -Message ("Failed to create remote session: {0}" -f $_.Exception.Message)
            return
        }
    }

    # --- Collect datasets via private helpers ---
    try {
        $osInfo = Get-SnapshotOS      -Session $session
        $cpuInfo = Get-SnapshotCPU     -Session $session
        $memoryInfo = Get-SnapshotMemory  -Session $session
        $diskInfo = Get-SnapshotDisks   -Session $session
        $netInfo = Get-SnapshotNetwork -Session $session
        $identity = Get-SnapshotIdentity -Session $session
        $services = Get-SnapshotServices -Session $session
    }
    catch {
        Write-Log -Level Error -Message ("Snapshot collection failed: {0}" -f $_.Exception.Message)
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        throw
    }

    # --- Close session if remote ---
    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        Write-Log -Level Info -Message "Remote session closed."
    }

    # --- Build final snapshot object ---
    $snapshot = [pscustomobject]@{
        ComputerName = $ComputerName
        Timestamp    = (Get-Date)
        OS           = $osInfo
        CPU          = $cpuInfo
        Memory       = $memoryInfo
        Disks        = $diskInfo
        Network      = $netInfo
        Identity     = $identity
        Services     = $services
    }

    # --- Export CSV ---
    $fileName = "SystemSnapshot_{0}_{1:yyyyMMdd_HHmmss}.csv" -f $ComputerName, (Get-Date)
    $csvPath = Join-Path $exportPath $fileName

    try {
        $flat = Convert-SnapshotToFlatObject -Snapshot $snapshot
        $rows = Convert-FlatSnapshotToRows -FlatObject $flat
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-Log -Level Ok -Message ("Snapshot exported to {0}" -f $csvPath)
    }
    catch {
        Write-Log -Level Warn -Message ("Failed to export snapshot CSV: {0}" -f $_.Exception.Message)
    }

    # --- Output snapshot object ---
    return $snapshot
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-SystemUptime.ps1
`powershell
function Get-SystemUptime {
    <#
        .SYNOPSIS
        Returns system uptime locally or via PowerShell Remoting.

        .DESCRIPTION
        Defaults to using Win32_OperatingSystem.LastBootUpTime on the target system
        for maximum reliability across endpoints. Optionally, you can force the
        TickCount method.

        .PARAMETER ComputerName
        One or more remote computer names. Omit for local system.

        .PARAMETER Credential
        Credential for remote sessions.

        .PARAMETER Method
        Uptime calculation method:
        - LastBoot (default): (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        - TickCount:         [Environment]::TickCount64 (fast, may be unreliable on some endpoints)

        .EXAMPLE
        Get-SystemUptime
        .EXAMPLE
        Get-SystemUptime -ComputerName 'SRV01','SRV02'
        .EXAMPLE
        Get-SystemUptime -ComputerName SRV01 -Credential (Get-Credential) -Method TickCount

        .OUTPUTS
        PSCustomObject with ComputerName, BootTime, Uptime (TimeSpan), Days/Hours/Minutes/Seconds,
        TotalSeconds, Method, and (if applicable) Error.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [ValidateSet('LastBoot', 'TickCount')]
        [string]$Method = 'LastBoot'
    )

    $sb = {
        param([string]$Method)

        function Get-UptimeFromLastBoot {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $boot = $os.LastBootUpTime
            $now = Get-Date
            $ts = $now - $boot

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                BootTime     = $boot
                Uptime       = $ts
                Days         = $ts.Days
                Hours        = $ts.Hours
                Minutes      = $ts.Minutes
                Seconds      = $ts.Seconds
                TotalSeconds = [math]::Round($ts.TotalSeconds, 0)
                Method       = 'LastBoot'
            }
        }

        function Get-UptimeFromTickCount {
            $ms = [System.Environment]::TickCount64
            # Fallback if the endpoint returns 0 or negative (shouldn't, but we guard it)
            if ($ms -le 0) {
                return Get-UptimeFromLastBoot
            }

            $ts = [TimeSpan]::FromMilliseconds($ms)

            # Approximate BootTime from TickCount (may differ from LastBoot because TickCount may pause in sleep)
            $bootApprox = (Get-Date).AddMilliseconds(-$ms)

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                BootTime     = $bootApprox
                Uptime       = $ts
                Days         = $ts.Days
                Hours        = $ts.Hours
                Minutes      = $ts.Minutes
                Seconds      = $ts.Seconds
                TotalSeconds = [math]::Round($ts.TotalSeconds, 0)
                Method       = 'TickCount'
            }
        }

        try {
            switch ($Method) {
                'TickCount' { Get-UptimeFromTickCount }
                default { Get-UptimeFromLastBoot }
            }
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Error        = $_.Exception.Message
                Method       = $Method
            }
        }
    }

    if (-not $ComputerName) {
        return & $sb -ArgumentList $Method
    }

    $results = foreach ($cn in $ComputerName) {
        try {
            Invoke-Command -ComputerName $cn -ScriptBlock $sb -ArgumentList $Method -Credential $Credential -ErrorAction Stop
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $cn
                Error        = $_.Exception.Message
                Method       = $Method
            }
        }
    }

    return $results
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Get-TechToolboxConfig.ps1
`powershell
function Get-TechToolboxConfig {
    <#
    .SYNOPSIS
        Loads and returns the TechToolbox configuration from config.json.
    .DESCRIPTION
        This cmdlet reads the config.json file located in the Config folder of
        the TechToolbox module and returns its contents as a hashtable. If no
        path is provided, it uses the default location relative to the module.
    .PARAMETER Path
        Optional path to the config.json file. If not provided, the default
        location relative to the module is used.
    .INPUTS
        None. You cannot pipe objects to Get-TechToolboxConfig.
    .OUTPUTS
        Hashtable representing the configuration.
    .EXAMPLE
        Get-TechToolboxConfig -Path "C:\TechToolbox\Config\config.json"
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [string] $Path
    )

    # Determine config path (explicit override wins)
    if ($Path) {
        $configPath = $Path
    }
    else {
        # Reliable module root when code is running inside an imported module
        $moduleDir = $ExecutionContext.SessionState.Module.ModuleBase
        $configPath = Join-Path $moduleDir 'Config\Config.json'
    }

    # Validate path
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "config.json not found at '$configPath'. Provide -Path or ensure the module's Config folder contains config.json."
    }

    # Load JSON
    try {
        $raw = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to read or parse config.json from '$configPath': $($_.Exception.Message)"
    }

    # Validate required root keys
    $rootNames = $raw.PSObject.Properties.Name | ForEach-Object { $_.ToLower() }
    if (-not ($rootNames -contains 'settings')) {
        throw "Missing required key 'settings' in config.json."
    }

    # Recursive normalizer
    function ConvertTo-Hashtable {
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            if ($null -eq $InputObject) { return $null }

            if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
                $hash = @{}
                foreach ($prop in $InputObject.PSObject.Properties) {
                    $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
                }
                return $hash
            }

            if ($InputObject -is [System.Collections.IDictionary]) {
                $hash = @{}
                foreach ($key in $InputObject.Keys) {
                    $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
                }
                return $hash
            }

            if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
                $list = @()
                foreach ($item in $InputObject) {
                    $list += ConvertTo-Hashtable $item
                }
                return $list
            }

            return $InputObject
        }
    }

    # Always normalize to nested hashtables
    $script:TechToolboxConfig = ConvertTo-Hashtable $raw

    return $script:TechToolboxConfig
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-ToolboxHelp.ps1
`powershell
function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    .DESCRIPTION
        The Get-ToolboxHelp cmdlet displays help information for TechToolbox
        public commands. It can show an overview of the module, list all
        available commands, or provide detailed help for a specific command.
        Additionally, it can display the effective configuration settings used
        by TechToolbox.
    .PARAMETER Name
        The name of the TechToolbox command to get help for.
    .PARAMETER List
        Switch to list all available TechToolbox commands.
    .PARAMETER ShowEffectiveConfig
        Switch to display the effective configuration settings used by
        TechToolbox.
    .PARAMETER AsJson
        When used with -ShowEffectiveConfig, outputs the configuration in JSON
        format.
    .INPUTS
        None. You cannot pipe objects to Get-ToolboxHelp.
    .OUTPUTS
        None. Output is written to the host.
    .EXAMPLE
        Get-ToolboxHelp -List
        # Lists all available TechToolbox commands.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$List,
        [switch]$ShowEffectiveConfig,
        [switch]$AsJson
    )

    # Load merged runtime config
    $Config = Get-TechToolboxConfig

    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "        TechToolbox Help Center         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "A technician-grade PowerShell toolkit for:" -ForegroundColor Gray
    Write-Host "  • Diagnostics" -ForegroundColor Gray
    Write-Host "  • Automation" -ForegroundColor Gray
    Write-Host "  • Environment-agnostic workflows" -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " Common Commands:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp -List" -ForegroundColor Yellow
    Write-Host "    Displays all available commands." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp Invoke-SubnetScan" -ForegroundColor Yellow
    Write-Host "    Shows detailed help for Invoke-SubnetScan." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Invoke-PurviewPurge -CaseName 'XYZ123'" -ForegroundColor Yellow
    Write-Host "    Creates a Case search and purges the search results." -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " For full help on any command:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp <CommandName>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan

    # Show effective configuration
    if ($ShowEffectiveConfig) {
        Write-Host ""
        Write-Host "TechToolbox Effective Configuration" -ForegroundColor Cyan
        Write-Host "----------------------------------------"

        if ($AsJson) {
            $Config | ConvertTo-Json -Depth 10
        }
        else {
            $Config | Format-List
        }

        Write-Host ""
        return
    }

    # List all public functions
    if ($List) {
        Write-Host ""
        Write-Host "TechToolbox Commands" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        Get-Command -Module TechToolbox |
        Where-Object { $_.CommandType -eq 'Function' } |
        Select-Object -ExpandProperty Name |
        Sort-Object |
        ForEach-Object { Write-Host "  $_" }
        Write-Host ""
        return
    }

    # If a specific function was requested
    if ($Name) {
        try {
            Write-Host ""
            Write-Host "Help for: $Name" -ForegroundColor Cyan
            Write-Host "----------------------------------------"
            Get-Help $Name -Full
            Write-Host ""
        }
        catch {
            Write-Host "No help found for '$Name'." -ForegroundColor Yellow
        }
        return
    }

    # Clear-BrowserProfileData
    if ($Name -eq 'Clear-BrowserProfileData') {
        Write-Host ""
        Write-Host "Clear-BrowserProfileData" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SubnetScan
    if ($Name -eq 'Invoke-SubnetScan') {
        Write-Host ""
        Write-Host "Invoke-SubnetScan" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-RemoteInstalledSoftware
    if ($Name -eq 'Get-RemoteInstalledSoftware') {
        Write-Host ""
        Write-Host "Get-RemoteInstalledSoftware" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-BatteryHealth
    if ($Name -eq 'Get-BatteryHealth') {
        Write-Host ""
        Write-Host "Get-BatteryHealth" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-MessageTrace
    if ($Name -eq 'Get-MessageTrace') {
        Write-Host ""
        Write-Host "Get-MessageTrace" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-TechToolboxConfig
    if ($Name -eq 'Get-TechToolboxConfig') {
        Write-Host ""
        Write-Host "Get-TechToolboxConfig" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-ToolboxHelp
    if ($Name -eq 'Get-ToolboxHelp') {
        Write-Host ""
        Write-Host "Get-ToolboxHelp" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-WindowsProductKey
    if ($Name -eq 'Get-WindowsProductKey') {
        Write-Host ""
        Write-Host "Get-WindowsProductKey" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-AADSyncRemote
    if ($Name -eq 'Invoke-AADSyncRemote') {
        Write-Host ""
        Write-Host "Invoke-AADSyncRemote" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-DownloadsCleanup
    if ($Name -eq 'Invoke-DownloadsCleanup') {
        Write-Host ""
        Write-Host "Invoke-DownloadsCleanup" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-PurviewPurge
    if ($Name -eq 'Invoke-PurviewPurge') {
        Write-Host ""
        Write-Host "Invoke-PurviewPurge" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SystemRepair
    if ($Name -eq 'Invoke-SystemRepair') {
        Write-Host ""
        Write-Host "Invoke-SystemRepair" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-PageFileSize
    if ($Name -eq 'Set-PageFileSize') {
        Write-Host ""
        Write-Host "Set-PageFileSize" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-ProxyAddress
    if ($Name -eq 'Set-ProxyAddress') {
        Write-Host ""
        Write-Host "Set-ProxyAddress" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-DnsQueryLogger
    if ($Name -eq 'Start-DnsQueryLogger') {
        Write-Host ""
        Write-Host "Start-DnsQueryLogger" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Copy-Directory
    if ($Name -eq 'Copy-Directory') {
        Write-Host ""
        Write-Host "Copy-Directory" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Reset-WindowsUpdateComponents
    if ($Name -eq 'Reset-WindowsUpdateComponents') {
        Write-Host ""
        Write-Host "Reset-WindowsUpdateComponents" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Test-PathAs
    if ($Name -eq 'Test-PathAs') {
        Write-Host ""
        Write-Host "Test-PathAs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemSnapshot
    if ($Name -eq 'Get-SystemSnapshot') {
        Write-Host ""
        Write-Host "Get-SystemSnapshot" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Search-User
    if ($Name -eq 'Search-User') {
        Write-Host ""
        Write-Host "Search-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Disable-User
    if ($Name -eq 'Disable-User') {
        Write-Host ""
        Write-Host "Disable-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    #Remove-Printers
    if ($Name -eq 'Remove-Printers') {
        Write-Host ""
        Write-Host "Remove-Printers" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-DomainAdminCred
    if ($Name -eq 'Initialize-DomainAdminCred') {
        Write-Host ""
        Write-Host "Initialize-DomainAdminCred" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-DomainAdminCredential
    if ($Name -eq 'Get-DomainAdminCredential') {
        Write-Host ""
        Write-Host "Get-DomainAdminCredential" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Enable-NetFx3
    if ($Name -eq 'Enable-NetFx3') {
        Write-Host ""
        Write-Host "Enable-NetFx3" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-TTWordList
    if ($Name -eq 'Initialize-TTWordList') {
        Write-Host ""
        Write-Host "Initialize-TTWordList" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemUptime
    if ($Name -eq 'Get-SystemUptime') {
        Write-Host ""
        Write-Host "Get-SystemUptime" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-AutodiscoverXmlInteractive
    if ($Name -eq 'Get-AutodiscoverXmlInteractive') {
        Write-Host ""
        Write-Host "Get-AutodiscoverXmlInteractive" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-PDQDiagLocalElevated
    if ($Name -eq 'Start-PDQDiagLocalElevated') {
        Write-Host ""
        Write-Host "Start-PDQDiagLocalElevated" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-PDQDiagLogs
    if ($Name -eq 'Get-PDQDiagLogs') {
        Write-Host ""
        Write-Host "Get-PDQDiagLogs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-LocalLLM
    if ($Name -eq 'Invoke-LocalLLM') {
        Write-Host ""
        Write-Host "Invoke-LocalLLM" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return

    #Invoke-CodeAssistant
    } elseif ($Name -eq 'Invoke-CodeAssistant') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistant" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Get-WindowsProductKey.ps1
`powershell
function Get-WindowsProductKey {
    <#
    .SYNOPSIS
    Retrieves Windows activation information, including OEM product key, partial
    product keys, and activation report.
    .DESCRIPTION
    This function gathers Windows activation details from the local or a remote
    computer using CIM and WMI. It retrieves the OEM product key, partial product
    keys, and the output of the SLMGR /DLV command. The results are exported to a
    timestamped log file in a configured directory.
    .PARAMETER ComputerName
    The name of the computer to query. Defaults to the local computer.
    .PARAMETER Credential
    Optional PSCredential for remote connections.
    .INPUTS
        None. You cannot pipe objects to Get-WindowsActivationInfo.
    .OUTPUTS
        [pscustomobject] with properties:
        - ComputerName
        - OemProductKey
        - PartialKeys
        - ActivationReport
    .EXAMPLE
    Get-WindowsActivationInfo -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
    Get-WindowsActivationInfo
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Determine export root from config
    $exportRoot = $script:TechToolboxConfig["settings"]["windowsActivation"]["logDir"]
    if (-not (Test-Path -LiteralPath $exportRoot)) {
        New-Item -Path $exportRoot -ItemType Directory -Force | Out-Null
    }

    # Helper for remote execution
    function Invoke-Remote {
        param(
            [string]$ComputerName,
            [string]$Command,
            [System.Management.Automation.PSCredential]$Credential
        )

        if ($ComputerName -eq $env:COMPUTERNAME) {
            return Invoke-Expression $Command
        }

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = { param($cmd) Invoke-Expression $cmd }
            ArgumentList = $Command
            ErrorAction  = 'Stop'
        }

        if ($Credential) { $params.Credential = $Credential }

        return Invoke-Command @params
    }

    # OEM Product Key
    try {
        $oemParams = @{
            ClassName    = 'SoftwareLicensingService'
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $oemParams.Credential = $Credential }

        $oemKey = (Get-CimInstance @oemParams).OA3xOriginalProductKey
    }
    catch {
        $oemKey = $null
    }

    # Partial Keys
    try {
        $prodParams = @{
            ClassName    = 'SoftwareLicensingProduct'
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $prodParams.Credential = $Credential }

        $partialKeys = Get-CimInstance @prodParams |
        Where-Object { $_.PartialProductKey } |
        Select-Object Name, Description, LicenseStatus, PartialProductKey
    }
    catch {
        $partialKeys = $null
    }

    # Activation Report
    try {
        $slmgrOutput = Invoke-Remote -ComputerName $ComputerName `
            -Command 'cscript.exe //Nologo C:\Windows\System32\slmgr.vbs /dlv' `
            -Credential $Credential

        $slmgrOutput = $slmgrOutput -join "`n"
    }
    catch {
        $slmgrOutput = "Failed to retrieve slmgr report: $_"
    }

    # Build final object
    $result = [pscustomobject]@{
        ComputerName     = $ComputerName
        OemProductKey    = $oemKey
        PartialKeys      = $partialKeys
        ActivationReport = $slmgrOutput
    }

    # Build timestamped filename
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $fileName = $script:TechToolboxConfig["settings"]["windowsActivation"]["fileNameFormat"]
    $fileName = $fileName -replace '{computer}', $ComputerName
    $fileName = $fileName -replace '{yyyyMMdd-HHmmss}', $timestamp
    $exportPath = Join-Path $exportRoot $fileName

    # Build export content
    $logContent = @()
    $logContent += "Computer Name: $ComputerName"
    $logContent += "OEM Product Key: $oemKey"
    $logContent += ""
    $logContent += "=== Partial Keys ==="

    if ($partialKeys) {
        foreach ($item in $partialKeys) {
            $logContent += "Name: $($item.Name)"
            $logContent += "Description: $($item.Description)"
            $logContent += "LicenseStatus: $($item.LicenseStatus)"
            $logContent += "PartialProductKey: $($item.PartialProductKey)"
            $logContent += ""
        }
    }
    else {
        $logContent += "None found."
    }

    $logContent += ""
    $logContent += "=== SLMGR /DLV Output ==="
    $logContent += $slmgrOutput

    # Write to disk
    $logContent | Out-File -FilePath $exportPath -Encoding UTF8
    Write-Host "Windows activation info exported to: $exportPath"

    # Return object last for pipeline safety
    return $result
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Enable-NetFx3.ps1
`powershell

function Enable-NetFx3 {
    <#
    .SYNOPSIS
        Enables .NET Framework 3.5 (NetFx3) locally or on remote computers.

    .DESCRIPTION
        Local mode (default): runs on the current machine; enforces optional
        timeout via DISM path; returns exit 0 on success (including
        3010/reboot-required), 1 on failure (PDQ-friendly). Remote mode: when
        -ComputerName is provided, runs via WinRM using -Credential (or falls
        back to $script:domainAdminCred if not supplied). Returns per-target
        result objects (no hard exit).

    .PARAMETER ComputerName
        One or more remote computers to run against. If omitted, runs locally.

    .PARAMETER Credential
        PSCredential to use for remoting. If omitted and $script:domainAdminCred
        exists, it will be used. Otherwise remoting requires your current
        credentials to have access.

    .PARAMETER Source
        Optional SxS source for offline/WSUS-only environments. Prefer a UNC
        path for remoting (e.g., \\server\share\Win11\sources\sxs).

    .PARAMETER Quiet
        Reduce chatter (maps to NoRestart for cmdlet path; DISM already uses
        /Quiet).

    .PARAMETER NoRestart
        Do not restart automatically.

    .PARAMETER TimeoutMinutes
        For DISM path, maximum time to wait. Default 45 minutes. (Local:
        controls DISM path selection; Remote: enforced on target.)

    .PARAMETER Validate
        AAfter enablement, query feature state to confirm it is Enabled (best
        effort).

    .OUTPUTS
        Local: process exit code (0 or 1) via 'exit'. Remote: [pscustomobject]
        per target with fields ComputerName, ExitCode, Success, RebootRequired,
        State, Message.

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
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [string]$Source,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 45,
        [switch]$Validate
    )

    # If ComputerName provided → Remote mode
    if ($ComputerName -and $ComputerName.Count -gt 0) {
        # Resolve credential: explicit > module default > none
        if (-not $Credential -and $script:domainAdminCred) {
            $Credential = $script:domainAdminCred
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] Using module domainAdminCred for remoting."
        }

        # Warn if Source looks like a local drive path (prefer UNC for remote)
        if ($Source -and -not ($Source.StartsWith('\\'))) {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] -Source '$Source' is not a UNC path. Ensure it exists on EACH target."
        }

        Write-Log -Level 'Info' -Message "[Enable-NetFx3] Remote mode → targets: $($ComputerName -join ', ')"

        # Build the remote scriptblock (self-contained; no dependency on local functions)
        $sb = {
            param($src, $timeoutMinutes, $validate, $noRestart, $quiet)

            $ErrorActionPreference = 'Stop'
            $overallSuccess = $false
            $exit = 1
            $state = $null
            $msg = $null

            try {
                # Prefer DISM to enforce timeout and consistent exit code
                $argsList = @(
                    '/online',
                    '/enable-feature',
                    '/featurename:NetFx3',
                    '/All',
                    '/Quiet',
                    '/NoRestart'
                )
                if ($src) { $argsList += "/Source:`"$src`""; $argsList += '/LimitAccess' }

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'dism.exe'
                $psi.Arguments = ($argsList -join ' ')
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true

                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $psi

                if (-not $proc.Start()) {
                    $msg = "Failed to start DISM."
                    throw $msg
                }

                $proc.BeginOutputReadLine()
                $proc.BeginErrorReadLine()

                $timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, $timeoutMinutes)).TotalMilliseconds
                if (-not $proc.WaitForExit($timeoutMs)) {
                    try { $proc.Kill() } catch {}
                    $msg = "Timeout after $timeoutMinutes minutes."
                    $exit = 1
                }
                else {
                    $exit = $proc.ExitCode
                    if ($exit -in 0, 3010) {
                        $overallSuccess = $true
                    }
                    else {
                        $msg = "DISM failed with exit code $exit."
                    }
                }

                if ($overallSuccess -and $validate) {
                    try {
                        $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
                        if ($state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                            $overallSuccess = $false
                            if (-not $msg) { $msg = "Feature state after enablement: $state" }
                            if ($exit -in 0, 3010) { $exit = 1 } # normalize to failure if state isn't right
                        }
                    }
                    catch {
                        if (-not $msg) { $msg = "Validation failed: $($_.Exception.Message)" }
                    }
                }
            }
            catch {
                $msg = $_.Exception.Message
            }

            [pscustomobject]@{
                ComputerName   = $env:COMPUTERNAME
                ExitCode       = $exit
                Success        = [bool]$overallSuccess
                RebootRequired = ($exit -eq 3010)
                State          = $state
                Message        = $msg
            }
        }

        $icmParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $sb
            ArgumentList = @($Source, $TimeoutMinutes, [bool]$Validate, [bool]$NoRestart, [bool]$Quiet)
        }
        if ($Credential) { $icmParams.Credential = $Credential }

        $results = Invoke-Command @icmParams

        # Log summary and return objects (no hard exit in remote mode)
        foreach ($r in $results) {
            if ($r.Success) {
                if ($r.RebootRequired) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Success (reboot required)."
                }
                else {
                    Write-Log -Level 'Ok' -Message "[Enable-NetFx3][$($r.ComputerName)] Success."
                }
            }
            else {
                $tail = if ($r.Message) { " - $($r.Message)" } else { "" }
                Write-Log -Level 'Error' -Message "[Enable-NetFx3][$($r.ComputerName)] Failed (Exit $($r.ExitCode))$tail"
            }
        }

        return $results
    }

    # ----------------------------
    # Local mode (original logic)
    # ----------------------------
    Write-Log -Level 'Info' -Message "[Enable-NetFx3] Starting enablement (local)."

    $params = @{
        Online      = $true
        FeatureName = 'NetFx3'
        All         = $true
    }
    if ($PSBoundParameters.ContainsKey('Source') -and $Source) {
        $params.Source = $Source
        $params.LimitAccess = $true  # Avoid WU/WSUS when explicit source is provided
    }
    if ($Quiet) { $params.NoRestart = $true }
    if ($NoRestart) { $params.NoRestart = $true }

    $useDirectDism = ($TimeoutMinutes -gt 0)
    Write-Log -Level 'Info'  -Message "[Enable-NetFx3] Enabling .NET Framework 3.5 (NetFx3)..."
    Write-Log -Level 'Debug' -Message ("[Enable-NetFx3] Using {0} path." -f ($(if ($useDirectDism) { 'DISM (timeout)' } else { 'Enable-WindowsOptionalFeature' })))

    $overallSuccess = $false
    $dismExit = $null

    try {
        if (-not $useDirectDism) {
            $result = Enable-WindowsOptionalFeature @params -ErrorAction Stop
            Write-Log -Level 'Ok' -Message "[Enable-NetFx3] State: $($result.State)"
            $overallSuccess = $true
        }
        else {
            $argsList = @(
                '/online', '/enable-feature', '/featurename:NetFx3', '/All', '/Quiet', '/NoRestart'
            )
            if ($params.ContainsKey('Source')) {
                $argsList += "/Source:`"$($params.Source)`""
                $argsList += '/LimitAccess'
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'dism.exe'
            $psi.Arguments = ($argsList -join ' ')
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi

            if (-not $proc.Start()) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed to start DISM."
                exit 1
            }

            $proc.add_OutputDataReceived({ param($s, $e) if ($e.Data) { Write-Log -Level 'Info' -Message $e.Data } })
            $proc.add_ErrorDataReceived( { param($s, $e) if ($e.Data) { Write-Log -Level 'Warn' -Message $e.Data } })
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()

            $timeoutMs = [int][TimeSpan]::FromMinutes($TimeoutMinutes).TotalMilliseconds
            if (-not $proc.WaitForExit($timeoutMs)) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Timeout after $TimeoutMinutes minutes. Attempting to terminate DISM..."
                try { $proc.Kill() } catch {}
                exit 1
            }

            $dismExit = $proc.ExitCode
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] DISM exit code: $dismExit"

            if ($dismExit -in 0, 3010) {
                $overallSuccess = $true
                if ($dismExit -eq 3010) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Reboot required to complete NetFx3 enablement."
                }
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] DISM reported failure."
            }
        }
    }
    catch {
        Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed: $($_.Exception.Message)"
        $overallSuccess = $false
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
            Write-Log -Level 'Info' -Message "[Enable-NetFx3] Feature state: $state"
            if ($state -in 'Enabled', 'EnablePending', 'EnabledPending') {
                Write-Log -Level 'Ok' -Message "[Enable-NetFx3] NetFx3 enablement validated."
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] NetFx3 state not enabled after operation."
                $overallSuccess = $false
            }
        }
        catch {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Validation skipped: $($_.Exception.Message)"
        }
    }

    if ($overallSuccess) { exit 0 } else { exit 1 }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-AADSyncRemote.ps1
`powershell

function Invoke-AADSyncRemote {
    <#
    .SYNOPSIS
        Remotely triggers Azure AD Connect (ADSync) sync cycle (Delta/Initial)
        on a target server via PSRemoting.
    .DESCRIPTION
        Creates a remote PSSession (Kerberos or credential-based) to the AAD
        Connect host, validates ADSync module/service, and triggers
        Start-ADSyncSyncCycle. Uses TechToolbox config for defaults and
        Write-Log for unified logging.
    .PARAMETER ComputerName
        FQDN/hostname of AAD Connect server.
    .PARAMETER PolicyType
        Sync policy type: Delta or Initial. Default pulled from config
        (AADSync.DefaultPolicyType).
    .PARAMETER Port
        WinRM port: 5985 (HTTP) or 5986 (HTTPS). Default pulled from config
        (AADSync.DefaultPort).
    .PARAMETER Credential
        PSCredential for remote connection. If not supplied, Kerberos auth
        is used.
    .INPUTS
        None. You cannot pipe objects to Invoke-AADSyncRemote.
    .OUTPUTS
        None. Output is written to the Information stream.
    .EXAMPLE
        Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta
    .EXAMPLE
        Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Initial -UseKerberos -WhatIf
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()] [string]$ComputerName,
        [Parameter()] [ValidateSet('Delta', 'Initial')] [string]$PolicyType,
        [Parameter()] [ValidateSet(5985, 5986)] [int]$Port,
        [Parameter()] [pscredential]$Credential
    )

    # --- Config & defaults ---
    $cfg = Get-TechToolboxConfig
    $aadSync = $cfg["settings"]["aadSync"]
    $defaults = $cfg["settings"]["defaults"]

    # PolicyType (parameter > config > fallback)
    if (-not $PSBoundParameters.ContainsKey('PolicyType') -or [string]::IsNullOrWhiteSpace($PolicyType)) {
        $PolicyType = $aadSync["defaultPolicyType"]
        if ([string]::IsNullOrWhiteSpace($PolicyType)) { $PolicyType = 'Delta' }
    }

    # Port (parameter > config > fallback)
    if (-not $PSBoundParameters.ContainsKey('Port') -or $Port -eq 0) {
        $Port = [int]$aadSync["defaultPort"]
        if ($Port -eq 0) { $Port = 5985 }
    }

    # Prompt for hostname if missing
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $shouldPromptHost = $defaults["promptForHostname"]
        if ($null -eq $shouldPromptHost) { $shouldPromptHost = $true }

        if ($shouldPromptHost) {
            $ComputerName = Read-Host -Prompt 'Enter the FQDN or hostname of the AAD Connect server'
        }
        else {
            throw "ComputerName is required and prompting is disabled by config."
        }
    }
    $ComputerName = $ComputerName.Trim()

    # --- Connect session (credential-based only) ---
    $session = $null
    try {
        Write-Log -Level Info -Message ("Creating remote session to {0} on port {1} ..." -f $ComputerName, $Port)

        $session = New-PSSession -ComputerName $ComputerName `
            -Port $Port `
            -UseSSL:($Port -eq 5986) `
            -Credential $Credential `
            -Authentication Default `
            -ErrorAction Stop

        Write-Log -Level Ok -Message "Session established using supplied credentials."
    }
    catch {
        Write-Log -Level Error -Message ("Failed to create remote session: {0}" -f $_.Exception.Message)
        return
    }

    # --- Remote check + sync trigger ---
    try {
        Write-Log -Level Info -Message ("Checking ADSync module and service state on {0} ..." -f $ComputerName)

        $precheck = Test-AADSyncRemote -Session $session
        if ($precheck.Status -eq 'PreCheckFailed') {
            Write-Log -Level Error -Message ("Remote pre-checks failed: {0}" -f $precheck.Errors)
            return
        }

        $result = Invoke-RemoteADSyncCycle -Session $session -PolicyType $PolicyType -WhatIf:$WhatIfPreference -Confirm:$false
        Write-Log -Level Ok -Message ("Sync ({0}) triggered successfully on {1}." -f $PolicyType, $ComputerName)

        # Pretty table to Information stream
        $table = $result | Format-Table ComputerName, PolicyType, Status, Errors -AutoSize | Out-String
        Write-Information $table
    }
    catch {
        Write-Log -Level Error -Message ("Unhandled error: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            Write-Log -Level Info -Message "Remote session closed."
        }
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-DownloadsCleanup.ps1
`powershell

function Invoke-DownloadsCleanup {
    <#
    .SYNOPSIS
        Cleans up old files from Downloads folders on local or remote machines.
    .DESCRIPTION
        This cmdlet connects to a specified remote computer (or the local machine
        if -Local is used) and scans all user Downloads folders for files last
        modified on or before a specified cutoff year. Those files are deleted to
        help free up disk space and reduce clutter.
    .PARAMETER ComputerName
        The name of the remote computer to clean up. If omitted, -Local must be
        used.
    .PARAMETER CutoffYear
        The year threshold; files last modified on or before this year will be
        deleted. Defaults to config value.
    .PARAMETER Local
        If specified, runs the cleanup on the local machine instead of a remote
        computer.
    .INPUTS
        None. You cannot pipe objects to Invoke-DownloadsCleanup.
    .OUTPUTS
        [pscustomobject] entries summarizing cleanup results per user.
    .EXAMPLE
        Invoke-DownloadsCleanup -ComputerName "Workstation01"
    .EXAMPLE
        Invoke-DownloadsCleanup -Local -CutoffYear 2020
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()][string]$ComputerName,
        [Parameter()][int]$CutoffYear,
        [switch]$Local
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $dlCfg = $cfg["settings"]["downloadsCleanup"]

    # Defaults
    if (-not $CutoffYear) { $CutoffYear = $dlCfg["cutoffYear"] }
    $dryRun = $dlCfg["dryRun"]

    # If -Local is used, ignore ComputerName entirely
    if ($Local) {
        Write-Log -Level Info -Message "Running Downloads cleanup locally."

        $result = & {
            param($CutoffYear, $DryRun)

            $basePath = "C:\Users"
            $users = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue

            $report = @()

            foreach ($user in $users) {
                $downloadsPath = Join-Path $user.FullName "Downloads"

                if (-not (Test-Path $downloadsPath)) {
                    $report += [pscustomobject]@{
                        User    = $user.Name
                        Path    = $downloadsPath
                        Status  = "No Downloads folder"
                        Deleted = 0
                    }
                    continue
                }

                $oldFiles = Get-ChildItem -Path $downloadsPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime.Year -le $CutoffYear }

                $deletedCount = 0

                foreach ($file in $oldFiles) {
                    if ($DryRun) {
                        $deletedCount++
                        continue
                    }

                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $deletedCount++
                    }
                    catch {
                        $report += [pscustomobject]@{
                            User    = $user.Name
                            Path    = $file.FullName
                            Status  = "Failed: $($_.Exception.Message)"
                            Deleted = 0
                        }
                    }
                }

                $report += [pscustomobject]@{
                    User    = $user.Name
                    Path    = $downloadsPath
                    Status  = "OK"
                    Deleted = $deletedCount
                }
            }

            return $report

        } -ArgumentList $CutoffYear, $dryRun

        foreach ($entry in $result) {
            if ($entry.Status -eq "OK") {
                Write-Log -Level Ok -Message "[$($entry.User)] Deleted $($entry.Deleted) old files."
            }
            elseif ($entry.Status -like "Failed*") {
                Write-Log -Level Warn -Message "[$($entry.User)] Failed to delete: $($entry.Path) — $($entry.Status)"
            }
            else {
                Write-Log -Level Info -Message "[$($entry.User)] $($entry.Status)"
            }
        }

        Write-Log -Level Ok -Message "Local Downloads cleanup completed."
        return
    }

    # ────────────────────────────────────────────────────────────────
    # REMOTE EXECUTION (default)
    # ────────────────────────────────────────────────────────────────

    if (-not $ComputerName) {
        Write-Log -Level Error -Message "You must specify -ComputerName or use -Local."
        return
    }

    # Prompt for credentials if config says so
    $creds = $null
    if ($cfg["settings"]["defaults"]["promptForCredentials"]) {
        $creds = Get-Credential -Message "Enter credentials for $ComputerName"
    }

    Write-Log -Level Info -Message "Connecting to $ComputerName..."

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $creds
        Write-Log -Level Ok -Message "Connected to $ComputerName."
    }
    catch {
        Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
        return
    }

    Write-Log -Level Info -Message "Scanning Downloads folders on $ComputerName..."

    $result = Invoke-Command -Session $session -ScriptBlock {
        param($CutoffYear, $DryRun)

        $basePath = "C:\Users"
        $users = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue

        $report = @()

        foreach ($user in $users) {
            $downloadsPath = Join-Path $user.FullName "Downloads"

            if (-not (Test-Path $downloadsPath)) {
                $report += [pscustomobject]@{
                    User    = $user.Name
                    Path    = $downloadsPath
                    Status  = "No Downloads folder"
                    Deleted = 0
                }
                continue
            }

            $oldFiles = Get-ChildItem -Path $downloadsPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime.Year -le $CutoffYear }

            $deletedCount = 0

            foreach ($file in $oldFiles) {
                if ($DryRun) {
                    $deletedCount++
                    continue
                }

                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $deletedCount++
                }
                catch {
                    $report += [pscustomobject]@{
                        User    = $user.Name
                        Path    = $file.FullName
                        Status  = "Failed: $($_.Exception.Message)"
                        Deleted = 0
                    }
                }
            }

            $report += [pscustomobject]@{
                User    = $user.Name
                Path    = $downloadsPath
                Status  = "OK"
                Deleted = $deletedCount
            }
        }

        return $report

    } -ArgumentList $CutoffYear, $dryRun

    Remove-PSSession $session

    foreach ($entry in $result) {
        if ($entry.Status -eq "OK") {
            Write-Log -Level Ok -Message "[$($entry.User)] Deleted $($entry.Deleted) old files."
        }
        elseif ($entry.Status -like "Failed*") {
            Write-Log -Level Warn -Message "[$($entry.User)] Failed to delete: $($entry.Path) — $($entry.Status)"
        }
        else {
            Write-Log -Level Info -Message "[$($entry.User)] $($entry.Status)"
        }
    }

    Write-Log -Level Ok -Message "Downloads cleanup completed on $ComputerName."
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-PurviewPurge.ps1
`powershell

function Invoke-PurviewPurge {
    <#
    .SYNOPSIS
        End-to-end Purview HardDelete purge workflow: connect, clone search,
        wait, purge, optionally disconnect.
    .DESCRIPTION
        Imports ExchangeOnlineManagement (if needed), connects to Purview with
        SearchOnly session, prompts for any missing inputs (config-driven),
        clones an existing search (mailbox-only), waits for completion, and
        submits a HardDelete purge. Uses Write-Log and supports
        -WhatIf/-Confirm.
    .PARAMETER UserPrincipalName
        The UPN to use for connecting to Purview (Exchange Online).
    .PARAMETER CaseName
        The eDiscovery Case Name/ID containing the Compliance Search to clone.
    .PARAMETER ContentMatchQuery
        The KQL/keyword query to match items to purge (e.g.,
        'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned
        Assets"'). If omitted, a new mailbox-only search will be created via
        prompted KQL query.
    .PARAMETER Log
        A hashtable of logging configuration options to merge into the module-
        scope logging bag. See Get-TechToolboxConfig "settings.logging" for
        available keys.
    .PARAMETER ShowProgress
        Switch to enable console logging/progress output for this invocation.
    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" `
            -CaseName "Legal Case 123" -ContentMatchQuery 'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets"'
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CaseName,

        # The KQL/keyword query to match items to purge (e.g., 'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets"')
        [Parameter()][ValidateNotNullOrEmpty()][string]$ContentMatchQuery,

        # Optional naming override/prefix; the function will add a timestamp suffix to ensure uniqueness
        [Parameter()][ValidateNotNullOrEmpty()][string]$SearchNamePrefix = "TTX-Purge",

        [Parameter()][hashtable]$Log,
        [switch]$ShowProgress
    )

    # Global safety
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    try {
        # ---- Config & defaults ----
        $cfg = Get-TechToolboxConfig
        $purv = $cfg["settings"]["purview"]
        $defaults = $cfg["settings"]["defaults"]
        $exo = $cfg["settings"]["exchangeOnline"]

        # Support both legacy and purge.* keys in config
        $timeoutSeconds = [int]$purv["timeoutSeconds"]
        if ($timeoutSeconds -le 0) { $timeoutSeconds = 1200 }
        $pollSeconds = [int]$purv["pollSeconds"]
        if ($pollSeconds -le 0) { $pollSeconds = 5 }

        # Registration wait (configurable)
        $regTimeout = [int]$purv["registrationWaitSeconds"]
        if ($regTimeout -le 0) { $regTimeout = 90 }
        $regPoll = [int]$purv["registrationPollSeconds"]
        if ($regPoll -le 0) { $regPoll = 3 }
        
        # ----- Query prompt + validation/normalization -----
        $promptQuery = $defaults["promptForContentMatchQuery"] ?? $true

        while ($true) {
            if ([string]::IsNullOrWhiteSpace($ContentMatchQuery)) {
                if ($promptQuery) {
                    $ContentMatchQuery = Read-Host 'Enter ContentMatchQuery (e.g., from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets")'
                }
                else {
                    throw "ContentMatchQuery is required but prompting is disabled by config."
                }
            }

            $normRef = [ref] $null
            $isValid = $false
            try {
                $isValid = Test-ContentMatchQuery -Query $ContentMatchQuery -Normalize -NormalizedQuery $normRef
            }
            catch {
                # If the validator ever throws, treat as invalid and re-prompt
                Write-Warning ("Validator error: {0}" -f $_.Exception.Message)
                $ContentMatchQuery = $null
                continue
            }

            if (-not $isValid) {
                Write-Warning "KQL appears invalid (unbalanced quotes/parentheses or unsupported property). Please re-enter."
                $ContentMatchQuery = $null
                continue
            }

            # Valid: commit normalized value (if provided) and break
            if ($normRef.Value) {
                $ContentMatchQuery = $normRef.Value
            }
            Write-Log -Level Info -Message ("Final ContentMatchQuery: {0}" -f $ContentMatchQuery)
            break
        }

        # ---- Module & session ----
        Import-ExchangeOnlineModule -ErrorAction Stop
        if ($autoConnect) {
            Connect-PurviewSearchOnly -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        }
        else {
            Write-Log -Level Info -Message "AutoConnect disabled by config; ensure an active Purview session exists."
        }

        # ---- Build a unique search name ----
        $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $baseName = "{0}-{1}" -f $SearchNamePrefix, $CaseName
        $searchName = "{0}-{1}" -f $baseName, $ts

        Write-Log -Level Info -Message ("Creating mailbox-only Compliance Search '{0}' in case '{1}'..." -f $searchName, $CaseName)
        Write-Log -Level Info -Message "Scope: ExchangeLocation=All"

        # ---- Create the mailbox-only search (ALL mailboxes) ----
        $newParams = @{
            Name              = $searchName
            Case              = $CaseName
            ExchangeLocation  = 'All'
            ContentMatchQuery = $ContentMatchQuery
        }

        # Create (respects WhatIf)
        if ($PSCmdlet.ShouldProcess(("Case '{0}'" -f $CaseName), ("Create compliance search '{0}' (mailbox-only / All mailboxes)" -f $searchName))) {
            $null = New-ComplianceSearch @newParams
            Write-Log -Level Ok -Message ("Search created: {0}" -f $searchName)
        }
        else {
            Write-Log -Level Info -Message "Creation skipped due to -WhatIf/-Confirm."
            return
        }

        # ---- Wait until the search object is registered/visible ----
        Write-Log -Level Info -Message ("Waiting for search '{0}' to register (timeout={1}s, poll={2}s)..." -f $searchName, $regTimeout, $regPoll)
        $registered = Wait-ComplianceSearchRegistration -SearchName $searchName -TimeoutSeconds $regTimeout -PollSeconds $regPoll
        if (-not $registered) {
            throw "Search object '$searchName' was not visible after creation (waited ${regTimeout}s). Aborting."
        }

        # ---- Start the search after registration ----
        if ($PSCmdlet.ShouldProcess(("Search '{0}'" -f $searchName), 'Start compliance search')) {
            Start-ComplianceSearch -Identity $searchName
            Write-Log -Level Info -Message ("Search started: {0}" -f $searchName)
        }
        else {
            Write-Log -Level Info -Message "Start skipped due to -WhatIf/-Confirm."
            return
        }

        # ---- Wait until completion ----
        Write-Log -Level Info -Message ("Waiting for search '{0}' to complete (timeout={1}s, poll={2}s)..." -f $searchName, $timeoutSeconds, $pollSeconds)
        $searchObj = Wait-SearchCompletion -SearchName $searchName -CaseName $CaseName -TimeoutSeconds $timeoutSeconds -PollSeconds $pollSeconds -ErrorAction Stop

        if ($null -eq $searchObj) { throw "Search object not returned for '$searchName' (case '$CaseName')." }
        Write-Log -Level Ok -Message ("Search status: {0}; Items: {1}" -f $searchObj.Status, $searchObj.Items)

        if ($searchObj.Items -le 0) {
            throw "Search '$searchName' returned 0 mailbox items. Purge aborted."
        }

        # ---- Purge (HardDelete) via your existing helper ----
        if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $searchName), 'Submit Purview HardDelete purge')) {
            $null = Invoke-HardDelete -SearchName $searchName -CaseName $CaseName -Confirm:$false -ErrorAction Stop
            Write-Log -Level Ok -Message ("[Done] Purview HardDelete purge submitted for '{0}' in case '{1}'." -f $searchName, $CaseName)
        }
        else {
            Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
        }

        # ---- Summary ----
        Write-Log -Level Ok -Message ("Summary: search='{0}' status='{1}' items={2} purgeSubmitted={3}" -f $searchName, $searchObj.Status, $searchObj.Items, $true)
    }
    catch {
        Write-Error ("[ERROR] {0}" -f $_.Exception.Message)
        if ($script:log["enableConsole"]) {
            Write-Log -Level Error -Message ("[ERROR] {0}" -f $_.Exception.Message)
        }
        throw
    }
    finally {
        [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo)
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SubnetScan.ps1
`powershell

function Invoke-SubnetScan {
    <#
.SYNOPSIS
    Scans a subnet (locally or remotely) and can export results to CSV.
.DESCRIPTION
    Orchestrates a subnet scan by calling Invoke-SubnetScanLocal. Applies
    defaults from config.settings.subnetScan and exports locally to
    config.settings.subnetScan.exportDir when -ExportCsv is requested. Can also
    execute the scan on a remote host if -ComputerName is specified.
.PARAMETER ComputerName
    Specifies the remote computer on which to execute the subnet scan. If
    not specified, the scan will be executed locally.
.PARAMETER Port
    Specifies the TCP port to test on each host. Defaults to the value in
    config.settings.subnetScan.defaultPort or 80 if not specified.
.PARAMETER ResolveNames
    Switch to enable name resolution (PTR → NetBIOS → mDNS) for each host.
    Defaults to the value in config.settings.subnetScan.resolveNames or
    $false if not specified.
.PARAMETER HttpBanner
    Switch to enable HTTP banner retrieval for each host. Defaults to the
    value in config.settings.subnetScan.httpBanner or $false if not specified.
.PARAMETER ExportCsv
    Switch to enable exporting scan results to CSV. Defaults to the value in
    config.settings.subnetScan.exportCsv or $false if not specified.
.PARAMETER LocalOnly
    Switch to force the scan to execute locally, even if -ComputerName is
    specified.
.INPUTS
    None
.OUTPUTS
    System.Collections.Generic.List[PSCustomObject]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        # Remote options
        [string]$ComputerName,
        [ValidateSet('WSMan', 'SSH')]
        [string]$Transport = 'WSMan',
        [pscredential]$Credential,       # WSMan (domain/local); SSH (username only if not using key)
        [string]$UserName,               # SSH user if not using -Credential
        [string]$KeyFilePath,            # SSH key (optional)
        [switch]$LocalOnly,

        # Scan behavior (nullable by omission; we default from config)
        [int]$Port,
        [switch]$ResolveNames,
        [switch]$HttpBanner,

        # Export control
        [switch]$ExportCsv,
        [ValidateSet('Local', 'Remote')]
        [string]$ExportTarget = 'Local'
    )

    Set-StrictMode -Version Latest
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'

    try {
        # --- CONFIG & DEFAULTS ---
        $cfg = Get-TechToolboxConfig -Verbose
        if (-not $cfg) { throw "TechToolbox config is null/empty. Ensure Config\config.json exists and is valid JSON." }

        # Keep ?. tight (no whitespace between ? and . /  )
        $scanCfg = $cfg['settings']?['subnetScan']
        if (-not $scanCfg) { throw "Config missing 'settings.subnetScan'." }

        # Defaults only if user didn’t supply
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $scanCfg['defaultPort'] ?? 80 }
        if (-not $PSBoundParameters.ContainsKey('ResolveNames')) { $ResolveNames = [bool]($scanCfg['resolveNames'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('HttpBanner')) { $HttpBanner = [bool]($scanCfg['httpBanner'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('ExportCsv')) { $ExportCsv = [bool]($scanCfg['exportCsv'] ?? $false) }

        # Local export dir resolved now (used when ExportTarget=Local)
        $localExportDir = $scanCfg['exportDir']
        if ($ExportCsv -and $ExportTarget -eq 'Local') {
            if (-not $localExportDir) { throw "Config 'settings.subnetScan.exportDir' is missing." }
            if (-not (Test-Path -LiteralPath $localExportDir)) {
                New-Item -ItemType Directory -Path $localExportDir -Force | Out-Null
            }
        }

        Write-Log -Level Info -Message ("SubnetScan: CIDR={0} Port={1} ResolveNames={2} HttpBanner={3} ExportCsv={4} Target={5}" -f `
                $CIDR, $Port, $ResolveNames, $HttpBanner, $ExportCsv, $ExportTarget)

        # --- EXECUTION LOCATION ---
        $runLocal = $LocalOnly -or (-not $ComputerName)
        $results = $null

        if ($runLocal) {
            Write-Log -Level Info -Message "Executing subnet scan locally."
            # Worker should not export in local mode if ExportTarget=Local (we export here)
            $doRemoteExport = $false
            $results = Invoke-SubnetScanLocal -CIDR $CIDR -Port $Port -ResolveNames:$ResolveNames -HttpBanner:$HttpBanner -ExportCsv:$doRemoteExport
        }
        else {
            Write-Log -Level Info -Message "Executing subnet scan on remote host: $ComputerName via $Transport"

            # Build session
            $session = $null
            try {
                if ($Transport -eq 'WSMan') {
                    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
                }
                else {
                    # SSH remoting (PowerShell 7+)
                    if (-not $UserName -and $Credential) { $UserName = $Credential.UserName }
                    if (-not $UserName) { throw "For SSH transport, specify -UserName or -Credential." }

                    $sshParams = @{ HostName = $ComputerName; UserName = $UserName; ErrorAction = 'Stop' }
                    if ($KeyFilePath) { $sshParams['KeyFilePath'] = $KeyFilePath }
                    elseif ($Credential) { $sshParams['Password'] = $Credential.GetNetworkCredential().Password }

                    $session = New-PSSession @sshParams
                }
                Write-Log -Level Ok -Message "Connected to $ComputerName."
            }
            catch {
                Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
                return
            }

            try {
                # Ensure TechToolbox module is present & importable on remote
                $moduleRoot = 'C:\TechToolbox'
                $moduleManifest = Join-Path $moduleRoot 'TechToolbox.psd1'

                $remoteHasModule = Invoke-Command -Session $session -ScriptBlock {
                    param($moduleManifestPath)
                    Test-Path -LiteralPath $moduleManifestPath
                } -ArgumentList $moduleManifest

                if (-not $remoteHasModule) {
                    Write-Log -Level Info -Message "TechToolbox not found on remote; copying module..."
                    # Copy the whole folder (adjust if your layout differs)
                    Copy-Item -ToSession $session -Path 'C:\TechToolbox' -Destination 'C:\' -Recurse -Force
                }

                # Import module and run worker
                $doRemoteExport = $ExportCsv -and ($ExportTarget -eq 'Remote')

                $results = Invoke-Command -Session $session -ScriptBlock {
                    param($CIDR, $Port, $ResolveNames, $HttpBanner, $DoExport)

                    # Import module
                    Import-Module 'C:\TechToolbox\TechToolbox.psd1' -Force -ErrorAction Stop

                    Invoke-SubnetScanLocal -CIDR $CIDR -Port $Port -ResolveNames:$ResolveNames -HttpBanner:$HttpBanner -ExportCsv:$DoExport
                } -ArgumentList $CIDR, $Port, $ResolveNames, $HttpBanner, $doRemoteExport
            }
            catch {
                Write-Log -Level Error -Message "Remote scan failed: $($_.Exception.Message)"
                return
            }
            finally {
                if ($session) { Remove-PSSession $session }
            }
        }

        # Export locally (only if requested & results present)
        if ($ExportCsv -and $ExportTarget -eq 'Local' -and $results) {
            try {
                $cidrSafe = $CIDR -replace '[^\w\-\.]', '_'
                $csvPath = Join-Path $localExportDir ("subnet-scan-{0}-{1}.csv" -f $cidrSafe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log -Level Ok -Message "Results exported to $csvPath"
            }
            catch {
                Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
            }
        }

        # Console summary (responders only)
        if ($results) {
            Write-Host "Discovered hosts:" -ForegroundColor DarkYellow
            $results |
            Select-Object IP, RTTms, MacAddress, NetBIOS, PTR, Mdns, PortOpen, ServerHdr |
            Format-Table -AutoSize
        }

        return $results
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SystemRepair.ps1
`powershell
function Invoke-SystemRepair {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations locally or via PSRemoting.
    .DESCRIPTION
        Wraps common repair operations (DISM RestoreHealth,
        StartComponentCleanup, ResetBase, SFC, and Windows Update component
        reset) in a TechToolbox-style function with optional remote execution
        and credential support.
    .PARAMETER RestoreHealth
        Runs DISM /RestoreHealth.
    .PARAMETER StartComponentCleanup
        Runs DISM /StartComponentCleanup.
    .PARAMETER ResetBase
        Runs DISM /StartComponentCleanup /ResetBase.
    .PARAMETER SfcScannow
        Runs SFC /scannow.
    .PARAMETER ResetUpdateComponents
        Resets Windows Update components.
    .PARAMETER ComputerName
        Specifies the remote computer name to run the operations on. If not
        specified, and -Local is not set, the function will check the config for
        a default computer name.
    .PARAMETER Local
        If set, forces local execution regardless of ComputerName or config
        settings.
    .PARAMETER Credential
        Specifies the credentials to use for remote execution. Ignored if -Local
        is set.
    .INPUTS
        None. You cannot pipe objects to Invoke-SystemRepair.
    .OUTPUTS
        None. Output is written to the Information stream.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -SfcScannow
        Runs DISM RestoreHealth and SFC /scannow locally.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -ComputerName "Client01" -Credential (Get-Credential)
        Runs DISM RestoreHealth on the remote computer "Client01" using the
        specified credentials.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [switch]$RestoreHealth,

        [Parameter()]
        [switch]$StartComponentCleanup,

        [Parameter()]
        [switch]$ResetBase,

        [Parameter()]
        [switch]$SfcScannow,

        [Parameter()]
        [switch]$ResetUpdateComponents,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Local,

        [Parameter()]
        [pscredential]$Credential
    )

    # Short-circuit: nothing selected
    if (-not ($RestoreHealth -or $StartComponentCleanup -or $ResetBase -or $SfcScannow -or $ResetUpdateComponents)) {
        Write-Log -Level Warn -Message "No operations specified. Choose at least one operation to run."
        return
    }

    # --- Config hook (future-friendly) ---
    $cfg = Get-TechToolboxConfig
    $settings = $cfg["settings"]
    $repair = $settings["systemRepair"] 

    $runRemoteDefault = $repair["runRemote"] ?? $true

    # Decide local vs remote
    $targetComputer = $ComputerName
    if (-not $Local) {
        if (-not $targetComputer -and $repair.ContainsKey("defaultComputerName")) {
            $targetComputer = $repair["defaultComputerName"]
        }
    }

    $runRemoteEffective =
    -not $Local -and
    -not [string]::IsNullOrWhiteSpace($targetComputer) -and
    $runRemoteDefault

    $targetLabel = if ($runRemoteEffective) {
        "remote host $targetComputer"
    }
    else {
        "local machine"
    }

    Write-Log -Level Info -Message ("Preparing system repair operations on {0}." -f $targetLabel)

    # Build a friendly description for ShouldProcess
    $ops = @()
    if ($RestoreHealth) { $ops += "DISM RestoreHealth" }
    if ($StartComponentCleanup) { $ops += "DISM StartComponentCleanup" }
    if ($ResetBase) { $ops += "DISM ResetBase" }
    if ($SfcScannow) { $ops += "SFC /scannow" }
    if ($ResetUpdateComponents) { $ops += "Reset Windows Update Components" }

    $operationDesc = $ops -join ", "

    if ($PSCmdlet.ShouldProcess($targetLabel, "Run: $operationDesc")) {

        if ($runRemoteEffective) {
            Write-Log -Level Info -Message ("Executing repair operations remotely on [{0}]." -f $targetComputer)

            Invoke-SystemRepairRemote `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents `
                -ComputerName $targetComputer `
                -Credential $Credential
        }
        else {
            Write-Log -Level Info -Message "Executing repair operations locally."

            Invoke-SystemRepairLocal `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents
        }

        Write-Log -Level Ok -Message ("System repair operations completed on {0}." -f $targetLabel)
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Set-PageFileSize.ps1
`powershell

function Set-PageFileSize {
    <#
    .SYNOPSIS
        Sets the pagefile size on a remote computer via CIM/WMI.
    .DESCRIPTION
        This cmdlet connects to a remote computer using PowerShell remoting and
        configures the pagefile size according to user input or specified parameters.
        It can also prompt for a reboot to apply the changes.
    .PARAMETER ComputerName
        The name of the remote computer to configure the pagefile on.
    .PARAMETER InitialSize
        The initial size of the pagefile in MB. If not provided, the user will be
        prompted to enter a value within configured limits.
    .PARAMETER MaximumSize
        The maximum size of the pagefile in MB. If not provided, the user will be
        prompted to enter a value within configured limits.
    .PARAMETER Path
        The path to the pagefile. If not provided, the default path from the config
        will be used.
    .INPUTS
        None. You cannot pipe objects to Set-PageFileSize.
    .OUTPUTS
        None. Output is written to the Information stream.
    .EXAMPLE
        Set-PageFileSize -ComputerName "Server01.domain.local"
    .EXAMPLE
        Set-PageFileSize -ComputerName "Server01.domain.local" -InitialSize 4096 -MaximumSize 8192 -Path "C:\pagefile.sys"
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][int]$InitialSize,
        [Parameter()][int]$MaximumSize,
        [Parameter()][string]$Path
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $pfCfg = $cfg["settings"]["pagefile"]

    # Defaults from config
    if (-not $Path) { $Path = $pfCfg["defaultPath"] }
    $minSize = $pfCfg["minSizeMB"]
    $maxSize = $pfCfg["maxSizeMB"]

    # Prompt for sizes locally before remoting
    if (-not $InitialSize) {
        $InitialSize = Read-Int -Prompt "Enter initial pagefile size (MB)" -Min $minSize -Max $maxSize
    }

    if (-not $MaximumSize) {
        $MaximumSize = Read-Int -Prompt "Enter maximum pagefile size (MB)" -Min $InitialSize -Max $maxSize
    }

    # Credential prompting based on config
    $creds = $null
    if ($cfg["settings"]["defaults"]["promptForCredentials"]) {
        $creds = Get-Credential -Message "Enter credentials for $ComputerName"
    }

    Write-Log -Level Info -Message "Connecting to $ComputerName..."

    # Kerberos/Negotiate only
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $creds
        Write-Log -Level Ok -Message "Connected to $ComputerName."
    }
    catch {
        Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
        return
    }

    Write-Log -Level Info -Message "Applying pagefile settings on $ComputerName..."

    # Remote scriptblock — runs entirely on the target machine
    $result = Invoke-Command -Session $session -ScriptBlock {
        param($Path, $InitialSize, $MaximumSize)

        try {
            $computersys = Get-CimInstance Win32_ComputerSystem
            if ($computersys.AutomaticManagedPagefile) {
                $computersys | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false } | Out-Null
            }

            $pagefile = Get-CimInstance Win32_PageFileSetting -Filter "Name='$Path'"

            if (-not $pagefile) {
                New-CimInstance Win32_PageFileSetting -Property @{
                    Name        = $Path
                    InitialSize = $InitialSize
                    MaximumSize = $MaximumSize
                } | Out-Null
            }
            else {
                $pagefile | Set-CimInstance -Property @{
                    InitialSize = $InitialSize
                    MaximumSize = $MaximumSize
                } | Out-Null
            }

            return @{
                Success = $true
                Message = "Pagefile updated: $Path (Initial=$InitialSize MB, Max=$MaximumSize MB)"
            }
        }
        catch {
            return @{
                Success = $false
                Message = $_.Exception.Message
            }
        }

    } -ArgumentList $Path, $InitialSize, $MaximumSize

    Remove-PSSession $session

    # Handle result
    if ($result.Success) {
        Write-Log -Level Ok -Message $result.Message
    }
    else {
        Write-Log -Level Error -Message "Remote failure: $($result.Message)"
        return
    }

    # Reboot prompt
    $resp = Read-Host "Reboot $ComputerName now? (y/n)"
    if ($resp -match '^(y|yes)$') {
        Write-Log -Level Info -Message "Rebooting $ComputerName..."
        Restart-Computer -ComputerName $ComputerName -Force -Credential $creds
    }
    else {
        Write-Log -Level Warn -Message "Reboot later to apply changes."
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Set-ProxyAddress.ps1
`powershell

function Set-ProxyAddress {
    <#
    .SYNOPSIS
    Sets the primary SMTP proxy address for an Active Directory user.

    .DESCRIPTION
    This function sets the primary SMTP proxy address for a specified Active
    Directory user. It ensures that the new primary address is added correctly
    and removes any existing primary SMTP addresses.

    .PARAMETER Username
    The username (sAMAccountName) of the Active Directory user.

    .PARAMETER ProxyAddress
    The new primary SMTP proxy address to set (e.g., user@example.com).

    .INPUTS
        None. You cannot pipe objects to Set-ProxyAddress.

    .OUTPUTS
        None. Output is written to the Information stream.

    .EXAMPLE
    Set-ProxyAddress -Username "jdoe" -ProxyAddress "jdoe@example.com"

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')][string]$ProxyAddress
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "The ActiveDirectory module is required to run this script. $_"
        return
    }
    $PrimarySMTP = "SMTP:$ProxyAddress"
    try {
        Set-ADUser -Identity $Username -Add @{ proxyAddresses = $PrimarySMTP } -ErrorAction Stop
        Write-Host "Primary SMTP address '$PrimarySMTP' added to user '$Username'."
    }
    catch {
        Write-Error "Failed to add primary SMTP address '$PrimarySMTP' to user '$Username'. Error: $($_.Exception.Message)"
    }
    $user = Get-ADUser -Identity $Username -Properties proxyAddresses
    $existingProxyAddresses = @()
    if ($user.proxyAddresses) {
        $existingProxyAddresses = @($user.proxyAddresses)
    }

    # Remove any existing primary SMTP entries and any duplicates of the new primary address (case-insensitive)
    $filteredProxyAddresses = $existingProxyAddresses | Where-Object {
        ($_ -notlike 'SMTP:*') -and
        ($_.ToLower() -ne $PrimarySMTP.ToLower())
    }

    # Add the new primary SMTP address
    $updatedProxyAddresses = $filteredProxyAddresses + $PrimarySMTP

    # Replace proxyAddresses to ensure there is a single, correct primary SMTP value
    Set-ADUser -Identity $Username -Replace @{ proxyAddresses = $updatedProxyAddresses }
    Write-Host "Primary SMTP address '$PrimarySMTP' set for user '$Username'."
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-DnsQueryLogger.ps1
`powershell

function Start-DnsQueryLogger {
    <#
    .SYNOPSIS
        Starts real-time DNS query logging using the Windows DNS debug log.
    .DESCRIPTION
        This cmdlet starts logging DNS queries by enabling the Windows DNS debug log.
        It reads configuration settings from the TechToolbox config.json file to
        determine if DNS logging is enabled, the log file path, and parsing mode.
        If logging is enabled, it ensures the log directory exists and starts the
        DNS query logger.
    
    .INPUTS
        None. You cannot pipe objects to Start-DnsQueryLogger.

    .OUTPUTS
        None. Output is written to the Information stream.

    .EXAMPLE
        Start-DnsQueryLogger
        Starts the DNS query logger based on the configuration settings.

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param()

    # Load config
    $cfg = $script:TechToolboxConfig
    $dnsCfg = $cfg["settings"]["dnsLogging"]

    if (-not $dnsCfg["enabled"]) {
        Write-Log -Level Warn -Message "DNS logging disabled in config.json"
        return
    }

    $logDir = $dnsCfg["logPath"]
    $parseMode = $dnsCfg["parseMode"]

    # Ensure directory exists
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    Write-Log -Level Info -Message "Starting DNS query logger. Output: $dnsLog"

    # Call private worker
    Start-DnsQueryLoggerWorker -OutputPath $dnsLog
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Start-PDQDiagLocalElevated.ps1
`powershell
function Start-PDQDiagLocalElevated {
    <#
    .SYNOPSIS
      Open a new elevated PowerShell console (UAC), then run the local PDQ diag
      under SYSTEM.
    
    .DESCRIPTION
      - Spawns a new console with RunAs (UAC prompt).
      - In that console: Import-Module TechToolbox, call private
        Start-PDQDiagLocalSystem.
      - Captures full transcript to C:\PDQDiagLogs\LocalRun_<timestamp>.log.
      - On error, writes detailed info and optionally pauses so you can read it.
    
    .PARAMETER LocalDropPath
      Destination folder for the final ZIP. Default: C:\PDQDiagLogs
    
    .PARAMETER ExtraPaths
      Additional files/folders to include.
    
    .PARAMETER ConnectDataPath
      Root for PDQ Connect agent data. Default:
      "$env:ProgramData\PDQ\PDQConnectAgent"
    
    .PARAMETER StayOpen
      Keep the elevated console open after it finishes (adds -NoExit and a prompt).
    
    .PARAMETER ForcePwsh
      Prefer pwsh.exe explicitly; otherwise auto-detect pwsh then powershell.
    
    .EXAMPLE
      Start-PDQDiagLocalElevated -StayOpen
    
    .EXAMPLE
      Start-PDQDiagLocalElevated -ExtraPaths 'C:\Temp\PDQ','D:\Logs\PDQ'
    #>
    [CmdletBinding()]
    param(
        [string]  $LocalDropPath = 'C:\PDQDiagLogs',
        [string[]]$ExtraPaths,
        [string]  $ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),
        [switch]  $StayOpen,
        [switch]  $ForcePwsh
    )

    # Resolve the module path (ensure the elevated console imports the same module)
    $module = Get-Module -Name TechToolbox -ListAvailable | Select-Object -First 1
    if (-not $module) { throw "TechToolbox module not found in PSModulePath." }
    $modulePath = $module.Path

    # Ensure local drop path exists (used for transcript and final ZIP)
    if (-not (Test-Path -LiteralPath $LocalDropPath)) {
        New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
    }

    # Pre-compute timestamp so both runner + private use the same naming (optional/consistent)
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $finalZip = Join-Path $LocalDropPath ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $timestamp)
    $logPath = Join-Path $LocalDropPath ("LocalRun_{0}.log" -f $timestamp)

    # Safely render ExtraPaths as a PowerShell literal
    $extraLiteral = if ($ExtraPaths) {
        $escaped = $ExtraPaths | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }
        "@(" + ($escaped -join ',') + ")"
    }
    else { '@()' }

    # Build the runner script content that will execute in the elevated console
    $runnerLines = @()
    $runnerLines += '$ErrorActionPreference = "Continue"'
    $runnerLines += '$VerbosePreference = "Continue"'
    $runnerLines += "if (-not (Test-Path -LiteralPath `"$LocalDropPath`")) { New-Item -ItemType Directory -Path `"$LocalDropPath`" -Force | Out-Null }"
    $runnerLines += "Start-Transcript -Path `"$logPath`" -IncludeInvocationHeader -Force | Out-Null"
    $runnerLines += "`$modulePath = `"$modulePath`""
    $runnerLines += 'Import-Module $modulePath -Force'
    $runnerLines += ""
    $runnerLines += "Write-Host ('[LOCAL] Running Start-PDQDiagLocalSystem (SYSTEM)...') -ForegroundColor Cyan"
    $runnerLines += "try {"
    $runnerLines += "    Start-PDQDiagLocalSystem -LocalDropPath `"$LocalDropPath`" -ConnectDataPath `"$ConnectDataPath`" -ExtraPaths $extraLiteral -Timestamp `"$timestamp`" | Format-List *"
    $runnerLines += "    Write-Host ('[LOCAL] Expected ZIP: $finalZip') -ForegroundColor Green"
    $runnerLines += "} catch {"
    $runnerLines += "    Write-Host ('[ERROR] ' + `$_.Exception.Message) -ForegroundColor Red"
    $runnerLines += "    if (`$Error.Count -gt 0) {"
    $runnerLines += "        Write-Host '--- $Error[0] (detailed) ---' -ForegroundColor Yellow"
    $runnerLines += "        `$Error[0] | Format-List * -Force"
    $runnerLines += "    }"
    $runnerLines += "    throw"
    $runnerLines += "} finally {"
    $runnerLines += "    Stop-Transcript | Out-Null"
    $runnerLines += "}"
    if ($StayOpen) {
        # Keep the elevated console open so you can review logs/output
        $runnerLines += "Write-Host 'Transcript saved to: $logPath' -ForegroundColor Yellow"
        $runnerLines += "Read-Host 'Press Enter to close this elevated window'"
    }

    $runnerScript = Join-Path $env:TEMP ("PDQDiag_LocalElevated_{0}.ps1" -f $timestamp)
    Set-Content -Path $runnerScript -Value ($runnerLines -join [Environment]::NewLine) -Encoding UTF8

    # Pick host exe (pwsh preferred if available or forced; else Windows PowerShell)
    $hostExe = $null
    if ($ForcePwsh) {
        $hostExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue)?.Source
        if (-not $hostExe) { throw "ForcePwsh requested, but pwsh.exe not found." }
    }
    else {
        $hostExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue)?.Source
        if (-not $hostExe) { $hostExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue)?.Source }
    }
    if (-not $hostExe) { throw "Neither pwsh.exe nor powershell.exe found on PATH." }

    $prelude = '$env:TT_ExportLocalHelper="1";'
    $args = @()
    if ($StayOpen) { $args += '-NoExit' }
    $args = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $prelude + " & `"$runnerScript`"")

    # Launch elevated; parent console stays open
    Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $args -WindowStyle Normal | Out-Null

    # Emit a quick hint in the parent console
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'Launched'
        ZipExpected  = $finalZip
        Transcript   = $logPath
        Notes        = "Elevated console opened. Output + errors captured to transcript. Use -StayOpen to keep the window open."
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Clear-BrowserProfileData.ps1
`powershell
function Clear-BrowserProfileData {
    <#
    .SYNOPSIS
        Clears cache, cookies, and optional local storage for Chrome/Edge
        profiles.
    .DESCRIPTION
        Stops browser processes (optional), discovers Chromium profile folders,
        and clears cache/cookies/local storage per switches. Logging is
        centralized via Write-Log.
    .PARAMETER Browser
        Chrome, Edge, or All. Default: All.
    .PARAMETER Profiles
        One or more profile names to target (e.g., 'Default','Profile 1'). If
        omitted, all known profiles.
    .PARAMETER IncludeCookies
        Clears cookie databases. Default: $true
    .PARAMETER IncludeCache
        Clears browser cache folders. Default: $true
    .PARAMETER SkipLocalStorage
        Skips clearing 'Local Storage' content when $true. Default: $false
    .PARAMETER KillProcesses
        Attempts to stop browser processes before deletion. Default: $true
    .PARAMETER SleepAfterKillMs
        Milliseconds to wait after killing processes. Default: 1500
    .INPUTS
        None. You cannot pipe objects to Clear-BrowserProfileData.
    .OUTPUTS
        [PSCustomObject] with properties:
            Browser             - The browser processed (Chrome/Edge)
            Profile             - The profile name processed
            CacheCleared        - $true if cache was cleared
            CookiesCleared      - $true if cookies were cleared
            LocalStorageCleared - $true if local storage was cleared
            Timestamp           - DateTime of operation
    .EXAMPLE
        Clear-BrowserProfileData -Browser Chrome -Profiles 'Default','Profile 2' -WhatIf
    .EXAMPLE
        Clear-BrowserProfileData -Browser All -IncludeCache:$true -IncludeCookies:$false -Confirm
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidateSet('Chrome', 'Edge', 'All')]
        [string]$Browser = 'All',

        [string[]]$Profiles,

        [bool]$IncludeCookies = $true,
        [bool]$IncludeCache = $true,
        [bool]$SkipLocalStorage = $false,

        [bool]$KillProcesses = $true,
        [int]  $SleepAfterKillMs = 1500
    )

    begin {
        # --- Config & Defaults ---
        $cfg = Get-TechToolboxConfig

        # Resolve settings.browserCleanup safely (works for hashtables or PSCustomObjects)
        $bc = @{}
        if ($cfg) {
            $settings = $cfg['settings']
            if ($null -eq $settings) { $settings = $cfg.settings }
            if ($settings) {
                $bc = $settings['browserCleanup']
                if ($null -eq $bc) { $bc = $settings.browserCleanup }
            }
            if ($null -eq $bc) { $bc = @{} }
        }

        # Apply config-driven defaults only when the parameter wasn't provided
        if (-not $PSBoundParameters.ContainsKey('IncludeCache') -and $bc.ContainsKey('includeCache')) { $IncludeCache = [bool]$bc['includeCache'] }
        if (-not $PSBoundParameters.ContainsKey('IncludeCookies') -and $bc.ContainsKey('includeCookies')) { $IncludeCookies = [bool]$bc['includeCookies'] }
        if (-not $PSBoundParameters.ContainsKey('SkipLocalStorage') -and $bc.ContainsKey('skipLocalStorage')) { $SkipLocalStorage = [bool]$bc['skipLocalStorage'] }
        if (-not $PSBoundParameters.ContainsKey('KillProcesses') -and $bc.ContainsKey('killProcesses')) { $KillProcesses = [bool]$bc['killProcesses'] }
        if (-not $PSBoundParameters.ContainsKey('SleepAfterKillMs') -and $bc.ContainsKey('sleepAfterKillMs')) { $SleepAfterKillMs = [int] $bc['sleepAfterKillMs'] }

        # Browser (string default)
        if (-not $PSBoundParameters.ContainsKey('Browser') -and [string]::IsNullOrWhiteSpace($Browser)) {
            if ($bc.ContainsKey('defaultBrowser') -and $bc['defaultBrowser']) {
                $Browser = [string]$bc['defaultBrowser']
            }
        }

        # Profiles (array or string)
        if (-not $PSBoundParameters.ContainsKey('Profiles') -and $bc.ContainsKey('defaultProfiles') -and $null -ne $bc['defaultProfiles']) {
            $dp = $bc['defaultProfiles']
            $Profiles = @(
                if ($dp -is [System.Collections.IEnumerable] -and -not ($dp -is [string])) { $dp }
                else { "$dp" }
            )
        }

        # Metadata per browser
        $BrowserMeta = @{
            Chrome = @{ ProcessName = 'chrome'; DisplayName = 'Google Chrome' }
            Edge   = @{ ProcessName = 'msedge'; DisplayName = 'Microsoft Edge' }
        }
    }

    process {
        $targetBrowsers = switch ($Browser) {
            'Chrome' { @('Chrome') }
            'Edge' { @('Edge') }
            'All' { @('Chrome', 'Edge') }
        }

        if ($WhatIfPreference) {
            Write-Information "=== DRY RUN SUMMARY ==="
            Write-Information ("Browsers: {0}" -f ($targetBrowsers -join ', '))
            Write-Information "Include Cache: $IncludeCache"
            Write-Information "Include Cookies: $IncludeCookies"
            Write-Information "Skip Local Storage: $SkipLocalStorage"
            Write-Information "Kill Processes: $KillProcesses"
            Write-Information ("Profiles filter: {0}" -f (($Profiles ?? @()) -join ', '))
            Write-Information "======================="
        }

        foreach ($b in $targetBrowsers) {
            Write-Log -Level Info -Message "=== Processing $b ==="

            $browserName = $BrowserMeta[$b].DisplayName
            $processName = $BrowserMeta[$b].ProcessName

            # Optional: stop processes
            if ($KillProcesses) {
                if ($PSCmdlet.ShouldProcess("$browserName ($processName)", "Stop processes")) {
                    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds $SleepAfterKillMs
                }
            }

            $userData = Get-BrowserUserDataPath -Browser $b
            $profileDirs = @(Get-BrowserProfileFolders -UserDataPath $userData)  # ensure array

            if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                Write-Log -Level Warn -Message "No profiles found for $b at '$userData'."
                continue
            }

            Write-Log -Level Info -Message ("Discovered profiles: {0}" -f ($profileDirs.Name -join ', '))

            # Optional filter by provided profile names
            if ($Profiles) {
                $profileDirs = @($profileDirs | Where-Object { $Profiles -contains $_.Name })
                Write-Log -Level Info -Message ("Filtered profiles: {0}" -f ($profileDirs.Name -join ', '))
                if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                    Write-Log -Level Warn -Message "No profiles remain after filtering. Skipping $b."
                    continue
                }
            }

            foreach ($prof in $profileDirs) {
                # Support DirectoryInfo or string
                $profileName = try { $prof.Name } catch { Split-Path -Path $prof -Leaf }
                $profilePath = try { $prof.FullName } catch { [string]$prof }

                Write-Log -Level Info -Message "Profile: '$profileName' ($profilePath)"

                # Cookies & Local Storage
                if ($IncludeCookies) {
                    $cookieStatus = Clear-CookiesForProfile -ProfilePath $profilePath -SkipLocalStorage:$SkipLocalStorage
                    # (No output—driver consumes status silently; use $cookieStatus for debug if needed)
                }
                else {
                    Write-Log -Level Info -Message "Cookies deletion skipped by configuration."
                }

                # Cache
                if ($IncludeCache) {
                    # If your cache helper returns status, capture silently to avoid tables
                    $cacheStatus = Clear-CacheForProfile -ProfilePath $profilePath
                    # Or: $null = Clear-CacheForProfile -ProfilePath $profilePath
                }
                else {
                    Write-Log -Level Info -Message "Cache deletion skipped by configuration."
                }

                Write-Log -Level Ok -Message "Finished: $profileName"
            }

            Write-Log -Level Ok -Message "=== Completed $b ==="
        }

        # No PSCustomObject results returned
        return
    }

    end {
        Write-Log -Level Ok -Message "All requested browser profile cleanup completed."
    }
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Copy-Directory.ps1
`powershell
function Copy-Directory {
    <#
    .SYNOPSIS
        Copies a directory to another directory using Robocopy.
    .DESCRIPTION
        Supports local or remote execution via PowerShell Remoting. Uses
        config-driven defaults for logging, flags, retries, and mirror behavior.
    .PARAMETER Source
        The source directory to copy.
    .PARAMETER DestinationRoot
        The root destination directory where the source folder will be copied.
        The final destination will be DestinationRoot\SourceFolderName.
    .PARAMETER ComputerName
        The name of the remote computer to perform the copy on. If omitted, the
        copy is performed locally unless -Local is specified.
    .PARAMETER Local
        Switch to force local execution of the copy.
    .PARAMETER Mirror
        Switch to enable mirror mode (/MIR) for the copy, which deletes files in
        the destination that no longer exist in the source.
    .PARAMETER Credential
        Optional PSCredential to use for remote connections.
    .INPUTS
        None. You cannot pipe objects to Copy-Directory.
    .OUTPUTS
        The final destination path where the directory was copied.
    .EXAMPLE
        Copy-Directory -Source "C:\Data\FolderA" -DestinationRoot "D:\Backup"
        Copies FolderA to D:\Backup\FolderA locally.
    .EXAMPLE
        Copy-Directory -Source "C:\Data\FolderA" -DestinationRoot "D:\Backup" -ComputerName "Server01"
        Copies FolderA to D:\Backup\FolderA on the remote computer Server01.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Local,

        [Parameter()]
        [switch]$Mirror,

        [Parameter()]
        [pscredential]$Credential
    )

    # --- Config ---
    $cfg = Get-TechToolboxConfig
    $settings = $cfg["settings"]
    $copy = $settings["copyDirectory"]

    $runRemote = $copy["runRemote"] ?? $true
    $defaultComp = $copy["defaultComputerName"]
    $logDir = $copy["logDir"] ?? "C:\LogsAndExports\TechToolbox\Logs\Robocopy"
    $retryCount = $copy["retryCount"] ?? 2
    $waitSeconds = $copy["waitSeconds"] ?? 5
    $copyFlags = $copy["copyFlags"] ?? @("/E", "/COPYALL")
    $mirrorCfg = $copy["mirror"] ?? $false

    # Effective mirror mode (param overrides config)
    $mirrorEffective = if ($Mirror.IsPresent) { $true } else { [bool]$mirrorCfg }

    if ($mirrorEffective) {
        # /MIR implies /E + purge; ignore configured copyFlags when mirroring
        $copyFlags = @("/MIR", "/COPYALL")
    }

    # Ensure log directory exists (local)
    if (-not (Test-Path -Path $logDir -PathType Container)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Derive folder name & destination
    $folderName = Split-Path -Path $Source -Leaf
    $destination = Join-Path -Path $DestinationRoot -AdditionalChildPath $folderName

    # Log file (local path; may be on remote share if desired)
    $logFile = Join-Path -Path $logDir -AdditionalChildPath ("{0}-robocopy.log" -f $folderName)

    Write-Log -Level Info -Message "Preparing to copy directory..."
    Write-Log -Level Info -Message (" Source: {0}" -f $Source)
    Write-Log -Level Info -Message (" Destination root: {0}" -f $DestinationRoot)
    Write-Log -Level Info -Message (" Effective destination: {0}" -f $destination)
    Write-Log -Level Info -Message (" Log file: {0}" -f $logFile)

    if ($mirrorEffective) {
        Write-Log -Level Warn -Message "MIRROR MODE ENABLED: destination deletions will occur to match source (/MIR)."
    }

    # Decide local vs remote
    $targetComputer = $ComputerName
    if (-not $Local) {
        if (-not $targetComputer -and $defaultComp) {
            $targetComputer = $defaultComp
        }
    }

    $runRemoteEffective =
    -not $Local -and
    -not [string]::IsNullOrWhiteSpace($targetComputer) -and
    $runRemote

    $targetDescription = if ($runRemoteEffective) {
        "{0} (remote on {1})" -f $destination, $targetComputer
    }
    else {
        "{0} (local)" -f $destination
    }

    if ($mirrorEffective) {
        $targetDescription = "$targetDescription [MIRROR: deletions may occur]"
    }

    if ($PSCmdlet.ShouldProcess($targetDescription, "Copy directory via Robocopy")) {

        if ($runRemoteEffective) {
            Write-Log -Level Info -Message (" Executing Robocopy remotely on [{0}]." -f $targetComputer)

            Start-RobocopyRemote `
                -Source $Source `
                -Destination $destination `
                -LogFile $logFile `
                -RetryCount $retryCount `
                -WaitSeconds $waitSeconds `
                -CopyFlags $copyFlags `
                -ComputerName $targetComputer `
                -Credential $Credential
        }
        else {
            Write-Log -Level Info -Message " Executing Robocopy locally."

            Start-RobocopyLocal `
                -Source $Source `
                -Destination $destination `
                -LogFile $logFile `
                -RetryCount $retryCount `
                -WaitSeconds $waitSeconds `
                -CopyFlags $copyFlags `
                -Credential $Credential
        }

        Write-Log -Level Ok -Message ("Copy completed for folder '{0}'." -f $folderName)
    }

    return $destination
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Find-LargeFiles.ps1
`powershell

function Find-LargeFiles {
    <#
    .SYNOPSIS
    Finds large files recursively and (optionally) exports results to CSV.

    .DESCRIPTION
    Searches under one or more directories for files larger than a minimum size.
    Paths can be provided by parameter, config
    (settings.largeFileSearch.defaultSearchDirectory), or prompt. If -Export is
    specified, results are saved to CSV in the configured export directory
    (settings.largeFileSearch.exportDirectory) or a path you provide.

    .PARAMETER SearchDirectory
    One or more root directories to search. If omitted, will use config or
    prompt.

    .PARAMETER MinSizeMB
    Minimum size threshold in MB. If omitted, will use config
    (settings.largeFileSearch.defaultMinSizeMB) or default of 256.

    .PARAMETER Depth
    Optional maximum recursion depth (PowerShell 7+ only).

    .PARAMETER Export
    When present, exports results to CSV.

    .PARAMETER ExportDirectory
    Override the export directory (otherwise uses
    settings.largeFileSearch.exportDirectory).

    .PARAMETER CsvDelimiter
    Optional CSV delimiter (default ',').

    .EXAMPLE
    Find-LargeFiles -SearchDirectory 'C:\','D:\Shares' -MinSizeMB 512 -Export -Verbose

    .EXAMPLE
    Find-LargeFiles -Export  # uses config search dirs (or prompts) and exports to config exportDirectory

    .NOTES
    Outputs PSCustomObject with FullName and SizeMB. Also writes CSV when
    -Export is used.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] $SearchDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $MinSizeMB,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $Depth,

        [Parameter(Mandatory = $false)]
        [switch] $Export,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $ExportDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $CsvDelimiter = ','
    )

    begin {
        # Helper: Try to use module's Get-TechToolboxConfig; if not found, fallback to local file.
        function _Get-Config {
            $cmd = Get-Command -Name 'Get-TechToolboxConfig' -ErrorAction SilentlyContinue
            if ($cmd) {
                try { return Get-TechToolboxConfig } catch { Write-Verbose "Get-TechToolboxConfig failed: $($_.Exception.Message)" }
            }
            $defaultPath = 'C:\TechToolbox\Config\config.json'
            if (Test-Path -LiteralPath $defaultPath) {
                try {
                    return Get-Content -LiteralPath $defaultPath -Raw | ConvertFrom-Json -ErrorAction Stop
                }
                catch { Write-Verbose "Failed to parse config.json at ${defaultPath}: $($_.Exception.Message)" }
            }
            return $null
        }

        $cfg = _Get-Config

        # Resolve MinSizeMB: param > config > default (256)
        if (-not $PSBoundParameters.ContainsKey('MinSizeMB')) {
            $MinSizeMB = if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['defaultMinSizeMB']) {
                [int]$cfg['settings']['largeFileSearch']['defaultMinSizeMB']
            }
            else {
                256
            }
        }

        # Resolve SearchDirectory: param > config > prompt
        if (-not $SearchDirectory -or $SearchDirectory.Count -eq 0) {
            $fromCfg = @()
            if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['defaultSearchDirectory']) {
                if ($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] -is [string]) {
                    $fromCfg = @($cfg['settings']['largeFileSearch']['defaultSearchDirectory'])
                }
                elseif ($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] -is [System.Collections.IEnumerable]) {
                    $fromCfg = @($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] | ForEach-Object { $_ })
                }
            }
            if ($fromCfg.Count -gt 0) {
                $SearchDirectory = $fromCfg
                Write-Verbose "Using search directories from config: $($SearchDirectory -join '; ')"
            }
            else {
                $inputPath = Read-Host "Enter directories to search (use ';' to separate multiple)"
                $SearchDirectory = $inputPath -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
        }

        # Normalize and validate directories
        $SearchDirectory = $SearchDirectory |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
        ForEach-Object {
            if (-not (Test-Path -LiteralPath $_)) {
                Write-Warning "Path not found: $_ (skipping)"
                $null
            }
            else { $_ }
        } | Where-Object { $_ }

        if (-not $SearchDirectory -or $SearchDirectory.Count -eq 0) {
            throw "No valid search directories were provided."
        }

        $minBytes = [int64]$MinSizeMB * 1MB

        # Resolve ExportDirectory if -Export is used and no override is provided.
        if ($Export -and -not $PSBoundParameters.ContainsKey('ExportDirectory')) {
            if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['exportDirectory']) {
                $ExportDirectory = [string]$cfg['settings']['largeFileSearch']['exportDirectory']
                Write-Verbose "Using export directory from config: $ExportDirectory"
            }
            else {
                throw "Export requested, but 'settings.largeFileSearch.exportDirectory' was not found in config and no -ExportDirectory was provided."
            }
        }

        # Ensure export directory exists if we will export
        if ($Export) {
            try {
                $null = New-Item -ItemType Directory -Path $ExportDirectory -Force -ErrorAction Stop
            }
            catch {
                throw "Failed to ensure export directory '$ExportDirectory': $($_.Exception.Message)"
            }
        }

        # Build output list
        $results = New-Object System.Collections.Generic.List[object]
    }

    process {
        $totalRoots = $SearchDirectory.Count
        $rootIndex = 0

        foreach ($root in $SearchDirectory) {
            $rootIndex++
            Write-Verbose "Scanning $root ($rootIndex of $totalRoots) …"

            try {
                $gciParams = @{
                    Path        = $root
                    File        = $true
                    Recurse     = $true
                    ErrorAction = 'SilentlyContinue'
                    Force       = $true
                }
                if ($PSBoundParameters.ContainsKey('Depth')) {
                    # PowerShell 7+ supports -Depth on Get-ChildItem
                    $gciParams['Depth'] = $Depth
                }

                $count = 0
                Get-ChildItem @gciParams |
                Where-Object { $_.Length -ge $minBytes } |
                Sort-Object Length -Descending |
                ForEach-Object {
                    $count++
                    if ($PSBoundParameters.Verbose) {
                        # Lightweight progress when -Verbose is on
                        Write-Progress -Activity "Scanning $root" -Status "Found $count large files…" -PercentComplete -1
                    }

                    [PSCustomObject]@{
                        FullName = $_.FullName
                        SizeMB   = [math]::Round(($_.Length / 1MB), 2)
                    }
                } | ForEach-Object { [void]$results.Add($_) }

                if ($PSBoundParameters.Verbose) {
                    Write-Progress -Activity "Scanning $root" -Completed
                }
            }
            catch {
                Write-Warning "Error scanning '$root': $($_.Exception.Message)"
            }
        }
    }

    end {
        # Emit combined, globally sorted output to pipeline
        $sorted = $results | Sort-Object SizeMB -Descending
        $sorted

        if ($Export) {
            # Determine filename
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $defaultName = "LargeFiles_${timestamp}.csv"

            $fileName = $defaultName
            if ($cfg -and $cfg.settings -and $cfg.settings.largeFileSearch -and $cfg.settings.largeFileSearch.exportFileNamePattern) {
                $pattern = [string]$cfg.settings.largeFileSearch.exportFileNamePattern
                # Simple token replacement for {yyyyMMdd_HHmmss}
                $fileName = $pattern -replace '\{yyyyMMdd_HHmmss\}', $timestamp
                if ([string]::IsNullOrWhiteSpace($fileName)) { $fileName = $defaultName }
            }

            $exportPath = Join-Path -Path $ExportDirectory -ChildPath $fileName

            try {
                $sorted | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8 -Delimiter $CsvDelimiter -Force
                Write-Host "Exported $($sorted.Count) items to: $exportPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to export CSV to '$exportPath': $($_.Exception.Message)"
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-TTWordList.ps1
`powershell

function Initialize-TTWordList {
    [CmdletBinding()]
    param(
        [string]$Path = 'C:\TechToolbox\Config\wordlist.txt',
        [switch]$NoAmbiguous
    )

    # Curated starter list (add to this as you like)
    $words = @'
river
stone
blue
green
tiger
forest
echo
delta
nova
ember
maple
cedar
birch
pine
spruce
willow
aspen
elm
fir
hemlock
oak
silver
shadow
crimson
cobalt
onyx
raven
falcon
otter
fox
wolf
lynx
badger
eagle
harbor
summit
meadow
prairie
canyon
valley
spring
autumn
winter
summer
breeze
cloud
storm
thunder
rain
snow
frost
glacier
aurora
comet
meteor
orbit
quartz
granite
basalt
pebble
coral
reef
tide
lagoon
moss
fern
copper
iron
nickel
zinc
amber
topaz
agate
jade
opal
pearl
sapphire
ruby
garnet
swift
brisk
rapid
steady
bold
bright
quiet
gentle
keen
vivid
lively
nimble
solid
lofty
noble
true
prime
vantage
zenith
apex
vertex
vector
gamma
omega
alpha
sigma
photon
quark
ion
pixel
matrix
cipher
beacon
signal
kernel
crypto
evergreen
lake
riverbank
brook
cove
grove
ridge
peak
hollow
dawn
dusk
ember
flare
spark
glow
blaze
shade
marble
slate
shale
granule
opaline
auric
argent
bronze
brass
steel
carbon
graphite
neon
argon
radon
xenon
sonic
echoes
north
south
east
west
midway
frontier
praxis
nimbus
cirrus
stratus
cumulus
zephyr
current
eddy
vortex
ripple
cascade
deltaic
arbor
thicket
bramble
meander
vernal
solstice
equinox
tundra
taiga
sierra
mesa
butte
cairn
grottos
harvest
emberly
solace
tranquil
serene
poise
steadfast
anchor
keystone
waypoint
signal
beacon
lumen
prism
spectra
radian
vector
scalar
tensor
axial
normal
median
summitry
'@ -split "`n"

    $clean = $words |
    ForEach-Object { $_.Trim().ToLowerInvariant() } |
    Where-Object { $_ -match '^[a-z]{3,10}$' } |
    Select-Object -Unique

    if ($NoAmbiguous) {
        $clean = $clean | Where-Object { $_ -notmatch '[ilo]' }
    }

    $clean | Sort-Object | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Host "Word list written: $Path (`$NoAmbiguous=$NoAmbiguous)"
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Remove-Printers.ps1
`powershell

function Remove-Printers {
    <#
    .SYNOPSIS
        Removes all printers from the system, with optional removal of ports,
        drivers, and per-user mappings.
    .DESCRIPTION
        Uses Win32_Printer (CIM) to remove queues after resetting the spooler
        and clearing the spool folder. Optionally removes TCP/IP ports and
        printer drivers. Adds fallbacks for provider hiccups and frees common
        process locks (splwow64/PrintIsolationHost). Can also remove per-user
        connections across all profiles.
    .PARAMETER IncludePorts
        Also remove TCP/IP printer ports (non-standard).
    .PARAMETER IncludeDrivers
        Also remove printer drivers (after queues are gone).
    .PARAMETER Force
        Best-effort forced cleanup of driver packages via pnputil if standard
        removal fails.
    .PARAMETER AllUsers
        Attempt to remove per-user network printer connections for all user
        profiles.
    .PARAMETER PassThru
        Output a summary object with counts and failures.
    .EXAMPLE
        Remove-Printers -IncludePorts -IncludeDrivers -Force -AllUsers -PassThru
    .EXAMPLE
        Remove-Printers -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch] $IncludePorts,
        [switch] $IncludeDrivers,
        [switch] $Force,
        [switch] $AllUsers,
        [switch] $PassThru
    )

    $cfg = Get-TechToolboxConfig
    $defs = $cfg.defaults
    $log = $cfg.logging
    $paths = $cfg.paths

    # Counters
    $removedPrinters = 0; $failedPrinters = @()
    $removedPorts = 0; $failedPorts = @()
    $removedDrivers = 0; $failedDrivers = @()
    $removedUserMaps = 0; $failedUserMaps = @()

    Begin {
        Write-Log -Level Info -Message "=== Remove-Printers started ==="
    }

    Process {
        # Track original spooler state
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $spoolerWasRunning = $false
        if ($spooler) { $spoolerWasRunning = $spooler.Status -eq 'Running' }

        # 1) Stop spooler and clear jobs
        if ($PSCmdlet.ShouldProcess("Spooler", "Stop and clear PRINTERS folder")) {
            Write-Log -Level Info -Message "Stopping Print Spooler..."
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

            $spoolPath = Join-Path $env:WINDIR 'System32\spool\PRINTERS'
            if (Test-Path $spoolPath) {
                Write-Log -Level Info -Message "Clearing spool folder: $spoolPath"
                Get-ChildItem -Path $spoolPath -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            }

            Write-Log -Level Info -Message "Starting Print Spooler..."
            Start-Service -Name Spooler -ErrorAction SilentlyContinue
        }

        # (Optional) Remove per-user connections for all profiles
        if ($AllUsers) {
            Write-Log -Level Info -Message "Removing per-user network printer connections for all profiles..."
            # Enumerate mounted + offline hives under HKEY_USERS
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' } |
            ForEach-Object { $_.PSChildName }

            foreach ($sid in $userSids) {
                $connKey = "Registry::HKEY_USERS\$sid\Printers\Connections"
                if (Test-Path $connKey) {
                    Get-ChildItem $connKey -ErrorAction SilentlyContinue | ForEach-Object {
                        # Value names typically look like ,Server,Queue (commas)
                        $raw = $_.PSChildName.Trim()
                        # Normalize to \\server\queue if possible
                        $serverQueue = $raw -replace '^,', '' -replace ',', '\'
                        if ($serverQueue -notmatch '^\\\\') { $serverQueue = "\\$serverQueue" }
                        if ($PSCmdlet.ShouldProcess("User:${sid} Mapping '$serverQueue'", "Disconnect")) {
                            try {
                                # Current process context removes only for current user,
                                # so we invoke PrintUIEntry targeting the path (best-effort).
                                rundll32 printui.dll, PrintUIEntry /dn /q /n "$serverQueue"
                                $removedUserMaps++
                                Write-Log -Level Info -Message "  - Disconnected $serverQueue for ${sid}"
                            }
                            catch {
                                $failedUserMaps += $serverQueue
                                Write-Log -Level Warn -Message "    Failed to disconnect $serverQueue for ${sid}: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping per-user mapping removal (use -AllUsers to enable)."
        }

        # 2) Remove printers via Win32_Printer (bypasses MSFT_Printer provider issues)
        Write-Log -Level Info -Message "Removing all printers via Win32_Printer..."
        Get-CimInstance Win32_Printer | ForEach-Object {
            $name = $_.Name
            if ($PSCmdlet.ShouldProcess("Printer '$name'", "Remove")) {
                try {
                    $_ | Remove-CimInstance -ErrorAction Stop
                    $removedPrinters++
                    Write-Log -Level Info -Message "  - Removed $name"
                }
                catch {
                    $failedPrinters += $name
                    Write-Log -Level Warn -Message "    Failed to remove '$name': $($_.Exception.Message)"
                }
            }
        }

        # 3) Optional: remove ports (with WMI fallback)
        if ($IncludePorts) {
            Write-Log -Level Info -Message "Removing TCP/IP printer ports..."
            $standardPrefixes = @('FILE:', 'LPT', 'COM', 'WSD', 'XPS', 'SHRFAX:', 'PORTPROMPT:', 'NULL:')
            $ports = @()

            try {
                $ports = Get-PrinterPort -ErrorAction Stop
            }
            catch {
                Write-Log -Level Warn -Message "Get-PrinterPort failed, falling back to Win32_TCPIPPrinterPort..."
                $ports = Get-WmiObject -Class Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue |
                ForEach-Object { New-Object psobject -Property @{ Name = $_.Name } }
            }

            $ports = $ports | Where-Object {
                $n = $_.Name
                -not ($standardPrefixes | ForEach-Object { $n.StartsWith($_, 'CurrentCultureIgnoreCase') }) `
                    -and ($n -notmatch '^(nul:|PDF:)')
            }

            foreach ($p in $ports) {
                if ($PSCmdlet.ShouldProcess("Port '$($p.Name)'", "Remove")) {
                    try {
                        Remove-PrinterPort -Name $p.Name -ErrorAction Stop
                        $removedPorts++
                        Write-Log -Level Info -Message "  - Removed port $($p.Name)"
                    }
                    catch {
                        $failedPorts += $p.Name
                        Write-Log -Level Warn -Message "    Failed to remove port '$($p.Name)': $($_.Exception.Message)"
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping port removal (use -IncludePorts to enable)."
        }

        # 4) Optional: remove drivers (free common locks first)
        if ($IncludeDrivers) {
            # Make sure spooler is running
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service Spooler -ErrorAction SilentlyContinue
            }

            # Free common locks
            Get-Process splwow64, PrintIsolationHost -ErrorAction SilentlyContinue | ForEach-Object {
                try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {}
            }

            Write-Log -Level Info -Message "Removing printer drivers..."
            $drivers = Get-PrinterDriver -ErrorAction SilentlyContinue
            foreach ($d in $drivers) {
                if ($PSCmdlet.ShouldProcess("Driver '$($d.Name)'", "Remove")) {
                    try {
                        Remove-PrinterDriver -Name $d.Name -ErrorAction Stop
                        $removedDrivers++
                        Write-Log -Level Info -Message "  - Removed driver '$($d.Name)'"
                    }
                    catch {
                        $failedDrivers += $d.Name
                        Write-Log -Level Warn -Message "    Failed to remove driver '$($d.Name)': $($_.Exception.Message)"

                        if ($Force) {
                            # Attempt package removal by published name (oemXX.inf)
                            Write-Log -Level Info -Message "    Enumerating driver packages via pnputil..."
                            $enum = & pnputil /enum-drivers 2>$null
                            if ($enum) {
                                # crude but effective matching
                                $blocks = ($enum -join "`n") -split "(?ms)^Published Name : "
                                $targets = $blocks | Where-Object { $_ -match [regex]::Escape($d.Name) -and $_ -match "Class\s*:\s*Printer" }
                                foreach ($blk in $targets) {
                                    if ($blk -match '^(oem\d+\.inf)') {
                                        $oem = $matches[1]
                                        try {
                                            Write-Log -Level Info -Message "    Forcing removal of ${oem} via pnputil..."
                                            & pnputil /delete-driver $oem /uninstall /force | Out-Null
                                        }
                                        catch {
                                            Write-Log -Level Warn -Message "    pnputil failed for ${oem}: $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping driver removal (use -IncludeDrivers to enable)."
        }

        # Restore spooler to original state
        if ($spoolerWasRunning) {
            # ensure it's up
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service -Name Spooler -ErrorAction SilentlyContinue
            }
        }
        else {
            # it was stopped before we began; stop it again
            if ($PSCmdlet.ShouldProcess("Spooler", "Restore to Stopped state")) {
                Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            }
        }
    }

    End {
        Write-Log -Level Info -Message "=== Remove-Printers completed ==="
        if ($PassThru) {
            [pscustomobject]@{
                PrintersRemoved = $removedPrinters
                PrintersFailed  = $failedPrinters
                PortsRemoved    = $removedPorts
                PortsFailed     = $failedPorts
                DriversRemoved  = $removedDrivers
                DriversFailed   = $failedDrivers
                UserMapsRemoved = $removedUserMaps
                UserMapsFailed  = $failedUserMaps
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Reset-WindowsUpdateComponents.ps1
`powershell
function Reset-WindowsUpdateComponents {
    <#
    .SYNOPSIS
    Resets Windows Update components locally or on a remote machine.
    .DESCRIPTION
    This function stops Windows Update-related services, renames key folders,
    and restarts the services to reset Windows Update components. It can operate
    on the local or a remote computer using PowerShell remoting. A log file is
    generated summarizing the actions taken.
    .PARAMETER ComputerName
    The name of the computer to reset Windows Update components on. Defaults to
    the local computer.
    .PARAMETER Credential
    Optional PSCredential for remote connections.
    .INPUTS
        None. You cannot pipe objects to Reset-WindowsUpdateComponents.
    .OUTPUTS
        [PSCustomObject] with properties:
            StoppedServices - Array of services that were stopped
            RenamedFolders  - Array of folders that were renamed
            Errors          - Array of error messages encountered
    .EXAMPLE
    Reset-WindowsUpdateComponents -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
    Reset-WindowsUpdateComponents
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Load config
    $logDir = $script:TechToolboxConfig["settings"]["windowsUpdate"]["logDir"]
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Helper for remote execution
    function Invoke-Remote {
        param(
            [string]$ComputerName,
            [scriptblock]$ScriptBlock,
            [System.Management.Automation.PSCredential]$Credential
        )

        if ($ComputerName -eq $env:COMPUTERNAME) {
            return & $ScriptBlock
        }

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $ScriptBlock
            ErrorAction  = 'Stop'
        }

        if ($Credential) { $params.Credential = $Credential }

        return Invoke-Command @params
    }

    # Scriptblock that runs on local or remote machine
    $resetScript = {
        $result = [ordered]@{
            StoppedServices = @()
            RenamedFolders  = @()
            Errors          = @()
        }

        $services = 'wuauserv', 'cryptsvc', 'bits', 'msiserver'

        foreach ($svc in $services) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                $result.StoppedServices += $svc
            }
            catch {
                $result.Errors += "Failed to stop $svc $($_.Exception.Message)"
            }
        }

        # Delete qmgr files
        try {
            Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction Stop
        }
        catch {
            $result.Errors += "Failed to delete qmgr files: $($_.Exception.Message)"
        }

        # Rename SoftwareDistribution
        try {
            $sd = Join-Path $env:SystemRoot "SoftwareDistribution"
            if (Test-Path $sd) {
                Rename-Item -Path $sd -NewName "SoftwareDistribution.old" -Force
                $result.RenamedFolders += "SoftwareDistribution → SoftwareDistribution.old"
            }
        }
        catch {
            $result.Errors += "Failed to rename SoftwareDistribution: $($_.Exception.Message)"
        }

        # Rename catroot2
        try {
            $cr = Join-Path $env:SystemRoot "System32\catroot2"
            if (Test-Path $cr) {
                Rename-Item -Path $cr -NewName "catroot2.old" -Force
                $result.RenamedFolders += "catroot2 → catroot2.old"
            }
        }
        catch {
            $result.Errors += "Failed to rename catroot2: $($_.Exception.Message)"
        }

        # Restart services
        foreach ($svc in $services) {
            try {
                Start-Service -Name $svc -ErrorAction Stop
            }
            catch {
                $result.Errors += "Failed to start $svc $($_.Exception.Message)"
            }
        }

        return [pscustomobject]$result
    }

    # Execute
    $resetResult = Invoke-Remote -ComputerName $ComputerName -ScriptBlock $resetScript -Credential $Credential

    # Export log
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $exportPath = Join-Path $logDir ("WUReset_{0}_{1}.txt" -f $ComputerName, $timestamp)

    $log = @()
    $log += "Windows Update Reset Report"
    $log += "Computer: $ComputerName"
    $log += "Timestamp: $timestamp"
    $log += ""
    $log += "Stopped Services:"
    $log += $resetResult.StoppedServices
    $log += ""
    $log += "Renamed Folders:"
    $log += $resetResult.RenamedFolders
    $log += ""
    $log += "Errors:"
    $log += $resetResult.Errors

    $log | Out-File -FilePath $exportPath -Encoding UTF8

    Write-Host "Windows Update components reset. Log saved to: $exportPath" -ForegroundColor Green

    return $resetResult
}
[SIGNATURE BLOCK REMOVED]

`### FILE: Initialize-DomainAdminCred.ps1
`powershell

function Initialize-DomainAdminCred {
    <#
    .SYNOPSIS
    Initializes the Domain Admin Credential in the session by loading from
    config or prompting the user.
    .DESCRIPTION
    This function checks if the domain admin credential is stored in the
    configuration. If not, it prompts the user to enter the credential via
    Get-Credential, stores it securely in the config file, and reconstructs
    the PSCredential object for use in the current session.
    .EXAMPLE
    Initialize-DomainAdminCred
    Initializes the domain admin credential for the session.
    .NOTES
    This will pull credentials from
    $script:cfg.settings.passwords.domainAdminCred. And set it to
    $script:domainAdminCred for session use.
    #>
    [CmdletBinding()]
    param()

    Write-Log -Level 'Debug' -Message "[Initialize-DomainAdminCred] Starting credential initialization."

    # Ensure config is loaded
    if (-not $script:cfg) {
        Write-Log -Level 'Error' -Message "[Initialize-DomainAdminCred] Config not loaded. Initialize-Config must run first."
        throw "[Initialize-DomainAdminCred] Config not loaded."
    }

    # Navigate to credential node safely
    $credNode = $null
    try {
        $credNode = $script:cfg.settings.passwords.domainAdminCred
    }
    catch {
        # Create missing hierarchy
        if (-not $script:cfg.settings) { $script:cfg.settings = @{} }
        if (-not $script:cfg.settings.passwords) { $script:cfg.settings.passwords = @{} }
        $credNode = $null
    }

    # Determine if prompting is required
    $needCred = $false
    if (-not $credNode) { $needCred = $true }
    elseif (-not $credNode.username) { $needCred = $true }
    elseif (-not $credNode.password) { $needCred = $true }

    if ($needCred) {
        Write-Log -Level 'Warn' -Message "[Initialize-DomainAdminCred] No stored domain admin credentials found. Prompting user."

        $cred = Get-Credential -Message "Enter Domain Admin Credential"

        # Ensure config branch exists
        if (-not $script:cfg.settings.passwords) {
            $script:cfg.settings.passwords = @{}
        }

        # Store updated credential
        $script:cfg.settings.passwords.domainAdminCred = @{
            username = $cred.UserName
            password = ConvertFrom-SecureString $cred.Password
        }

        # Save updated config.json
        $configPath = $script:ConfigPath
        try {
            $script:cfg | ConvertTo-Json -Depth 25 | Set-Content -Path $configPath
            Write-Log -Level 'Ok' -Message "[Initialize-DomainAdminCred] Saved domainAdminCred to $configPath"
        }
        catch {
            Write-Log -Level 'Error' -Message "[Initialize-DomainAdminCred] Failed to write config: $($_.Exception.Message)"
            throw
        }
    }

    # Reconstruct PSCredential for session use
    try {
        $username = $script:cfg.settings.passwords.domainAdminCred.username
        $securePwd = $script:cfg.settings.passwords.domainAdminCred.password | ConvertTo-SecureString
        $script:domainAdminCred = New-Object -TypeName PSCredential -ArgumentList $username, $securePwd

        Write-Log -Level 'Debug' -Message "[Initialize-DomainAdminCred] Domain admin credential loaded into session."
    }
    catch {
        Write-Log -Level 'Error' -Message "[Initialize-DomainAdminCred] Failed to build PSCredential: $($_.Exception.Message)"
        throw
    }
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Invoke-SCW.ps1
`powershell
function Invoke-SCW {
    (Get-Module TechToolbox).Invoke({ Invoke-SanityCheck })
}

[SIGNATURE BLOCK REMOVED]

`### FILE: Test-PathAs.ps1
`powershell

function Test-PathAs {
    <#
    .SYNOPSIS
    Tests whether a path exists using alternate credentials.

    .DESCRIPTION
    Test-PathAs uses the TechToolbox impersonation subsystem to evaluate whether
    a file system path exists under the security context of the specified
    credential. This is useful for validating SMB access, deployment accounts,
    service accounts, and cross-domain permissions.

    .PARAMETER Path
    The file system or UNC path to test.

    .PARAMETER Credential
    The credential to impersonate while testing the path.

    .INPUTS
        None. You cannot pipe objects to Test-PathAs.

    .OUTPUTS
        [bool] $true if the path exists, otherwise $false.

    .EXAMPLE
    Test-PathAs -Path "\\server\share\installer.msi" -Credential $cred

    .EXAMPLE
    Test-PathAs -Path "C:\RestrictedFolder" -Credential $svc

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    Invoke-Impersonation -Credential $Credential -ScriptBlock {
        Test-Path -LiteralPath $Path
    }
}
[SIGNATURE BLOCK REMOVED]

`
```
