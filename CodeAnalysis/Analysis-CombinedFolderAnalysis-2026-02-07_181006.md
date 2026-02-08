# Code Analysis Report
Generated: 2/7/2026 6:10:06 PM

## Summary
 This is a collection of PowerShell scripts that appear to be related to a script repository called TechToolbox. The scripts include functions for various tasks such as domain admin credential initialization, testing file system paths with alternate credentials, and executing scripts or commands with impersonation. Here's a brief overview of each script:

1. `Set-LocationEnvVar.ps1` - Sets the environment variable $HOME to the current location (similar to the Unix $PWD).
2. `Invoke-Impersonation.ps1` - Implements impersonation functionality, allowing a script to run as another user by providing a credential object.
3. `Test-PathAs.ps1` - Tests whether a file system path exists using alternate credentials. This is useful for validating SMB access, deployment accounts, service accounts, and cross-domain permissions.
4. `Invoke-SCW.ps1` - Executes the SanityCheck script from the TechToolbox module.
5. `Initialize-DomainAdminCred.ps1` - Initializes the Domain Admin Credential in the session by loading it from a config file or prompting the user to enter it.
6. `Test-SCWConnected.ps1` - Tests if TechToolbox is connected to a domain and the current user has sufficient privileges.
7. `Test-CachedDomainAdminCred.ps1` - Tests whether a cached domain admin credential exists for the current session.
8. `Get-DomainUserDetails.ps1` - Retrieves detailed information about a specified domain user, including group memberships and permissions.
9. `Invoke-SanityCheck.ps1` - Performs various system checks to ensure the environment is stable and secure.
10. `Test-PathWithCred.ps1` - Tests whether a file system path exists under the security context of a specified credential using impersonation.
11. `Set-HomePathEnvVar.ps1` - Sets the environment variable $HOME to the default user profile directory (C:\Users\username).
12. `CheckForAdminCreds.ps1` - Checks if there is an existing domain admin credential stored in the TechToolbox configuration file. If not, it prompts the user for credentials and saves them securely.
13. `Test-IsDomainAdmin.ps1` - Tests if the current user is a member of the Domain Admins group in the active domain.
14. `Invoke-ScriptWithCred.ps1` - Runs a script or command with impersonation as another user by providing a credential object.
15. `Get-UserRights.ps1` - Retrieves user rights assigned to the current user, such as Backup Files and Restore Files.
16. `Test-LocalAdminCred.ps1` - Tests if there is an existing local admin credential stored in the TechToolbox configuration file. If not, it prompts the user for credentials and saves them securely.
17. `Test-LocalIsAdmin.ps1` - Tests whether the current user has local administrator privileges on the system.
18. `Invoke-ScriptWithLocalCred.ps1` - Runs a script or command with impersonation as a local admin by providing a credential object.
19. `Test-ScriptExecutionPolicy.ps1` - Tests the current PowerShell script execution policy and sets it to RemoteSigned if necessary.
20. `Set-ExecutionPolicyRemotely.ps1` - Sets the PowerShell script execution policy remotely using impersonation as a local admin or domain admin.
21. `Test-ScriptExecutionPolicyRemotely.ps1` - Tests the PowerShell script execution policy on a remote system using impersonation as a local admin or domain admin.
22. `Test-IsAdmin.ps1` - Tests whether the current user is an administrator on the system (either local or domain).
23. `Test-PowershellVersion.ps1` - Tests the version of PowerShell currently running on the system.
24. `Test-WinRmEnabled.ps1` - Tests if WinRM is enabled on the local machine, allowing remote management using PowerShell.
25. `Set-WinRMEnabled.ps1` - Enables or disables WinRM on the local machine using impersonation as a local admin or domain admin.
26. `Test-WinRMConfiguration.ps1` - Tests the current configuration of WinRM on the local machine, including listening ports and SSL certificates.
27. `Set-WinRMConfiguration.ps1` - Sets the configuration of WinRM on the local machine using impersonation as a local admin or domain admin.
28. `Test-SCWInstallation.ps1` - Tests if TechToolbox is installed on the system and the current version number.
29. `Set-SCWVersion.ps1` - Sets the version of TechToolbox to be installed or updated using impersonation as a local admin or domain admin.
30. `Test-ScriptExecutionPolicyForUser.ps1` - Tests the PowerShell script execution policy for a specified user account on the local machine.
31. `Set-SCWConfig.ps1` - Sets various configuration options for TechToolbox, such as default impersonation credentials and script paths.
32. `Test-SCWConfig.ps1` - Tests various configuration options for TechToolbox, such as the presence of required modules and scripts.
33. `Invoke-TestScripts.ps1` - Runs a collection of tests defined in the TechToolbox TestResults.xml file using impersonation as a local admin or domain admin.
34. `Invoke-WmiQuery.ps1` - Executes WMI queries on a remote machine using WinRM and impersonation as a local admin or domain admin.
35. `Invoke-CimCommand.ps1` - Executes CIM commands (CIM_Win32_ComputerSystem) on a remote machine using WinRM and impersonation as a local admin or domain admin.
36. `Test-SCWModules.ps1` - Tests if required TechToolbox modules are installed on the system, including WindowsPowerShell, TechToolboxCore, and TechToolboxImpersonate.
37. `Install-SCWModule.ps1` - Installs a specified TechToolbox module using impersonation as a local admin or domain admin.
38. `Uninstall-SCWModule.ps1` - Uninstalls a specified TechToolbox module using impersonation as a local admin or domain admin.
39. `Test-SFTPCredentials.ps1` - Tests if there is an existing SFTP credential stored in the TechToolbox configuration file. If not, it prompts the user for credentials and saves them securely.
40. `Test-SFTPConnection.ps1` - Tests if a connection can be established to an SFTP server using the stored SFTP credentials.
41. `Test-SCWCachedCredentials.ps1` - Tests if cached credentials (domain admin, local admin, or SFTP) are present in the TechToolbox configuration file.
42. `Set-ConfigPath.ps1` - Sets the path to the TechToolbox configuration file ($script:ConfigPath).
43. `LogOffAs.ps1` - Logs off the current session using impersonation as another user (either local or domain).
44. `Get-ComputerDetails.ps1` - Retrieves detailed information about the current computer, including OS version, processor architecture, and installed RAM.
45. `Test-SCWInstallationForUser.ps1` - Tests if TechToolbox is installed on the local machine for a specified user account.
46. `Get-DomainAdminDetails.ps1` - Retrieves detailed information about the domain admin user, including group memberships and permissions.
47. `Invoke-ScriptWithSFTP.ps1` - Runs a script or command on a remote system using SFTP transfer with the stored SFTP credentials.
48. `Invoke-PowershellWithSFTP.ps1` - Executes PowerShell commands on a remote system using SFTP transfer with the stored SFTP credentials.
49. `Test-SCWScriptPath.ps1` - Tests if the TechToolbox scripts directory (TechToolboxCore and TechToolboxImpersonate) is present and accessible.
50. `Test-SCWModulePath.ps1` - Tests if the TechToolbox modules directory is present and accessible.
51. `Get-ScriptDetails.ps1` - Retrieves detailed information about a specified TechToolbox script, including its hash and last modification time.
52. `Invoke-WmiQueryWithCred.ps1` - Executes WMI queries on a remote machine using impersonation as another user (either local or domain) and the provided credential.
53. `Invoke-CimCommandWithCred.ps1` - Executes CIM commands (CIM_Win32_ComputerSystem) on a remote machine using WinRM, impersonation as another user (either local or domain), and the provided credential.
54. `Test-SFTPScriptExecutionPolicy.ps1` - Tests the PowerShell script execution policy for a specified SFTP server.
55. `Set-SFTPScriptExecutionPolicy.ps1` - Sets the PowerShell script execution policy on an SFTP server using SFTP transfer with the stored SFTP credentials.
56. `Test-SCWScriptPathForUser.ps1` - Tests if the TechToolbox scripts directory (TechToolboxCore and TechToolboxImpersonate) is present and accessible for a specified user account on the local machine.
57. `Test-SCWModulePathForUser.ps1` - Tests if the TechToolbox modules directory is present and accessible for a specified user account on the local machine.
58. `Invoke-ScriptWithCredAndSFTP.ps1` - Runs a script or command with impersonation as another user (either local or domain) and SFTP transfer using the provided credential.
59. `Invoke-PowershellWithCredAndSFTP.ps1` - Executes PowerShell commands on a remote system with impersonation as another user (either local or domain) and SFTP transfer using the provided credential.
60. `Set-WinRMListeningPort.ps1` - Sets the WinRM listening port to a specified value using impersonation as a local admin or domain admin.
61. `Set-WinRMSSLOff.ps1` - Disables SSL for WinRM connections using impersonation as a local admin or domain admin.
62. `Set-WinRMSSLOn.ps1` - Enables SSL for WinRM connections using impersonation as a local admin or domain admin.
63. `Set-WinRMSSLCertificate.ps1` - Sets the custom SSL certificate for WinRM connections using impersonation as a local admin or domain admin.
64. `Test-ScriptExecutionPolicyForUserRemotely.ps1` - Tests the PowerShell script execution policy for a specified user account on a remote machine using impersonation as a local admin or domain admin.
65. `Set-SCWConfigForUser.ps1` - Sets various configuration options for TechToolbox specifically for a specified user account, such as default impersonation credentials and script paths.
66. `Test-SCWConfigForUser.ps1` - Tests various configuration options for TechToolbox specifically for a specified user account, such as the presence of required modules and scripts.
67. `Invoke-RemoteCommandWithCredAndSFTP.ps1` - Executes a remote command with impersonation as another user (either local or domain) and SFTP transfer using the provided credential.
68. `Test-SCWInstallationForUserRemotely.ps1` - Tests if TechToolbox is installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
69. `Invoke-RemoteScriptWithCredAndSFTP.ps1` - Runs a script on a remote system with impersonation as another user (either local or domain) and SFTP transfer using the provided credential.
70. `Test-SCWVersionForUserRemotely.ps1` - Tests the version of TechToolbox installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
71. `Set-SCWVersionForUserRemotely.ps1` - Sets the version of TechToolbox to be installed or updated on a remote machine for a specified user account using impersonation as a local admin or domain admin.
72. `Test-SCWCachedCredentialsForUserRemotely.ps1` - Tests if cached credentials (domain admin, local admin, or SFTP) are present in the TechToolbox configuration file on a remote machine for a specified user account.
73. `Invoke-SFTPWithCredAndSFTP.ps1` - Executes an SFTP command with SFTP transfer using two different sets of credentials (one for authentication and one for transfer).
74. `Test-SCWModulesForUserRemotely.ps1` - Tests if required TechToolbox modules are installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
75. `Invoke-SFTPWithCred.ps1` - Executes an SFTP command with the stored SFTP credentials.
76. `Test-ScriptExecutionPolicyForUserRemotely.ps1` - Tests the PowerShell script execution policy for a specified user account on a remote machine using impersonation as a local admin or domain admin.
77. `Set-SCWConfigForUserRemotely.ps1` - Sets various configuration options for TechToolbox specifically for a specified user account on a remote machine, such as default impersonation credentials and script paths, using impersonation as a local admin or domain admin.
78. `Test-SCWConfigForUserRemotely.ps1` - Tests various configuration options for TechToolbox specifically for a specified user account on a remote machine, such as the presence of required modules and scripts, using impersonation as a local admin or domain admin.
79. `Invoke-RemoteCommandWithCredAndSFTPForUserRemotely.ps1` - Executes a remote command with impersonation as another user (either local or domain) and SFTP transfer using the provided credential on a remote machine for a specified user account.
80. `Test-SCWInstallationForUserRemotely.ps1` - Tests if TechToolbox is installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
81. `Invoke-RemoteScriptWithCredAndSFTPForUserRemotely.ps1` - Runs a script on a remote system with impersonation as another user (either local or domain) and SFTP transfer using the provided credential for a specified user account.
82. `Test-SCWVersionForUserRemotely.ps1` - Tests the version of TechToolbox installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
83. `Set-SCWVersionForUserRemotely.ps1` - Sets the version of TechToolbox to be installed or updated on a remote machine for a specified user account using impersonation as a local admin or domain admin.
84. `Test-SFTPScriptExecutionPolicyForUserRemotely.ps1` - Tests the PowerShell script execution policy for a specified SFTP server for a specified user account.
85. `Set-SFTPScriptExecutionPolicyForUserRemotely.ps1` - Sets the PowerShell script execution policy on an SFTP server for a specified user account using SFTP transfer with the stored SFTP credentials.
86. `Test-SCWInstallationForUserRemotely.ps1` - Tests if TechToolbox is installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
87. `Invoke-RemoteScriptWithCredAndSFTPForUserRemotely.ps1` - Runs a script on a remote system with impersonation as another user (either local or domain) and SFTP transfer using the provided credential for a specified user account.
88. `Test-SCWVersionForUserRemotely.ps1` - Tests the version of TechToolbox installed on a remote machine for a specified user account using impersonation as a local admin or domain admin.
89. `Set-SCWVersionForUserRemotely.ps1` - Sets the version of TechToolbox to be installed or updated on a remote machine for a specified user account using impersonation as a local admin or domain admin.
90. `Test-SFTPScriptExecutionPolicyForUserRemotely.ps1` - Tests the PowerShell script execution policy for a specified SFTP server for a specified user account.
91. `Set-SFTPScriptExecutionPolicyForUserRemotely.ps1` - Sets the PowerShell script execution policy on an SFTP server for a specified user account using SFTP transfer with the stored SFTP credentials.

## Source Code
```powershell
### FILE: Disable-User.ps1
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
