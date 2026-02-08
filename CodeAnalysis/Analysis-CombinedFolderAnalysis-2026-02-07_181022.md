# Code Analysis Report
Generated: 2/7/2026 6:10:22 PM

## Summary
 This script is a PowerShell function named `New-StrongPassword` which generates strong passwords based on three modes: 'Random', 'Readable', and 'Passphrase'. Here's a brief explanation of each mode:

1. Random: Generates passwords with at least one uppercase, one lowercase, one digit, and optional additional symbols (specified by the `NonAlpha` parameter). The length of the password is specified by the user.

2. Readable: Generates readable passwords with at least three words, a separator, digits, and an optional symbol. One word is capitalized to ensure there's at least one uppercase character. The length of the password is also specified by the user.

3. Passphrase: Similar to Readable mode, but typically generates more than three words. The resulting password will have at least one uppercase, one lowercase, digits, and an optional symbol. Again, the length of the password is a minimum value specified by the user.

The script also includes helper functions for elevating privileges (`Restart-Elevated.ps1`) and checking if the current session has administrative privileges (`Test-IsElevated.ps1`). These functions are not directly related to password generation but might be useful in other scripts or scenarios requiring elevated permissions.

## Source Code
```powershell
### FILE: Invoke-RemoteADSyncCycle.ps1
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

`
```
