# Code Analysis Report
Generated: 2/7/2026 8:01:52 PM

## Summary
 This is a PowerShell script named Format-UserRecord.ps1 that formats an Active Directory user record into a custom object with various properties, including identity, mailbox, attributes, manager, group membership, and password/expiry details (AD-only). The script also includes the option to cache resolved objects for faster lookups.

The script first checks if the user account never expires by examining both the friendly property and the UAC bit. It then determines whether the user must change their password at the next logon, calculates the password expiry time (if available), and falls back to a constructed PasswordExpired attribute if necessary. The script also calculates how many days remain until password expiry.

The final output is a custom object with the following properties:
- Identity: SamAccountName, UserPrincipalName, DisplayName, ObjectGuid, DistinguishedName
- Mailbox / addresses: Mail, PrimarySmtpAddress, SmtpAddresses, ProxyAddressesRaw
- AD attributes: Enabled, WhenCreated, LastLogon, Department, Title
- Manager (resolved): ManagerDn, ManagerUpn, ManagerName, ManagerSamAccountName, ManagerMail
- Group membership (resolved): MemberOfDn, MemberOfNames, MemberOfSamAccountNames, MemberOfResolved
- Password / expiry (AD-only): PasswordExpired, PasswordExpiryTime, DaysUntilPasswordExpiry, MustChangePasswordAtNextLogon, PasswordNeverExpires
- Provenance: Source, FoundInAD, RawAD

The script also includes error handling and caching of resolved objects for faster lookups.

## Source Code
```powershell
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

```
