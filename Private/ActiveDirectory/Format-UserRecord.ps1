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

        function Edit-ProxyAddresses {
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
            $px = Edit-ProxyAddresses -AdUser $AD
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

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDty48RzB8WEjFN
# vkSDsUjL2YnmvqVDPn0gxqN9DFOoO6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA1K3gMgY2A
# a1LpIfgqrSmFDjiitKQS2plU9v9/XZO26TANBgkqhkiG9w0BAQEFAASCAgAwj4oe
# thP5GS8ruN1mndEnL5+2CTPomM5JdlW56kZ6gqI31d5jfBYhGcxu7hBc+Z/oRiDJ
# 20vRgxZ59wcvXzvU6E7m9X4nwglgoW3/cWKFgUoUmAXlR4RCBRxhH2eYLXrZYRGp
# G1x0fkbEURTXRPnOTmWhN4KMOaOHbhWamLOJVdQeMlB8hK5BnltllTnoz07JXAuW
# PLpYrLha+2bZQl8itVaKO+ROZ7qMMqTlMFuXxx2jeQWcJ52R3+3rYoWbTwTEGFvL
# qiTH9ENjDXLhiQZtuARuPHSYGyfHlYTr3FL8pPiCfEsSv9rRPgRwjn43NmfJTmu3
# P0chXDl4tUV+0qivTjlCaQqoJPFf/TSe7osyAfwLp2ANXphBk8RJDMAngFE30Se5
# cf37E3jbj2DKrKgx8EBdPPsoo2k6q/A8McfS0khTvpsHe2tgysMbkYnHocYTlJqF
# U5cQa8MihVhG5Qrg2wlenhjmoEtmNrlhZ/yUAxtAo3LvIH4wf9uDRSvpJ/q0tnyQ
# qOykx0lK4eeTE/AjzDpwZbm3PaLgVx39/+o3p0Yp4s0nK1gThdfa6av802XmIu4Q
# CeOhlFZiGK1nawtbB5GBVSYWBtFtMwhZc/xyZX6xRXn9T1gU+qjyYW7Lbmlzsw2k
# au7Z+yJWA9Fd/jCsINV3jfpePYmEkZ9J0vwOD6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTEwMDQ1MTFaMC8GCSqGSIb3DQEJBDEiBCDFUd0gDI33D6VXRzut
# wgb9pJPz86gTTpEAb6bZTni6LzANBgkqhkiG9w0BAQEFAASCAgABfgRCD2uAUdm3
# +NyoBDENIgJDMyMdj+bYNg6bT3yLTYTzACVzzZ8c9MjSV8Knn6+nfUttomL46Daa
# f6iFNmPxvqQgkAYxMXiAmXBOA7HVYkMyg4FOqxxk81fE4wgaYEBMGMROFNSSlbnk
# Hn3hqlMKU9WHv/zKhmoQKi/xaDVd1PBllrwa8A9d90GI5VAVMlkHh3RM51AQ3hKT
# y72LfOgLAZo61lle2T7T7HZ2CpobtIpaX7JNp9Eac192L2zLukyA/xJsVOJublCE
# QPelTY8JRLoxLLyM0rOShuHX2+oY6h7X2KlSpygEs4JFBf4W1OpPEARUZy4aRbvU
# r8oUkXoblwRuVKjkn2z4OAyxyajTgp4xfHwXmbm0cc5FnlvekxTAwlvecLxbxu39
# FJRwkOM85vJ/MdGxDWCnsBAtTHVdmLNgsz7FcsAIcbiwz2X0rQxNRAOD9QW8NMJD
# 1xi14tvPQ6GUfdrFbAcnf/lQoxDgOV8kD9k2FF7M/lDrmeoJeGIFXeYJ56wH9SzK
# yp+RU6fjAClLLVYDLjATavhaQAH1/i+9QLGwWbPGL8c85dbLXFLYpVX9vSAoxivb
# yJwR8VOSqanqyT1uynBxoT2uZxIAusWaWZMAjmUNRJ28uSolrvqXLHXIkbLOWAaT
# ToTX9y48by6bQBQR88GxG9fp9GbzjQ==
# SIG # End signature block
