
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
        Initialize-TechToolboxRuntime
        Import-Module ActiveDirectory -ErrorAction Stop

        # Load config (throws if missing essentials)
        $cfg = $script:cfg
        $Tenant = $cfg.settings.tenant
        $Naming = $cfg.settings.naming
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

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDqLNLTnQzUhFQx
# pMhP0a2te5xAND3Ocx4WSOyusGpXHKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBkJErKhgYH
# 7QQj25dkP32uMUPXlpszWRlEj9Hy+ptQqjANBgkqhkiG9w0BAQEFAASCAgDZAkoz
# vsKwCf7zjqCTCftotjqXIcjkJ/QY37xC263g21pKpG9mszMqROO6CAooukS4hRmY
# vSiDBdY61U1eCLmOesKEnaHAF0bNEvac2sp5skV5vaOINb8iM0f+oacDuCQaYqDz
# Yqn6Eonjb0E117xirKzx5oYtsR+hshogitbzGRY5TXqIfUagsiIUlr1+bAIzsHPo
# Pvad1JuIO8Cf5bCO+bBPlGCO1rklatAvoUAjhqq1iF2J1alPS2RYBkjg3JB8MFkC
# StrsgrgzXJ3vFkJ60B6cblQZmomthy5dI2iT0kBCFcSFTZRhltX0XoAg/R4grbBp
# 0gIhjDb0rUwIxeodh+MTZ2tO/3yGYIk6GRlXtxo5DnvJAlON//5FdiWMNgf78AU+
# pnSffsFbcu664P59O7y69kuWCRPls2LQz/r0THRVNx+h4hEtG34CU17gZfKmuuHu
# pTr0Z5oLsZ6IQb5Bqih9auuGPN0HYn7rEJSTxiCDGlIIrt5+dk9Bk4kNeNCKfBp2
# vrMCLrkKaaMf33gDt19aazXi1R1WQmAXNUYZFg9ZDJ8M/7dpFneb83/B5rTs6SHJ
# c5UW/XZJPhXtVHJ18cjuimCQMx6qY+mTLOrbD93+OrOYvEobcd7HkMHL6Iw0rqBn
# h/kf8Yej2lBDiSg/1grxxbHSdTI9CG3OnNKazqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTExNjQ1MDJaMC8GCSqGSIb3DQEJBDEiBCD+MaogchOhu+IBlgN4
# plyVMEBHWp1czrTA8Tt1WFwhPTANBgkqhkiG9w0BAQEFAASCAgBihA/hZ8eckL9r
# PMRiAbFQ6Zi5faMMganlA12HWMMl0vtVl024k3pXjpM9SKA0Iyo8ZcsRNhPJbjub
# DsAWxfZ6rv+fUsOfAeTnUgMgD0MwIElbN/mwy4M/1h/BekYvUtEwLa/sWUlQb+os
# NSuWPh9VfdX/FRH1O3r+d5Ewv2o40y+v6ZACH6H2gb+L+YIcdeFV3ocK9uu870MS
# fHILxz6OmXdPiGU+5/i5bkFPjf9LXOduFlnJruUqj5/5O+YnqRpmyfEQ1sdDIOwU
# vl2DCTDp70MdIbp0icjfOG06mE6jeq12y5+ph8HFKSXk++rhTVBVaOGNQXfGe3Yg
# 9SH2zxxpYTfKKrjQqDJ5MV/GDZj4V6aRd6l9pk7juKjajTVyqkZXkkRabvr8oOXs
# sCCXpKV4G3iNbmAJ5Q53Z0o7ev9hoMbfDbu+zdutQLCxlGltfEDQBEoqre9b9wAD
# w5LB5x1mUuQRSXSlvd5A6rFpN9SSXkWQjIq0bUmUvbevJA3p6NaZcZeIdwySym7d
# ECWRIsINBU9d9qoKa+/A1E1DD5dYs0+plFHGXZLBOmzYzemlUkY2BMAGiK1sl1RV
# uL7fKgrmWrF2yjrCQjxJ0yb2FPUiTkfIOYXvM/gND9hDy/Eddzm+66ki8WKLslYK
# G8OWu5swrCDhu953S2n8BRqs4/5bXw==
# SIG # End signature block
