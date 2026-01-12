
function New-OnPremUserFromTemplate {
    <#
    .SYNOPSIS
        Create a new on-premises AD user based on a template user.
    .DESCRIPTION
        This cmdlet creates a new Active Directory user by copying attributes
        and group memberships from a specified template user. The new user's
        naming conventions (UPN, SAM, mailNickname) are derived from
        configuration settings unless overridden.
    .PARAMETER TemplateIdentity
        The identity (sAMAccountName, distinguishedName, etc.) of the template
        user to copy attributes and group memberships from.
    .PARAMETER TemplateSearch
        A hashtable of attribute-value pairs to search for the template user.
    .PARAMETER GivenName
        The given (first) name of the new user.
    .PARAMETER Surname
        The surname (last name) of the new user.
    .PARAMETER DisplayName
        The display name of the new user.
    .PARAMETER TargetOU
        The distinguished name of the OU where the new user will be created. If
        not provided, the template user's OU will be used.
    .PARAMETER SamAccountName
        The sAMAccountName of the new user. If not provided, it will be derived
        from naming conventions.
    .PARAMETER UpnPrefix
        The UPN prefix of the new user. If not provided, it will be derived from
        naming conventions.
    .PARAMETER MailNickname
        The mailNickname (alias) of the new user. If not provided, it will be
        derived from naming conventions.
    .PARAMETER CopyAttributes
        An array of attribute names to copy from the template user to the new
        user.
    .PARAMETER ExcludedGroups
        An array of group names to exclude when copying group memberships from
        the template user.
    .PARAMETER InitialPasswordLength
        The length of the initial random password for the new user.
    .EXAMPLE
        New-OnPremUserFromTemplate -TemplateIdentity "jdoe" -GivenName "John" -Surname "Smith" -DisplayName "John Smith" -TargetOU "OU=Users,DC=example,DC=com"
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
        [string]$MailNickname,

        [string[]]$CopyAttributes = @(
            'department', 'title', 'physicalDeliveryOfficeName', 'telephoneNumber',
            'streetAddress', 'l', 'st', 'postalCode', 'company',
            'extensionAttribute1', 'extensionAttribute2', 'extensionAttribute3'
        ),

        [string[]]$ExcludedGroups = @(
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Protected Users', 'Server Operators', 'Account Operators', 'Backup Operators',
            'Print Operators', 'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers'
        ),

        [int]$InitialPasswordLength = 16
    )

    begin {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Load config if not provided
        $Config = Get-TechToolboxConfig
        # Basic structure checks
        if (-not $Config.ContainsKey('settings')) {
            throw "Config missing root 'settings' object (hashtable)."
        }
        if (-not $Config['settings'].ContainsKey('tenant')) {
            throw "Config missing 'settings.tenant'."
        }
        if (-not $Config['settings'].ContainsKey('naming')) {
            throw "Config missing 'settings.naming'."
        }

        # Extract tenant & naming hashtables
        $Tenant = $Config['settings']['tenant']
        $Naming = $Config['settings']['naming']

        # Required value
        if (-not $Tenant.ContainsKey('upnSuffix') -or [string]::IsNullOrWhiteSpace($Tenant['upnSuffix'])) {
            throw "Config upnSuffix is required (e.g., 'company.com')."
        }

        # Expose these to process block
        Set-Variable -Name "Tenant" -Value $Tenant -Scope 1
        Set-Variable -Name "Naming" -Value $Naming -Scope 1
    }

    process {
        # 1) Resolve template user
        $templateUser = $null
        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' {
                $templateUser = Get-ADUser -Identity $TemplateIdentity -Properties * -ErrorAction Stop
            }
            'BySearch' {
                if (-not $TemplateSearch) { throw "Provide -TemplateSearch (e.g., @{ Username='jdoe'; Title='Engineer' })." }
                $ldapFilterParts = foreach ($k in $TemplateSearch.Keys) {
                    $val = [System.Text.RegularExpressions.Regex]::Escape($TemplateSearch[$k])
                    "($k=$val)"
                }
                $ldapFilter = "(&" + ($ldapFilterParts -join '') + ")"
                $templateUser = Get-ADUser -LDAPFilter $ldapFilter -Properties * -ErrorAction Stop | Select-Object -First 1
                if (-not $templateUser) { throw "No template user matched filter $ldapFilter." }
            }
            default { throw "Unexpected parameter set." }
        }

        Write-Verbose "Template: $($templateUser.SamAccountName) / $($templateUser.UserPrincipalName)"

        # 2) Derive naming via config.settings.naming (unless caller overrides)
        if (-not $UpnPrefix -or -not $SamAccountName -or -not $MailNickname) {
            $nm = Resolve-Naming -Naming $Naming -GivenName $GivenName -Surname $Surname
            if (-not $UpnPrefix) { $UpnPrefix = $nm.UpnPrefix }
            if (-not $SamAccountName) { $SamAccountName = $nm.Sam }
            if (-not $MailNickname) { $MailNickname = $nm.Alias }
        }

        $newUpn = "$UpnPrefix@$($Tenant.upnSuffix)"

        # 3) Resolve target OU (default to template's OU)
        if (-not $TargetOU) {
            $TargetOU = ($templateUser.DistinguishedName -replace '^CN=.*?,')
        }

        # 4) Idempotency check
        $exists = Get-ADUser -LDAPFilter "(userPrincipalName=$newUpn)" -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Warning "User UPN '$newUpn' already exists. Aborting."
            return
        }

        # 5) Create new user
        $initialPassword = New-RandomPassword -length $InitialPasswordLength -nonAlpha 3
        $securePass = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        $newParams = @{
            Name                  = $DisplayName
            GivenName             = $GivenName
            Surname               = $Surname
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $newUpn
            Enabled               = $true
            Path                  = $TargetOU
            ChangePasswordAtLogon = $true
            AccountPassword       = $securePass
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Create AD user")) {
            New-ADUser @newParams
            Write-Verbose "Created: $newUpn in $TargetOU"
        }

        # 6) Copy selected attributes from template
        $setParams = @{}
        foreach ($attr in $CopyAttributes) {
            $val = $templateUser.$attr
            if ($null -ne $val -and $val -ne '') { $setParams[$attr] = $val }
        }

        # Mail + mailNickname + proxyAddresses
        $primaryProxy = "SMTP:$UpnPrefix@$($Tenant.upnSuffix)"
        $otherProxies = @()
        $templateProxies = $templateUser.proxyAddresses
        if ($templateProxies) {
            $otherProxies = $templateProxies | Where-Object { $_ -notmatch '^SMTP:' }
        }
        $proxiesToSet = @($primaryProxy) + $otherProxies

        $setParams['mail'] = $newUpn
        $setParams['mailNickname'] = $MailNickname

        if ($PSCmdlet.ShouldProcess($newUpn, "Apply attributes")) {
            if ($setParams.Count -gt 0) { Set-ADUser -Identity $SamAccountName @setParams }
            Set-ADUser -Identity $SamAccountName -Add @{ proxyAddresses = $proxiesToSet } -ErrorAction SilentlyContinue
            Write-Verbose "Attributes + proxyAddresses applied."
        }

        # 7) Copy group memberships (exclude known admin/builtin)
        $tmplGroupDNs = (Get-ADUser $templateUser -Property memberOf).memberOf
        $tmplGroupNames = foreach ($dn in ($tmplGroupDNs ?? @())) {
            (Get-ADGroup -Identity $dn -ErrorAction SilentlyContinue).Name
        }

        $toAdd = $tmplGroupNames | Where-Object { $_ -and ($ExcludedGroups -notcontains $_) }
        if ($PSCmdlet.ShouldProcess($newUpn, "Add group memberships")) {
            foreach ($gName in $toAdd) {
                try {
                    Add-ADGroupMember -Identity $gName -Members $SamAccountName -ErrorAction Stop
                    Write-Verbose "Added to: $gName"
                }
                catch {
                    Write-Warning "Group add failed '$gName': $($_.Exception.Message)"
                }
            }
        }

        # 8) Output summary
        [pscustomobject]@{
            UserPrincipalName = $newUpn
            SamAccountName    = $SamAccountName
            DisplayName       = $DisplayName
            TargetOU          = $TargetOU
            CopiedAttributes  = $CopyAttributes
            GroupsAdded       = $toAdd
            InitialPassword   = $initialPassword  # Store securely
        }
    }
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCgcnlgUTGMbpY1
# to+FCT8wYritlYu72PG9Sxku52LVUKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDC39cAE4VZ
# 5hsZp9rCwZOQ0oWABh+r2SVfQaRGp14bMjANBgkqhkiG9w0BAQEFAASCAgC7H7IX
# FK5NWXzCKGvlxMb7KuCHF4b5DvufWbtT3vKoHb/XQCqh64DX2GNg6bMZjBdPQ29L
# cocPApb6EzMyd9G0mRyOegCiyw4ZSsgnyJ0hbosmUxY06XCG1ILPg+aEEA7FbKne
# YsfbqzWgUFZbu0Z2wsTWm/nA5WswQ7t2foObB7n/va33weqo9dCoZ5durUyNs+O2
# +WCB4FxO5TAKw4x+HxcHS7JHkA+OsfjLvwI7atqZJRX85TKP4mkzpgBjIuZbXLW6
# 1xtBWdAm51ofCo9wrQLyh+E//TRIlyqKFgj29o3ScsOvoKOCpCigUOdOSqSmP8Ct
# N7UxGTBq3T6eH4st2klO8HFz37ApOv1mxR42Bn2S2ugUiujhB/DxkFLWf1Fz1HD3
# B27rJ6wEOTzQT5qhOXi8oTD7WreYmhp6Ar0wOUB0znAyF21FIeog9vehMIYIvW9r
# 3BH99Erv+U7jkDOdcD3+uCudzs2UsWha4iEKWKk6X/fLLLxsPuHSUCLrpOFKAsvs
# xGGbcdsOFZBSade7q6/w4YfKO+Qvb3uQVBIPFmzu54c/qAo2n0h/tpkcGr8lGbj/
# uvZUGaj7Xq9u+iIzlOq1RJ+zQ84UH5NZLWccUSIDt+6IbzFEiR5ADjuQXVUji28K
# /uZEZLMNzmlgZGb+emYvSdUQr/apVR077D4L96GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTIxODQ1MzdaMC8GCSqGSIb3DQEJBDEiBCB1K2uPEFvoKXqBbrXk
# H/eQhZStp8quaF7mp4MIfwzxRzANBgkqhkiG9w0BAQEFAASCAgCD/vGERL6Mb68M
# bXT5/82PZNuYBePHZ7Ohi1scYv3EkaZ6sZ38w/ou1FhXN3lhvunodgQhlfhwsF4D
# 6TiUr9t8AuU2yrpFDZ5EGcXNy0W9ED8YY82U5ahSGVqkoPcJVacHHmjqvUmfB7Su
# eVNsz4wq5swqCtyYKw50ESYEyVBjvM0SiE82KbJARDZFLD6M/jAuN4dodYLj4Gj9
# U+zMH9USngiK6mhuVFqqBKalwAuFu1+pmwyF53m9QxuMpeahjx0ay5ddBLWnJxhe
# WM/QcEiDIiy5LlKB00CeOrDZKAgsTrbERtQE8FvL0G2tGMd9ak+Wluhn64FYz9O2
# 3xuggedW07qhStVCccvkx/8jg6rLqboa3l9AWlDqXqUyMIdrj6hHttuoDIde5KEa
# BuwD+buK+RLC1+bSSYccSyI3/0mhh35kjoJ0+dwT1lqHR1WwirQR++exkTu4XWLF
# fD1JUs3exCd9h4kvnOo9cn4XW+QvLZSBa36eKQO1/nOaVnz3I33BHCf9pYxTw3yO
# 82rX9SHt/rWhI+3/ZeelbCdmwPlaDFhpVBZWtsh3FVKgeBCTQcHJ62CeYCGvs9oT
# 3FRgVf45sEIYI5C8j34LPHiBb8FZsrpnCLiVhMVj3frBqhrmLcED8cujo4w/CmBp
# 8AMvbuMZiAvvBb/3+kjbt+17hDvD5w==
# SIG # End signature block
