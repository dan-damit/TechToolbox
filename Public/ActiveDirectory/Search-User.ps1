function Search-User {
    <#
    .SYNOPSIS
        Searches Active Directory for a user and returns a normalized unified
        record.

    .DESCRIPTION
        Resolves a user identity against Active Directory using a two-phase
        lookup strategy:

          Phase 1 — Exact match
            Queries AD by sAMAccountName (if no @ present) or userPrincipalName
            (if input looks like a UPN). Uses an RFC 4515-escaped LDAP filter to
            prevent injection.

          Phase 2 — Broad fallback (if Phase 1 returns no results)
            Constructs an OR filter across sAMAccountName, userPrincipalName,
            displayName (wildcard), and optionally mail and proxyAddresses.
            Fallback attributes can be disabled individually via
            -EnableMailSearch:$false / -EnableProxyAddressSearch:$false.

        The matched AD object is passed through Format-UserRecord, which
        normalises fields and optionally resolves the manager's UPN/name/SAM
        and expands group memberships into structured objects.

        SCOPE
          - Active Directory is always queried (requires ActiveDirectory module).
          - Graph / Entra ID lookups are explicitly excluded.
          - The -IncludeEXO and -IncludeTeams switches are reserved for future
            integration hooks; the underlying wrappers (Get-ExchangeUser,
            Get-TeamsUser) are not yet implemented and those parameters are
            currently no-ops declared in the param block.

        MULTIPLICITY
          By default a single PSCustomObject is returned. If more than one AD
          object matches, a terminating error is thrown with a sample of the
          matching sAMAccountNames. Pass -AllowMultiple to suppress the error
          and receive all matches as an array.

        AD CONFIGURATION
          Server, SearchBase, and SearchScope default to values from
          settings.ad in config.json and can be overridden per-call.

    .PARAMETER Identity
        The user to look up. Accepts:
          - sAMAccountName  (e.g. "jdoe")
          - User Principal Name  (e.g. "jdoe@company.com")
          - Display name (partial match supported in fallback phase)
          - Primary SMTP or proxy address (when -EnableMailSearch /
            -EnableProxyAddressSearch are active)

        The value is RFC 4515-escaped before use in any LDAP filter.

    .PARAMETER Server
        Fully-qualified hostname or IP of the domain controller to target.
        Overrides settings.ad.domainController in config.json. When omitted,
        the AD cmdlets use their default DC selection logic.

    .PARAMETER SearchBase
        Distinguished name of the OU or container to scope the search to.
        Overrides settings.ad.searchBase in config.json.

    .PARAMETER SearchScope
        LDAP search scope. Valid values: Base, OneLevel, Subtree (default).
        Overrides settings.ad.searchScope in config.json.

    .PARAMETER Credential
        PSCredential used for all AD operations including manager and group
        resolution. When omitted, the current session identity is used.

    .PARAMETER EnableProxyAddressSearch
        Includes proxyAddresses (both SMTP: and smtp: prefixes) in the Phase 2
        fallback filter. Enabled by default; pass -EnableProxyAddressSearch:$false
        to restrict the fallback to name/UPN/SAM attributes only.

    .PARAMETER EnableMailSearch
        Includes the mail attribute in the Phase 2 fallback filter. Enabled by
        default; pass -EnableMailSearch:$false to restrict the fallback to
        name/UPN/SAM/proxyAddresses attributes only.

    .PARAMETER ResolveManager
        When enabled (default), the user's manager DN is resolved to a
        structured object containing UPN, Name, sAMAccountName, and mail.
        Pass -ResolveManager:$false to skip this lookup and return the raw
        manager DN instead (faster in environments with many lookups).

    .PARAMETER ResolveGroups
        When enabled (default), the user's MemberOf attribute is expanded into
        structured objects containing Name, sAMAccountName, GroupScope, and
        GroupCategory. Pass -ResolveGroups:$false to skip group expansion and
        return the raw DN list instead.

    .PARAMETER AllowMultiple
        By default, if more than one AD object matches the identity, a
        terminating error is thrown to prevent ambiguous operations downstream.
        Specify -AllowMultiple to suppress that error and return all matches as
        an array of normalized PSCustomObjects. Useful for audit/reporting
        scenarios.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        System.Management.Automation.PSCustomObject
        A single normalized user record produced by Format-UserRecord, or $null
        if no match is found. When -AllowMultiple is specified and multiple
        matches exist, returns an array of PSCustomObjects.

    .EXAMPLE
        Search-User -Identity "jdoe"

        Looks up jdoe by sAMAccountName. Returns a normalized user record, or
        $null if not found.

    .EXAMPLE
        Search-User -Identity "jdoe@company.com"

        Exact UPN lookup. Falls back to broad search across display name, mail,
        and proxyAddresses attributes if not found in Phase 1.

    .EXAMPLE
        Search-User -Identity "John Doe"

        No exact match possible; falls directly to Phase 2 and searches
        displayName with a wildcard filter (*John Doe*).

    .EXAMPLE
        Search-User -Identity "jdoe" -ResolveManager:$false -ResolveGroups:$false

        Fastest lookup — skips manager and group resolution. Useful when only
        basic identity fields (UPN, SamAccountName, mail, etc.) are needed.

    .EXAMPLE
        Search-User -Identity "jdoe" -Server "dc01.company.com" -SearchBase "OU=Users,DC=company,DC=com"

        Targets a specific domain controller and limits the search to a
        single OU.

    .EXAMPLE
        Search-User -Identity "jdoe" -AllowMultiple

        Returns all AD users matching "jdoe" instead of throwing on ambiguity.

    .EXAMPLE
        Search-User -Identity "jdoe" -EnableProxyAddressSearch:$false -EnableMailSearch:$false

        Restricts the Phase 2 fallback to sAMAccountName, userPrincipalName,
        and displayName only — no mail or proxy address matching.

    .NOTES
        - Requires the ActiveDirectory module (RSAT or AD DS role).
        - The AD: PSDrive is intentionally removed after import to suppress
          re-initialization noise on subsequent calls.
        - LDAP filter values are RFC 4515-escaped to prevent filter injection.
        - The -IncludeEXO and -IncludeTeams parameters are declared but not yet
          implemented; they are reserved for future EXO/Teams integration.
        - $ErrorActionPreference is temporarily set to 'Stop' internally and
          restored in a finally block, so callers' preference is preserved.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/search-user

    .LINK
        Format-UserRecord

    .LINK
        Disable-User
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
        Initialize-TechToolboxRuntime
        $cfg = $script:cfg
        $adCfg = $cfg.settings.ad
        $searchCfg = $cfg.settings.userSearch
        $ADprops = $searchCfg.props

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
            Get-ActiveDirectoryModule
        }
        finally {
            $WarningPreference = $prevWarn
        }

        # Optional: ensure the AD: drive isn’t lingering (prevents later re-init noise)
        Remove-PSDrive -Name AD -ErrorAction SilentlyContinue

        # --- Helpers ---
        function Register-LdapFilterValue {
            param([Parameter(Mandatory)] [string]$Value)
            # RFC 4515 escaping: \ * ( ) NUL -> escaped hex
            $v = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
            # NUL not likely in user input; keep for completeness
            $v = ($v -replace '\x00', '\00')
            return $v
        }

        # AD property set needed by Format-UserRecord.
        # Ensure critical fields are always requested even if omitted from config.
        $props = @($ADprops)
        foreach ($requiredProp in @('lockedOut')) {
            if ($props -notcontains $requiredProp) {
                $props += $requiredProp
            }
        }

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
        $idEsc = Register-LdapFilterValue $Identity
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

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfFa4Q13fMM05x
# VHkYKVk/uD1xYgSg5ROWcOsBmwGx/aCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCB
# QsDteMxdLla9z8oKCfUIRWKsboG8eeLBmPzDh1WLyjANBgkqhkiG9w0BAQEFAASC
# AYAzwblN9A36YyHWV5AiWwFhvyvD/ZTGXB6V60UJBYJRQH6TsDaTpxE+G5qitkxy
# 8xXuW7TRJiBdp+yHOJClz5pTgIfnK7awAOtRnOWZTtpWY2vOE+spOWwVm2cgSrlG
# 0Voy87MfZEuMiGPjb89grZ6w1T6uK/kzzDYb1H5JH/I6fSKX22AEZpf2yxtyORFx
# 5IAlXEXwH2c/9k3u/AHmZqAQU7qYSwRB7SishJU5m7fzmMRXLbYEP4w1HBKlYs7O
# Lp5XEThGaS9BJpgftbBOoDB2oDw7Nr9D0gEdhXPt6w4xPS+KrX9fKr8wxjaLlPfz
# OkbJp43BbHs0ZYFmb4+0WYl4wOF/TdJUW2UJ8TZADEq0Vhns7bVW3q5OPkfjsiQf
# PL3aePEcfdEgHdmLAmkH+S4uiLHQSr71cmR0ZriyjKOaYVnVrXaEGkN8xZArjvav
# FHtKWXZeo3MhoBJXCkqhCG37tTym8b/KKvV2uhgtzRtF9ni5yQvl6dm/234vSyLd
# I1ehggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxMzU1WjAvBgkqhkiG
# 9w0BCQQxIgQgXHZ/LnPYG86j88DT3Nf9HtV4COOFue2GodkrPDkHt/IwDQYJKoZI
# hvcNAQEBBQAEggIAVvtI3N0FhRHPA5Q5VxpYuO8YRwwobhBUekPQfdJwcjDb3Gdv
# F41uYwEE46Fs6oHG06oI6yVUUK7793Mx8Etrjj5Hjzr/6m1a/vKS/X4KpqtKjHz9
# VuoAofyuZ0xi2jlhCDu/HUogCkzB8WBpjL8GUcV+04Iywqx8f/eZhbicNS1sN2mn
# 7reCBynToHFef50wS8zRZmbKeCnJ6wqzgTnqAgc97LaxP44KEEhN7sIQJu90TLIF
# C38re0kkWJWh7Od5Lt4/z4EMxsFWl7DGGJXuxOAaOGge5MeKVapbMltZ7AIq+D91
# +oLEz1wGOQImtVbQe42C9cUSZTZ9NvcPRONT8Kz6tWFG/L8vu2TCzhyWd3MDIyG/
# 94Kam+Ohg3DKkJrzkR06SvFr/AvnjepST+74vKOSiJl8XhN+b1LHjTumSQYA3292
# JCjiJpPQG48OVCbz4vathJSFaXvMlKSy8Zdlbgv+EzLGG42nulCJAK2QGqJfD0NH
# zbzHXcI24EE3ZyejpC2P6ToQTWtkT5CIUFUFj46QRgwXLFijVFyrFB5CFi3ylpsV
# dhDtDgqkY3oV92BdN3mchb96t9CqlT95cEMKulD2w362Tw6h4PuLDbuTBM9HDtbE
# ScQW7Rtvkf093YO2FFlCeURayIUHs10TsAHzVWUmmJDkyotppsegqRe8aCY=
# SIG # End signature block
