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
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfFa4Q13fMM05x
# VHkYKVk/uD1xYgSg5ROWcOsBmwGx/aCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCBQsDteMxd
# Lla9z8oKCfUIRWKsboG8eeLBmPzDh1WLyjANBgkqhkiG9w0BAQEFAASCAgB1xZzu
# gt2/ybSE0BpEOwFN+vqlMdP3OUOvE2OTg/x8xTLWnITjUokC4wBam6tiWlyaC+x/
# aDiW3B8dvncd4PQDnwjdP4Rp89nyVf6Eyc67RfRHuiYKIaIOoygFEEvvej/6h/wC
# 5ZuMSzdfmJ0xhmjgZl/VOHnoRY6ybhgCOkIvNWsIImpM9Pu+twHkSRapUS2u2vR8
# C2yWVN1rS1dQCB7zAehWJsvd8H0Gg1JSlg3QAUB+1qjLSjuuVhP4/tCJ+yplde5U
# 2b7nXsOD71IpAVb7QUVLwPtu2iyKVFqKYjYT8WwQW33tSJ/b9DiX0RfyPObOe19i
# Pxih7Ar2s4SDL7dSTT4n4bUprdiT6u0t88FHxz5/ww0WVg7Wnko/TQsnrzDUukEd
# DhR1/f+t/dqS6edduPpSOkpxvB13IjbrE/JL2/K4XWBAx7JLtNYbI/zX4Y+yyz+d
# 19KBFVVaoaClyzBK3XGeovM8U9nxmnHYJ0z8npX+wyNEVt2u5HRsZ1fT1CmwyGcA
# eO1Ylu3c3BxTbjBVSYNsRy+CLnM107beyKmChSIb4EQ0f/HzpTuWhHAOjaw1PcZ5
# cwyAxdbT8j7FG8qzzPh4vvc4AoHUDxn1+/M/iA2HM9iNBKILB6igBdNhYVUoNmS/
# uFfBcIp3X+Gne9Qy/vUPzZDhiUEqNbbM9W5RCaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MTgxNzE4MjZaMC8GCSqGSIb3DQEJBDEiBCA4ngrOXxU3zVRITRx+
# ip0JIiiCoeVRRJTRJrWFYv+9EjANBgkqhkiG9w0BAQEFAASCAgCOrhyvTbGuVks+
# PHMopagNUh2AXJAjU0GrRRrhB+3QiwU80j4N7+fSl9I/7jr8BkDAYe949P4WElnE
# ufbQw3XedGMUpa1wsIl2+w4l4Hz4pwhKhJ0n20UiXkMvYgebfOAVnU5fDI17AMY+
# 3AxgBtWOZI83e/XpGQixjnEBd9bkuBh/zhBPRjhNCXV77iRqZX+xEoEQ3J8bfiYE
# iCyLD1idw6LmC/qexxHn9X5d3EMLPmPlvbA8H85hbmnu+6E8v0jUgE2WrWs/d88t
# SJ5D/S+fV9UjQy9ZEch+w6RssVhRN1JeIfib6eknaE49/MDXnR6oP9sDEjSBjWZy
# /kpXUpfvylnNlbH6rcN6MD0gQ9CFROy24cY1uIHQiUqcFe6q4h8B0K1VAypFADgm
# EitV0jx94uv0mkrsaSmfopWilZ/GZlFFgYBRH6Ldt82GKMM5o3uVzdDXAj1loDjb
# j4prAOw+p6NTaLJsA4hdBK8njqmmuw4VMBHdZcyJOC5NUo2tTaVQoWWLr/1/eUcc
# GCIq7Bt2dK0rdYUBS5sVKegSe+yiF8Kfm6ID1Bc1srUfboMzlv4d1DPFfzIpyWnK
# 1IuDjgxvfNnGpdRpvu7x/2gzW6IwzHjRWeaEN8yBAGRZsVJ66j1eSYIhVeNz/n5s
# xgce1hS7ANCquO05XW/0jnKN8mSYBw==
# SIG # End signature block
