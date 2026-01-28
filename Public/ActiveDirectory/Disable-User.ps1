
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
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA6ZTl7jwfzO3y6
# wAjRCGo6pvYyMp5YFtzdxF9M8kJT26CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBsXjPA8hl3
# I97IRUpRdsbGlRgyz6E22LB+aM1e8AfG9zANBgkqhkiG9w0BAQEFAASCAgCHMzJ2
# R7be71N3xE3h2CEOOkjWytW09Bobp4o+SJl1v+zs8EJ22a1yPi5J+WfM4+GxgNTn
# YMKX/n0cQMcsQKfG1HxMDO8+zCBRoHjM3XvN29vDPGgbULEer2sXSEn3iADwZ9QE
# M9PglInjsgwCYiuTMhgjnLmJrXecnrjnST7b0KG0ekRZVHQ26gqRsk+/TWPzG96k
# qoemPh/pKgsx1ZWhzasuguY8frzOWVfUungScRcjDioLCM/6czV3G8Kr9fNBJqOd
# 7JES+YdY+FB/N1kGZ1cOw6bMV/QSKog+RjxFTTf21+tyb1QCHdNIva6cnTJAYO8R
# tSdm5y/pJRkeGdA5u28m/eEzJeZLonXF0FjDEuhPdVRbPS6qkG3+c9Ac7x99IPhZ
# hHrJBIxIrQPgMuXIqlpUlVef/C6sPObGXrF3bAjJBOeiMu08781DNi9lZd/yEiN4
# TpgcsNbxgR5XLFyHfEuaLPjiSgXkWgq21wWYxiFNuih5SPiskejMaYIfvTYLKyac
# gj4k0kbYnWKHnh7lXNo79PirWYcGg1uJ6YGsirZ4l+DF8H3sYV/ikq40SfeUQs1W
# 9m4mdVvc00HDPtecRwSUW2KK9Bsorf8jRsQDYRJ+6W9AL55rr3tH0xqzyNDfpjMP
# bCTLuTKAacUm6yAPkZOm4RZYGHlLcTzstgiUYKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMjgyMTQxMTZaMC8GCSqGSIb3DQEJBDEiBCAa6bGjm94iV2AbZKS8
# 7zzGPV/wAuI71TPrBULODU0L2jANBgkqhkiG9w0BAQEFAASCAgAWugrYObyBbMYb
# pbi7r5a7yElSh23QPW5ObalYl0iIJnTo23Ab8RJ4IR1kd9sFCDDyiP2rITfPoj3s
# /cUaiFP2zRbpAdm/7Uhp8G74u/mC9fQO7q5jQSNC88bSnNGfcHodLuvdSZ/bIDCP
# NU0qOUibx/F8eJjlbGaN+ItvXYTPIaIQmL3F1LdXXezKU7dLCJ+UGGi9b8nNzHXO
# jDn3WFYJEkZtxTpsYIOzF4XZOkBvU6WrU9gmb3oWeFhPEXiM7KEuQA1UarlXyQfe
# oczWfA1kmvpOClAsH/MhmehP0KEF070+8YPulHrxTtpztqjg05UmYdfcjElGja8H
# 6EKO5v2GUEf2YqJbY119iz0W0h9FYIe94V9FnZqsG5RqDNpWkrSnCcqK8cH+Tvd+
# oH3tAhksk4i3SB6CASwi6Si5qPGQlNxXf3wuZ28FtV3F7JG2jub7D93th25ZvY98
# e3mSqZ16nYxLSUObzz+tQ1tZqRlysvAkFtFX/BWV2A1aAfYr8Jv4Rz0SzY2K+ZeP
# 463Qy3C7UbJ2yqlOVxnFOTAPpVbjI4X7LxdlnBHa5UQ6ncR8o2XjcBTEgrIoG3Ym
# 5FYUOlolat6kzwWTrlD9DyIvtIMzt3L1BFaO+O1b1u643jnRgZO9JHhD67sb3bUl
# TMY9vjFtRA203V1m3nrg75akCBg9nw==
# SIG # End signature block
