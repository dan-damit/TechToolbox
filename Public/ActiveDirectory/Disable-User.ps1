function Disable-User {
    <#
    .SYNOPSIS
        Disables an Active Directory user account and performs offboarding
        tasks.
    .DESCRIPTION
        Disables an AD user, moves it to a specified OU, removes group
        memberships, and optionally performs cloud offboarding tasks (EXO,
        Teams) without Graph.
    .PARAMETER Identity
        The identity of the user to disable (sAMAccountName, UPN, etc.).
    .PARAMETER IncludeEXO
        Include Exchange Online offboarding (convert to shared, grant manager
        access).
    .PARAMETER IncludeTeams
        Include Microsoft Teams offboarding (sign-out / cleanup via wrapper).
    .PARAMETER Credential
        Optional AD credential for on-prem operations.
    .INPUTS
        String (Identity)
    .OUTPUTS
        PSCustomObject with step results.
    .EXAMPLE
        Disable-User -Identity 'jdoe' -IncludeEXO -IncludeTeams
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)][string]$Identity,
        [switch]$IncludeEXO,
        [switch]$IncludeTeams,
        [pscredential]$Credential
    )

    # --- Runtime init (config/logging/env) ---
    Initialize-TechToolboxRuntime

    # StrictMode-friendly nested lookups
    function Get-Cfg {
        param([Parameter(Mandatory)][hashtable]$Root, [Parameter(Mandatory)][string[]]$Path)
        $node = $Root
        foreach ($k in $Path) {
            if ($node -is [hashtable] -and $node.ContainsKey($k)) { $node = $node[$k] }
            else { return $null }
        }
        return $node
    }

    $user = $null
    $exoConnected = $false
    $results = [ordered]@{}

    try {
        Write-Log -Level Info -Message ("Starting Disable-User workflow for '{0}'..." -f $Identity)

        # --- Config load & validation ---
        $cfg = $script:cfg
        if (-not $cfg) { throw "Effective config is null. Check config.json path and schema." }

        $settings = Get-Cfg -Root $cfg -Path @('settings')
        if (-not $settings) { throw "Config missing 'settings' node." }

        $off = Get-Cfg -Root $settings -Path @('offboarding')
        if (-not $off) { throw "Config missing 'settings.offboarding' node." }

        $exo = Get-Cfg -Root $settings -Path @('exchangeOnline')
        $teamsCfg = Get-Cfg -Root $settings -Path @('teams')

        # Respect config defaults only when caller did not specify switches
        if (-not $PSBoundParameters.ContainsKey('IncludeEXO') -and $exo -and $exo.includeInOffboarding) { $IncludeEXO = $true }
        if (-not $PSBoundParameters.ContainsKey('IncludeTeams') -and $teamsCfg -and $teamsCfg.includeInOffboarding) { $IncludeTeams = $true }

        if ($off.PSObject.Properties.Name -contains 'disabledOU' -and [string]::IsNullOrWhiteSpace($off.disabledOU)) {
            Write-Log -Level Warn -Message "settings.offboarding.disabledOU is empty; OU move will be skipped."
        }

        # --- Resolve user (Graph-free Search-User) ---
        Write-Log -Level Info -Message ("Offboarding: Resolving user '{0}'..." -f $Identity)
        $suParams = @{ Identity = $Identity; IncludeEXO = $IncludeEXO; IncludeTeams = $IncludeTeams }
        if ($Credential) { $suParams.Credential = $Credential }
        try { $user = Search-User @suParams } catch { throw "Search-User error for '$Identity': $($_.Exception.Message)" }
        if (-not $user) { throw "User '$Identity' not found." }

        # --- Lazy-load AD helpers exactly when needed ---
        Use-Private 'ActiveDirectory\Disable-ADUserAccount.ps1'  -RequiredFunction 'Disable-ADUserAccount'
        Use-Private 'ActiveDirectory\Move-UserToDisabledOU.ps1'  -RequiredFunction 'Move-UserToDisabledOU'
        Use-Private 'ActiveDirectory\Remove-ADUserGroups.ps1'    -RequiredFunction 'Remove-ADUserGroups'
        Use-Private 'ActiveDirectory\Write-OffboardingSummary.ps1'    -RequiredFunction 'Write-OffboardingSummary'
        Use-Private 'ActiveDirectory\Format-UserRecord.ps1'    -RequiredFunction 'Format-UserRecord'

        # --- Disable AD user ---
        Write-Log -Level Info -Message ("Offboarding: Disabling AD account for '{0}'..." -f $user.SamAccountName)
        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Disable AD account")) {
            $disableParams = @{ SamAccountName = $user.SamAccountName; DisabledOU = $off.disabledOU }
            if ($Credential) { $disableParams.Credential = $Credential }
            $results.ADDisable = Disable-ADUserAccount @disableParams
        }

        # Determine if OU move already happened in Disable-ADUserAccount
        $movedHandled = $false
        if ($results.ADDisable) {
            if ($results.ADDisable -is [hashtable]) { $movedHandled = [bool]$results.ADDisable['MovedToOU'] }
            else { $movedHandled = [bool]$results.ADDisable.MovedToOU }
        }

        # --- Move to Disabled OU if still needed ---
        if ($off.disabledOU -and -not $movedHandled) {
            Write-Log -Level Info -Message ("Offboarding: Moving '{0}' to Disabled OU..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Move AD user to Disabled OU")) {
                $moveParams = @{ SamAccountName = $user.SamAccountName; TargetOU = $off.disabledOU }
                if ($Credential) { $moveParams.Credential = $Credential }
                $results.MoveOU = Move-UserToDisabledOU @moveParams
            }
        }

        # --- Optional: cleanup AD groups ---
        if ($off.cleanupADGroups) {
            Write-Log -Level Info -Message ("Offboarding: Cleaning AD group memberships for '{0}'..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Cleanup AD group memberships")) {
                $grpParams = @{ SamAccountName = $user.SamAccountName }
                if ($Credential) { $grpParams.Credential = $Credential }
                $results.ADGroups = Remove-ADUserGroups @grpParams
            }
        }

        # --- Hybrid auto-disable short-circuit ---
        if ($off.useHybridAutoDisable) {
            Write-Log -Level Info -Message "Hybrid auto-disable enabled; cloud actions deferred to AAD Connect."
            Write-OffboardingSummary -User $user -Results $results
            Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ? $user.UserPrincipalName : $Identity))
            return [pscustomobject]$results
        }

        # --- Cloud actions (Graph-free) ---
        Write-Log -Level Info -Message "Proceeding with cloud offboarding actions (Graph-free)..."

        # Exchange Online (convert mailbox, grant manager access)
        if ($IncludeEXO) {
            Use-Private 'Exchange\Import-ExchangeOnlineIfNeeded.ps1'    -RequiredFunction 'Import-ExchangeOnlineIfNeeded'
            Use-Private 'Exchange\Connect-ExchangeOnlineIfNeeded.ps1'     -RequiredFunction 'Connect-ExchangeOnlineIfNeeded'
            Use-Private 'M365\Convert-MailboxToShared.ps1'            -RequiredFunction 'Convert-MailboxToShared'
            Use-Private 'M365\Grant-ManagerMailboxAccess.ps1'         -RequiredFunction 'Grant-ManagerMailboxAccess'
            Use-Private 'Exchange\Invoke-DisconnectExchangeOnline.ps1'    -RequiredFunction 'Invoke-DisconnectExchangeOnline'

            $showProgress = $false
            if ($exo -and ($exo.PSObject.Properties.Name -contains 'showProgress')) { $showProgress = [bool]$exo.showProgress }

            try {
                $null = Connect-ExchangeOnlineIfNeeded -ShowProgress:$showProgress
                $exoConnected = $true
            }
            catch {
                Write-Log -Level Warn -Message ("EXO connect failed: {0}" -f $_.Exception.Message)
            }

            if ($user.UserPrincipalName) {
                if (Get-Command -Name Convert-MailboxToShared -ErrorAction SilentlyContinue) {
                    if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Convert mailbox to shared")) {
                        Write-Log -Level Info -Message ("Converting mailbox to shared for '{0}'..." -f $user.UserPrincipalName)
                        $results.Mailbox = Convert-MailboxToShared -Identity $user.UserPrincipalName
                    }
                }
                if (Get-Command -Name Grant-ManagerMailboxAccess -ErrorAction SilentlyContinue) {
                    if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Grant manager mailbox access")) {
                        Write-Log -Level Info -Message ("Granting manager access for '{0}'..." -f $user.UserPrincipalName)
                        $results.ManagerAccess = Grant-ManagerMailboxAccess -Identity $user.UserPrincipalName
                    }
                }
            }
        }

        # Teams (Graph-free)
        if ($IncludeTeams) {
            Use-Private 'Teams\Connect-MicrosoftTeamsIfNeeded.ps1'  -RequiredFunction 'Connect-MicrosoftTeamsIfNeeded'
            Use-Private 'Teams\Remove-TeamsUser.ps1'                -RequiredFunction 'Remove-TeamsUser'

            try { $null = Connect-MicrosoftTeamsIfNeeded } catch {
                Write-Log -Level Warn -Message ("Teams connect failed: {0}" -f $_.Exception.Message)
            }

            if ($user.UserPrincipalName -and (Get-Command -Name Remove-TeamsUser -ErrorAction SilentlyContinue)) {
                if ($PSCmdlet.ShouldProcess($user.UserPrincipalName, "Teams sign-out / cleanup")) {
                    Write-Log -Level Info -Message ("Signing out of Teams / cleanup for '{0}'..." -f $user.UserPrincipalName)
                    $results.Teams = Remove-TeamsUser -Identity $user.UserPrincipalName
                }
            }
        }

        # --- Summary & return ---
        Write-Log -Level Info -Message ("Offboarding: Generating summary for '{0}'..." -f ($user.UserPrincipalName ? $user.UserPrincipalName : $Identity))
        Write-OffboardingSummary -User $user -Results $results
        Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ? $user.UserPrincipalName : $Identity))
        return [pscustomobject]$results
    }
    catch {
        $who = ($user -and $user.UserPrincipalName) ? $user.UserPrincipalName : $Identity
        Write-Log -Level Error -Message ("Disable-User failed for '{0}': {1}" -f $who, $_.Exception.Message)
        throw
    }
    finally {
        if ($IncludeEXO -and $exoConnected) {
            try { Invoke-DisconnectExchangeOnline -ExchangeOnline $exo } catch {}
        }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWM/pht43uGncN
# hYy1CoAE8+koS1c9VDlCIB3wdBcyIKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAzYJw3y8/d
# Ek1hyiBYzfFdm0TKqfscncsDghEVSii95jANBgkqhkiG9w0BAQEFAASCAgCvKtyz
# DnBo7S8cgi2Wkg9q/+DTDsvKJimwCiedhZ06d1ONlSV0eMvl3DNDouT6Loqx6Iy4
# gwashG7pOHxAaBKgu+X7ZbV3KoVZHsBPjiLNhnaxRDpN6YN+3lik5XHqjfe2zZ7J
# dwKhPCdDEmU2QLM/iFxgPx/3exju2kSVJnqh1qMb/0Ez9keDTpSjRgQgqTq1JqfC
# Y3P/lQWbzS14uB9Dci6QxgJPMFIN+sPRREhz9OdekB+VjdOIMZO/aiPzhLgIdzr7
# bFb5kI2VGh+4k/wpX0SYT3bXzOl1cq4SGcTN05UqQGdmS0BwCgSsU7M1U+uPnLfo
# PPUsvrSXEN2oAFCg9e/X0cf5lRWZ+xKTczxfcmFJO4/Frr7szEyQnd8uXMVDIT+m
# VRujuMN3XHC44gbAszvOfZmFVji2FHK/1iI3NEiIbX8Vos+onl6pVuHE95txjczE
# VaHPytmIkUvnefOQ1C5lappbEPxugXWnBZ28O0cyRV32Cy5RWKGhjygqGaiyJ2Q3
# UWfalbruoQpb1aptARi7dCXQe7Y0ywVXixmXnGchaBuZbv9BXWo//J95AgKRGv38
# mmoWCZq+BBEHAxfPrIpIkdeuNuCNz/CDsPtakx+gFvH0/jbbz7C8ui/4Oa25HYSJ
# zo+fPLuMVgfJo3yq5aPILy/tuofJru3+m5keIaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTAyMjUzMjdaMC8GCSqGSIb3DQEJBDEiBCB6WyZnssXL3fdRyUcC
# p+5EXwS+ioRuXAE9ikOuY7b5ZzANBgkqhkiG9w0BAQEFAASCAgBXRT5/xXEjX1kV
# J9cQiFrfqu/v0fggsawHDlNRoyS6h9uAHWbKYfzXRIsTsdEnuUSJa+qgkwkLMhjt
# /9d1ueleXoZRW4JPKS8njO3VOIdTKDjd3vyiiWhfaiDC/TazfVjfGA3Vl4Spkw7q
# Oa1bzE5DyQjSlSr7XludsgJTS3WH3zvI7y3jjJ+qSyAOuXvJmc2atTV2A+Rb0kz7
# vQmwHSWVmhf1JkT/7pEXalI9AfeFz8DguoWUOstjXiO0UPSWBtYD6qsV3gBuxrXi
# ZNq1td9cP55VG3xQ6JtQE9hYDBZbD/03nfTe9UdAG21f/ditN63vGwuyE44P2sDL
# Dje5W7WKfVvW2IWdsxHiJaQKITM91uAa3AT4U7GdGgHM8Q9kwSiml3gMWbATR5An
# KVeeBev9KkRy/708O0TdlglD9hVR+UEDsgagbNsuqE/Ll0yAXwcmuCNPwMG9jenZ
# qF8bUJQ8m9t7CyJRWOdr5/6etncch5pxiBDsxHoZyjSRceD3nL2iZE7SGHjt7rhH
# XNuEKxzqH34Vcn/NXABcxJ2NDW2sofATCSFvpoZQN+tHPcTQgvD/Xznf2wUqXFaL
# orvD19Iq5VOYXILZlX9fexUQKikOkmmgM/s8ReCITCjcImbffTCYTFdKNcijydWk
# UjDGnq6riMAaS8aOgMue4jAqS7CkeA==
# SIG # End signature block
