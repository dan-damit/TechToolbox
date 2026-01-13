
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
    .PARAMETER SearchName
        The original Compliance Search Name/ID to clone. If omitted, a new
        mailbox-only search will be created via prompted KQL query.
    .PARAMETER Log
        A hashtable of logging configuration options to merge into the module-
        scope logging bag. See Get-TechToolboxConfig "settings.logging" for
        available keys.
    .PARAMETER ShowProgress
        Switch to enable console logging/progress output for this invocation.
    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" `
            -CaseName "Legal Case 123" -SearchName "Original Search"
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter()][ValidateNotNullOrEmpty()][string]$CaseName,
        [Parameter()][ValidateNotNullOrEmpty()][string]$SearchName,
        [Parameter()][hashtable]$Log,
        [switch]$ShowProgress
    )

    # Global safety
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
 
    # Defensive: guarantee $script:log exists in this module scope
    if (-not (Get-Variable -Name log -Scope Script -ErrorAction SilentlyContinue)) {
        Set-Variable -Name log -Scope Script -Value @{ enableConsole = $false }
    }

    # --- Ensure a module-scope logging bag exists, then merge ---
    if (-not ($script:log -is [hashtable])) {
        # Safe defaults; do not assume console until asked
        $script:log = @{ enableConsole = $false }
    }
    if ($Log) {
        foreach ($k in $Log.Keys) { $script:log[$k] = $Log[$k] }
    }

    # Allow caller to force console on via -ShowProgress
    if ($ShowProgress) { $script:log["enableConsole"] = $true }

    # Turn on Information/Verbose streams BEFORE try if console requested
    if ($script:log["enableConsole"]) {
        $InformationPreference = 'Continue'
        $VerbosePreference = 'Continue'
    }

    # Initialize any variables referenced in finally (StrictMode-safe)
    [bool]$autoDisconnect = $false

    try {
        # Initialize for StrictMode safety
        [string]$cloneName = $null
        $searchObj = $null
        [bool]$submitted = $false

        # Load config
        $cfg = Get-TechToolboxConfig
        $purv = $cfg["settings"]["purview"]
        $defaults = $cfg["settings"]["defaults"]

        $promptCase = $defaults["promptForCaseName"] ?? $true
        $promptSearch = $defaults["promptForSearchName"] ?? $true
        $autoConnect = $purv["autoConnect"] ?? $true
        $autoDisconnect = $purv["autoDisconnectPrompt"] ?? $true   # now set for finally

        # Import EXO module
        Ensure-ExchangeOnlineModule -ErrorAction Stop

        # Prompt inputs
        if (-not $UserPrincipalName) { $UserPrincipalName = Read-Host "Enter UPN (e.g., user@domain.com)" }
        if (-not $CaseName) {
            if ($promptCase) { $CaseName = Read-Host "Enter eDiscovery Case Name/ID" }
            else { throw "CaseName is required but prompting is disabled by config." }
        }
        if (-not $SearchName) {
            if ($promptSearch) {
                $SearchName = Read-Host "Enter original Compliance Search Name/ID in case '$CaseName' (or press Enter to create new)"
            }
            else {
                Write-Log -Level Info -Message "No SearchName provided and prompting disabled; proceeding to clone/create."
            }
        }

        # Connect (IPPS/ Purview) if enabled
        if ($autoConnect) {
            Connect-PurviewSearchOnly -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        }
        else {
            Write-Log -Level Info -Message "AutoConnect disabled by config; ensure an active Purview session exists."
        }

        # Clone or create mailbox-only search (filter output to the string name)
        Write-Log -Level Info -Message ("Cloning/creating mailbox-only search from '{0}' in case '{1}'..." -f $SearchName, $CaseName)

        $cloneName = New-MailboxSearchClone -CaseName $CaseName -OriginalSearchName $SearchName |
        Where-Object { $_ -is [string] } |
        Select-Object -First 1

        if ([string]::IsNullOrWhiteSpace($cloneName)) { throw "Clone name was not resolved to a string." }
        Write-Log -Level Ok -Message ("Clone name: '{0}'" -f $cloneName)

        # Wait for search completion
        $timeout = [int]$purv.purge.timeoutSeconds; if ($timeout -le 0) { $timeout = 1200 }
        $poll = [int]$purv.purge.pollSeconds; if ($poll -le 0) { $poll = 5 }

        Write-Log -Level Info -Message ("Waiting for search '{0}' (case '{1}') to complete (timeout={2}s, poll={3}s)..." -f $cloneName, $CaseName, $timeout, $poll)
        $searchObj = Wait-SearchCompletion -SearchName $cloneName -CaseName $CaseName -TimeoutSeconds $timeout -PollSeconds $poll -ErrorAction Stop

        if ($null -eq $searchObj) { throw "Search object not returned for '$cloneName' (case '$CaseName')." }
        Write-Log -Level Ok -Message ("Search status: {0}; Items: {1}" -f $searchObj.Status, $searchObj.Items)
        if ($searchObj.Items -le 0) { throw "Search '$cloneName' returned 0 mailbox items. Purge aborted." }

        # Submit HardDelete purge (respects -WhatIf/-Confirm)
        if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $cloneName), 'Submit Purview HardDelete purge')) {
            $null = Invoke-HardDelete -SearchName $cloneName -CaseName $CaseName -Confirm:$false -ErrorAction Stop
            $submitted = $true
            Write-Log -Level Ok -Message ("[Done] Purview HardDelete purge submitted for '{0}' in case '{1}'." -f $cloneName, $CaseName)
        }
        else {
            Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
        }

        # Final breadcrumb
        Write-Log -Level Ok -Message ("Summary: clone='{0}' status='{1}' items={2} purgeSubmitted={3}" -f $cloneName, $searchObj.Status, $searchObj.Items, $submitted)
    }
    catch {
        # Guaranteed-visible error; avoids relying on $script:log in early failure
        Write-Error ("[ERROR] {0}" -f $_.Exception.Message)

        # If console enabled, also use your logger
        if ($script:log["enableConsole"]) {
            Write-Log -Level Error -Message ("[ERROR] {0}" -f $_.Exception.Message)
        }
        throw
    }
    finally {
        if ($autoDisconnect) {
            $disconnect = Read-Host "Disconnect Exchange Online session now? (Y/N)"
            if ($disconnect -match '^(?i)(Y|YES)$') {
                try {
                    Disconnect-ExchangeOnline -Confirm:$false
                    if ($script:log["enableConsole"]) { Write-Log -Level Info -Message "Disconnected from Exchange Online." }
                }
                catch {
                    if ($script:log["enableConsole"]) { Write-Log -Level Warn -Message ("Failed to disconnect cleanly: {0}" -f $_.Exception.Message) }
                }
            }
            else {
                if ($script:log["enableConsole"]) { Write-Log -Level Info -Message "Session remains connected." }
            }
        }
        else {
            if ($script:log["enableConsole"]) { Write-Log -Level Info -Message "AutoDisconnectPrompt disabled by config; leaving session as-is." }
        }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC71Lh1HNbjSsHa
# gWSj2fpyPQI6iNQVyftGpYRMPONyT6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAd1igU43S1
# j0dbAyqVPvYhISboq0JpE8jRcF9DuyJMNzANBgkqhkiG9w0BAQEFAASCAgC8Fsnf
# 87FsnUceon9JfcmZOrTcewy/r/PLwQoJwg+JSkVPaB1ojvb7GJBJOt+NTJT0pKKG
# D+SYJYZlGQnyAjdzSVWAPJlsGZNvdU5ODWn+bTZ6FXi+AryBV+ahqTY4org6tYXm
# QoXnjjliuO5vD/na748k1qWbNWvEbV9hhOQ96zprTPoPxScwI3y1rZY6vmqxAVjI
# ENLDAF4fO0q91sH3pz//qV+n0Eb8sIZbIvTAVFM4zmg7bUE6ZGFF92PjkMSpIcbL
# GaWTEVbzIgCATBMXvuKKDte++jlO22NNakIbzqzr144Egu40KPMiYP50i22Crk8a
# 0XuVmTqlK0EcxedyMW/LqhMmYb8/3lC+knmBRjbOuNEN+DsvAuJr6dLrlzFFezXI
# pkNIjd446fa6bd+0T763se/9ZDa79yXoppbaVZj67DG3/HoR3FunHGRs6H6IuSoJ
# b8oRS3fkt/87X9wcrzZ68uEc1Bud8l4pnmb6FtAnRO8BD+g1b1vauo3AnZw6gWWH
# /P2EW3OKhSZbQrXLN8hPxaJcLqOgUQbgC8W0W2kIJSpV1zUOo7QDlSF9+iQvCGxS
# gdFkhbM9m5opCAEYGLyGKLlIx14XsEsadhwOe6p5d3iqtIL6mNMDRXDshrFhVtCy
# XDWA6qxqR5nLnFV58GNIao4gqebtGFyVCqDneaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTMyMjExMjJaMC8GCSqGSIb3DQEJBDEiBCATJP1IxUl0uc80PzVI
# 70LaSm1l8+k+umilZcbHMON3STANBgkqhkiG9w0BAQEFAASCAgCVRH9bECByxPkm
# LnbWxEDQ56iPp8mwxvFX2PmGBbXe0Wi+2ZUQrgL4afip4WfN8AzxGtLRE9iRJ9wL
# W6pkvmzgKN82rDWwP8EyDlcLSjEp0CWkh6GZkbjvNB8MjqiEqalYiIhoGQ+gvvlm
# udvaeTcLKDWTHMWtYXVvGGhhjPaeW5i1MBIUPZxAYHlv85MT0NC4kM4yLr0YYwZ8
# TR+XlVn/FEElEzCv+5hhAyPozkoJU3P5Az1mpiSUkDz/9oBLiatOz42eiXJUf1Xv
# AQgiV62L0LVUaoXWiz78gocVjZuQFTpawx0A+Jw1qdx6X957bY/4Vw2Wekx0OPz8
# pS77cU7RRWoCWE6dtmT5jBPb+ZgGCeh3jDWZoEsxhnveqS6K0OYmD7zIM5DLnqoe
# JtCUzyD7KsfBMZZk1VTpF1wLQFpYoz4OOzby+jshR4b1U2Fg7lwV+V+vnOxyU9fY
# gCL8gAqMnt+FqCe4wZfFuU5+L4ybYXguAWbArLfwNLzA3JMmB1Nhhm07PjOmchFO
# 9whCIJldiwQAmAnfSRQ5mr5yorFoBDYoW0OM2oOAD7FASfQrO+3RCvqa3bi4PFzU
# mjb4pdXpoE6hwdhjnjBYWC4JI/hE6uxoVCYZbxasJbZxRGRSJMq+zf7DxsJYMrf1
# EJCoifcaGC563VSNuuJBMrumuFt/Mw==
# SIG # End signature block
