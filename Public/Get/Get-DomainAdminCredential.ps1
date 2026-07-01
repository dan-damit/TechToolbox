function Get-DomainAdminCredential {
    <#
        .SYNOPSIS
        Retrieves, prompts for, persists, or clears the module's domain admin
        credential.

        .DESCRIPTION
        Provides a centralized credential workflow for the module's domain admin
        account. The function supports four primary behaviors:

            1. RETURN CACHED CREDENTIAL
                     If an in-memory PSCredential already exists in
                     $script:domainAdminCred, it is reused by default to avoid repeated
                     prompts during the same session.

            2. REBUILD FROM STORED SETTINGS
                     If no in-memory credential is available, the function attempts to
                     reconstruct one from:
                         - settings.passwords.domainAdminCred.username in config.json
                         - passwords.domainAdminCred.username in config.secrets.json
                         - passwords.domainAdminCred.password in config.secrets.json

                     The password is stored only as DPAPI-protected SecureString text and
                     can only be decrypted under the same Windows user / machine /
                     security context that created it.

            3. PROMPT FOR NEW CREDENTIAL
                     If no usable cached/stored credential exists, or if -ForcePrompt is
                     supplied, the function prompts interactively via Get-Credential and
                     stores the result in memory for the current session.

            4. PERSIST OR CLEAR STORED VALUES
                     -Persist writes the username to config.json and config.secrets.json,
                     plus the DPAPI-protected password blob to config.secrets.json.
                     -Clear removes both stored values and clears the in-memory cache.

        STORAGE MODEL The username is stored in both config.json and
        config.secrets.json for compatibility and easier secrets-only portability.
        The password is never written to config.json; it is stored only in
        config.secrets.json using ConvertFrom-SecureString, which relies on
        Windows DPAPI by default.

        SHOULDPROCESS / SAFETY This function supports -WhatIf and -Confirm for
        operations that modify stored credential state, specifically:

            - clearing persisted values
            - persisting a newly entered credential

        Read-only retrieval and in-memory cache reuse do not require
        confirmation.

        RETURN BEHAVIOR By default, this function is side-effect oriented and
        returns nothing. Specify -PassThru when you want the resulting
        PSCredential object returned to the pipeline.

        .PARAMETER Clear
        Clears the stored domain admin credential from both config.json and
        config.secrets.json, and removes the in-memory cached credential from
        $script:domainAdminCred.

        When specified, the function performs only the clear operation and then
        returns without prompting.

        .PARAMETER ForcePrompt
        Forces an interactive Get-Credential prompt even when a cached in-memory
        credential or decryptable stored credential already exists.

        Use this when the stored credential is stale, incorrect, or needs to be
        replaced for the current session.

        .PARAMETER Persist
        Persists a prompted credential to disk after successful entry.

        The username is written to both config.json and config.secrets.json,
        and the password is written to config.secrets.json as DPAPI-protected
        SecureString text. This parameter has effect only when the function
        enters the prompt path.

        .PARAMETER PassThru
        Returns the resolved PSCredential object to the pipeline.

        Without -PassThru, the function performs retrieval, prompting,
        persistence, or clearing as requested but emits no output object.

        .INPUTS
        None. This function does not accept pipeline input.

        .OUTPUTS
        System.Management.Automation.PSCredential Returned only when -PassThru
        is specified.

        None Returned when -PassThru is not specified, or when -Clear is used
        without requesting output.

        .EXAMPLE
        Get-DomainAdminCredential

        Resolves the domain admin credential using the default precedence order:
        in-memory cache first, then stored config/secrets, then an interactive
        prompt if needed. No object is returned unless -PassThru is also
        supplied.

        .EXAMPLE
        Get-DomainAdminCredential -PassThru

        Retrieves the domain admin credential and returns it as a PSCredential
        object for immediate use by the caller.

        .EXAMPLE
        Get-DomainAdminCredential -ForcePrompt -PassThru

        Forces a fresh credential prompt, updates the in-memory cache for the
        current session, and returns the PSCredential object.

        .EXAMPLE
        Get-DomainAdminCredential -ForcePrompt -Persist

        Prompts for a fresh credential and persists it: username to config.json
        and config.secrets.json, password to config.secrets.json as
        DPAPI-protected text.

        .EXAMPLE
        Get-DomainAdminCredential -Clear -Confirm

        Prompts for confirmation, then removes the stored username and password
        and clears the in-memory credential cache.

        .EXAMPLE
        $cred = Get-DomainAdminCredential -ForcePrompt -Persist -PassThru

        Prompts for a credential, persists it for future runs, and stores the
        resulting PSCredential in $cred for immediate downstream use.

        .NOTES
        - Requires Initialize-TechToolboxRuntime, Checkpoint-ConfigBranch,
            Get-SecretsPath, Read-Secrets, Save-Config, and Write-Secrets.
        - Stored passwords are protected with DPAPI and are generally usable
            only by the same Windows user on the same machine and under the same
            security context that created them.
        - If DPAPI decryption fails, the function logs a warning and falls back
            to prompting instead of terminating immediately.
        - -Persist affects only newly prompted credentials; it does not re-save
            an already cached or reconstructed credential unless prompting
            occurs.
        - -Clear returns immediately after clearing state and does not prompt.

        .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-DomainAdminCredential

        .LINK
        Get-SecretsPath

        .LINK
        Read-Secrets

        .LINK
        Write-Secrets

        .LINK
        Save-Config
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [switch]$Clear,
        [switch]$ForcePrompt,
        [switch]$Persist,
        [switch]$PassThru
    )

    Initialize-TechToolboxRuntime
    Checkpoint-ConfigBranch

    $secretsPath = Get-SecretsPath
    $secrets = Read-Secrets

    $cfgNode = $script:cfg.settings.passwords.domainAdminCred
    $storedUserCfg = [string]$cfgNode.username
    $storedUserSecrets = [string]$secrets.passwords.domainAdminCred.username
    $hasStoredUserCfg = -not [string]::IsNullOrWhiteSpace($storedUserCfg)
    $hasStoredUserSecrets = -not [string]::IsNullOrWhiteSpace($storedUserSecrets)
    # Prefer secrets as the canonical source; fall back to config.json for legacy values.
    $storedUser = if ($hasStoredUserSecrets) { $storedUserSecrets } elseif ($hasStoredUserCfg) { $storedUserCfg } else { '' }
    $storedBlob = [string]$secrets.passwords.domainAdminCred.password

    # --- CLEAR path ---
    if ($Clear) {
        $target = "domainAdminCred (config.json + config.secrets.json)"
        if ($PSCmdlet.ShouldProcess($target, "Clear username + DPAPI password and in-memory cache")) {
            try {
                $cfgNode.username = ''
                Save-Config

                $secrets.passwords.domainAdminCred.username = ''
                $secrets.passwords.domainAdminCred.password = ''
                Write-Secrets -Secrets $secrets | Out-Null

                $script:domainAdminCred = $null

                Write-Log -Level 'Ok' -Message "[Get-DomainAdminCredential] Cleared stored domainAdminCred (config + secrets) and in-memory cache."
            }
            catch {
                Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Failed to clear and persist: $($_.Exception.Message)"
                throw
            }
        }
        return
    }

    # --- Use cached in-memory credential unless forcing prompt ---
    if (-not $ForcePrompt -and $script:domainAdminCred -is [System.Management.Automation.PSCredential]) {
        if ($PassThru) { return $script:domainAdminCred } else { return }
    }

    # --- If not forcing prompt, try to rebuild from stored values ---
    $hasUser = -not [string]::IsNullOrWhiteSpace($storedUser)
    $hasPass = -not [string]::IsNullOrWhiteSpace($storedBlob)

    if (-not $ForcePrompt -and $hasUser -and $hasPass) {
        try {
            $securePwd = $storedBlob | ConvertTo-SecureString
            $script:domainAdminCred = [PSCredential]::new($storedUser, $securePwd)

            # One-time migration: if username existed only in config.json, backfill secrets.
            if (-not $hasStoredUserSecrets -and $hasStoredUserCfg) {
                try {
                    $secrets.passwords.domainAdminCred.username = $storedUserCfg
                    Write-Secrets -Secrets $secrets | Out-Null
                    Write-Log -Level 'Debug' -Message "[Get-DomainAdminCredential] Backfilled domain admin username to config.secrets.json from config.json."
                }
                catch {
                    Write-Log -Level 'Warn' -Message "[Get-DomainAdminCredential] Rebuilt credential, but failed to backfill username to config.secrets.json: $($_.Exception.Message)"
                }
            }

            Write-Log -Level 'Debug' -Message "[Get-DomainAdminCredential] Reconstructed credential from config.json + config.secrets.json."
            if ($PassThru) { return $script:domainAdminCred } else { return }
        }
        catch {
            # DPAPI mismatch usually means: different user or different machine or different security context
            Write-Log -Level 'Warn' -Message "[Get-DomainAdminCredential] Failed to decrypt stored password (DPAPI). Likely different user/machine/context. Will prompt. Details: $($_.Exception.Message)"
            # fall through to prompt
        }
    }

    # --- PROMPT path ---
    try {
        $cred = Get-Credential -Message "Enter Domain Admin Credential"
    }
    catch {
        Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Prompt cancelled or failed: $($_.Exception.Message)"
        throw
    }

    $script:domainAdminCred = $cred

    # Persist on request
    if ($Persist) {
        $target = "domainAdminCred username (config.json) + password (config.secrets.json)"
        if ($PSCmdlet.ShouldProcess($target, "Persist username and DPAPI-protected password")) {
            try {
                # Username -> config.json and config.secrets.json
                $cfgNode.username = $cred.UserName
                Save-Config

                $secrets.passwords.domainAdminCred.username = $cred.UserName

                # Password -> secrets file only (DPAPI protected)
                $secrets.passwords.domainAdminCred.password = ConvertFrom-SecureString $cred.Password
                Write-Secrets -Secrets $secrets | Out-Null

                Write-Log -Level 'Ok' -Message "[Get-DomainAdminCredential] Persisted username to config.json + config.secrets.json and password to config.secrets.json ($secretsPath)."
            }
            catch {
                Write-Log -Level 'Error' -Message "[Get-DomainAdminCredential] Failed to persist credential: $($_.Exception.Message)"
                throw
            }
        }
    }

    if ($PassThru) { return $script:domainAdminCred }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOyJLXnIdoEeQ2
# E6L8sg1x8JaE60bP7LZDJm4idJPQP6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBTvUcOMElX
# yWyOCNnA0Gq+lkLkCo4NbwKBlremElhWijANBgkqhkiG9w0BAQEFAASCAgAPMPey
# A4GymPJXo/0gVvHEnzAtkkF9uQwIenRepvSwMc0PdeD1RJtzd1xQmZ61Oqov5h8n
# d/R+MiOyPLyAWJt+MOegtomf8aMHA3miC7MQZZNA81iDu7YgWkQpkB4EcBn+Vbnc
# d1myUNjIQE9KNFjJUJU4ImVUJXmNBHEGgUtNYMn2uMHA1MTZu/MFTc5+EazyEd+t
# wW5EBMY/G0ISlyIbb/BJt7yIKX6Y8KmbsRjWAQ3ZVe6eIMS6uwqm7pOgc6eDphhd
# l6RNJPZcvYpXJBxdrqP9utkS0mgZ8bKDJMcqvhRwVEklcSBgwQLPLSTLF3iz4Jc5
# OuJrMkT5IWVCJ8pdOY32zFkNaNGJbrsRz2KfDxyYaZo6VGIFkliEChQrAlMmH1Ys
# KE9wp1F2UawmeotSVDpwbLUbpm/rzBKqoRSv50V51IG2N/d7uraARk3Bjk2fLrD+
# 5qnvf1RfcSnxuAEdeVl2K2Nd5UstasEY8G+TnfY8qZIZBw9gXH2RhOHQNCihNu23
# WnrvpXfMr0U3c7NQWZ+yZziPlnhsWin8oYDI1+mMajivxtrxrAT6AXYWKbtyS+96
# dSynaubHZP/xQd3G09/xk9i1lm1ZFqKVU0wyPA5qdQki1c4zCfRCXtpY70OOBxrv
# 63io9KS5MrmOIN3bILQQo7nM2pRPe5WVePL1wqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MDExNDIwMzVaMC8GCSqGSIb3DQEJBDEiBCCfnt7jQTTHQQXIkiV9
# aLpmt+yjuGq8cEAV8ev3w+RdZjANBgkqhkiG9w0BAQEFAASCAgDLglxx5v7z9s3Q
# 1Qrmq3O+DQ8L6LPgCSFL1Knsv3sDdo5sP8+/VMu4x1/Sqbff1+gSPEC+H+/DLdlP
# AcqyjK/mHpFVuCW0TY/O3IG1u/+oNf3v3cSR2TAUV7jImfCpGxMuhkrru2MvnimY
# CpbextfiKlS7lKrn2e76y/ol1rmzKwJhlQrh3BFuLxfWJOWlVUanMmYHP1lh6Xqk
# S8Ib/qZEX8r+ZR9UZ+5lyd+b/UGopMDRlky1z2qGxX0KoLwfnxg14PsR53icAQl2
# +/BEP7LIlqDQ7G4fCNjXeKRnldTwFMkXv3j55G8sURmeBpWr7Yvmyme70Yi/9syW
# g09e2XT5gl5mSCByrd9UUmz7eC5OkEvQNAwe0FkcSUFhpFku+33xRrIYqLOHhiQP
# 44uknK6MaV9dO83ng1rAKfdl1+CEbogckchuwh07hxQhlgv4nVN+MBkQ8UZukE5g
# t09yJcN15J+VntRscV06JXCNaiJ7D9WTIneEj5iPemEYg6VLKWrwyrPkkM/BE0fK
# nMtu+dmk2ciwWOGNJnh8JF+TG5WLQ1PmtK1rhPG+yTqhkoxgFb2mBNcUkrPPaPJn
# daOi7BMtPHGCEcfsyrp4MguwosqLkYAmGgsxvqN5Sf7fTV04a8AEiSb+minYCTPw
# woX1LRVh0hCZzvkYz5UfAjrBrsh9Jg==
# SIG # End signature block
