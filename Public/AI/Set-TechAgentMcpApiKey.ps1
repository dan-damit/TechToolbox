function Set-TechAgentMcpApiKey {
    <#
    .SYNOPSIS
        Securely sets, rotates, or clears DPAPI-encrypted API keys for MCP servers.

    .DESCRIPTION
        Stores secrets under settings.agent.<secretKeyName> in config.secrets.json
        using DPAPI. This command never writes plain-text keys to disk.

    .PARAMETER ServerName
        Optional MCP server name from settings.agent.mcp.servers in config.json.
        When supplied without -SecretKeyName, the command uses the server's
        credentialSecretKeyName if present, otherwise derives one.

    .PARAMETER SecretKeyName
        Explicit secret key name under settings.agent.

    .PARAMETER ApiKey
        Secure API key value to store. If omitted in Set mode and running
        interactively, you will be prompted.

    .PARAMETER Clear
        Removes the stored encrypted key for the resolved secret key name.

    .PARAMETER PassThru
        Returns an object summarizing the operation.

    .EXAMPLE
        Set-TechAgentMcpApiKey -ServerName tavily

    .EXAMPLE
        $secure = Read-Host 'Enter MCP API key' -AsSecureString
        Set-TechAgentMcpApiKey -SecretKeyName mcpTavilyApiKeyEncrypted -ApiKey $secure

    .EXAMPLE
        Set-TechAgentMcpApiKey -ServerName tavily -Clear
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter()]
        [string]$ServerName,

        [Parameter()]
        [ValidatePattern('^[A-Za-z0-9._-]{1,128}$')]
        [string]$SecretKeyName,

        [Parameter(ParameterSetName = 'Set')]
        [securestring]$ApiKey,

        [Parameter(ParameterSetName = 'Clear', Mandatory)]
        [switch]$Clear,

        [Parameter()]
        [switch]$PassThru
    )

    Initialize-TechToolboxRuntime

    if ([string]::IsNullOrWhiteSpace($ServerName) -and [string]::IsNullOrWhiteSpace($SecretKeyName)) {
        throw 'Provide -ServerName or -SecretKeyName.'
    }

    $cfg = $script:cfg.settings.agent

    $resolvedSecretKeyName = $SecretKeyName
    $resolvedServerName = $ServerName
    $resolutionSource = 'Parameter'

    if ([string]::IsNullOrWhiteSpace($resolvedSecretKeyName) -and -not [string]::IsNullOrWhiteSpace($ServerName)) {
        $mcpConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'mcp'
        $mcpServers = @()
        if ($null -ne $mcpConfig) {
            $mcpServers = @(Get-TTAgentConfigValue -ConfigObject $mcpConfig -KeyName 'servers')
        }

        $matchingServer = $null
        foreach ($candidate in $mcpServers) {
            if ($null -eq $candidate) {
                continue
            }

            $candidateName = [string](Get-TTAgentConfigValue -ConfigObject $candidate -KeyName 'name')
            if ([string]::Equals($candidateName, $ServerName, [System.StringComparison]::OrdinalIgnoreCase)) {
                $matchingServer = $candidate
                $resolvedServerName = $candidateName
                break
            }
        }

        if ($null -ne $matchingServer) {
            $configuredSecretKeyName = [string](Get-TTAgentConfigValue -ConfigObject $matchingServer -KeyName 'credentialSecretKeyName')
            if (-not [string]::IsNullOrWhiteSpace($configuredSecretKeyName)) {
                $resolvedSecretKeyName = $configuredSecretKeyName.Trim()
                $resolutionSource = 'ServerConfig'
            }
        }

        if ([string]::IsNullOrWhiteSpace($resolvedSecretKeyName)) {
            $nameParts = @()
            foreach ($part in ($ServerName -split '[^A-Za-z0-9]+')) {
                if ([string]::IsNullOrWhiteSpace($part)) {
                    continue
                }

                $nameParts += ($part.Substring(0, 1).ToUpperInvariant() + $part.Substring(1).ToLowerInvariant())
            }

            if ($nameParts.Count -eq 0) {
                throw ("Unable to derive a secret key name from server name '{0}'. Provide -SecretKeyName explicitly." -f $ServerName)
            }

            $resolvedSecretKeyName = ('mcp{0}ApiKeyEncrypted' -f ($nameParts -join ''))
            $resolutionSource = 'DerivedFromServerName'
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedSecretKeyName)) {
        throw 'Failed to resolve a secret key name. Provide -SecretKeyName explicitly.'
    }

    if ($resolvedSecretKeyName.Length -gt 128) {
        throw 'Resolved secret key name exceeds the 128-character limit.'
    }

    if ($resolvedSecretKeyName -notmatch '^[A-Za-z0-9._-]+$') {
        throw 'Resolved secret key name contains unsupported characters.'
    }

    $result = [ordered]@{
        Success       = $false
        Action        = if ($Clear.IsPresent) { 'Clear' } else { 'Set' }
        ServerName    = if ([string]::IsNullOrWhiteSpace($resolvedServerName)) { $null } else { $resolvedServerName }
        SecretKeyName = $resolvedSecretKeyName
        Source        = $resolutionSource
        SecretsPath   = $null
        KeyStored     = $false
        Detail        = $null
    }

    $isInteractive = $false
    if (Get-Command -Name Test-TTInteractive -ErrorAction SilentlyContinue) {
        $isInteractive = (Test-TTInteractive)
    }

    $secrets = Read-Secrets
    if (-not ($secrets -is [hashtable])) {
        $secrets = @{}
    }

    if (-not $secrets.ContainsKey('settings') -or -not ($secrets.settings -is [hashtable])) {
        $secrets.settings = @{}
    }

    if (-not $secrets.settings.ContainsKey('agent') -or -not ($secrets.settings.agent -is [hashtable])) {
        $secrets.settings.agent = @{}
    }

    if ($Clear.IsPresent) {
        if ($PSCmdlet.ShouldProcess("settings.agent.$resolvedSecretKeyName", 'Remove DPAPI-encrypted MCP API key')) {
            if ($secrets.settings.agent.ContainsKey($resolvedSecretKeyName)) {
                [void]$secrets.settings.agent.Remove($resolvedSecretKeyName)
            }

            $result.SecretsPath = Write-Secrets -Secrets $secrets
            $result.Success = $true
            $result.KeyStored = $false
            $result.Detail = ("Cleared MCP API key secret '{0}'." -f $resolvedSecretKeyName)
            Write-Log -Level Warn -Message $result.Detail
        }

        if ($PassThru.IsPresent) {
            return [pscustomobject]$result
        }

        return
    }

    if ($null -eq $ApiKey) {
        if (-not $isInteractive) {
            throw 'ApiKey was not provided and session is non-interactive. Pass -ApiKey as SecureString.'
        }

        $ApiKey = Read-Host 'Enter MCP API key' -AsSecureString
    }

    $encryptedApiKey = ConvertFrom-SecureString -SecureString $ApiKey
    if ([string]::IsNullOrWhiteSpace($encryptedApiKey)) {
        throw 'Failed to encrypt API key. No value was produced.'
    }

    if ($PSCmdlet.ShouldProcess("settings.agent.$resolvedSecretKeyName", 'Store DPAPI-encrypted MCP API key')) {
        $secrets.settings.agent[$resolvedSecretKeyName] = $encryptedApiKey
        $result.SecretsPath = Write-Secrets -Secrets $secrets
        $result.Success = $true
        $result.KeyStored = $true
        $result.Detail = ("Stored MCP API key in settings.agent.{0} as DPAPI-encrypted secret." -f $resolvedSecretKeyName)
        Write-Log -Level Ok -Message $result.Detail
    }

    if ($PassThru.IsPresent) {
        return [pscustomobject]$result
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCUesQKRaZwcAvW
# wZ2YKlrrVNHwEYvFEtvPxmh0B4QWhqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDDleUBcmGc
# 2AOddGiZU6YAftLgmxyPg1clX38IB5la1DANBgkqhkiG9w0BAQEFAASCAgA1sUzt
# S3D1VJgTKdfzGAXyAT8wt7jCeTvt83ttx60DY3j/eqs2WS4U+smPRcZAesEucBjk
# 2asA2dp6Bvui0LiCSxOvasUVtAWGZ5B5cCjX/ZCveUmef+ezFmtLra0SJOO1lIlJ
# 4QxTEID7TblAvmPdF/bZFBeI//UCvMmzLXqOWZ2TkA6MAYhy33K4ia5DyWMQdhpt
# kPO3/swOQ010BQig8PecegEniUsa3ufc0dNpPoLYtZR0lV06/Md7+7pkpL90ERiJ
# sqXvsMHCz+QERY/FYCPWVYy4lCDhwLOO/T+lCx2Ga8viayjmpsv8Jymcsx/a1j2t
# 6NnhjoQpyg8vm/ivqjWwz8TrR8jhi9nXB8JbYqACKfH+NBA/1Fx35Bl+E/lbaQ7o
# US1630uIfY/l5gnyLrzfsvXNJjg+zlawKK7G4GQeehX1VFzo7Shht5ECbBqt7SHd
# 1BnU9MNrjRknlRIHTPnlxjJQ/j4/WUU+oM1mDiMC/JPvyUG9ibBGlg+J8XX1UWWB
# OAqt1ySSwAa+fVXmVvIsNTwrh5szGxhwaArp22wJGgJsOYDcn/Ezhy5ATIuUcd2E
# kisSnkI05FLWzizek14Fivt7yB3S6k37DLIqbqbZZkYiHbJmaf73uI8Xb+P9vZeh
# 65ykUcFDyQyhBbIfsVErVnY1QnB66Zm8MQvRXaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MTUwMjU5MTJaMC8GCSqGSIb3DQEJBDEiBCClqdvG2oOORavZGiNI
# SnErzT56c6cGkE36UMzlOgnQqDANBgkqhkiG9w0BAQEFAASCAgCnvJjhUO1NQQrT
# TzIP7QCCkbhHzXG0DlcMRjJ2X8/fYRV1El1yQoY3buxZr8AafV7YjhYH94sUBZuo
# U0zrYgIQ+N3DjQnkGjY6qX25u7Jk1ndE1OhjBxWLRSKm1HRburXR/3GADwP+Hn0O
# Qt/C+maZzT6gihMFSZA53pnovyDcp2NfQ7emq7Zc0CreqCRnwZq2/+cvHDo9wlUG
# WFsBnok7KVXd5ETr2DyaPQk866XO4Cpykff1gKliVseryr3q5B2IfyznoIXxyTqb
# iNC52BYeVGqdwVpTSpynxWSRVCOV23pOlXzBYXeNAU5Evex87A2G/2hAfiVqcRLC
# lSFZqfMX++4IB+MBoAjxkJSjyy76VqmH+Z+0IHx3Bco0aYeUn5eXtxERLqN7INGL
# A9RdJuMQjFYnJ1Aje3hYDYvulAwwnBJ/OUf5WHgSlXsqdchNRoxgfkZbgifBTUST
# hIGkkSgiy63/2K+ybGjxFnH4KyHyEbnU2tcpYfbHukFRF1B++lcedRtlm22wsfjY
# NE6FC7eFgo8Dd9ojJjVxvrcP3hNYFLviLXhlORYFKwHpB0NB0F7QDIsY3MMcl3wd
# 3v3HlF9x5ctXQO//CIBJ5c6fNWvpbJsp3lGGVGwjEXatvkLy9j+BY6r39LF/Ki1v
# +ja+RLh7FkywiujSgWWM9rV6TIVLdA==
# SIG # End signature block
