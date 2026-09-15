function Get-TTAgentConfigValue {
    [CmdletBinding()]
    param(
        $ConfigObject,
        [string]$KeyName
    )

    if ($null -eq $ConfigObject -or [string]::IsNullOrWhiteSpace($KeyName)) {
        return $null
    }

    if ($ConfigObject -is [hashtable] -and $ConfigObject.ContainsKey($KeyName)) {
        return $ConfigObject[$KeyName]
    }

    $property = $ConfigObject.PSObject.Properties[$KeyName]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Resolve-TTAgentCloudApiKey {
    [CmdletBinding()]
    param(
        $ConfigObject,
        [string]$ProviderName,
        [string]$EnvVarName,
        [string]$EncryptedOverride,
        [switch]$PreferEncryptedOnly
    )

    if ($ProviderName -eq 'ollama') {
        return @{ Key = $null; Source = 'NotRequired'; Error = $null }
    }

    if (-not $PreferEncryptedOnly.IsPresent -and -not [string]::IsNullOrWhiteSpace($EnvVarName)) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvVarName)
        if (-not [string]::IsNullOrWhiteSpace($envValue)) {
            return @{ Key = $envValue; Source = "Environment:$EnvVarName"; Error = $null }
        }
    }

    $encryptedValue = $EncryptedOverride
    if ([string]::IsNullOrWhiteSpace($encryptedValue)) {
        $encryptedValue = [string](Get-TTAgentConfigValue -ConfigObject $ConfigObject -KeyName 'apiKeyEncrypted')
    }

    if ([string]::IsNullOrWhiteSpace($encryptedValue)) {
        return @{ Key = $null; Source = 'Missing'; Error = $null }
    }

    try {
        $secureApiKey = $encryptedValue | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)
        try {
            $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        if ([string]::IsNullOrWhiteSpace($plainApiKey)) {
            return @{ Key = $null; Source = 'DPAPI'; Error = 'DPAPI blob decrypted to empty value.' }
        }

        return @{ Key = $plainApiKey; Source = 'DPAPI'; Error = $null }
    }
    catch {
        return @{ Key = $null; Source = 'DPAPI'; Error = $_.Exception.Message }
    }
}

function Resolve-TTAgentStoredSecret {
    [CmdletBinding()]
    param(
        $ConfigObject,
        [string]$SecretKeyName,
        [string]$EnvVarName
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvVarName)) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvVarName)
        if (-not [string]::IsNullOrWhiteSpace($envValue)) {
            return @{ Key = $envValue; Source = "Environment:$EnvVarName"; Error = $null }
        }
    }

    $encryptedValue = [string](Get-TTAgentConfigValue -ConfigObject $ConfigObject -KeyName $SecretKeyName)
    if ([string]::IsNullOrWhiteSpace($encryptedValue)) {
        return @{ Key = $null; Source = 'Missing'; Error = $null }
    }

    try {
        $secureValue = $encryptedValue | ConvertTo-SecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        try {
            $plainValue = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        if ([string]::IsNullOrWhiteSpace($plainValue)) {
            return @{ Key = $null; Source = 'DPAPI'; Error = 'DPAPI blob decrypted to empty value.' }
        }

        return @{ Key = $plainValue; Source = 'DPAPI'; Error = $null }
    }
    catch {
        return @{ Key = $null; Source = 'DPAPI'; Error = $_.Exception.Message }
    }
}

function Resolve-TTAgentMcpBearerSecret {
    [CmdletBinding()]
    param(
        $ConfigObject,
        $ServerConfigObject
    )

    $serverName = [string](Get-TTAgentConfigValue -ConfigObject $ServerConfigObject -KeyName 'name')
    if ([string]::IsNullOrWhiteSpace($serverName)) {
        $serverName = 'unnamed'
    }

    $envVarName = [string](Get-TTAgentConfigValue -ConfigObject $ServerConfigObject -KeyName 'credentialEnvironmentVariable')
    if ([string]::IsNullOrWhiteSpace($envVarName)) {
        return @{
            Key        = $null
            Source     = 'MissingEnvironmentVariableName'
            Error      = 'credentialEnvironmentVariable is required for bearer-auth MCP servers.'
            ServerName = $serverName
            EnvVarName = $null
        }
    }

    $trimmedEnvVarName = $envVarName.Trim()
    $envValue = [Environment]::GetEnvironmentVariable($trimmedEnvVarName)
    if (-not [string]::IsNullOrWhiteSpace($envValue)) {
        return @{
            Key        = $envValue
            Source     = "Environment:$trimmedEnvVarName"
            Error      = $null
            ServerName = $serverName
            EnvVarName = $trimmedEnvVarName
        }
    }

    $encryptedOverride = [string](Get-TTAgentConfigValue -ConfigObject $ServerConfigObject -KeyName 'credentialSecretEncryptedOverride')
    if (-not [string]::IsNullOrWhiteSpace($encryptedOverride)) {
        $overrideResolution = Resolve-TTAgentStoredSecret -ConfigObject @{ mcpInlineEncryptedSecret = $encryptedOverride } -SecretKeyName 'mcpInlineEncryptedSecret' -EnvVarName ''
        return @{
            Key        = [string]$overrideResolution.Key
            Source     = 'McpCredentialSecretEncryptedOverride'
            Error      = [string]$overrideResolution.Error
            ServerName = $serverName
            EnvVarName = $trimmedEnvVarName
        }
    }

    $secretKeyName = [string](Get-TTAgentConfigValue -ConfigObject $ServerConfigObject -KeyName 'credentialSecretKeyName')
    if ([string]::IsNullOrWhiteSpace($secretKeyName)) {
        return @{
            Key        = $null
            Source     = 'Missing'
            Error      = $null
            ServerName = $serverName
            EnvVarName = $trimmedEnvVarName
        }
    }

    $secretResolution = Resolve-TTAgentStoredSecret -ConfigObject $ConfigObject -SecretKeyName $secretKeyName -EnvVarName ''
    return @{
        Key        = [string]$secretResolution.Key
        Source     = "DPAPI:settings.agent.$secretKeyName"
        Error      = [string]$secretResolution.Error
        ServerName = $serverName
        EnvVarName = $trimmedEnvVarName
    }
}

function Test-TTAgentInteractiveSession {
    [CmdletBinding()]
    param()

    if (Get-Command -Name Test-TTInteractive -ErrorAction SilentlyContinue) {
        return (Test-TTInteractive)
    }

    try {
        return ($Host -and $Host.UI -and $Host.UI.RawUI -and -not [Console]::IsInputRedirected)
    }
    catch {
        return $false
    }
}

function Request-TTAgentCloudApiKeyPersistence {
    [CmdletBinding()]
    param(
        [string]$ProviderName,
        [string]$EnvVarName,
        [bool]$DisableApiKeyPrompt
    )

    if ($DisableApiKeyPrompt) {
        return @{ Key = $null; Source = 'PromptDisabled'; Error = $null }
    }

    if (-not (Test-TTAgentInteractiveSession)) {
        return @{ Key = $null; Source = 'NonInteractive'; Error = $null }
    }

    Write-Warning (
        "Cloud provider '{0}' has no usable API key from environment variable or DPAPI config secret." -f $ProviderName
    )

    $storeChoice = Read-Host "Store an encrypted API key in config.secrets.json now? [Y/N]"
    if ([string]::IsNullOrWhiteSpace($storeChoice) -or $storeChoice.Trim().ToUpperInvariant() -ne 'Y') {
        return @{ Key = $null; Source = 'PromptDeclined'; Error = $null }
    }

    $secureApiKey = Read-Host 'Enter cloud API key' -AsSecureString
    $encryptedApiKey = ConvertFrom-SecureString $secureApiKey

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)
    try {
        $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    if ([string]::IsNullOrWhiteSpace($plainApiKey)) {
        return @{ Key = $null; Source = 'Prompt'; Error = 'Entered API key was empty.' }
    }

    try {
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

        $secrets.settings.agent.apiKeyEncrypted = $encryptedApiKey
        $secretsPath = Write-Secrets -Secrets $secrets

        Write-Log -Level Ok -Message (
            'Stored DPAPI-encrypted cloud API key in config secrets file: {0}' -f $secretsPath
        )

        if (-not [string]::IsNullOrWhiteSpace($EnvVarName)) {
            [Environment]::SetEnvironmentVariable($EnvVarName, $plainApiKey, 'Process')
        }

        return @{ Key = $plainApiKey; Source = 'Prompt+DPAPI'; Error = $null }
    }
    catch {
        return @{ Key = $null; Source = 'Prompt+DPAPI'; Error = $_.Exception.Message }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTSGGdFp1ECb0M
# /4gzD5bh+SbDPTQjCv5gSeZpZmPDsqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDZdhpZ1DqQ
# Tyll68wbyTIXRclP3TVEJjiUmD+m6YzPxjANBgkqhkiG9w0BAQEFAASCAgBgkLva
# 4ZRiuv3uabrixgCyxwAjCb+GikElE+0BYrUb24TSr53yIHeOBjT2SFKlmgYbqRML
# nk34BI/7SkSt98R+BbYjhwd9eTHa7lV6e725u+7GXHGCFtmWsHvgFGNu1IXVikAh
# wZLmebMNmdgquieTlo9p/v5UMu5nkaKBSsSFnR6FG9qIGAqc8Ej4dHw13yY2QLRT
# xIa3Mt9gPssoDhbUMpG7vM7+8vukrNlN0jZQ533vvX6FJ3KsE2mNBh8ehKlJYbgC
# rIk8izS3tvQ8zv24vIjeohTGOLUljueFfRDpwDX3LJ9RxJG4RF9/FVPHEhQtqZV5
# FY0RnEUONOPpYjAfZbRUIdLbnRQDYZJa2oNSIzOwQM48JKIqtUZBxiQg2ihZweMx
# 7STKTPXiIo6e6ELUGVLx3dghKabOIciAVFkNisXXSLAVFT4AhWYCyhySJj3DPj50
# qfaCAhiQ016q7A8gpYxs4sGof7nu0TQVo4f9RmFyxshIUKwP4VfSBD72vdFr0LrX
# PjQbpiqSGI54U5f1j/b2esmQWhKH10ICHm5q5cKDmuCH8VSzqYl1t+81DJbsG1xk
# DY++kDBRhbacPVrdrfcSps8i6YRO9GcvnC8RW78YiIeTSUNj9k4yBMwMNqDtF2AG
# 4PU+gRFNYl0PjAZRdytBuJD7Ean67Br8amURYaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MTUwMjU5MTFaMC8GCSqGSIb3DQEJBDEiBCA/lJg8DcOosiD1Xj3m
# Dmqz8fuZJcmKuZNNy4GuzL7W/DANBgkqhkiG9w0BAQEFAASCAgCwHTk3I9LLGxjq
# IIGp3ihRNKggGDPgdWoqsa35HGNe2npUbsJMu4R/eL2x7xfDvmfyJFmel5N6Zt0e
# UAcnWBKr9KWahXakdt1UAyX63C/jzIzeL1SETkvzO2RuaoqoNqZa52+As9A4EQdH
# 0uL+BXhRIevUlQuK0snLVoW6VwOkUFj6d3iqJGMHiLUyrsb+Y2ROgcs7BTmjuNZO
# S++SmvnqkUhqLGL5SoZP2xAOQMNY75LsaZplucCL8gyq36EOxubRXkZdB/i85OAK
# bdIFjntf8hIQZDkH0IK8EjICCJIyKkHDGcNWDEuuMSDwOqb6Q+YnYd9719UXI7yu
# yeDysxKpn6+fML/QS7TZ8EjksX7mtw4lR+vjpERLPwTmbbt2B3Vwf9t/x/3p0E3Z
# RtToTTKWfyCHJ8QpxSwFTmNuPTuFMHx3vjcysPhhDGqvjZxQDrJZBl8XfKO5/m7E
# +vDb+llnLbMeth5jwYU6x9Q2O0BnYizrbaXi4opp7tP7Qg6xXel3DbrRp8fCRoY/
# s0UBb3otTfw/9Wik/jEZRkuMiX6PfoaYXzi6EXyd1pNF9k71L111fAkfYg2ist5c
# V54m88qXVrj133wprDYoF+nM+z7uh8Y3qIj5/l1NFbEYUg3hhS1LFwpoVKIiQqcG
# FhXA5ltIG9kgY/jcSYUK+7oqMVfbcQ==
# SIG # End signature block
