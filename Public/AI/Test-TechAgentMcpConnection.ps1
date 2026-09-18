function Test-TechAgentMcpConnection {
    <#
    .SYNOPSIS
        Runs deterministic MCP startup diagnostics for configured servers.

    .DESCRIPTION
        Executes MCP bootstrap directly against each configured server in isolation
        and returns concrete status details without relying on LLM tool selection.

        For each server, this command reports:
        - Name
        - Endpoint
        - Enabled
        - Authentication mode
        - Connection status
        - Last connection error
        - OAuth status
        - Number of tools registered
        - Number of resources registered
        - Number of prompts registered

    .PARAMETER ServerName
        Optional server name filter. Defaults to all configured MCP servers.

    .PARAMETER IncludeDisabled
        Includes disabled servers in output. Disabled servers are skipped from
        runtime initialization and reported as Disabled.

    .PARAMETER TimeoutSeconds
        Diagnostic timeout budget per server. For OAuth servers this value is
        also applied to interactive timeout to prevent long hangs.

    .PARAMETER AsJson
        Returns compact JSON for automation.

    .EXAMPLE
        Test-TechAgentMcpConnection

    .EXAMPLE
        Test-TechAgentMcpConnection -ServerName pdq-connect -TimeoutSeconds 45

    .EXAMPLE
        Test-TechAgentMcpConnection -AsJson
    #>

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [string[]]$ServerName,

        [Parameter()]
        [switch]$IncludeDisabled,

        [Parameter()]
        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 45,

        [Parameter()]
        [switch]$AsJson
    )

    Initialize-TechToolboxRuntime

    $agentSettings = Get-TTAgentConfigValue -ConfigObject $script:cfg.settings -KeyName 'agent'
    $mcpSettings = Get-TTAgentConfigValue -ConfigObject $agentSettings -KeyName 'mcp'
    if ($null -eq $mcpSettings) {
        throw 'MCP configuration is missing at settings.agent.mcp.'
    }

    $servers = @()
    $serverValues = Get-TTAgentConfigValue -ConfigObject $mcpSettings -KeyName 'servers'
    if ($null -ne $serverValues) {
        $servers = @($serverValues)
    }

    if ($servers.Count -eq 0) {
        throw 'No MCP servers are configured at settings.agent.mcp.servers.'
    }

    if ($ServerName -and $ServerName.Count -gt 0) {
        $nameSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $ServerName) {
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                [void]$nameSet.Add($name.Trim())
            }
        }

        $servers = @(
            foreach ($server in $servers) {
                if ($null -eq $server) { continue }
                $candidateName = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'name')
                if ($nameSet.Contains($candidateName)) {
                    $server
                }
            }
        )

        if ($servers.Count -eq 0) {
            throw 'No MCP servers matched -ServerName.'
        }
    }

    $moduleRoot = $script:ModuleRoot
    $assemblyCandidates = @(
        (Join-Path $moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'),
        (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish\TechToolbox.Agent.dll'),
        (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'),
        (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll')
    )

    $existingAssemblyCandidates = @(
        foreach ($candidate in $assemblyCandidates) {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
            }
        }
    )

    $agentAssemblyPath = $null
    if ($existingAssemblyCandidates.Count -gt 0) {
        $agentAssemblyPath = (
            $existingAssemblyCandidates |
            Sort-Object -Property LastWriteTimeUtc -Descending |
            Select-Object -First 1 -ExpandProperty FullName
        )
    }

    if ([string]::IsNullOrWhiteSpace($agentAssemblyPath)) {
        throw 'Unable to locate TechToolbox.Agent runtime assembly.'
    }

    [void][System.Reflection.Assembly]::LoadFrom($agentAssemblyPath)

    $jsonOptions = [System.Text.Json.JsonSerializerOptions]::new()
    $jsonOptions.PropertyNameCaseInsensitive = $true
    $jsonOptions.Converters.Add([System.Text.Json.Serialization.JsonStringEnumConverter]::new())

    $mcpConfigType = [Type]::GetType('TechToolbox.Agent.Configuration.McpConfiguration, TechToolbox.Agent', $true)
    $agentConfigurationType = [Type]::GetType('TechToolbox.Agent.Configuration.AgentConfiguration, TechToolbox.Agent', $true)
    $agentModeType = [Type]::GetType('TechToolbox.Agent.Configuration.AgentMode, TechToolbox.Agent', $true)
    $mcpBootstrapType = [Type]::GetType('TechToolbox.Agent.Mcp.McpBootstrap, TechToolbox.Agent', $true)

    $createForMode = $agentConfigurationType.GetMethod('CreateForMode', [type[]]@($agentModeType))
    $initializeAsync = $mcpBootstrapType.GetMethod('InitializeAsync', [type[]]@($agentConfigurationType, [System.Threading.CancellationToken]))

    $results = [System.Collections.Generic.List[object]]::new()
    $setObjectProperty = {
        param(
            $Object,
            [string]$Name,
            $Value
        )

        if ($null -eq $Object) {
            return
        }

        $property = $Object.PSObject.Properties[$Name]
        if ($null -ne $property) {
            $property.Value = $Value
            return
        }

        $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
    }

    foreach ($server in $servers) {
        if ($null -eq $server) {
            continue
        }

        $name = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'name')
        if ([string]::IsNullOrWhiteSpace($name)) {
            $name = 'unnamed'
        }

        [bool]$enabled = $false
        $enabledValue = Get-TTAgentConfigValue -ConfigObject $server -KeyName 'enabled'
        if ($enabledValue -is [bool]) {
            $enabled = [bool]$enabledValue
        }
        else {
            [void][bool]::TryParse([string]$enabledValue, [ref]$enabled)
        }

        $authMode = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'authMode')
        $transport = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'transport')
        $endpoint = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'endpoint')

        if ([string]::IsNullOrWhiteSpace($endpoint) -and $transport -eq 'Stdio') {
            $command = [string](Get-TTAgentConfigValue -ConfigObject $server -KeyName 'command')
            $arguments = @((Get-TTAgentConfigValue -ConfigObject $server -KeyName 'arguments'))
            $endpoint = "stdio: $command $($arguments -join ' ')".Trim()
        }

        if (-not $enabled -and -not $IncludeDisabled.IsPresent) {
            continue
        }

        if (-not $enabled) {
            $results.Add([pscustomobject]@{
                    Name                = $name
                    Endpoint            = $endpoint
                    Enabled             = $false
                    AuthenticationMode  = $authMode
                    ConnectionStatus    = 'Disabled'
                    LastConnectionError = $null
                    OAuthStatus         = if ($authMode -eq 'OAuth2') { 'Disabled' } else { 'NotApplicable' }
                    FailureCode         = $null
                    ToolCount           = 0
                    ResourceCount       = $null
                    PromptCount         = $null
                    RuntimeAssemblyPath = $agentAssemblyPath
                })
            continue
        }

        $serverClone = $server | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
        & $setObjectProperty -Object $serverClone -Name 'enabled' -Value $true
        & $setObjectProperty -Object $serverClone -Name 'requestTimeoutSeconds' -Value $TimeoutSeconds
        if ($serverClone.authMode -eq 'OAuth2') {
            if ($null -eq $serverClone.oauth) {
                $serverClone | Add-Member -NotePropertyName oauth -NotePropertyValue ([pscustomobject]@{})
            }

            $tokenCacheIdentity = [string](Get-TTAgentConfigValue -ConfigObject $serverClone.oauth -KeyName 'tokenCacheIdentity')
            if ([string]::IsNullOrWhiteSpace($tokenCacheIdentity)) {
                $profileId = [string](Get-TTAgentConfigValue -ConfigObject $serverClone -KeyName 'profileId')
                if ([string]::IsNullOrWhiteSpace($profileId)) {
                    $profileId = 'default'
                }

                & $setObjectProperty -Object $serverClone.oauth -Name 'tokenCacheIdentity' -Value ("profile/{0}" -f $profileId)
            }

            $allowedRedirectUris = @()
            foreach ($uri in @((Get-TTAgentConfigValue -ConfigObject $serverClone.oauth -KeyName 'allowedRedirectUris'))) {
                if ($null -eq $uri) {
                    continue
                }

                $uriText = [string]$uri
                if (-not [string]::IsNullOrWhiteSpace($uriText)) {
                    $allowedRedirectUris += $uriText
                }
            }
            & $setObjectProperty -Object $serverClone.oauth -Name 'allowedRedirectUris' -Value @($allowedRedirectUris)

            & $setObjectProperty -Object $serverClone.oauth -Name 'interactiveTimeout' -Value ([TimeSpan]::FromSeconds($TimeoutSeconds).ToString('c'))
            & $setObjectProperty -Object $serverClone.oauth -Name 'metadataTimeout' -Value ([TimeSpan]::FromSeconds([Math]::Min($TimeoutSeconds, 60)).ToString('c'))
            & $setObjectProperty -Object $serverClone.oauth -Name 'tokenTimeout' -Value ([TimeSpan]::FromSeconds([Math]::Min($TimeoutSeconds, 60)).ToString('c'))
        }

        $singleServerConfig = [ordered]@{
            enabled = $true
            servers = @($serverClone)
        }

        $connectionStatus = 'Unknown'
        $lastError = $null
        $oauthStatus = if ($authMode -eq 'OAuth2') { 'Unknown' } else { 'NotApplicable' }
        $failureCode = $null
        $toolCount = 0
        $runtime = $null

        try {
            $mcpConfigJson = $singleServerConfig | ConvertTo-Json -Depth 64 -Compress
            $mcpConfig = [System.Text.Json.JsonSerializer]::Deserialize($mcpConfigJson, $mcpConfigType, $jsonOptions)

            $mode = [System.Enum]::Parse($agentModeType, 'TechToolbox')
            $agentConfiguration = $createForMode.Invoke($null, @($mode))
            $agentConfiguration.Mcp = $mcpConfig

            $runtimeTask = $initializeAsync.Invoke($null, @($agentConfiguration, [System.Threading.CancellationToken]::None))
            $runtime = $runtimeTask.GetAwaiter().GetResult()

            foreach ($provider in @($runtime.Providers)) {
                try {
                    $toolCount += @($provider.DiscoverTools()).Count
                }
                catch {
                }
            }

            $connectionStatus = 'Connected'
            if ($authMode -eq 'OAuth2') {
                $oauthStatus = 'Connected'
            }
            $failureCode = $null
        }
        catch {
            $root = $_.Exception
            while ($null -ne $root.InnerException) {
                $root = $root.InnerException
            }

            $exceptionText = [string]$_.Exception.Message
            $rootText = [string]$root.Message
            if (-not [string]::IsNullOrWhiteSpace($rootText) -and -not [string]::Equals($exceptionText, $rootText, [System.StringComparison]::Ordinal)) {
                $exceptionText = "$exceptionText | root: $rootText"
            }
            if ([string]::IsNullOrWhiteSpace($exceptionText)) {
                $exceptionText = [string]$_.Exception.GetType().Name
            }

            $lastError = ($exceptionText -replace '\s+', ' ').Trim()
            if ($lastError.Length -gt 1024) {
                $lastError = $lastError.Substring(0, 1024)
            }

            $failureMatch = [regex]::Match($lastError, '(AUTHORIZATION_REQUIRED|AUTH_CONTEXT_INVALID|AUTHORIZATION_CODE_MISSING|TOKEN_ENDPOINT_FAILURE|TOKEN_RESPONSE_INVALID|METADATA_DISCOVERY_FAILED|AUTHENTICATION_UNAVAILABLE|AUTHENTICATION_FAILED|AUTHENTICATION_TIMEOUT|REQUEST_TIMEOUT|CONNECTION_FAILED|INVALID_ENDPOINT)')
            if ($failureMatch.Success) {
                $failureCode = $failureMatch.Groups[1].Value
            }

            $connectionStatus = 'Failed'
            if ($authMode -eq 'OAuth2') {
                if ($lastError -match 'AUTHORIZATION_REQUIRED') {
                    $oauthStatus = 'AuthorizationRequired'
                }
                elseif ($lastError -match 'METADATA_DISCOVERY_FAILED') {
                    $oauthStatus = 'MetadataDiscoveryFailed'
                }
                elseif ($lastError -match 'TOKEN_ENDPOINT_FAILURE|TOKEN_RESPONSE_INVALID|AUTHORIZATION_CODE_MISSING') {
                    $oauthStatus = 'TokenExchangeFailed'
                }
                elseif ($lastError -match 'AUTH_CONTEXT_INVALID|AUTHENTICATION_UNAVAILABLE|AUTHENTICATION_FAILED') {
                    $oauthStatus = 'AuthenticationFailed'
                }
                elseif ($lastError -match 'AUTHENTICATION_TIMEOUT|TIMEOUT') {
                    $oauthStatus = 'TimedOut'
                }
                elseif ($lastError -match 'relative URI') {
                    $oauthStatus = 'MetadataInvalidEndpoint'
                }
                else {
                    $oauthStatus = 'Failed'
                }
            }
        }
        finally {
            if ($null -ne $runtime) {
                try {
                    $runtime.DisposeAsync().AsTask().GetAwaiter().GetResult()
                }
                catch {
                }
            }
        }

        $results.Add([pscustomobject]@{
                Name                = $name
                Endpoint            = $endpoint
                Enabled             = $true
                AuthenticationMode  = $authMode
                ConnectionStatus    = $connectionStatus
                LastConnectionError = $lastError
                OAuthStatus         = $oauthStatus
                FailureCode         = $failureCode
                ToolCount           = $toolCount
                ResourceCount       = $null
                PromptCount         = $null
                RuntimeAssemblyPath = $agentAssemblyPath
            })
    }

    if ($AsJson.IsPresent) {
        return ($results | ConvertTo-Json -Depth 6)
    }

    return $results
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoOvzX79VBzZhQ
# WMgYZor0wV7qaQl+3ifX1roE0a3DnqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBJ9RlchIy/
# vkVBGRb/jhIWDqiPRFw2iiYQi4M5H6Sr9zANBgkqhkiG9w0BAQEFAASCAgCYt6Mt
# YH/WhOgmgT8vUOxM/cRvBrd1iwXIMsDhP9C33En7/3mPFSXR3S1Hldp9CI+6pmh7
# nk3cMHN734hryqBvHrVq8oOit0YXdEN8Dm+uTgOvQ/aQGlKPw+Y9GzPxjnP/1CV/
# YKrylyEleCXWnyWdaqfOauiwdWa27jC2+BheQ4a6mcbBJVh61JSatviT88sNAOD9
# lxg4pB+4gRuMTXq8iNqwJBGPXJCYTSTI/2H4DaQ7HEeYhIhPIhDUvtV1YP0alW80
# QVjFu4q+Y6AGoMRyZgdNULf13n1yNdDXyU8hn2a7Vp9o51EKvSy+L+haxE2ONLJS
# ApTc7nptlILYmMg4ZM14KUw9usiM+81QNnG+PN2FbCIybkbrv58qtDJJj2V9LbTM
# cwqRDYjoNz5ACuLf4xbUKMgFr3if200UhXpHvgxubBSl1+PBhZRE6yueYGVl6pBE
# tutGY1M1XfkvLP081F+W3kD+dQVDp9I3uspv76BtAEhvx4Y1w2f3Lz+71gGQvD+E
# r6kx4hHi+rUZBAETvpzdrH5VBkFZsd5GBeRTgqtMuGbhciIh/c0tAno1WycINtva
# 7OJy328lrClXfVtrGieZMmh4LNNs+HFd5Efj26dHfox+nN80I3rplyOAmmnPOIy5
# gG0TYKAFehFHL/sXyRhuqhdcCCWKiB8sU6ZG6KGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MTgyMzA0MTNaMC8GCSqGSIb3DQEJBDEiBCDi7VoSSWpL6jAj3s2u
# 1TYKP0uxJQTH//a97Vm/YdPqHDANBgkqhkiG9w0BAQEFAASCAgAFYLIsaWprLaNH
# saCu0aEN+rTte62HWt3C+q68T5FkLkZzo11uerSF1BdAkpgDgzvjcxceG1d+kbcg
# KOHGFTwGuMzNNyvaX6qVnUdReLi0wX3SHhovI4EnjN/N/Wr6+j6OajW9r/pThKbn
# yp3hTIYZRfXgvLr4Mwrv1JCG+WCF0O7iBioyk6rzgb1hT8RLD+4aN4cn5+avP/Jl
# TUQdSJcLJsDqb9KRhL2pj8HtTIbjBEbPZh1WYjIOD3FWNQkcocxM+6TVWVNHlQLt
# qtznNDPY/qOARCcw9OJp/4iST2bXxPELo9Y4x/idRS63u0diqV1Kb9+CLJVq1bYR
# vbCmSLEuxR7NWLPQBFXkOuqqsCirtFUYhhlGGHfk6tUGlL4Xx1NLhPn9JTTgcdv3
# dJHBQ3d02jH1aZz6VEgEKu2giMp/CcFF/nT2k8TOFT5C/3DmuqbKNOVm54U7c3k3
# 3iF9/2i2cOa4XFMv6vAqG8B3n8lqmLkiJBKRRiqEcE0aZzdZ4mD9D268P5vXWUum
# DZ21WruUkIUYjLKS5yb1DgUnnvb0UYbn6btgrRZwqn/r+/yh8u10/GxnFMTKzkDj
# CHblXAYezqv34tqVr5sKvTFFC7bQxU5HoAP9HqKy+E/2kW41MbHS2NEQoPLB6IIc
# Dc/sp5zxJiLIO6vWDger3OGQQnrsTw==
# SIG # End signature block
