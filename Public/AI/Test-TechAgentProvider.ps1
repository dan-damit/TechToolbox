function Test-TechAgentProvider {
    <#
    .SYNOPSIS
        Validates TechAgent LLM provider configuration and connectivity.

    .DESCRIPTION
        Performs a self-test for the configured or specified LLM provider used by
        Invoke-TechAgent. The command validates required inputs (provider/model/
        endpoint/deployment/API key env var) and can execute a minimal live API
        request to verify authentication and response parsing.

        Supported providers:
        - ollama
        - openai
        - openai-compatible
        - azure-openai

    .PARAMETER Provider
        LLM provider to validate. Defaults to settings.agent.provider or ollama.

    .PARAMETER Model
        Model identifier to validate. For ollama/openai providers this should be
        set directly or in settings.agent.model.

    .PARAMETER Endpoint
        Optional endpoint URL. Required for azure-openai and openai-compatible.

    .PARAMETER Deployment
        Azure OpenAI deployment name. Required when provider is azure-openai.

    .PARAMETER ApiVersion
        API version used for Azure OpenAI. Defaults to 2024-10-21.

    .PARAMETER ApiKeyEnvVar
        Name of environment variable containing cloud API key.
        Defaults to settings.agent.apiKeyEnvVar or TT_AGENT_LLM_API_KEY.

    .PARAMETER ApiKeyEncrypted
        Optional DPAPI-protected API key blob produced by ConvertFrom-SecureString.
        When provided, this takes precedence over settings.agent.apiKeyEncrypted.

    .PARAMETER DisableApiKeyPrompt
        Disables interactive prompt for capturing and storing a missing cloud API key.
        Use this for non-interactive automation scenarios.

    .PARAMETER NoNetwork
        Validate configuration only. Skips the live provider call.

    .PARAMETER TimeoutSeconds
        Timeout for the live provider request.

    .EXAMPLE
        Test-TechAgentProvider

    .EXAMPLE
        Test-TechAgentProvider -Provider ollama -Model ornith:35b

    .EXAMPLE
        $env:TT_AGENT_LLM_API_KEY = '<key>'
        Test-TechAgentProvider -Provider openai -Model gpt-4o-mini

    .EXAMPLE
        $env:TT_AGENT_LLM_API_KEY = '<key>'
        Test-TechAgentProvider -Provider azure-openai -Endpoint https://contoso.openai.azure.com -Deployment gpt-4o-mini

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Test-TechAgentProvider
    #>

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateSet('ollama', 'openai', 'openai-compatible', 'azure-openai')]
        [string]$Provider,

        [Parameter()]
        [string]$Model,

        [Parameter()]
        [string]$Endpoint,

        [Parameter()]
        [string]$Deployment,

        [Parameter()]
        [string]$ApiVersion,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKeyEnvVar,

        [Parameter()]
        [string]$ApiKeyEncrypted,

        [Parameter()]
        [switch]$DisableApiKeyPrompt,

        [Parameter()]
        [switch]$NoNetwork,

        [Parameter()]
        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 30
    )

    Initialize-TechToolboxRuntime

    $cfg = $script:cfg.settings.agent

    $getConfigValue = {
        param(
            $configObject,
            [string]$keyName
        )

        if ($null -eq $configObject -or [string]::IsNullOrWhiteSpace($keyName)) {
            return $null
        }

        if ($configObject -is [hashtable] -and $configObject.ContainsKey($keyName)) {
            return $configObject[$keyName]
        }

        $property = $configObject.PSObject.Properties[$keyName]
        if ($null -ne $property) {
            return $property.Value
        }

        return $null
    }

    $resolveCloudApiKey = {
        param(
            $configObject,
            [string]$providerName,
            [string]$envVarName,
            [string]$encryptedOverride
        )

        if ($providerName -eq 'ollama') {
            return @{ Key = $null; Source = 'NotRequired'; Error = $null }
        }

        if (-not [string]::IsNullOrWhiteSpace($envVarName)) {
            $envValue = [Environment]::GetEnvironmentVariable($envVarName)
            if (-not [string]::IsNullOrWhiteSpace($envValue)) {
                return @{ Key = $envValue; Source = "Environment:$envVarName"; Error = $null }
            }
        }

        $encryptedValue = $encryptedOverride
        if ([string]::IsNullOrWhiteSpace($encryptedValue)) {
            $encryptedValue = [string](& $getConfigValue $configObject 'apiKeyEncrypted')
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

    $isInteractiveSession = {
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

    $promptAndPersistCloudApiKey = {
        param(
            [string]$providerName,
            [string]$envVarName
        )

        if ($DisableApiKeyPrompt.IsPresent) {
            return @{ Key = $null; Source = 'PromptDisabled'; Error = $null }
        }

        if (-not (& $isInteractiveSession)) {
            return @{ Key = $null; Source = 'NonInteractive'; Error = $null }
        }

        Write-Warning (
            "Cloud provider '{0}' has no usable API key from environment variable or DPAPI config secret." -f $providerName
        )

        $storeChoice = Read-Host "Store an encrypted API key in config.secrets.json now? [Y/N]"
        if ([string]::IsNullOrWhiteSpace($storeChoice) -or $storeChoice.Trim().ToUpperInvariant() -ne 'Y') {
            return @{ Key = $null; Source = 'PromptDeclined'; Error = $null }
        }

        $secureApiKey = Read-Host "Enter cloud API key" -AsSecureString
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

            if (-not [string]::IsNullOrWhiteSpace($envVarName)) {
                [Environment]::SetEnvironmentVariable($envVarName, $plainApiKey, 'Process')
            }

            return @{ Key = $plainApiKey; Source = "Prompt+DPAPI:$secretsPath"; Error = $null }
        }
        catch {
            return @{ Key = $null; Source = 'Prompt+DPAPI'; Error = $_.Exception.Message }
        }
    }

    if ([string]::IsNullOrWhiteSpace($Provider)) {
        $providerValue = & $getConfigValue $cfg 'provider'
        if (-not [string]::IsNullOrWhiteSpace([string]$providerValue)) {
            $Provider = [string]$providerValue
        }
    }
    if ([string]::IsNullOrWhiteSpace($Provider)) {
        $Provider = 'ollama'
    }
    $Provider = $Provider.Trim().ToLowerInvariant()

    if ([string]::IsNullOrWhiteSpace($Model)) {
        $modelValue = & $getConfigValue $cfg 'model'
        if (-not [string]::IsNullOrWhiteSpace([string]$modelValue)) {
            $Model = [string]$modelValue
        }
    }

    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        $endpointValue = & $getConfigValue $cfg 'endpoint'
        if (-not [string]::IsNullOrWhiteSpace([string]$endpointValue)) {
            $Endpoint = [string]$endpointValue
        }
    }

    if ([string]::IsNullOrWhiteSpace($Deployment)) {
        $deploymentValue = & $getConfigValue $cfg 'deployment'
        if (-not [string]::IsNullOrWhiteSpace([string]$deploymentValue)) {
            $Deployment = [string]$deploymentValue
        }
    }

    if ([string]::IsNullOrWhiteSpace($ApiVersion)) {
        $apiVersionValue = & $getConfigValue $cfg 'apiVersion'
        if (-not [string]::IsNullOrWhiteSpace([string]$apiVersionValue)) {
            $ApiVersion = [string]$apiVersionValue
        }
    }
    if ([string]::IsNullOrWhiteSpace($ApiVersion)) {
        $ApiVersion = '2024-10-21'
    }

    if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
        $apiKeyEnvVarValue = & $getConfigValue $cfg 'apiKeyEnvVar'
        if (-not [string]::IsNullOrWhiteSpace([string]$apiKeyEnvVarValue)) {
            $ApiKeyEnvVar = [string]$apiKeyEnvVarValue
        }
    }
    if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
        $ApiKeyEnvVar = 'TT_AGENT_LLM_API_KEY'
    }

    $result = New-Object psobject
    $result | Add-Member -NotePropertyName Success -NotePropertyValue $false
    $result | Add-Member -NotePropertyName Provider -NotePropertyValue $Provider
    $result | Add-Member -NotePropertyName Model -NotePropertyValue $Model
    $result | Add-Member -NotePropertyName Endpoint -NotePropertyValue $Endpoint
    $result | Add-Member -NotePropertyName Deployment -NotePropertyValue $Deployment
    $result | Add-Member -NotePropertyName ApiVersion -NotePropertyValue $ApiVersion
    $result | Add-Member -NotePropertyName ApiKeyEnvVar -NotePropertyValue $ApiKeyEnvVar
    $result | Add-Member -NotePropertyName ApiKeySource -NotePropertyValue 'None'
    $result | Add-Member -NotePropertyName ApiKeyPresent -NotePropertyValue $false
    $result | Add-Member -NotePropertyName PerformedLiveNetworkTest -NotePropertyValue (-not $NoNetwork.IsPresent)
    $result | Add-Member -NotePropertyName Status -NotePropertyValue 'NotStarted'
    $result | Add-Member -NotePropertyName Detail -NotePropertyValue ''
    $result | Add-Member -NotePropertyName HttpStatusCode -NotePropertyValue $null
    $result | Add-Member -NotePropertyName ResponsePreview -NotePropertyValue $null

    if ($Provider -eq 'ollama') {
        $ollamaCommand = Get-Command -Name ollama -ErrorAction SilentlyContinue
        if (-not $ollamaCommand) {
            $result.Status = 'ConfigurationError'
            $result.Detail = 'Ollama executable not found in PATH.'
            return [pscustomobject]$result
        }

        try {
            $ollamaListOutput = & $ollamaCommand.Source list 2>&1
            if ($LASTEXITCODE -ne 0) {
                $result.Status = 'ProviderError'
                $result.Detail = ("Unable to query local Ollama models: {0}" -f (($ollamaListOutput | Out-String).Trim()))
                return [pscustomobject]$result
            }

            $availableModels = @()
            foreach ($line in $ollamaListOutput) {
                $trimmed = "$line".Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
                if ($trimmed -match '^NAME\s+') { continue }

                $parts = $trimmed -split '\s+'
                if ($parts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
                    $availableModels += $parts[0]
                }
            }

            $availableModels = @($availableModels | Sort-Object -Unique)
            if (-not [string]::IsNullOrWhiteSpace($Model) -and $availableModels -notcontains $Model) {
                $result.Status = 'ConfigurationError'
                $result.Detail = ("Configured model '{0}' is not available locally. Available: {1}" -f $Model, ($availableModels -join ', '))
                return [pscustomobject]$result
            }

            $result.Success = $true
            $result.Status = if ($NoNetwork.IsPresent) { 'ConfigurationValidated' } else { 'Connected' }
            $result.Detail = 'Ollama is available and model validation passed.'
            return [pscustomobject]$result
        }
        catch {
            $result.Status = 'ProviderError'
            $result.Detail = $_.Exception.Message
            return [pscustomobject]$result
        }
    }

    $apiKeyResolution = & $resolveCloudApiKey -configObject $cfg -providerName $Provider -envVarName $ApiKeyEnvVar -encryptedOverride $ApiKeyEncrypted
    $apiKey = [string]$apiKeyResolution.Key
    $result.ApiKeySource = [string]$apiKeyResolution.Source

    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        $promptResolution = & $promptAndPersistCloudApiKey -providerName $Provider -envVarName $ApiKeyEnvVar
        if (-not [string]::IsNullOrWhiteSpace([string]$promptResolution.Key)) {
            $apiKey = [string]$promptResolution.Key
            $result.ApiKeySource = [string]$promptResolution.Source
        }
        elseif (-not [string]::IsNullOrWhiteSpace([string]$promptResolution.Error)) {
            $result.Status = 'ProviderError'
            $result.Detail = ("API key prompt/store failed via {0}: {1}" -f $promptResolution.Source, $promptResolution.Error)
            return [pscustomobject]$result
        }
    }

    $result.ApiKeyPresent = -not [string]::IsNullOrWhiteSpace($apiKey)
    if (-not $result.ApiKeyPresent) {
        $result.Status = 'ConfigurationError'
        if (-not [string]::IsNullOrWhiteSpace([string]$apiKeyResolution.Error)) {
            $result.Detail = ("API key resolution failed via {0}: {1}" -f $apiKeyResolution.Source, $apiKeyResolution.Error)
        }
        else {
            $result.Detail = ("Missing API key. Set environment variable '{0}', configure settings.agent.apiKeyEncrypted, or run Set-TechAgentApiKey." -f $ApiKeyEnvVar)
        }
        return [pscustomobject]$result
    }

    if ($Provider -eq 'azure-openai') {
        if ([string]::IsNullOrWhiteSpace($Endpoint)) {
            $result.Status = 'ConfigurationError'
            $result.Detail = 'azure-openai requires Endpoint.'
            return [pscustomobject]$result
        }
        if ([string]::IsNullOrWhiteSpace($Deployment)) {
            $result.Status = 'ConfigurationError'
            $result.Detail = 'azure-openai requires Deployment.'
            return [pscustomobject]$result
        }
    }
    elseif ($Provider -eq 'openai-compatible') {
        if ([string]::IsNullOrWhiteSpace($Endpoint)) {
            $result.Status = 'ConfigurationError'
            $result.Detail = 'openai-compatible requires Endpoint.'
            return [pscustomobject]$result
        }
        if ([string]::IsNullOrWhiteSpace($Model)) {
            $result.Status = 'ConfigurationError'
            $result.Detail = 'openai-compatible requires Model.'
            return [pscustomobject]$result
        }
    }
    elseif ([string]::IsNullOrWhiteSpace($Model)) {
        $result.Status = 'ConfigurationError'
        $result.Detail = 'openai requires Model.'
        return [pscustomobject]$result
    }

    if ($NoNetwork.IsPresent) {
        $result.Success = $true
        $result.Status = 'ConfigurationValidated'
        $result.Detail = 'Provider settings and API key presence validated. Live network test skipped.'
        return [pscustomobject]$result
    }

    try {
        $uri = $null
        $headers = @{ 'Content-Type' = 'application/json' }
        $body = $null

        if ($Provider -eq 'azure-openai') {
            $headers['api-key'] = $apiKey
            $baseEndpoint = $Endpoint.TrimEnd('/')
            $uri = "{0}/openai/deployments/{1}/chat/completions?api-version={2}" -f $baseEndpoint, $Deployment, $ApiVersion
            $body = New-Object System.Collections.Specialized.OrderedDictionary
            $body.Add(
                'messages',
                @(
                    @{ role = 'system'; content = 'You are a health-check assistant. Return valid JSON only.' },
                    @{ role = 'user'; content = 'Return JSON: {"ok":true,"provider":"azure-openai"}' }
                )
            )
            $body.Add('temperature', 0)
            $body.Add('top_p', 1)
            $body.Add('max_tokens', 64)
            $body.Add('stream', $false)
            $body.Add('response_format', @{ type = 'json_object' })
        }
        else {
            $headers['Authorization'] = "Bearer $apiKey"
            $uri = if ([string]::IsNullOrWhiteSpace($Endpoint)) {
                'https://api.openai.com/v1/chat/completions'
            }
            else {
                $Endpoint
            }

            $body = New-Object System.Collections.Specialized.OrderedDictionary
            $body.Add('model', $Model)
            $body.Add(
                'messages',
                @(
                    @{ role = 'system'; content = 'You are a health-check assistant. Return valid JSON only.' },
                    @{ role = 'user'; content = 'Return JSON: {"ok":true,"provider":"openai"}' }
                )
            )
            $body.Add('temperature', 0)
            $body.Add('top_p', 1)
            $body.Add('max_tokens', 64)
            $body.Add('stream', $false)
            $body.Add('response_format', @{ type = 'json_object' })
        }

        $requestJson = $body | ConvertTo-Json -Depth 8
        $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $requestJson -TimeoutSec $TimeoutSeconds -ErrorAction Stop

        $content = $null
        if ($response -and $response.choices -and $response.choices.Count -gt 0) {
            $message = $response.choices[0].message
            if ($null -ne $message) {
                if ($message.content -is [string]) {
                    $content = [string]$message.content
                }
                elseif ($message.content -is [System.Collections.IEnumerable]) {
                    $parts = @()
                    foreach ($item in $message.content) {
                        if ($item -and $item.text) {
                            $parts += [string]$item.text
                        }
                    }
                    $content = ($parts -join '')
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($content)) {
            $result.Status = 'ProviderError'
            $result.Detail = 'Provider returned success but empty content.'
            return [pscustomobject]$result
        }

        $result.Success = $true
        $result.Status = 'Connected'
        $result.Detail = 'Live provider call succeeded.'
        $result.ResponsePreview = if ($content.Length -le 240) { $content } else { $content.Substring(0, 240) }
        return [pscustomobject]$result
    }
    catch {
        $result.Status = 'ProviderError'
        $result.Detail = $_.Exception.Message

        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $result.HttpStatusCode = [int]$_.Exception.Response.StatusCode
        }

        return [pscustomobject]$result
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZ4XeATas654w+
# VlQ3Pdi86ktSr6Py7XYC2A8sXgkttaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD34ArOzVJ9
# CG+q2KZ+65Ui2mopKgvmDQtRH8/3Vs0WxjANBgkqhkiG9w0BAQEFAASCAgDPsRjq
# CpQiqFABJRuY1fx5GgxmHwRfCNHr1v8SX9TqIbyHvFRZ52DREvBwU1IofUZb2PL1
# zez15yHimfB3Dp2JBISXfd/ksLeheRvGMvJaPRfKxfGp3FsUwn+qCAoGJOw2dRqf
# hRcIvHWJzKoC4bLmp80WxRSOLi7gUGi+miv+6WoiWAtKnlRpFZj5q6NpJns9Fg6s
# EDLuhrXOh2Nut75r8hmC9MTNdBVSX0DfithSj4UcSteCDsk6viVocwUn/pJas54r
# m2YvPonFrTN6/T789sl4LbAVU9LeiAqY7Px0r2NITAXP5tYGiWbSotgBRVTTYS53
# xvx5pzB+hnaGLApML9yc4/xr0fTTVLddjyXOCVPdN8fiXsJA2I/8UZUiVFLf3shK
# 4l1kp8q2NNjm6s17mbqfYVb2UNNEr2J6CyfUA4QCxmwsoq4zrGDRY6Hi7F/7Mciu
# qR51S/ffGnM6cB/MjC2FHMTZSDuPlfoFG4cEol5iv/85gy8JmoU5DJPZ+ZFhl2TT
# ha52JrrRJ3kW/FjZpZM3rsHRIvK2+ff6BNGPPXZpXQjnN7Ak/ds7Cvc6tFfgIYlk
# e64P4CxqvoM0iZBwnO/IZ+tUInHtVHyb/QQ1U3nnNHu1oEl31VDWWRQLcOwG7y9P
# 5od4UJxLqcmPERxA8C7rwKRCZoLr6V+rZLV+SqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MjcyMjU0MzhaMC8GCSqGSIb3DQEJBDEiBCAoizWex6wErkTlF6DX
# ah3yRz1k+vSiD4++z5T39c0bMjANBgkqhkiG9w0BAQEFAASCAgAwhEY+6qzSd70c
# 6Sdp+v2AdnH2hlt/NfevMfTIWqC7rordzUhSBqJ/KuFuguzKw5heAoc+znAX3yP2
# ob7shYI5kJnAg61RwTi9hINHUa0BwpPxnF5Kk82+9EVMpqY60Je53IEv6guJaBAk
# vFvQdh6aYe5qH4GWcjFzjqPdKIbuV7QuPlbJYlWmTuQ3UOjxJ/UmhSvaYxMksEmS
# AsOC75RCXRfSS37b1nMM2zECB5DRi6LPwkpCarXwyf1wC3oqmxXSvZrH8xr1A7PP
# IdEZVlQzZQ5aCfCBtzmP/uckdsEvc5SAtXKRlN5j9K3r7jYkVBlVemufs+uewrPh
# oPO+AewqWXJGMFrcppj/uvXizMEgVOkvZcZLjfGTznQ/v3nChdkQ6eH+/z8Ovk8S
# TrgOdqehX+hRawGhFs5mYF2GB6QqD4qkVD/HjVIcKvPlZJyxJ42s+3CS0MXXnxoA
# zteO+4ObJhhJPOjKRxY5e7FG3VxecFh6JD3EROOr4USmc1hvomN7ckEsSXJ48Wil
# 2KY1u1k2SOYxWKGPT1D/qnJ6ldwHQlbosgpMH+JyiDm/wVO8rmRuxf4ecRUmdzoF
# P3vf+RRDtGMTC4CJTfU6rvA+H71ZFWzsUOAQ2koDdKCbzNQmuzOXIz6YL8/JwxK2
# ih1kwr82QsrQrUtIsxtuLd7mIZy+gQ==
# SIG # End signature block
