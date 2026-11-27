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
        Prefers encrypted config-based API key resolution and skips environment
        variable lookup. Use this when you want to force stored secret usage.

    .PARAMETER ApiKeyEncryptedBlob
        Optional DPAPI-protected API key blob produced by ConvertFrom-SecureString.
        When provided, this overrides settings.agent.apiKeyEncrypted.

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
        [switch]$ApiKeyEncrypted,

        [Parameter()]
        [string]$ApiKeyEncryptedBlob,

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
            [string]$encryptedOverride,
            [switch]$PreferEncryptedOnly
        )

        if ($providerName -eq 'ollama') {
            return @{ Key = $null; Source = 'NotRequired'; Error = $null }
        }

        if (-not $PreferEncryptedOnly.IsPresent -and -not [string]::IsNullOrWhiteSpace($envVarName)) {
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

    $apiKeyResolution = & $resolveCloudApiKey -configObject $cfg -providerName $Provider -envVarName $ApiKeyEnvVar -encryptedOverride $ApiKeyEncryptedBlob -PreferEncryptedOnly:$ApiKeyEncrypted
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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBzqCCgAqNRVpBj
# KOzaVM+Mo2ghrWnsC+k4762hhtWUsqCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCU
# v+250i/xpP3IK1iWWRi4C+SN/tBwfrTThSqa7h3N2zANBgkqhkiG9w0BAQEFAASC
# AYAiYKiPP/9uvEmHsovAxKu7kmQmke+n41dZ5yXdeAUN5kIFeM/wgROTPcWCwFi4
# P4COB/1AwPASwyVG0fT7cYGGVWjnzVkcWocVjlhy0hfXq03rVsdEWVgN/pVVfml8
# D3MHpO65nRegZKw4rrxPFYgBuQRvjHxZmPU258/XRl+TmvL4yXTyfKQzBBsiV3B8
# PGF4wOLqaMFMIvS+WZLGYYFBmCnS8c0bSPrUiH+sk1TOQQWL/arY2LOmfl7hzMeI
# bcpxoj5bZPtgvIUWkmYra+6oqFUJMjAHyOejOyn/dKgPTh4L5QdlM8ByrIUK33v+
# YqZgCFK1nGjOKYX3cOMIf87IGLpbIpSkYelGW3TlHFa4Jzn1jbQqg0I37Nz9k+u5
# ZPRI/Bgd9F5BZG+APiOEe6BqotPZ/mqtgj8WOXwEeZzQMr95wU6uUZtfamax2rQP
# bao2+Xhh1rh9V/Vvyow1aWHY8P4qn/NfZ3dqsXk3PQmfxO7Ouei261AKmc/PfMdt
# 99WhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDE0WjAvBgkqhkiG
# 9w0BCQQxIgQg+4lDhDx2MZ6WHsfCUvTsX3f5gSNi8GLsGrX3aJfBZ1gwDQYJKoZI
# hvcNAQEBBQAEggIAB0mtcsSFlyB0S4pqT8WsqXAK2/Exoa0AuOUa0Vn7t/GAh+VY
# 3hLmTaZW3Qzk5gzyw4O/Nec+0JjPqB3jdp8GErspZNxTn1WyKm2/HxIQlLyP9yn3
# CB383wwkah85z0Tf0gsY4Z+ckj0cmURfVgGX2e6E6u/3VAigljqqpJ+ZLtRA5iKs
# 4Kz+M1UfNlRlX2tbZ8evf1QSHS9CE26zSWy3jMgqIY8t+uMgri/Y0BYoNMPLdLO6
# IUSUj2WS3lbaHWPQb9LzvUdkM6UqQLfSgADhtpsLmn7CBEl/mtsHvfSewguXKNkX
# nDk0qmu3uYkpQHsJOooXhAVbDMvJcOMzYrOVKSFDxNdVzwAMPSCm9gj9qGhzJgAe
# kbrgD+pOH1T9UoIMNeQMapJtJLH5dz76xDHxSOUBLlzQRrULIR0hWNMy3myz6pzi
# dP1bMfHrGfBOqjLeKoIJoHeYdc6G29iz2n+NhQAoRQRUKDVbL/v5McrI4oVPrPu6
# bvDyhCvrnaGhisCHNczWBf78G9R9wpDZHl/+nQZGvsFFTnwAp06ZlBaTPKWFvgPH
# 1Yy4RbsVPG+q4VMjGQkP3td6AoKrNqqRGAz34ATIAegs+U/goI5QGpb3p/0RO9VM
# duNu5SG7dMlJE1Oo1XFWKAN+xnkvnh7Vibt11QesDQ0MTwbd9asDsXITRSk=
# SIG # End signature block
