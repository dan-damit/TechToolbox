function Invoke-TechAgent {
    <#
    .SYNOPSIS
        Sends a prompt to the TechToolbox local agent.

    .DESCRIPTION
        This function calls the TechToolbox.Agent C# runtime and prints the
        agent's response.

    .PARAMETER Prompt
        The natural-language instruction for the agent.

    .PARAMETER PromptFile
        Optional path to a prompt text file. If omitted and -Prompt is empty,
        Invoke-TechAgent attempts to load a default prompt file.

    .PARAMETER Model
        Optional Ollama model name (for example: phi4:14b,
        deepcoder:14b, medgemma1.5:4b).
        Mandatory if using OpenAI.

    .PARAMETER Provider
        LLM provider to use. Supported values: ollama, openai,
        openai-compatible, azure-openai.

    .PARAMETER Endpoint
        Optional provider endpoint URL.
        For Azure OpenAI, this should be the resource endpoint
        (for example https://name.openai.azure.com).

    .PARAMETER Deployment
        Azure OpenAI deployment name.

    .PARAMETER ApiVersion
        API version for cloud providers that require it.

    .PARAMETER ApiKeyEnvVar
        Environment variable name that holds the cloud API key.
        Defaults to TT_AGENT_LLM_API_KEY.

    .PARAMETER ApiKeyEncrypted
        Prefers encrypted config-based API key resolution and skips environment
        variable lookup. Use this when you want to force stored secret usage.

    .PARAMETER ApiKeyEncryptedBlob
        Optional DPAPI-protected API key blob produced by ConvertFrom-SecureString.
        When provided, this overrides settings.agent.apiKeyEncrypted.

    .PARAMETER DisableApiKeyPrompt
        Disables interactive prompt for capturing and storing a missing cloud API key.
        Use this for non-interactive automation scenarios.

    .PARAMETER MaxIterations
        Maximum number of tool/reasoning iterations before the agent concludes.

    .PARAMETER PromptHistoryItems
        Number of recent memory history entries to inject into prompt context.
        Set to 0 to disable recent history injection for this run.

    .PARAMETER Mode
        Controls whether the agent should execute tools (`execute`), produce a
        no-tool implementation plan (`plan`), or provide no-tool analysis
        (`analyze`), or stay in sandboxed chat mode (`chat`).

    .PARAMETER StrictPromptPreflight
        Turns prompt preflight warnings into a blocking validation failure when
        prompt quality is too low for reliable execution.

    .PARAMETER AutoPromptHint
        Prints a preflight-ready prompt rewrite suggestion when warnings or
        critical preflight findings are detected. This does not alter the
        current run's prompt.

    .PARAMETER AutoRerunFromHint
        Performs a single preflight rewrite pass using the generated prompt
        hint when prompt quality is weak. The command then continues with the
        rewritten prompt for this run only.

    .PARAMETER OutputContract
        Final response format contract. `markdown` allows Markdown output,
        `plain-text` requires plain text only, and `json` requires valid JSON
        object or array text in the final answer.

    .PARAMETER QualityProfile
        Sampling profile for response quality tuning. `precise` is deterministic,
        `balanced` is default, and `creative` increases variation.

    .PARAMETER ThinkingMode
        Thinking mode preference for models that support deeper reasoning.
        Supported values: `auto`, `on`, `off`.

    .PARAMETER ReasoningEffort
        Optional explicit reasoning effort override for GPT-5.3-Codex responses.
        Supported values: `low`, `medium`, `high`, `xhigh`.

    .PARAMETER ReasoningEffortAuto
        Automatically selects reasoning effort when no explicit override is
        supplied.

    .PARAMETER Quiet
        Legacy compatibility switch. Agent traces are now suppressed by default.

    .PARAMETER ConfirmDestructive
        Explicitly authorizes destructive operations for this run.

    .PARAMETER SignedFilePolicy
        Policy to use when overwriting an existing Authenticode-signed
        PowerShell file. 'ignore' blocks the overwrite and 'strip' allows the
        overwrite while removing the signature block text.

    .PARAMETER AutoRetryOnRecursion
        Enables a single automatic retry when the C# agent hits an iteration
        limit.

    .PARAMETER DisableAutoRetryOnRecursion
        Disables recursion-limit auto-retry for this invocation, overriding
        environment defaults.

    .PARAMETER NoTranscript
        Disables the per-run console transcript log.

    .PARAMETER AllowMetaTools
        Allows higher-order meta tools (for example Invoke-TechAgent)
        to be available to the agent for this run. Disabled by default to
        reduce recursive orchestration loops.

    .EXAMPLE
        Invoke-TechAgent "Run system diagnostics and summarize findings."

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Invoke-TechAgent
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt,

        [Parameter()]
        [string]$PromptFile,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Model,

        [Parameter()]
        [string]$RuntimeProfile,

        [Parameter()]
        [ValidateSet('ollama', 'openai', 'openai-compatible', 'azure-openai')]
        [string]$Provider,

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
        [ValidateRange(1, 500)]
        [int]$MaxIterations = 15,

        [Parameter()]
        [ValidateRange(0, 20)]
        [int]$PromptHistoryItems,

        [Parameter()]
        [ValidateSet('execute', 'plan', 'analyze', 'chat')]
        [string]$Mode,

        [Parameter()]
        [switch]$StrictPromptPreflight,

        [Parameter()]
        [switch]$AutoPromptHint,

        [Parameter()]
        [switch]$AutoRerunFromHint,

        [Parameter()]
        [ValidateSet('markdown', 'plain-text', 'json')]
        [string]$OutputContract,

        [Parameter()]
        [ValidateSet('precise', 'balanced', 'creative')]
        [string]$QualityProfile,

        [Parameter()]
        [ValidateSet('auto', 'on', 'off')]
        [string]$ThinkingMode,

        [Parameter()]
        [ValidateSet('low', 'medium', 'high', 'xhigh')]
        [string]$ReasoningEffort,

        [Parameter()]
        [switch]$ReasoningEffortAuto,

        [Parameter()]
        [switch]$Quiet,

        [Parameter()]
        [switch]$ConfirmDestructive,

        [Parameter()]
        [ValidateSet('ignore', 'strip')]
        [string]$SignedFilePolicy,

        [Parameter()]
        [switch]$AutoRetryOnRecursion,

        [Parameter()]
        [switch]$DisableAutoRetryOnRecursion,

        [Parameter()]
        [bool]$NoTranscript = $true,

        [Parameter()]
        [switch]$AllowMetaTools,

        [Parameter()]
        [pscredential]$ToolCredential,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ToolCredentialVariableName = 'dac'
    )

    # Initialize the TechToolbox runtime and load agent configuration
    Initialize-TechToolboxRuntime
    $cfg = $script:cfg.settings.agent
    if ([string]::IsNullOrWhiteSpace($Model) -and $cfg -and -not [string]::IsNullOrWhiteSpace($cfg.model)) {
        $Model = $cfg.model
    }
    if ([string]::IsNullOrWhiteSpace($RuntimeProfile) -and $cfg -and -not [string]::IsNullOrWhiteSpace([string]$cfg.runtimeProfile)) {
        $RuntimeProfile = [string]$cfg.runtimeProfile
    }
    if ([string]::IsNullOrWhiteSpace($Provider) -and $cfg -and -not [string]::IsNullOrWhiteSpace([string]$cfg.provider)) {
        $Provider = [string]$cfg.provider
    }
    if ([string]::IsNullOrWhiteSpace($Provider)) {
        $Provider = 'ollama'
    }
    $Provider = $Provider.Trim().ToLowerInvariant()

    $moduleRoot = Get-ModuleRoot
    $promptSourceLabel = 'inline -Prompt'

    if (-not [string]::IsNullOrWhiteSpace($Prompt) -and -not [string]::IsNullOrWhiteSpace($PromptFile)) {
        throw 'Invoke-TechAgent: Specify only one prompt source: -Prompt or -PromptFile.'
    }

    if (-not [string]::IsNullOrWhiteSpace($PromptFile)) {
        $resolvedPromptPath = if ([System.IO.Path]::IsPathRooted($PromptFile)) {
            $PromptFile
        }
        else {
            Join-Path $moduleRoot $PromptFile
        }

        if (-not (Test-Path -LiteralPath $resolvedPromptPath -PathType Leaf)) {
            throw "Invoke-TechAgent: Prompt file not found: $resolvedPromptPath"
        }

        $Prompt = Get-Content -LiteralPath $resolvedPromptPath -Raw
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw "Invoke-TechAgent: Prompt file is empty: $resolvedPromptPath"
        }

        $promptSourceLabel = "-PromptFile ($resolvedPromptPath)"
    }
    elseif ([string]::IsNullOrWhiteSpace($Prompt)) {
        $defaultPromptFile = $null
        if ($cfg -and $cfg.defaultPromptFile -and -not [string]::IsNullOrWhiteSpace([string]$cfg.defaultPromptFile)) {
            $defaultPromptFile = [string]$cfg.defaultPromptFile
        }

        if ([string]::IsNullOrWhiteSpace($defaultPromptFile)) {
            $defaultPromptFile = 'AI\prompt.txt'
        }

        $resolvedDefaultPromptPath = if ([System.IO.Path]::IsPathRooted($defaultPromptFile)) {
            $defaultPromptFile
        }
        else {
            Join-Path $moduleRoot $defaultPromptFile
        }

        if (-not (Test-Path -LiteralPath $resolvedDefaultPromptPath -PathType Leaf)) {
            throw (
                'Invoke-TechAgent: No prompt text supplied and default prompt file was not found: {0}. ' +
                'Provide -Prompt, provide -PromptFile, or create the default prompt file.' -f $resolvedDefaultPromptPath
            )
        }

        $Prompt = Get-Content -LiteralPath $resolvedDefaultPromptPath -Raw
        if ([string]::IsNullOrWhiteSpace($Prompt)) {
            throw "Invoke-TechAgent: Default prompt file is empty: $resolvedDefaultPromptPath"
        }

        $promptSourceLabel = "default prompt file ($resolvedDefaultPromptPath)"
    }

    $resolvedExecutionMode = Resolve-TTAgentExecutionMode -ModeFromParam $Mode -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('Mode')
    $resolvedOutputContract = Resolve-TTAgentOutputContract -ContractFromParam $OutputContract -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('OutputContract')
    $resolvedQualityProfile = Resolve-TTAgentQualityProfile -ProfileFromParam $QualityProfile -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('QualityProfile')

    $expandedFollowUpPrompt = Expand-TTAgentOptionZipFollowUpPrompt -PromptText $Prompt -Mode $resolvedExecutionMode
    if (-not [string]::Equals($expandedFollowUpPrompt, $Prompt, [System.StringComparison]::Ordinal)) {
        Write-Log -Level Info -Message (
            "`nInvoke-TechAgent: normalized terse option follow-up prompt into explicit ZIP-based weather retry prompt."
        )
        $Prompt = $expandedFollowUpPrompt
        $promptSourceLabel = 'option-follow-up normalization'
    }

    $resolvedThinkingMode = if ($PSBoundParameters.ContainsKey('ThinkingMode') -and -not [string]::IsNullOrWhiteSpace($ThinkingMode)) {
        $ThinkingMode.Trim().ToLowerInvariant()
    }
    elseif ($cfg -and $cfg.PSObject.Properties['thinkingMode']) {
        [string]$cfg.thinkingMode
    }
    else {
        'auto'
    }
    if ([string]::IsNullOrWhiteSpace($resolvedThinkingMode)) {
        $resolvedThinkingMode = 'auto'
    }
    $resolvedThinkingMode = $resolvedThinkingMode.Trim().ToLowerInvariant()
    switch ($resolvedThinkingMode) {
        'on' { $resolvedThinkingEnabled = $true }
        'off' { $resolvedThinkingEnabled = $false }
        default { $resolvedThinkingEnabled = $resolvedExecutionMode -eq 'analyze' -or $resolvedExecutionMode -eq 'plan' -or $resolvedExecutionMode -eq 'chat' }
    }

    $resolvedReasoningEffort = $null
    if ($PSBoundParameters.ContainsKey('ReasoningEffort') -and -not [string]::IsNullOrWhiteSpace($ReasoningEffort)) {
        $resolvedReasoningEffort = $ReasoningEffort.Trim().ToLowerInvariant()
    }
    elseif ($cfg -and $cfg.PSObject.Properties['reasoningEffort']) {
        $resolvedReasoningEffort = [string]$cfg.reasoningEffort
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedReasoningEffort)) {
        $resolvedReasoningEffort = $resolvedReasoningEffort.Trim().ToLowerInvariant()
        switch ($resolvedReasoningEffort) {
            'low' { }
            'medium' { }
            'high' { }
            'xhigh' { }
            default {
                Write-Warning (
                    "`nInvoke-TechAgent: Ignoring unsupported reasoning effort value '{0}'. Supported values: low, medium, high, xhigh." -f $resolvedReasoningEffort
                )
                $resolvedReasoningEffort = $null
            }
        }
    }

    $resolvedReasoningEffortAuto = $false
    if ($PSBoundParameters.ContainsKey('ReasoningEffortAuto')) {
        $resolvedReasoningEffortAuto = $ReasoningEffortAuto.IsPresent
    }
    elseif ($cfg -and $cfg.PSObject.Properties['reasoningEffortAuto']) {
        $resolvedReasoningEffortAuto = [bool]$cfg.reasoningEffortAuto
    }

    $qualitySettings = switch ($resolvedQualityProfile) {
        'precise' {
            [ordered]@{ Temperature = '0.10'; TopP = '0.85'; RepeatPenalty = '1.10' }
            break
        }
        'creative' {
            [ordered]@{ Temperature = '0.50'; TopP = '0.95'; RepeatPenalty = '1.00' }
            break
        }
        default {
            [ordered]@{ Temperature = '0.20'; TopP = '0.90'; RepeatPenalty = '1.05' }
            break
        }
    }

    $preflight = Invoke-TTAgentPromptPreflight -PromptText $Prompt -Mode $resolvedExecutionMode
    $preflightScore = [int]$preflight.Score
    $preflightWarningCount = @($preflight.Warnings).Count
    $preflightCriticalCount = @($preflight.Critical).Count

    $promptPreflightSummary = (
        "score={0}/100 mode={1} outputContract={2} qualityProfile={3} source={4}" -f $preflightScore, $resolvedExecutionMode, $resolvedOutputContract, $resolvedQualityProfile, $promptSourceLabel
    )
    $reasoningEffortSettings = (
        "override={0} auto={1}" -f $(if ([string]::IsNullOrWhiteSpace($resolvedReasoningEffort)) { '(none)' } else { $resolvedReasoningEffort }), $resolvedReasoningEffortAuto
    )

    if ($StrictPromptPreflight.IsPresent) {
        foreach ($warning in @($preflight.Warnings)) {
            Write-Warning ("`nInvoke-TechAgent preflight: {0}" -f $warning)
        }

        if (@($preflight.Critical).Count -gt 0) {
            foreach ($criticalMessage in @($preflight.Critical)) {
                Write-Warning ("`nInvoke-TechAgent preflight critical: {0}" -f $criticalMessage)
            }
        }
    }

    if ($AutoPromptHint.IsPresent) {
        $hint = New-TTAgentAutoPromptHint `
            -PromptText $Prompt `
            -Mode $resolvedExecutionMode `
            -OutputContract $resolvedOutputContract `
            -WarningCount $preflightWarningCount `
            -CriticalCount $preflightCriticalCount

        if (-not [string]::IsNullOrWhiteSpace($hint)) {
            Write-Log -Level Info -Message ("`nInvoke-TechAgent auto prompt hint:`n{0}" -f $hint)
        }
    }

    if ($AutoRerunFromHint.IsPresent) {
        $rerunHint = New-TTAgentAutoPromptHint `
            -PromptText $Prompt `
            -Mode $resolvedExecutionMode `
            -OutputContract $resolvedOutputContract `
            -WarningCount $preflightWarningCount `
            -CriticalCount $preflightCriticalCount

        $shouldAutoRewritePrompt = (
            -not [string]::IsNullOrWhiteSpace($rerunHint) -and (
                $preflightCriticalCount -gt 0 -or
                $preflightScore -lt 60 -or
                $preflightWarningCount -ge 3
            )
        )

        if ($shouldAutoRewritePrompt) {
            Write-Log -Level Warn -Message (
                "`nInvoke-TechAgent auto rerun: applying one-time prompt rewrite from preflight hint."
            )
            Write-Log -Level Info -Message ("Invoke-TechAgent auto rerun prompt:`n{0}" -f $rerunHint)

            $Prompt = $rerunHint
            $promptSourceLabel = 'auto-rerun hint rewrite'

            $preflight = Invoke-TTAgentPromptPreflight -PromptText $Prompt -Mode $resolvedExecutionMode
            $preflightScore = [int]$preflight.Score
            $preflightWarningCount = @($preflight.Warnings).Count
            $preflightCriticalCount = @($preflight.Critical).Count

            $promptPreflightSummary = (
                "score={0}/100 mode={1} outputContract={2} qualityProfile={3} source={4}" -f $preflightScore, $resolvedExecutionMode, $resolvedOutputContract, $resolvedQualityProfile, $promptSourceLabel
            )

            foreach ($warning in @($preflight.Warnings)) {
                Write-Warning ("`nInvoke-TechAgent preflight (auto rerun): {0}" -f $warning)
            }

            foreach ($criticalMessage in @($preflight.Critical)) {
                Write-Warning ("`nInvoke-TechAgent preflight critical (auto rerun): {0}" -f $criticalMessage)
            }
        }
    }

    if ($StrictPromptPreflight.IsPresent) {
        if ($preflightScore -lt 60 -or @($preflight.Critical).Count -gt 0) {
            $criticalSummary = if (@($preflight.Critical).Count -eq 0) {
                'none'
            }
            else {
                (@($preflight.Critical) -join '; ')
            }

            throw (
                "Invoke-TechAgent preflight failed (score={0}/100, mode={1}). Critical issues: {2}" -f $preflightScore, $resolvedExecutionMode, $criticalSummary
            )
        }
    }

    $waitTimeoutSeconds = [Math]::Max(300, ($MaxIterations * 180))
    $waitPollSeconds = 15
    $waitHeartbeatSeconds = 120

    if ($cfg -and $cfg.wait) {
        $timeoutCfg = $cfg.wait.timeoutSeconds -as [int]
        if ($null -ne $timeoutCfg -and $timeoutCfg -gt 0) {
            $waitTimeoutSeconds = $timeoutCfg
        }

        $pollCfg = $cfg.wait.pollSeconds -as [int]
        if ($null -ne $pollCfg -and $pollCfg -gt 0) {
            $waitPollSeconds = $pollCfg
        }

        $heartbeatCfg = $cfg.wait.heartbeatSeconds -as [int]
        if ($null -ne $heartbeatCfg -and $heartbeatCfg -ge 0) {
            $waitHeartbeatSeconds = $heartbeatCfg
        }
    }

    $transcriptStarted = $false
    $transcriptPath = $null
    $markdownPath = $null
    $markdownStatus = 'NotStarted'
    $markdownError = $null
    $markdownRecoveryReason = $null
    $markdownPostflightReason = $null
    $markdownPostflightAchieved = $true
    $markdownResponseLength = 0
    $markdownKnownFailureDetected = $false
    $markdownExpectedOutputExists = $false
    $capturedStdOut = ''
    $capturedStdErr = ''
    $markdownAdaptiveLimitsPreflight = ''
    $markdownPromptPreflightSummary = ''
    $markdownReasoningEffortSettings = ''
    $markdownRuntimeAssemblyPath = ''
    $runStartedUtc = [DateTime]::UtcNow
    $agentProc = $null
    $stdoutTask = $null
    $stderrTask = $null
    $requestPath = $null
    $resolvedApiKey = $null
    $toolCredentialPath = $null

    $expectedOutputPath = Resolve-TTAgentExpectedOutputPath -PromptText $Prompt

    $effectivePrompt = $Prompt
    if (-not [string]::IsNullOrWhiteSpace($expectedOutputPath)) {
        $effectivePrompt = @"
$Prompt

Hard requirement:
- Create the output file at this exact path: $expectedOutputPath
- Use WRITE-FILE to create/update the file.
- Do not return a final answer until WRITE-FILE has succeeded.
"@
    }

    if ($AutoRetryOnRecursion.IsPresent -and $DisableAutoRetryOnRecursion.IsPresent) {
        throw 'Specify only one of -AutoRetryOnRecursion or -DisableAutoRetryOnRecursion.'
    }

    try {
        $moduleRoot = Get-ModuleRoot
        $assemblyCandidates = @(
            (Join-Path $moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll')
        )

        $agentAssemblyPath = $null
        foreach ($candidatePath in $assemblyCandidates) {
            if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
                $agentAssemblyPath = [string]$candidatePath
                break
            }
        }

        if ([string]::IsNullOrWhiteSpace($agentAssemblyPath)) {
            throw "TechToolbox.Agent assembly not found. Install the packaged agent runtime or build/publish src\TechToolbox.Agent."
        }

        $markdownRuntimeAssemblyPath = $agentAssemblyPath
        $markdownPromptPreflightSummary = $promptPreflightSummary
        $markdownReasoningEffortSettings = $reasoningEffortSettings

        # Invoke-TechAgent now uses an internal terminal-state wait loop.
        # Keeping this self-contained avoids helper load drift and improves reliability.

        if ($Provider -eq 'ollama' -and -not [string]::IsNullOrWhiteSpace($Model)) {
            $normalizedModelName = $Model.Trim()
            $isAutoRoutingAlias = (
                $normalizedModelName -ieq 'auto' -or
                $normalizedModelName -ieq 'default' -or
                $normalizedModelName -ieq 'llama3'
            )

            if (-not $isAutoRoutingAlias) {
                $ollamaCommand = Get-Command -Name ollama -ErrorAction SilentlyContinue
                if (-not $ollamaCommand) {
                    throw "Ollama executable not found. Install Ollama or add it to PATH."
                }

                $ollamaListOutput = & $ollamaCommand.Source list 2>&1
                if ($LASTEXITCODE -ne 0) {
                    $ollamaError = ($ollamaListOutput | Out-String).Trim()
                    throw ("Unable to query local Ollama models: {0}" -f $ollamaError)
                }

                $availableModels = @()
                foreach ($line in $ollamaListOutput) {
                    $trimmed = "$line".Trim()
                    if ([string]::IsNullOrWhiteSpace($trimmed)) {
                        continue
                    }

                    if ($trimmed -match '^NAME\s+') {
                        continue
                    }

                    $parts = $trimmed -split '\s+'
                    if ($parts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
                        $availableModels += $parts[0]
                    }
                }

                if (-not $availableModels) {
                    throw ("No local Ollama models were found. Pull the requested model first: ollama pull {0}" -f $Model)
                }

                if ($availableModels -notcontains $Model) {
                    $knownModels = ($availableModels | Sort-Object -Unique) -join ', '
                    throw (
                        "Ollama model '{0}' is not available locally. Run: ollama pull {0}. Available models: {1}" -f $Model, $knownModels
                    )
                }
            }
        }

        $transcriptEnabled = $true
        $transcriptRoot = $null
        $markdownEnabled = $true
        $markdownRoot = $null
        if ($cfg -and $cfg.transcript) {
            if ($null -ne $cfg.transcript.enabled) {
                $transcriptEnabled = [bool]$cfg.transcript.enabled
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$cfg.transcript.outputRoot)) {
                $transcriptRoot = [string]$cfg.transcript.outputRoot
            }

            $markdownEnabledProperty = $cfg.transcript.PSObject.Properties['markdownEnabled']
            if ($null -ne $markdownEnabledProperty -and $null -ne $markdownEnabledProperty.Value) {
                $markdownEnabled = [bool]$markdownEnabledProperty.Value
            }

            $markdownOutputRootProperty = $cfg.transcript.PSObject.Properties['markdownOutputRoot']
            if ($null -ne $markdownOutputRootProperty -and -not [string]::IsNullOrWhiteSpace([string]$markdownOutputRootProperty.Value)) {
                $markdownRoot = [string]$markdownOutputRootProperty.Value
            }
        }

        if ($NoTranscript) {
            $transcriptEnabled = $false
        }

        if ($transcriptEnabled) {
            if ([string]::IsNullOrWhiteSpace($transcriptRoot)) {
                $transcriptRoot = Join-Path $moduleRoot 'LogsAndExports\Logs\TechAgentTranscripts'
            }

            try {
                $null = New-Item -ItemType Directory -Path $transcriptRoot -Force
                $transcriptPath = Join-Path $transcriptRoot ("TechAgent_{0}_{1}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $PID)
                Start-Transcript -Path $transcriptPath -Force | Out-Null
                $transcriptStarted = $true
                Write-Log -Level Info -Message ("Tech agent transcript started: {0}" -f $transcriptPath)
            }
            catch {
                Write-Log -Level Warn -Message ("Tech agent transcript could not be started: {0}" -f $_.Exception.Message)
            }
        }

        if ($markdownEnabled) {
            if ([string]::IsNullOrWhiteSpace($markdownRoot)) {
                $markdownRoot = Join-Path $moduleRoot 'LogsAndExports\Logs\TechAgentMarkdown'
            }

            try {
                $null = New-Item -ItemType Directory -Path $markdownRoot -Force
                $markdownPath = Join-Path $markdownRoot ("TechAgent_{0}_{1}.md" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $PID)
            }
            catch {
                $markdownPath = $null
                Write-Log -Level Warn -Message ("Tech agent markdown log could not be initialized: {0}" -f $_.Exception.Message)
            }
        }

        if ($ConfirmDestructive.IsPresent) {
            Write-Log -Level Warn -Message "Destructive operations explicitly authorized for this run."
        }

        $autoRetryOnIterationLimit = $false
        if ($AutoRetryOnRecursion.IsPresent) {
            $autoRetryOnIterationLimit = $true
        }
        elseif ($DisableAutoRetryOnRecursion.IsPresent) {
            $autoRetryOnIterationLimit = $false
        }

        if ([string]::IsNullOrWhiteSpace($Endpoint)) {
            $endpointValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'endpoint'
            if (-not [string]::IsNullOrWhiteSpace([string]$endpointValue)) {
                $Endpoint = [string]$endpointValue
            }
        }

        if ([string]::IsNullOrWhiteSpace($Deployment)) {
            $deploymentValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'deployment'
            if (-not [string]::IsNullOrWhiteSpace([string]$deploymentValue)) {
                $Deployment = [string]$deploymentValue
            }
        }

        if ([string]::IsNullOrWhiteSpace($ApiVersion)) {
            $apiVersionValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'apiVersion'
            if (-not [string]::IsNullOrWhiteSpace([string]$apiVersionValue)) {
                $ApiVersion = [string]$apiVersionValue
            }
        }

        if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
            $apiKeyEnvVarValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'apiKeyEnvVar'
            if (-not [string]::IsNullOrWhiteSpace([string]$apiKeyEnvVarValue)) {
                $ApiKeyEnvVar = [string]$apiKeyEnvVarValue
            }
        }

        if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
            $ApiKeyEnvVar = 'TT_AGENT_LLM_API_KEY'
        }

        if ($Provider -ne 'ollama') {
            $apiKeyResolution = Resolve-TTAgentCloudApiKey -ConfigObject $cfg -ProviderName $Provider -EnvVarName $ApiKeyEnvVar -EncryptedOverride $ApiKeyEncryptedBlob -PreferEncryptedOnly:$ApiKeyEncrypted
            $resolvedApiKey = [string]$apiKeyResolution.Key

            if ([string]::IsNullOrWhiteSpace($resolvedApiKey)) {
                $promptResolution = Request-TTAgentCloudApiKeyPersistence -ProviderName $Provider -EnvVarName $ApiKeyEnvVar -DisableApiKeyPrompt $DisableApiKeyPrompt.IsPresent
                if (-not [string]::IsNullOrWhiteSpace([string]$promptResolution.Key)) {
                    $resolvedApiKey = [string]$promptResolution.Key
                    $apiKeyResolution = $promptResolution
                }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$promptResolution.Error)) {
                    throw (
                        "Cloud provider '{0}' API key prompt/store failed via {1}: {2}" -f $Provider, $promptResolution.Source, $promptResolution.Error
                    )
                }
            }

            if ([string]::IsNullOrWhiteSpace($resolvedApiKey)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$apiKeyResolution.Error)) {
                    throw (
                        "Cloud provider '{0}' API key resolution failed via {1}: {2}" -f $Provider, $apiKeyResolution.Source, $apiKeyResolution.Error
                    )
                }

                throw (
                    "Cloud provider '{0}' requires an API key. Set environment variable '{1}', configure settings.agent.apiKeyEncrypted in config.secrets.json, run Set-TechAgentApiKey, or run interactively to store one now." -f $Provider, $ApiKeyEnvVar
                )
            }

            if ($Provider -eq 'azure-openai' -and [string]::IsNullOrWhiteSpace($Deployment)) {
                throw "Provider 'azure-openai' requires -Deployment (or settings.agent.deployment)."
            }
        }

        $resolvedAutoModelRoutingEnabled = $true
        $resolvedAutoModelRoutingThreshold = 50
        if ($cfg -and $cfg.PSObject.Properties['autoModelRouting']) {
            $autoModelRoutingConfig = $cfg.autoModelRouting
            if ($null -ne $autoModelRoutingConfig) {
                $autoModelRoutingEnabledValue = $null
                if ($autoModelRoutingConfig.PSObject.Properties['enabled']) {
                    $autoModelRoutingEnabledValue = $autoModelRoutingConfig.enabled
                }
                if ($null -ne $autoModelRoutingEnabledValue) {
                    $resolvedAutoModelRoutingEnabled = [bool]$autoModelRoutingEnabledValue
                }

                $autoModelRoutingThresholdValue = $null
                if ($autoModelRoutingConfig.PSObject.Properties['threshold']) {
                    $autoModelRoutingThresholdValue = $autoModelRoutingConfig.threshold
                }
                if ($null -ne $autoModelRoutingThresholdValue) {
                    [int]$parsedThreshold = 50
                    if ([int]::TryParse([string]$autoModelRoutingThresholdValue, [ref]$parsedThreshold)) {
                        $resolvedAutoModelRoutingThreshold = [Math]::Max(0, [Math]::Min(100, $parsedThreshold))
                    }
                }
            }
        }

        $resolvedModel = $Model
        if ([string]::IsNullOrWhiteSpace($resolvedModel)) {
            if ($Provider -eq 'ollama') {
                if ($resolvedAutoModelRoutingEnabled) {
                    $resolvedModel = 'auto'
                }
                else {
                    $resolvedModel = 'llama3'
                }
            }
            elseif ($Provider -ne 'azure-openai') {
                throw "Provider '$Provider' requires -Model (or settings.agent.model)."
            }
            else {
                $resolvedModel = ''
            }
        }

        if ($Provider -eq 'ollama') {
            $normalizedResolvedModel = if ($null -ne $resolvedModel) { $resolvedModel.Trim() } else { '' }
            $isAutoRoutingAlias = (
                [string]::IsNullOrWhiteSpace($normalizedResolvedModel) -or
                $normalizedResolvedModel -ieq 'auto' -or
                $normalizedResolvedModel -ieq 'default' -or
                $normalizedResolvedModel -ieq 'llama3'
            )

            if ($isAutoRoutingAlias) {
                try {
                    $llmClientFactoryType = $null
                    try {
                        $llmClientFactoryType = [TechToolbox.Agent.Llm.LlmClientFactory]
                    }
                    catch {
                        $null = Add-Type -Path $agentAssemblyPath -ErrorAction Stop
                        $llmClientFactoryType = [TechToolbox.Agent.Llm.LlmClientFactory]
                    }

                    if ($null -ne $llmClientFactoryType) {
                        $selectedPromptModel = $llmClientFactoryType::SelectModelForPrompt(
                            $effectivePrompt,
                            $resolvedExecutionMode,
                            $preflightScore,
                            0,
                            $null,
                            $resolvedAutoModelRoutingEnabled,
                            $resolvedAutoModelRoutingThreshold
                        )

                        if (-not [string]::IsNullOrWhiteSpace([string]$selectedPromptModel)) {
                            $resolvedModel = [string]$selectedPromptModel
                        }
                    }
                }
                catch {
                    Write-Log -Level Warn -Message ("Unable to resolve the effective Ollama model for this run. Keeping the alias value '{0}' in markdown output: {1}" -f $resolvedModel, $_.Exception.Message)
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($RuntimeProfile)) {
            $RuntimeProfile = $RuntimeProfile.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($RuntimeProfile)) {
            $RuntimeProfile = $null
        }

        $runtimeProfilesJson = $null
        $runtimeProfilesConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'runtimeProfiles'
        if ($null -ne $runtimeProfilesConfig) {
            try {
                $runtimeProfilesJson = $runtimeProfilesConfig | ConvertTo-Json -Depth 12 -Compress
            }
            catch {
                Write-Log -Level Warn -Message ("Failed to serialize settings.agent.runtimeProfiles: {0}" -f $_.Exception.Message)
                $runtimeProfilesJson = $null
            }
        }

        $resiliencePolicyJson = $null
        $resilienceConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'resilience'
        if ($null -eq $resilienceConfig) {
            $resilienceConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'resiliencePolicy'
        }
        if ($null -ne $resilienceConfig) {
            try {
                $resiliencePolicyJson = $resilienceConfig | ConvertTo-Json -Depth 12 -Compress
            }
            catch {
                Write-Log -Level Warn -Message ("Failed to serialize settings.agent.resilience: {0}" -f $_.Exception.Message)
                $resiliencePolicyJson = $null
            }
        }

        $memoryPath = $null
        $memoryPathValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'memoryPath'
        if (-not [string]::IsNullOrWhiteSpace([string]$memoryPathValue)) {
            $memoryPath = [string]$memoryPathValue
        }

        [int]$resolvedPromptHistoryItems = 2
        if ($PSBoundParameters.ContainsKey('PromptHistoryItems')) {
            $resolvedPromptHistoryItems = [int]$PromptHistoryItems
        }
        else {
            $promptHistoryItemsValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'promptHistoryItems'
            if ($null -ne $promptHistoryItemsValue) {
                [int]$parsedPromptHistoryItems = 0
                if ([int]::TryParse([string]$promptHistoryItemsValue, [ref]$parsedPromptHistoryItems)) {
                    $resolvedPromptHistoryItems = $parsedPromptHistoryItems
                }
            }
        }

        $resolvedPromptHistoryItems = [Math]::Max(0, [Math]::Min(20, $resolvedPromptHistoryItems))

        if (-not [string]::IsNullOrWhiteSpace($memoryPath)) {
            try {
                $memoryDirectory = Split-Path -Path $memoryPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($memoryDirectory)) {
                    $null = New-Item -ItemType Directory -Path $memoryDirectory -Force
                }

                if (-not (Test-Path -LiteralPath $memoryPath -PathType Leaf)) {
                    $memorySeed = @{
                        preferences          = @{}
                        facts                = @{}
                        _memoryFormatVersion = 2
                        history              = @()
                    } | ConvertTo-Json -Depth 4

                    Set-Content -LiteralPath $memoryPath -Value $memorySeed -Encoding utf8
                    Write-Log -Level Info -Message ("Initialized missing agent memory file: {0}" -f $memoryPath)
                }

                $memoryHistoryPath = Join-Path $memoryDirectory (([System.IO.Path]::GetFileNameWithoutExtension($memoryPath)) + '.history.json')
                if (-not (Test-Path -LiteralPath $memoryHistoryPath -PathType Leaf)) {
                    Set-Content -LiteralPath $memoryHistoryPath -Value '[]' -Encoding utf8
                    Write-Log -Level Info -Message ("Initialized missing agent memory history file: {0}" -f $memoryHistoryPath)
                }
            }
            catch {
                throw ("Failed to initialize agent memory files at '{0}': {1}" -f $memoryPath, $_.Exception.Message)
            }
        }

        $diagnosticTracePath = $null
        $diagnosticTracePathValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'diagnosticTracePath'
        if (-not [string]::IsNullOrWhiteSpace([string]$diagnosticTracePathValue)) {
            $diagnosticTracePath = [string]$diagnosticTracePathValue
            Write-Log -Level Info -Message ("Tech agent diagnostic trace path: {0}" -f $diagnosticTracePath)
        }

        $allowedFetchHosts = @()
        $fetchConfigValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'fetch'
        if ($null -ne $fetchConfigValue) {
            $allowedHostsValue = Get-TTAgentConfigValue -ConfigObject $fetchConfigValue -KeyName 'allowedHosts'
            if ($null -ne $allowedHostsValue) {
                foreach ($host in @($allowedHostsValue)) {
                    $hostText = [string]$host
                    if ([string]::IsNullOrWhiteSpace($hostText)) {
                        continue
                    }

                    $normalizedHost = $hostText.Trim().Trim('.').ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($normalizedHost)) {
                        continue
                    }

                    if ($allowedFetchHosts -notcontains $normalizedHost) {
                        $allowedFetchHosts += $normalizedHost
                    }
                }
            }
        }

        $searchWebProvider = 'brave'
        $searchWebEndpoint = $null
        $searchWebApiKeyEnvVar = 'TT_AGENT_SEARCH_WEB_API_KEY'
        $searchWebCountry = 'us'
        $searchWebLanguage = 'en'
        $searchWebSafeSearch = 'moderate'
        $searchWebDefaultCount = 5
        $searchWebConfigValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'searchWeb'
        if ($null -ne $searchWebConfigValue) {
            $searchProviderValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'provider'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchProviderValue)) {
                $searchWebProvider = [string]$searchProviderValue
            }

            $searchEndpointValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'endpoint'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchEndpointValue)) {
                $searchWebEndpoint = [string]$searchEndpointValue
            }

            $searchApiKeyEnvVarValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'apiKeyEnvVar'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchApiKeyEnvVarValue)) {
                $searchWebApiKeyEnvVar = [string]$searchApiKeyEnvVarValue
            }

            $searchCountryValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'country'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchCountryValue)) {
                $searchWebCountry = [string]$searchCountryValue
            }

            $searchLanguageValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'language'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchLanguageValue)) {
                $searchWebLanguage = [string]$searchLanguageValue
            }

            $searchSafeSearchValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'safeSearch'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchSafeSearchValue)) {
                $searchWebSafeSearch = [string]$searchSafeSearchValue
            }

            $searchDefaultCountValue = Get-TTAgentConfigValue -ConfigObject $searchWebConfigValue -KeyName 'defaultCount'
            if ($null -ne $searchDefaultCountValue) {
                [int]$parsedSearchCount = 0
                if ([int]::TryParse([string]$searchDefaultCountValue, [ref]$parsedSearchCount)) {
                    $searchWebDefaultCount = $parsedSearchCount
                }
            }
        }

        $resolvedSearchWebApiKey = $null
        if (-not [string]::IsNullOrWhiteSpace($searchWebApiKeyEnvVar)) {
            $searchWebApiKeyResolution = Resolve-TTAgentStoredSecret -ConfigObject $cfg -SecretKeyName 'searchWebApiKeyEncrypted' -EnvVarName $searchWebApiKeyEnvVar
            $resolvedSearchWebApiKey = [string]$searchWebApiKeyResolution.Key
        }

        $request = [ordered]@{
            Prompt                       = $effectivePrompt
            Model                        = $resolvedModel
            ExecutionMode                = $resolvedExecutionMode
            OutputContract               = $resolvedOutputContract
            QualityProfile               = $resolvedQualityProfile
            ThinkingMode                 = $resolvedThinkingMode
            ReasoningEffort              = $resolvedReasoningEffort
            ReasoningEffortAuto          = $resolvedReasoningEffortAuto
            PromptPreflightScore         = $preflightScore
            PromptPreflightWarningCount  = $preflightWarningCount
            PromptPreflightCriticalCount = $preflightCriticalCount
            RuntimeProfile               = $RuntimeProfile
            RuntimeProfilesJson          = $runtimeProfilesJson
            ResiliencePolicyJson         = $resiliencePolicyJson
            Verbose                      = $false
            MaxIterations                = $MaxIterations
            PromptHistoryItems           = $resolvedPromptHistoryItems
            ConfirmDestructive           = $ConfirmDestructive.IsPresent
            MemoryPath                   = $memoryPath
            AutoRetryOnRecursion         = $autoRetryOnIterationLimit
            ReturnMetadata               = $false
            SignedFilePolicy             = $(if ([string]::IsNullOrWhiteSpace($SignedFilePolicy)) { 'ignore' } else { $SignedFilePolicy })
            DiagnosticTracePath          = $diagnosticTracePath
            ExpectedOutputPath           = $expectedOutputPath
            AllowedFetchHosts            = @($allowedFetchHosts)
            SearchWebProvider            = $searchWebProvider
            SearchWebEndpoint            = $searchWebEndpoint
            SearchWebApiKeyEnvVar        = $searchWebApiKeyEnvVar
            SearchWebCountry             = $searchWebCountry
            SearchWebLanguage            = $searchWebLanguage
            SearchWebSafeSearch          = $searchWebSafeSearch
            SearchWebDefaultCount        = $searchWebDefaultCount
            AllowMetaTools               = $AllowMetaTools.IsPresent
            LlmProvider                  = $Provider
            LlmEndpoint                  = $Endpoint
            LlmDeployment                = $Deployment
            LlmApiVersion                = $ApiVersion
        }

        $requestPath = Join-Path ([System.IO.Path]::GetTempPath()) ("techtoolbox-agent-request-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $request | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $requestPath -Encoding utf8

        $effectiveToolCredential = $null
        if ($PSBoundParameters.ContainsKey('ToolCredential') -and $null -ne $ToolCredential) {
            $effectiveToolCredential = $ToolCredential
            Write-Log -Level Info -Message 'Tech agent credential source: -ToolCredential parameter.'
        }
        elseif (-not [string]::IsNullOrWhiteSpace($ToolCredentialVariableName)) {
            $credentialVarValue = $null

            $credentialVar = Get-Variable -Name $ToolCredentialVariableName -Scope 1 -ErrorAction SilentlyContinue
            if ($credentialVar) {
                $credentialVarValue = $credentialVar.Value
            }
            elseif ($null -eq $credentialVarValue) {
                $credentialVar = Get-Variable -Name $ToolCredentialVariableName -Scope Script -ErrorAction SilentlyContinue
                if ($credentialVar) { $credentialVarValue = $credentialVar.Value }
            }

            if ($null -eq $credentialVarValue) {
                $credentialVar = Get-Variable -Name $ToolCredentialVariableName -Scope Global -ErrorAction SilentlyContinue
                if ($credentialVar) { $credentialVarValue = $credentialVar.Value }
            }

            if ($credentialVarValue -is [System.Management.Automation.PSCredential]) {
                $effectiveToolCredential = [System.Management.Automation.PSCredential]$credentialVarValue
                Write-Log -Level Info -Message ("Tech agent credential source: variable '{0}'." -f $ToolCredentialVariableName)
            }
        }

        if ($null -ne $effectiveToolCredential) {
            $toolCredentialPath = Join-Path ([System.IO.Path]::GetTempPath()) ("techtoolbox-agent-credential-{0}.clixml" -f ([guid]::NewGuid().ToString('N')))
            $effectiveToolCredential | Export-Clixml -LiteralPath $toolCredentialPath -Force
        }

        $childPwsh = Join-Path $PSHOME 'pwsh.exe'
        if (-not (Test-Path -LiteralPath $childPwsh -PathType Leaf)) {
            $childPwsh = (Get-Process -Id $PID).Path
        }

        $childScript = @'
    $ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = Get-Content -LiteralPath $env:TT_AGENT_REQUEST_PATH -Raw | ConvertFrom-Json
$agentAssemblyPath = [System.IO.Path]::GetFullPath([string]$env:TT_AGENT_ASSEMBLY_PATH)
if (-not (Test-Path -LiteralPath $agentAssemblyPath -PathType Leaf)) {
    throw ("TechToolbox.Agent assembly not found at '{0}'." -f $agentAssemblyPath)
}

$loadedAgentAssembly = [System.Reflection.Assembly]::LoadFrom($agentAssemblyPath)
$agentCoreType = $loadedAgentAssembly.GetType('TechToolbox.Agent.Core.AgentCore', $false)
if ($null -eq $agentCoreType) {
    throw ("Unable to locate type 'TechToolbox.Agent.Core.AgentCore' in assembly '{0}'." -f $agentAssemblyPath)
}

$runAgentMethod = $agentCoreType.GetMethod(
    'RunAgent',
    [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static,
    $null,
    @(
        [string],
        [string],
        [bool],
        [int],
        [bool],
        [string],
        [bool],
        [bool],
        [string],
        [string],
        [string],
        [int],
        [System.Collections.Generic.IEnumerable[string]],
        [string],
        [string],
        [string],
        [string],
        [string],
        [string],
        [int],
        [bool],
        [string],
        [string],
        [string],
        [string],
        [string],
        [string],
        [string],
        [string],
        [string],
        [bool],
        [int],
        [int],
        [int],
        [string],
        [string],
        [string]
    ),
    $null
)

if ($null -eq $runAgentMethod) {
    throw "Unable to locate the legacy RunAgent overload with the expected parameter signature."
}

$allowedFetchHosts = [string[]]@()
if ($null -ne $request.AllowedFetchHosts) {
    $allowedFetchHosts = @($request.AllowedFetchHosts | ForEach-Object {
            if ($null -ne $_) {
                [string]$_
            }
        })
}

$result = $runAgentMethod.Invoke($null, @(
    [string]$request.Prompt,
    [string]$request.Model,
    [bool]$request.Verbose,
    [int]$request.MaxIterations,
    [bool]$request.ConfirmDestructive,
    [string]$request.MemoryPath,
    [bool]$request.AutoRetryOnRecursion,
    [bool]$request.ReturnMetadata,
    [string]$request.SignedFilePolicy,
    [string]$request.DiagnosticTracePath,
    [string]$request.ExpectedOutputPath,
    [int]$request.PromptHistoryItems,
    [string[]]$allowedFetchHosts,
    [string]$request.SearchWebProvider,
    [string]$request.SearchWebEndpoint,
    [string]$request.SearchWebApiKeyEnvVar,
    [string]$request.SearchWebCountry,
    [string]$request.SearchWebLanguage,
    [string]$request.SearchWebSafeSearch,
    [int]$request.SearchWebDefaultCount,
    [bool]$request.AllowMetaTools,
    [string]$request.LlmProvider,
    [string]$request.LlmEndpoint,
    [string]$request.LlmDeployment,
    [string]$request.LlmApiVersion,
    [string]$request.ExecutionMode,
    [string]$request.OutputContract,
    [string]$request.QualityProfile,
    [string]$request.ThinkingMode,
    [string]$request.ReasoningEffort,
    [bool]$request.ReasoningEffortAuto,
    [int]$request.PromptPreflightScore,
    [int]$request.PromptPreflightWarningCount,
    [int]$request.PromptPreflightCriticalCount,
    [string]$request.RuntimeProfile,
    [string]$request.RuntimeProfilesJson,
    [string]$request.ResiliencePolicyJson
))
[Console]::Write($result)
'@

        $encodedChildScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childScript))
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $childPwsh
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $startInfo.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)

        $adaptiveOverridesEnabled = $true
        $adaptiveLimitProfilesConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'adaptiveLimitProfiles'
        if ($null -ne $adaptiveLimitProfilesConfig) {
            $adaptiveEnabledConfigValue = Get-TTAgentConfigValue -ConfigObject $adaptiveLimitProfilesConfig -KeyName 'enabled'
            if ($null -ne $adaptiveEnabledConfigValue) {
                [bool]$adaptiveEnabledParsed = $true
                if ([bool]::TryParse([string]$adaptiveEnabledConfigValue, [ref]$adaptiveEnabledParsed)) {
                    $adaptiveOverridesEnabled = $adaptiveEnabledParsed
                }
            }
        }

        $disableAdaptiveRaw = [Environment]::GetEnvironmentVariable('TT_AGENT_DISABLE_ADAPTIVE_LIMIT_OVERRIDES')
        if (-not [string]::IsNullOrWhiteSpace($disableAdaptiveRaw)) {
            [bool]$disableAdaptiveParsed = $false
            if ([bool]::TryParse($disableAdaptiveRaw, [ref]$disableAdaptiveParsed) -and $disableAdaptiveParsed) {
                $adaptiveOverridesEnabled = $false
            }
        }

        $providerForAdaptive = if ([string]::IsNullOrWhiteSpace($Provider)) {
            'ollama'
        }
        else {
            $Provider.Trim().ToLowerInvariant()
        }

        $isLoopbackEndpoint = $false
        $isEndpointSpecified = -not [string]::IsNullOrWhiteSpace($Endpoint)
        if ($isEndpointSpecified) {
            try {
                $endpointUri = [System.Uri]$Endpoint
                $endpointHost = $endpointUri.Host.Trim().ToLowerInvariant()
                if ($endpointHost -eq 'localhost' -or $endpointHost -eq '127.0.0.1' -or $endpointHost -eq '::1') {
                    $isLoopbackEndpoint = $true
                }
            }
            catch {
                $isLoopbackEndpoint = $false
            }
        }

        $adaptiveLimitProfile = 'local-moderate'
        switch ($providerForAdaptive) {
            'openai' { $adaptiveLimitProfile = 'frontier-high' }
            'azure-openai' { $adaptiveLimitProfile = 'frontier-high' }
            'openai-compatible' {
                if ($isEndpointSpecified -and -not $isLoopbackEndpoint) {
                    $adaptiveLimitProfile = 'frontier-high'
                }
            }
        }

        $adaptiveProfileKey = if ($adaptiveLimitProfile -eq 'frontier-high') {
            'frontierHigh'
        }
        else {
            'localModerate'
        }

        $testAdaptiveModelMatch = {
            param(
                [string]$ModelName,
                [string]$Pattern,
                [bool]$UseRegex
            )

            if ([string]::IsNullOrWhiteSpace($ModelName) -or [string]::IsNullOrWhiteSpace($Pattern)) {
                return $false
            }

            if ($UseRegex) {
                try {
                    return [System.Text.RegularExpressions.Regex]::IsMatch($ModelName, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                }
                catch {
                    return $false
                }
            }

            if ($Pattern.Contains('*') -or $Pattern.Contains('?')) {
                return $ModelName -like $Pattern
            }

            return $ModelName.IndexOf($Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        }

        $selectedModelMatcherPattern = $null
        $selectedModelMatcherProfile = $null
        if ($null -ne $adaptiveLimitProfilesConfig) {
            $modelMatchersConfig = Get-TTAgentConfigValue -ConfigObject $adaptiveLimitProfilesConfig -KeyName 'modelMatchers'
            if ($null -ne $modelMatchersConfig) {
                foreach ($matcher in @($modelMatchersConfig)) {
                    if ($null -eq $matcher) {
                        continue
                    }

                    $matcherPattern = [string](Get-TTAgentConfigValue -ConfigObject $matcher -KeyName 'pattern')
                    $matcherProfileRaw = [string](Get-TTAgentConfigValue -ConfigObject $matcher -KeyName 'profile')
                    $matcherRegexValue = Get-TTAgentConfigValue -ConfigObject $matcher -KeyName 'useRegex'

                    if ([string]::IsNullOrWhiteSpace($matcherPattern) -or [string]::IsNullOrWhiteSpace($matcherProfileRaw)) {
                        continue
                    }

                    [bool]$matcherUseRegex = $false
                    if ($null -ne $matcherRegexValue) {
                        [bool]$parsedMatcherUseRegex = $false
                        if ([bool]::TryParse([string]$matcherRegexValue, [ref]$parsedMatcherUseRegex)) {
                            $matcherUseRegex = $parsedMatcherUseRegex
                        }
                    }

                    $normalizedMatcherProfile = $matcherProfileRaw.Trim()
                    switch -Regex ($normalizedMatcherProfile.ToLowerInvariant()) {
                        '^local[-_ ]?moderate$' { $normalizedMatcherProfile = 'localModerate'; break }
                        '^frontier[-_ ]?high$' { $normalizedMatcherProfile = 'frontierHigh'; break }
                        '^frontier[-_ ]?xl$' { $normalizedMatcherProfile = 'frontierXL'; break }
                    }

                    if ($normalizedMatcherProfile -ne 'localModerate' -and $normalizedMatcherProfile -ne 'frontierHigh' -and $normalizedMatcherProfile -ne 'frontierXL') {
                        continue
                    }

                    if (-not (& $testAdaptiveModelMatch -ModelName $resolvedModel -Pattern $matcherPattern -UseRegex $matcherUseRegex)) {
                        continue
                    }

                    $adaptiveProfileKey = $normalizedMatcherProfile
                    switch ($adaptiveProfileKey) {
                        'frontierXL' { $adaptiveLimitProfile = 'frontier-xl' }
                        'frontierHigh' { $adaptiveLimitProfile = 'frontier-high' }
                        default { $adaptiveLimitProfile = 'local-moderate' }
                    }
                    $selectedModelMatcherPattern = $matcherPattern
                    $selectedModelMatcherProfile = $adaptiveProfileKey
                    break
                }
            }
        }

        $adaptiveLocalDefaults = @{
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS' = '30000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS' = '30000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '12000'
        }
        $adaptiveFrontierDefaults = @{
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS' = '90000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS' = '90000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '30000'
            'TT_AGENT_LLM_MAX_OUTPUT_TOKENS' = '8192'
        }
        $adaptiveFrontierXlDefaults = @{
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS' = '120000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS' = '120000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '45000'
            'TT_AGENT_LLM_MAX_OUTPUT_TOKENS' = '12000'
        }

        $adaptiveEnvironmentDefaults = switch ($adaptiveProfileKey) {
            'frontierXL' { @{} + $adaptiveFrontierXlDefaults; break }
            'frontierHigh' { @{} + $adaptiveFrontierDefaults; break }
            default { @{} + $adaptiveLocalDefaults }
        }

        if ($null -ne $adaptiveLimitProfilesConfig) {
            $selectedAdaptiveProfile = Get-TTAgentConfigValue -ConfigObject $adaptiveLimitProfilesConfig -KeyName $adaptiveProfileKey
            if ($null -ne $selectedAdaptiveProfile) {
                $adaptivePropertyMap = @{
                    'readFileSummaryThresholdChars' = 'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS'
                    'maxToolResultChars' = 'TT_AGENT_MAX_TOOL_RESULT_CHARS'
                    'readFilePromptCompactThresholdChars' = 'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS'
                    'llmMaxOutputTokens' = 'TT_AGENT_LLM_MAX_OUTPUT_TOKENS'
                }

                foreach ($adaptivePropertyName in $adaptivePropertyMap.Keys) {
                    $adaptivePropertyValue = Get-TTAgentConfigValue -ConfigObject $selectedAdaptiveProfile -KeyName $adaptivePropertyName
                    if ($null -eq $adaptivePropertyValue) {
                        continue
                    }

                    [int]$parsedAdaptiveValue = 0
                    if ([int]::TryParse([string]$adaptivePropertyValue, [ref]$parsedAdaptiveValue) -and $parsedAdaptiveValue -gt 0) {
                        $adaptiveEnvironmentDefaults[[string]$adaptivePropertyMap[$adaptivePropertyName]] = [string]$parsedAdaptiveValue
                    }
                }
            }
        }

        $resolvedAdaptiveLimits = [ordered]@{}
        foreach ($key in @($adaptiveEnvironmentDefaults.Keys | Sort-Object)) {
            $resolvedAdaptiveLimits[$key] = [string]$adaptiveEnvironmentDefaults[$key]
        }

        $adaptiveOverridesApplied = [System.Collections.Generic.List[string]]::new()
        $adaptiveOverridesSkipped = [System.Collections.Generic.List[string]]::new()
        if ($adaptiveOverridesEnabled) {
            foreach ($entry in $adaptiveEnvironmentDefaults.GetEnumerator()) {
                $existingValue = [Environment]::GetEnvironmentVariable([string]$entry.Key)
                if ([string]::IsNullOrWhiteSpace($existingValue)) {
                    $startInfo.Environment[[string]$entry.Key] = [string]$entry.Value
                    $adaptiveOverridesApplied.Add(([string]$entry.Key))
                }
                else {
                    $adaptiveOverridesSkipped.Add(([string]$entry.Key))
                }
            }
        }

        $startInfo.Environment['TT_AGENT_ASSEMBLY_PATH'] = $agentAssemblyPath
        $startInfo.Environment['TT_AGENT_REQUEST_PATH'] = $requestPath
        $startInfo.Environment['TT_AGENT_LLM_TEMPERATURE'] = [string]$qualitySettings.Temperature
        $startInfo.Environment['TT_AGENT_LLM_TOP_P'] = [string]$qualitySettings.TopP
        $startInfo.Environment['TT_AGENT_LLM_REPEAT_PENALTY'] = [string]$qualitySettings.RepeatPenalty
        if (-not [string]::IsNullOrWhiteSpace($resolvedApiKey)) {
            $startInfo.Environment['TT_AGENT_LLM_API_KEY'] = $resolvedApiKey
        }
        if (-not [string]::IsNullOrWhiteSpace($resolvedSearchWebApiKey)) {
            $startInfo.Environment[$searchWebApiKeyEnvVar] = $resolvedSearchWebApiKey
        }
        if (-not [string]::IsNullOrWhiteSpace($toolCredentialPath)) {
            $startInfo.Environment['TT_AGENT_DEFAULT_CREDENTIAL_CLIXML'] = $toolCredentialPath
        }

        if ($adaptiveOverridesEnabled) {
            $resolvedAdaptiveLimitsJson = $resolvedAdaptiveLimits | ConvertTo-Json -Depth 4 -Compress
            $markdownAdaptiveLimitsPreflight = (
                "profile={0}; model={1}; provider={2}; endpointSpecified={3}; loopbackEndpoint={4}; matcherPattern={5}; matcherProfile={6}; applied={7}; skipped={8}; resolvedLimits={9}" -f
                $adaptiveLimitProfile,
                $resolvedModel,
                $providerForAdaptive,
                $isEndpointSpecified,
                $isLoopbackEndpoint,
                $(if ([string]::IsNullOrWhiteSpace($selectedModelMatcherPattern)) { '(none)' } else { $selectedModelMatcherPattern }),
                $(if ([string]::IsNullOrWhiteSpace($selectedModelMatcherProfile)) { '(none)' } else { $selectedModelMatcherProfile }),
                $adaptiveOverridesApplied.Count,
                $adaptiveOverridesSkipped.Count,
                $resolvedAdaptiveLimitsJson
            )
        }
        else {
            $markdownAdaptiveLimitsPreflight = 'Adaptive limit overrides disabled by configuration or TT_AGENT_DISABLE_ADAPTIVE_LIMIT_OVERRIDES=true.'
        }

        [void]$startInfo.ArgumentList.Add('-NoProfile')
        [void]$startInfo.ArgumentList.Add('-NonInteractive')
        [void]$startInfo.ArgumentList.Add('-EncodedCommand')
        [void]$startInfo.ArgumentList.Add($encodedChildScript)

        try {
            $agentProc = [System.Diagnostics.Process]::new()
            $agentProc.StartInfo = $startInfo
            if (-not $agentProc.Start()) {
                throw 'Failed to start child PowerShell process for TechToolbox.Agent.'
            }

            # Initialize agent state tracking
            $agentState = @{
                currentIteration       = 0
                totalIterations        = 0
                foundValidDecision     = $false
                lastResponseLength     = 0
                lastStoppedEarly       = $false
                consecutiveLlmFailures = 0
                lastToolName           = ''
                processExited          = $false
                exitCode               = -1
            }

            # Capture stdout/stderr asynchronously without event callbacks.
            # This is robust across hosts and still allows internal status polling.
            $stdoutTask = $agentProc.StandardOutput.ReadToEndAsync()
            $stderrTask = $agentProc.StandardError.ReadToEndAsync()

            # Define the poll script that drives the internal terminal-state loop.
            $pollScript = {
                if ($agentProc.HasExited) {
                    $agentState['processExited'] = $true
                    $agentState['exitCode'] = $agentProc.ExitCode
                    return $agentState
                }

                return $agentState
            }

            # Define terminal states
            $terminalStates = @{
                'AGENT_COMPLETED' = @{
                    Level   = 'Ok'
                    Message = 'Tech agent completed successfully.'
                    Return  = $true
                }
                'AGENT_FAILED'    = @{
                    Level   = 'Error'
                    Message = { param($obj, $status) "Tech agent failed with exit code {0}." -f $obj['exitCode'] }
                    Return  = $true
                }
            }

            # Use internal wait loop first; if it fails, fall back to simple process wait.
            $internalWaitSucceeded = $false
            try {
                $waitResult = Wait-TTInternalTerminalState `
                    -Target 'TechToolbox.Agent' `
                    -PollScript $pollScript `
                    -GetStatus { param($state) Get-TTAgentStatusFromState -State $state } `
                    -TerminalStates $terminalStates `
                    -TimeoutSeconds $waitTimeoutSeconds `
                    -PollSeconds 1 `
                    -TickMs 125 `
                    -HeartbeatSeconds 0
                $internalWaitSucceeded = $true
            }
            catch {
                Write-Log -Level Warn -Message ("Internal terminal-state wait failed; falling back to basic status mode: {0}" -f $_.Exception.Message)
            }

            if (-not $internalWaitSucceeded) {
                # Fallback: simple blocking read without animation
                Write-Log -Level E-Info -Message "`nAgent is running...`n"

                try {
                    while ($true) {
                        if ($agentProc.HasExited) {
                            break
                        }

                        Start-Sleep -Milliseconds 100
                    }
                }
                catch {
                    Write-Log -Level Warn -Message ("Error reading agent stdout: {0}" -f $_.Exception.Message)
                }

                if (-not $agentProc.WaitForExit($waitTimeoutSeconds * 1000)) {
                    try { $agentProc.Kill() } catch { }
                    throw ("Tech agent timed out after {0} seconds." -f $waitTimeoutSeconds)
                }
            }

            # Ensure process completion before awaiting output tasks.
            try {
                if (-not $agentProc.HasExited) {
                    $agentProc.WaitForExit()
                }
            }
            catch {
                Write-Log -Level Warn -Message ("Error waiting for agent completion: {0}" -f $_.Exception.Message)
            }

            $capturedStdOut = if ($stdoutTask) { [string]$stdoutTask.GetAwaiter().GetResult() } else { '' }

            $stdoutLines = [System.Collections.Generic.List[string]]::new()
            if (-not [string]::IsNullOrWhiteSpace($capturedStdOut)) {
                $rawStdoutLines = $capturedStdOut -split "`r?`n"
                foreach ($line in $rawStdoutLines) {
                    if ($line -ne $null) {
                        $stdoutLines.Add($line)
                        Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                    }
                }
            }

            $capturedStdErr = if ($stderrTask) { [string]$stderrTask.GetAwaiter().GetResult() } else { '' }

            # Final check of exit code
            if ($agentProc.ExitCode -ne 0) {
                $errorText = if ([string]::IsNullOrWhiteSpace($capturedStdErr)) { $capturedStdOut } else { $capturedStdErr }
                throw ("Tech agent exited with code {0}: {1}" -f $agentProc.ExitCode, $errorText.Trim())
            }

            $message = $capturedStdOut
        }
        catch {
            throw ("Tech agent failed: {0}" -f $_.Exception.Message)
        }

        $message = ([string]$message).Trim()
        $capturedStdOut = $message
        $markdownResponseLength = $message.Length
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = 'Tech agent completed successfully with no output.'
            $markdownResponseLength = $message.Length
        }

        $postflightAssessment = Test-TTAgentPostflightGoal -PromptText $Prompt -ResponseText $message -PreflightScore $preflightScore
        $markdownPostflightAchieved = [bool]$postflightAssessment.Achieved
        $markdownPostflightReason = if ([string]::IsNullOrWhiteSpace($postflightAssessment.Reason)) { '' } else { [string]$postflightAssessment.Reason }
        if (-not $StrictPromptPreflight.IsPresent -and -not $postflightAssessment.Achieved) {
            foreach ($warning in @($preflight.Warnings)) {
                Write-Warning ("`nInvoke-TechAgent postflight: {0}" -f $warning)
            }

            foreach ($criticalMessage in @($preflight.Critical)) {
                Write-Warning ("`nInvoke-TechAgent postflight critical: {0}" -f $criticalMessage)
            }

            if (-not [string]::IsNullOrWhiteSpace($postflightAssessment.Reason)) {
                Write-Warning ("`nInvoke-TechAgent postflight: {0}" -f $postflightAssessment.Reason)
            }

            if ($markdownStatus -eq 'NotStarted') {
                $markdownStatus = 'SuccessWithWarnings'
            }
        }

        # Surface orchestrator-level failures as real failures so markdown status
        # and caller behavior do not report false positives.
        $knownFailurePrefixes = @(
            'Agent returned invalid JSON twice.',
            'LLM request repeatedly failed',
            'Iteration limit reached.'
        )

        $knownFailureDetected = $false
        foreach ($failurePrefix in $knownFailurePrefixes) {
            if ($message.StartsWith($failurePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $knownFailureDetected = $true
                break
            }
        }
        $markdownKnownFailureDetected = $knownFailureDetected

        $expectedOutputExists = $false
        if (-not [string]::IsNullOrWhiteSpace($expectedOutputPath)) {
            $expectedOutputExists = Test-Path -LiteralPath $expectedOutputPath -PathType Leaf
            if (-not $expectedOutputExists) {
                throw ("Tech agent failed: expected output file was not created: {0}" -f $expectedOutputPath)
            }
        }
        $markdownExpectedOutputExists = $expectedOutputExists

        if ($knownFailureDetected) {
            if ($expectedOutputExists) {
                $markdownRecoveryReason = (
                    "Recovered known orchestrator failure text because expected output file exists at '{0}'. Message: {1}" -f $expectedOutputPath, $message
                )
                Write-Log -Level Warn -Message (
                    "Tech agent reported orchestrator failure text, but expected output file exists. Treating run as recovered success. Message: {0}" -f $message
                )
                $markdownStatus = 'SuccessRecovered'
            }
            else {
                throw ("Tech agent failed: {0}" -f $message)
            }
        }

        if ($markdownStatus -ne 'SuccessRecovered' -and $markdownStatus -ne 'SuccessWithWarnings') {
            $markdownStatus = 'Success'
        }

        return $message
    }
    catch {
        $markdownStatus = 'Error'
        $markdownError = $_.Exception.Message
        Write-Log -Level Error -Message ("Invoke-TechAgent failed: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($markdownPath)) {
            try {
                $exitCode = if ($markdownStatus -like 'Success*') { 0 } else { -1 }
                Write-TTAgentMarkdownLog `
                    -Path $markdownPath `
                    -Status $markdownStatus `
                    -PromptText $Prompt `
                    -ModelName $resolvedModel `
                    -IterationLimit $MaxIterations `
                    -DestructiveAuthorized $ConfirmDestructive.IsPresent `
                    -SignedFilePolicyValue $SignedFilePolicy `
                    -AutoRetryOnRecursionMode $(
                    if ($AutoRetryOnRecursion.IsPresent) { 'Enabled' }
                    elseif ($DisableAutoRetryOnRecursion.IsPresent) { 'Disabled' }
                    else { 'Default' }
                ) `
                    -ExecutionMode $resolvedExecutionMode `
                    -OutputContract $resolvedOutputContract `
                    -QualityProfile $resolvedQualityProfile `
                    -PromptSource $promptSourceLabel `
                    -PreflightScore $preflightScore `
                    -PreflightWarnings @($preflight.Warnings) `
                    -PreflightCritical @($preflight.Critical) `
                    -PromptPreflightSummary $markdownPromptPreflightSummary `
                    -ReasoningEffortSettings $markdownReasoningEffortSettings `
                    -RuntimeAssemblyPath $markdownRuntimeAssemblyPath `
                    -AdaptiveLimitsPreflight $markdownAdaptiveLimitsPreflight `
                    -ExpectedOutputPath $expectedOutputPath `
                    -StdOut $capturedStdOut `
                    -StdErr $capturedStdErr `
                    -ErrorText $markdownError `
                    -RecoveryReason $markdownRecoveryReason `
                    -PostflightAchieved $markdownPostflightAchieved `
                    -PostflightReason $markdownPostflightReason `
                    -ResponseLength $markdownResponseLength `
                    -KnownFailureDetected $markdownKnownFailureDetected `
                    -ExpectedOutputExists $markdownExpectedOutputExists `
                    -ExitCode $exitCode `
                    -TranscriptFile $transcriptPath `
                    -StartedUtc $runStartedUtc `
                    -CompletedUtc ([DateTime]::UtcNow)
            }
            catch {
                Write-Log -Level Warn -Message ("Tech agent markdown log could not be written: {0}" -f $_.Exception.Message)
            }
        }

        if ($transcriptStarted) {
            try { Stop-Transcript | Out-Null } catch { }
        }

        if (-not [string]::IsNullOrWhiteSpace($requestPath) -and (Test-Path -LiteralPath $requestPath -PathType Leaf)) {
            try { Remove-Item -LiteralPath $requestPath -Force } catch { }
        }

        if (-not [string]::IsNullOrWhiteSpace($toolCredentialPath) -and (Test-Path -LiteralPath $toolCredentialPath -PathType Leaf)) {
            try { Remove-Item -LiteralPath $toolCredentialPath -Force } catch { }
        }

        if ($agentProc) {
            try { $agentProc.Dispose() } catch { }
        }

    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALSOw+MDqxdzIE
# H0ZInaJRuiZ2T0lMGXCy52ehkmPpZ6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBP10hb8XZe
# zcW018Z6ZRF5O6Zx/hPWOAJUROgbz42R3jANBgkqhkiG9w0BAQEFAASCAgB/UrTo
# 5gTvhrl4SW7V7ojM1su+7LKODbtQ1i/zK5RU+75/wwU4KaiSg+bOlrw+u1LW1q36
# Z+HmnGp0/AOV/wQ4e29ZeShP9lCAcssz8dndSPuRyziCjXJ66BfemRMivA6xSqtL
# M7WrWFRzVINCi+zo0h36wb3bOApqVmPbv/rpFR1oZf7Su3IAqs2LqpeNdbZuy0SW
# edRoJQFhP9d1x3zISZRj1ldofhcKXwabsfA6yJV0dMHyPUTYlB4yBpUO/UyKZyP5
# WU8WaayefeU5W2/D1roMc0QYvlCFeLAR6PFiAvX41lqPYl9AdPkVdG4f8CWwt3NX
# NgjuUa8mRFjezB+/6iwkMvpUsC73A0pCTJDAzvF/Vx9B1G9+6AFnZ6mkpXnlOofq
# EMmsDCseb+1yyVi5/Q9P4bTC2ExgLu5z7TXoEsdFEJXdAzTV3PJhjmvFlFG9M3uH
# f+eUgZNUD9yAk9Lja6bqNpxArHco0ueBN1owxR/x0GjSwd+9auGXA3NFGArUUWTA
# WIq8kGNFoHI/vLqqxXF0Idhd/gpLJqgDKAY2iRTrgSktSH8kdKd7ICZtYPcJeDfd
# vF77u3+PsH5Kr+2VUIsMbwUV/GDIWGKD1hPPajjYen/+RyCjEuwyKbTb8F4iG7dk
# pZbQQ7UtvN8d2uigCA4iXzYdFYtX84epnYDo8qGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MDIwMjQzMjhaMC8GCSqGSIb3DQEJBDEiBCAM17mTt3UmHXeLjhcn
# yrSwu77b4HZ4UNiToccqs3daYjANBgkqhkiG9w0BAQEFAASCAgAijIDubgxOgExP
# XvJb7B0OYyVODkTkgkN/q/NQ/TDcGkS4eSl1tlTgLSq6B/cVCKtDtjnUc/xytVIk
# 4w2KYyYj0W2PTXFDcBxbu8+00EXoLWoyjcuFNtSl6TAz/k5rHz9kq23l37/ntmeK
# Amz+YnfoH5GpZOHZpWtJNm4T2Bg6zYnxsWsFZ1IlCiOGLjHbtL308XDK9w/t12LF
# sZPqLnoktXS4xut7f6Lkl7ssKPD/0mhMxPho+MFR1gVAwLGTvNx05g/Pr2dtFUoC
# Yy2N2KhcW0+QQUw2K2nbklaacYoceEdM4d29Gch+xY4JpS1aN7Jda08+PebPT1H3
# OKtqNKwlWFifCJH4d2iXJRlj/2AWVerh7X3o+duTA+CmwAq5mBQzPM4ASKKwwZMx
# fpFFh4xT15mKLHsDlcqP6U5vehqZHPrYT1oquHrodMMP9Dk5npRBtf/qxiXYeXM0
# 6kOJ1mIEGnU8LEDL3onY8ncXLQbiMZM7LSXkNmuzKqVd41TsS+M/N6jQEccyd9Pz
# t6GB7T1D3zpWF98bsBGkmWJAIK12ED1inqhpVGgibBz4DufCOKfsOGHxH6Y1MjB2
# z5mEHuOfq4lefDmommrdNJqXUZTbQmFkPo+MP9XXhaMzoZEsKuILiux4vi78bMUs
# cKfzx+Zkf+vkx/M24P9F7naNywRBVw==
# SIG # End signature block
