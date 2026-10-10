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
        Optional Ollama model name (for example: techtoolbox-qwen2_5-7b-lora:latest,
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
        Defaults to settings.agent.maxIterations from config (fallback: 50).

    .PARAMETER PromptHistoryItems
        Number of recent memory history entries to inject into prompt context.
        Set to 0 to disable recent history injection for this run.

    .PARAMETER Mode
        Controls whether the agent should execute tools (`execute`), produce a
        no-tool implementation plan (`plan`), or provide no-tool analysis
        (`analyze`). Legacy value `chat` is accepted for compatibility and
        maps to `analyze`.

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

    .PARAMETER RuntimeStrictMode
        Enables runtime strict mode for this invocation. Strict mode enforces
        bounded tool-category budgets and decision-repair limits.

    .PARAMETER DisableRuntimeStrictMode
        Disables runtime strict mode for this invocation, overriding
        configuration defaults.

    .PARAMETER StrictMaxDiscoveryToolCalls
        Maximum discovery-style tool calls allowed when runtime strict mode is
        enabled.

    .PARAMETER StrictMaxMutationToolCalls
        Maximum mutation-style tool calls allowed when runtime strict mode is
        enabled.

    .PARAMETER StrictMaxValidationToolCalls
        Maximum validation-style tool calls allowed when runtime strict mode is
        enabled.

    .PARAMETER StrictMaxDecisionRepairCycles
        Maximum decision-repair cycles allowed when runtime strict mode is
        enabled.

    .PARAMETER StrictAllowSingleFallbackTurn
        Allows one strict-mode fallback guidance turn after a budget is
        exceeded.

    .PARAMETER StrictDisableSingleFallbackTurn
        Disables the strict-mode fallback guidance turn. Budget exceedance will
        terminate immediately.

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
        [int]$MaxIterations,

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
        [ValidateSet('ignore', 'strip')]
        [string]$SignedFilePolicy,

        [Parameter()]
        [switch]$AutoRetryOnRecursion,

        [Parameter()]
        [switch]$DisableAutoRetryOnRecursion,

        [Parameter()]
        [switch]$RuntimeStrictMode,

        [Parameter()]
        [switch]$DisableRuntimeStrictMode,

        [Parameter()]
        [ValidateRange(1, 200)]
        [int]$StrictMaxDiscoveryToolCalls,

        [Parameter()]
        [ValidateRange(1, 200)]
        [int]$StrictMaxMutationToolCalls,

        [Parameter()]
        [ValidateRange(1, 200)]
        [int]$StrictMaxValidationToolCalls,

        [Parameter()]
        [ValidateRange(0, 50)]
        [int]$StrictMaxDecisionRepairCycles,

        [Parameter()]
        [switch]$StrictAllowSingleFallbackTurn,

        [Parameter()]
        [switch]$StrictDisableSingleFallbackTurn,

        [Parameter()]
        [bool]$NoTranscript = $true,

        [Parameter()]
        [switch]$AllowMetaTools,

        [Parameter()]
        [string[]]$WriteDirectory,

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

    [int]$resolvedMaxIterations = 50
    if ($PSBoundParameters.ContainsKey('MaxIterations')) {
        $resolvedMaxIterations = [int]$MaxIterations
    }
    else {
        $maxIterationsValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'maxIterations'
        if ($null -ne $maxIterationsValue) {
            [int]$parsedMaxIterations = 0
            if ([int]::TryParse([string]$maxIterationsValue, [ref]$parsedMaxIterations)) {
                $resolvedMaxIterations = $parsedMaxIterations
            }
        }
    }

    $resolvedMaxIterations = [Math]::Max(1, [Math]::Min(500, $resolvedMaxIterations))

    $resolvedWriteDirectorySettings = Resolve-TTAgentWriteDirectorySettings -WriteDirectory $WriteDirectory
    if ($PSBoundParameters.ContainsKey('WriteDirectory') -and $resolvedWriteDirectorySettings.AllowedRoots.Count -gt 0) {
        $env:TT_AGENT_FILESYSTEM_ROOT = $resolvedWriteDirectorySettings.FilesystemRoot
        $env:TT_AGENT_ALLOWED_PATH_ROOTS = $resolvedWriteDirectorySettings.EnvironmentRoots
    }

    [int]$resolvedOrchestratorRunDeadlineSeconds = 600
    $orchestratorRunDeadlineValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'orchestratorRunDeadlineSeconds'
    if ($null -ne $orchestratorRunDeadlineValue) {
        [int]$parsedRunDeadlineSeconds = 0
        if ([int]::TryParse([string]$orchestratorRunDeadlineValue, [ref]$parsedRunDeadlineSeconds)) {
            $resolvedOrchestratorRunDeadlineSeconds = $parsedRunDeadlineSeconds
        }
    }
    $resolvedOrchestratorRunDeadlineSeconds = [Math]::Max(300, [Math]::Min(1800, $resolvedOrchestratorRunDeadlineSeconds))

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
        default { $resolvedThinkingEnabled = $resolvedExecutionMode -eq 'analyze' -or $resolvedExecutionMode -eq 'plan' }
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

    $waitTimeoutSeconds = [Math]::Max(300, ($resolvedMaxIterations * 180))
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
    $markdownRagUsed = $false
    $markdownRagStatus = 'Unknown'
    $markdownRagModelEffective = '(none)'
    $markdownRagModelSource = 'none'
    $markdownRagEnabledConfigured = $false
    $markdownRagAttempted = $false
    $markdownRagProviderType = '(unknown)'
    $markdownRagExecutionMode = 'unknown'
    $markdownRagEnvironmentContextIncluded = $false
    $markdownRagEnvironmentContextProfile = 'standard'
    $markdownRagSourcesScanned = 0
    $markdownRagCandidatesScored = 0
    $markdownRagCandidatesSelected = 0
    $markdownRagCandidatesPacked = 0
    $markdownRagContextCharacters = 0
    $markdownRagModelConfigured = '(none)'
    $markdownRagStatusReason = '(none)'
    $markdownToolTrace = @()
    $agentMetadataToolNames = @()
    $agentMetadataParsed = $false
    $capturedStdOut = ''
    $capturedStdErr = ''
    $markdownAdaptiveLimitsPreflight = ''
    $markdownPromptPreflightSummary = ''
    $markdownReasoningEffortSettings = ''
    $markdownRuntimeAssemblyPath = ''
    $runStartedUtc = [DateTime]::UtcNow
    $agentProc = $null
    $agentState = $null
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

    if ($RuntimeStrictMode.IsPresent -and $DisableRuntimeStrictMode.IsPresent) {
        throw 'Specify only one of -RuntimeStrictMode or -DisableRuntimeStrictMode.'
    }

    if ($StrictAllowSingleFallbackTurn.IsPresent -and $StrictDisableSingleFallbackTurn.IsPresent) {
        throw 'Specify only one of -StrictAllowSingleFallbackTurn or -StrictDisableSingleFallbackTurn.'
    }

    try {
        $moduleRoot = Get-ModuleRoot
        $assemblyCandidates = @(
            (Join-Path $moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll')
        )

        $existingAssemblyCandidates = @(
            foreach ($candidatePath in $assemblyCandidates) {
                if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
                    Get-Item -LiteralPath $candidatePath -ErrorAction SilentlyContinue
                }
            }
        )

        $agentAssemblyPath = $null
        if ($existingAssemblyCandidates.Count -gt 0) {
            $agentAssemblyPath = [string](
                $existingAssemblyCandidates |
                Sort-Object -Property LastWriteTimeUtc -Descending |
                Select-Object -First 1 -ExpandProperty FullName
            )
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

        $retrievalConfigJson = $null
        $retrievalConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'retrieval'
        if ($null -ne $retrievalConfig) {
            try {
                $retrievalConfigJson = $retrievalConfig | ConvertTo-Json -Depth 12 -Compress
            }
            catch {
                Write-Log -Level Warn -Message ("Failed to serialize settings.agent.retrieval: {0}" -f $_.Exception.Message)
                $retrievalConfigJson = $null
            }
        }

        $resiliencePolicyJson = $null
        $resilienceConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'resilience'
        if ($null -eq $resilienceConfig) {
            $resilienceConfig = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'resiliencePolicy'
        }

        $strictOverrideRequested = (
            $RuntimeStrictMode.IsPresent -or
            $DisableRuntimeStrictMode.IsPresent -or
            $PSBoundParameters.ContainsKey('StrictMaxDiscoveryToolCalls') -or
            $PSBoundParameters.ContainsKey('StrictMaxMutationToolCalls') -or
            $PSBoundParameters.ContainsKey('StrictMaxValidationToolCalls') -or
            $PSBoundParameters.ContainsKey('StrictMaxDecisionRepairCycles') -or
            $StrictAllowSingleFallbackTurn.IsPresent -or
            $StrictDisableSingleFallbackTurn.IsPresent
        )

        if ($strictOverrideRequested -and $null -eq $resilienceConfig) {
            $resilienceConfig = [pscustomobject]@{}
        }

        if ($strictOverrideRequested -and $null -ne $resilienceConfig) {
            $setResilienceProperty = {
                param(
                    [object]$Target,
                    [string]$Name,
                    $Value
                )

                if ($Target -is [hashtable]) {
                    $Target[$Name] = $Value
                    return
                }

                $existingProperty = $Target.PSObject.Properties[$Name]
                if ($null -ne $existingProperty) {
                    $existingProperty.Value = $Value
                }
                else {
                    $Target | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
                }
            }

            if ($RuntimeStrictMode.IsPresent) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'RuntimeStrictModeEnabled' -Value $true
            }
            elseif ($DisableRuntimeStrictMode.IsPresent) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'RuntimeStrictModeEnabled' -Value $false
            }

            if ($PSBoundParameters.ContainsKey('StrictMaxDiscoveryToolCalls')) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictMaxDiscoveryToolCalls' -Value $StrictMaxDiscoveryToolCalls
            }

            if ($PSBoundParameters.ContainsKey('StrictMaxMutationToolCalls')) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictMaxMutationToolCalls' -Value $StrictMaxMutationToolCalls
            }

            if ($PSBoundParameters.ContainsKey('StrictMaxValidationToolCalls')) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictMaxValidationToolCalls' -Value $StrictMaxValidationToolCalls
            }

            if ($PSBoundParameters.ContainsKey('StrictMaxDecisionRepairCycles')) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictMaxDecisionRepairCycles' -Value $StrictMaxDecisionRepairCycles
            }

            if ($StrictAllowSingleFallbackTurn.IsPresent) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictAllowSingleFallbackTurn' -Value $true
            }
            elseif ($StrictDisableSingleFallbackTurn.IsPresent) {
                & $setResilienceProperty -Target $resilienceConfig -Name 'StrictAllowSingleFallbackTurn' -Value $false
            }
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

        $shellAllowedCommands = @()
        $shellConfigValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'shell'
        if ($null -ne $shellConfigValue) {
            $allowedCommandsValue = Get-TTAgentConfigValue -ConfigObject $shellConfigValue -KeyName 'allowedCommands'
            if ($null -ne $allowedCommandsValue) {
                foreach ($command in @($allowedCommandsValue)) {
                    $commandText = [string]$command
                    if ([string]::IsNullOrWhiteSpace($commandText)) {
                        continue
                    }

                    $normalizedCommand = [System.IO.Path]::GetFileNameWithoutExtension(([System.IO.Path]::GetFileName($commandText.Trim().Trim('"', "'")))).ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($normalizedCommand)) {
                        continue
                    }

                    if ($shellAllowedCommands -notcontains $normalizedCommand) {
                        $shellAllowedCommands += $normalizedCommand
                    }
                }
            }
        }

        $resolvedSearchWebApiKey = $null
        if (-not [string]::IsNullOrWhiteSpace($searchWebApiKeyEnvVar)) {
            $searchWebApiKeyResolution = Resolve-TTAgentStoredSecret -ConfigObject $cfg -SecretKeyName 'searchWebApiKeyEncrypted' -EnvVarName $searchWebApiKeyEnvVar
            $resolvedSearchWebApiKey = [string]$searchWebApiKeyResolution.Key
        }

        $resolvedMcpBearerCredentials = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $serializedMcpConfigForChild = $null
        $mcpConfigValue = Get-TTAgentConfigValue -ConfigObject $cfg -KeyName 'mcp'
        if ($null -ne $mcpConfigValue) {
            $mcpServers = @()
            $mcpServersValue = Get-TTAgentConfigValue -ConfigObject $mcpConfigValue -KeyName 'servers'
            if ($null -ne $mcpServersValue) {
                $mcpServers = @($mcpServersValue)
            }

            $normalizedMcpServersForChild = @()
            foreach ($mcpServer in $mcpServers) {
                if ($null -eq $mcpServer) {
                    continue
                }

                $serverClone = $mcpServer | ConvertTo-Json -Depth 64 | ConvertFrom-Json -Depth 64
                $oauthProperty = $serverClone.PSObject.Properties['oauth']
                if ($null -ne $oauthProperty -and $null -ne $oauthProperty.Value) {
                    $oauthConfig = $oauthProperty.Value
                    $allowedRedirectUris = @()
                    foreach ($uri in @((Get-TTAgentConfigValue -ConfigObject $oauthConfig -KeyName 'allowedRedirectUris'))) {
                        if ($null -eq $uri) {
                            continue
                        }

                        $uriText = [string]$uri
                        if (-not [string]::IsNullOrWhiteSpace($uriText)) {
                            $allowedRedirectUris += $uriText
                        }
                    }

                    $oauthAllowedRedirectUrisProperty = $oauthConfig.PSObject.Properties['allowedRedirectUris']
                    if ($null -ne $oauthAllowedRedirectUrisProperty) {
                        $oauthAllowedRedirectUrisProperty.Value = @($allowedRedirectUris)
                    }
                    else {
                        $oauthConfig | Add-Member -NotePropertyName 'allowedRedirectUris' -NotePropertyValue @($allowedRedirectUris)
                    }
                }

                if ($serverClone.name -eq 'filesystem') {
                    $filesystemWriteSettings = Resolve-TTAgentWriteDirectorySettings -WriteDirectory $WriteDirectory
                    $serverClone.arguments = $filesystemWriteSettings.Arguments
                }

                $normalizedMcpServersForChild += $serverClone
            }

            [bool]$mcpEnabled = $false
            $mcpEnabledValue = Get-TTAgentConfigValue -ConfigObject $mcpConfigValue -KeyName 'enabled'
            if ($null -ne $mcpEnabledValue) {
                [bool]$parsedMcpEnabled = $false
                if ([bool]::TryParse([string]$mcpEnabledValue, [ref]$parsedMcpEnabled)) {
                    $mcpEnabled = $parsedMcpEnabled
                }
                elseif ($mcpEnabledValue -is [bool]) {
                    $mcpEnabled = [bool]$mcpEnabledValue
                }
            }

            try {
                $normalizedMcpConfigForChild = [ordered]@{
                    enabled = $mcpEnabled
                    servers = @($normalizedMcpServersForChild)
                }
                $serializedMcpConfigForChild = ($normalizedMcpConfigForChild | ConvertTo-Json -Depth 16 -Compress)
            }
            catch {
                $serializedMcpConfigForChild = $null
            }

            if ($mcpEnabled) {
                foreach ($mcpServer in $mcpServers) {
                    if ($null -eq $mcpServer) {
                        continue
                    }

                    [bool]$serverEnabled = $false
                    $serverEnabledValue = Get-TTAgentConfigValue -ConfigObject $mcpServer -KeyName 'enabled'
                    if ($null -ne $serverEnabledValue) {
                        [bool]$parsedServerEnabled = $false
                        if ([bool]::TryParse([string]$serverEnabledValue, [ref]$parsedServerEnabled)) {
                            $serverEnabled = $parsedServerEnabled
                        }
                        elseif ($serverEnabledValue -is [bool]) {
                            $serverEnabled = [bool]$serverEnabledValue
                        }
                    }

                    if (-not $serverEnabled) {
                        continue
                    }

                    $transport = [string](Get-TTAgentConfigValue -ConfigObject $mcpServer -KeyName 'transport')
                    $authMode = [string](Get-TTAgentConfigValue -ConfigObject $mcpServer -KeyName 'authMode')
                    $credentialEnvironmentVariable = [string](Get-TTAgentConfigValue -ConfigObject $mcpServer -KeyName 'credentialEnvironmentVariable')
                    $isHttpBearerServer = (
                        [string]::Equals($transport, 'StreamableHttp', [System.StringComparison]::OrdinalIgnoreCase) -and
                        [string]::Equals($authMode, 'BearerEnvironmentVariable', [System.StringComparison]::OrdinalIgnoreCase)
                    )

                    # For stdio MCP servers (for example tavily-mcp), allow explicit
                    # credentialEnvironmentVariable + credentialSecretKeyName hydration
                    # from config secrets even when authMode is None.
                    $isStdioCredentialHydration = (
                        [string]::Equals($transport, 'Stdio', [System.StringComparison]::OrdinalIgnoreCase) -and
                        -not [string]::IsNullOrWhiteSpace($credentialEnvironmentVariable)
                    )

                    if (-not $isHttpBearerServer -and -not $isStdioCredentialHydration) {
                        continue
                    }

                    $mcpCredentialResolution = Resolve-TTAgentMcpBearerSecret -ConfigObject $cfg -ServerConfigObject $mcpServer
                    $mcpServerName = [string]$mcpCredentialResolution.ServerName
                    $mcpEnvVarName = [string]$mcpCredentialResolution.EnvVarName
                    $mcpCredentialValue = [string]$mcpCredentialResolution.Key
                    $mcpCredentialError = [string]$mcpCredentialResolution.Error

                    if ([string]::IsNullOrWhiteSpace($mcpCredentialValue)) {
                        if (-not $isHttpBearerServer) {
                            # Best effort for stdio credential hydration: skip when no
                            # value is available rather than failing unrelated MCP startup.
                            continue
                        }

                        if (-not [string]::IsNullOrWhiteSpace($mcpCredentialError)) {
                            throw (
                                "MCP server '{0}' bearer credential resolution failed via {1}: {2}" -f $mcpServerName, $mcpCredentialResolution.Source, $mcpCredentialError
                            )
                        }

                        if ([string]::IsNullOrWhiteSpace($mcpEnvVarName)) {
                            throw (
                                "MCP server '{0}' requires credentialEnvironmentVariable for bearer authentication." -f $mcpServerName
                            )
                        }

                        throw (
                            "MCP server '{0}' requires bearer credential '{1}'. Set environment variable '{1}' or configure settings.agent.mcp.servers[].credentialSecretKeyName with a DPAPI secret in config.secrets.json under settings.agent.<secretKeyName>." -f $mcpServerName, $mcpEnvVarName
                        )
                    }

                    if ($resolvedMcpBearerCredentials.ContainsKey($mcpEnvVarName)) {
                        if (-not [string]::Equals($resolvedMcpBearerCredentials[$mcpEnvVarName], $mcpCredentialValue, [System.StringComparison]::Ordinal)) {
                            throw (
                                "MCP credential conflict: multiple servers resolved different values for credential environment variable '{0}'." -f $mcpEnvVarName
                            )
                        }

                        continue
                    }

                    $resolvedMcpBearerCredentials[$mcpEnvVarName] = $mcpCredentialValue
                }
            }
        }

        $request = [ordered]@{
            Prompt                         = $effectivePrompt
            Model                          = $resolvedModel
            ExecutionMode                  = $resolvedExecutionMode
            OutputContract                 = $resolvedOutputContract
            QualityProfile                 = $resolvedQualityProfile
            ThinkingMode                   = $resolvedThinkingMode
            ReasoningEffort                = $resolvedReasoningEffort
            ReasoningEffortAuto            = $resolvedReasoningEffortAuto
            PromptPreflightScore           = $preflightScore
            PromptPreflightWarningCount    = $preflightWarningCount
            PromptPreflightCriticalCount   = $preflightCriticalCount
            RuntimeProfile                 = $RuntimeProfile
            RuntimeProfilesJson            = $runtimeProfilesJson
            ResiliencePolicyJson           = $resiliencePolicyJson
            RetrievalConfigJson            = $retrievalConfigJson
            McpConfigJson                  = $serializedMcpConfigForChild
            Verbose                        = $false
            MaxIterations                  = $resolvedMaxIterations
            PromptHistoryItems             = $resolvedPromptHistoryItems
            MemoryPath                     = $memoryPath
            AutoRetryOnRecursion           = $autoRetryOnIterationLimit
            ReturnMetadata                 = $true
            SignedFilePolicy               = $(if ([string]::IsNullOrWhiteSpace($SignedFilePolicy)) { 'ignore' } else { $SignedFilePolicy })
            DiagnosticTracePath            = $diagnosticTracePath
            ExpectedOutputPath             = $expectedOutputPath
            AllowedFetchHosts              = @($allowedFetchHosts)
            SearchWebProvider              = $searchWebProvider
            SearchWebEndpoint              = $searchWebEndpoint
            SearchWebApiKeyEnvVar          = $searchWebApiKeyEnvVar
            SearchWebCountry               = $searchWebCountry
            SearchWebLanguage              = $searchWebLanguage
            SearchWebSafeSearch            = $searchWebSafeSearch
            SearchWebDefaultCount          = $searchWebDefaultCount
            ShellAllowedCommands           = @($shellAllowedCommands)
            AllowMetaTools                 = $AllowMetaTools.IsPresent
            LlmProvider                    = $Provider
            LlmEndpoint                    = $Endpoint
            LlmDeployment                  = $Deployment
            LlmApiVersion                  = $ApiVersion
            OrchestratorRunDeadlineSeconds = $resolvedOrchestratorRunDeadlineSeconds
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
if ($null -ne $request.McpConfigJson -and -not [string]::IsNullOrWhiteSpace([string]$request.McpConfigJson)) {
    [Environment]::SetEnvironmentVariable('TT_AGENT_MCP_CONFIG_JSON', [string]$request.McpConfigJson, 'Process')
}
if ($null -ne $request.RetrievalConfigJson -and -not [string]::IsNullOrWhiteSpace([string]$request.RetrievalConfigJson)) {
    [Environment]::SetEnvironmentVariable('TT_AGENT_RETRIEVAL_CONFIG_JSON', [string]$request.RetrievalConfigJson, 'Process')
}
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
        [System.Collections.Generic.IEnumerable[string]],
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
        [string],
        [int]
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

$shellAllowedCommands = [string[]]@()
if ($null -ne $request.ShellAllowedCommands) {
    $shellAllowedCommands = @($request.ShellAllowedCommands | ForEach-Object {
            if ($null -ne $_) {
                [string]$_
            }
        })
}

$approvalDelegateType = [System.Func`2[
    TechToolbox.Agent.Registry.ToolAuthorizationRequest,
    System.Boolean
]]

$approvalMethod = [TechToolbox.Agent.Core.HostDestructiveApprovalAdapter].GetMethod(
    'RequestApproval',
    [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static
)

if ($null -eq $approvalMethod) {
    throw "Unable to locate TechToolbox.Agent.Core.HostDestructiveApprovalAdapter.RequestApproval."
}

$destructiveApprovalCallback = [System.Delegate]::CreateDelegate($approvalDelegateType, $approvalMethod)

$config = [TechToolbox.Agent.Configuration.AgentConfiguration]::new()
$config.Model = [string]$request.Model
$config.LlmProvider = [string]$request.LlmProvider
$config.ExecutionMode = [string]$request.ExecutionMode
$config.OutputContract = [string]$request.OutputContract
$config.QualityProfile = [string]$request.QualityProfile
$config.ThinkingMode = [string]$request.ThinkingMode
$config.ReasoningEffortOverride = if ([string]::IsNullOrWhiteSpace([string]$request.ReasoningEffort)) { $null } else { [string]$request.ReasoningEffort }
$config.EnableReasoningEffortAuto = [bool]$request.ReasoningEffortAuto
$config.PromptPreflightScore = [int]$request.PromptPreflightScore
$config.PromptPreflightWarningCount = [int]$request.PromptPreflightWarningCount
$config.PromptPreflightCriticalCount = [int]$request.PromptPreflightCriticalCount
$config.MaxIterations = [int]$request.MaxIterations
$config.AutoRetryOnIterationLimit = [bool]$request.AutoRetryOnRecursion
$config.ReturnMetadata = [bool]$request.ReturnMetadata
$config.SignedFilePolicy = if ([string]::IsNullOrWhiteSpace([string]$request.SignedFilePolicy)) { 'ignore' } else { [string]$request.SignedFilePolicy }
$config.DiagnosticTracePath = if ([string]::IsNullOrWhiteSpace([string]$request.DiagnosticTracePath)) { $null } else { [string]$request.DiagnosticTracePath }
$config.ExpectedOutputPath = if ([string]::IsNullOrWhiteSpace([string]$request.ExpectedOutputPath)) { $null } else { [string]$request.ExpectedOutputPath }
$config.RecentHistoryItemsInPrompt = [int]$request.PromptHistoryItems
$config.AllowMetaTools = [bool]$request.AllowMetaTools
$config.LlmEndpoint = if ([string]::IsNullOrWhiteSpace([string]$request.LlmEndpoint)) { $null } else { [string]$request.LlmEndpoint }
$config.LlmDeployment = if ([string]::IsNullOrWhiteSpace([string]$request.LlmDeployment)) { $null } else { [string]$request.LlmDeployment }
$config.LlmApiVersion = if ([string]::IsNullOrWhiteSpace([string]$request.LlmApiVersion)) { $null } else { [string]$request.LlmApiVersion }
$config.MemoryPath = if ([string]::IsNullOrWhiteSpace([string]$request.MemoryPath)) { $null } else { [string]$request.MemoryPath }
$config.OrchestratorRunDeadlineSeconds = [int]$request.OrchestratorRunDeadlineSeconds
$config.AllowedFetchHosts = [System.Collections.Generic.List[string]]::new()
if ($null -ne $request.AllowedFetchHosts) {
    foreach ($hostEntry in @($request.AllowedFetchHosts)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$hostEntry)) {
            $null = $config.AllowedFetchHosts.Add([string]$hostEntry)
        }
    }
}
$config.ShellAllowedCommands = [System.Collections.Generic.List[string]]::new()
if ($null -ne $request.ShellAllowedCommands) {
    foreach ($commandEntry in @($request.ShellAllowedCommands)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$commandEntry)) {
            $null = $config.ShellAllowedCommands.Add([string]$commandEntry)
        }
    }
}
$config.SearchWebProvider = [string]$request.SearchWebProvider
$config.SearchWebEndpoint = if ([string]::IsNullOrWhiteSpace([string]$request.SearchWebEndpoint)) { 'https://api.search.brave.com/res/v1/web/search' } else { [string]$request.SearchWebEndpoint }
$config.SearchWebApiKeyEnvVar = if ([string]::IsNullOrWhiteSpace([string]$request.SearchWebApiKeyEnvVar)) { 'TT_AGENT_SEARCH_WEB_API_KEY' } else { [string]$request.SearchWebApiKeyEnvVar }
$config.SearchWebCountry = if ([string]::IsNullOrWhiteSpace([string]$request.SearchWebCountry)) { 'us' } else { [string]$request.SearchWebCountry }
$config.SearchWebLanguage = if ([string]::IsNullOrWhiteSpace([string]$request.SearchWebLanguage)) { 'en' } else { [string]$request.SearchWebLanguage }
$config.SearchWebSafeSearch = if ([string]::IsNullOrWhiteSpace([string]$request.SearchWebSafeSearch)) { 'moderate' } else { [string]$request.SearchWebSafeSearch }
$config.SearchWebDefaultCount = [int]$request.SearchWebDefaultCount
$jsonDeserializeOptions = [System.Text.Json.JsonSerializerOptions]::new()
$jsonDeserializeOptions.PropertyNameCaseInsensitive = $true
$jsonDeserializeOptions.Converters.Add([System.Text.Json.Serialization.JsonStringEnumConverter]::new())
if (-not [string]::IsNullOrWhiteSpace([string]$request.RuntimeProfilesJson)) {
    $resolvedRuntimeProfiles = [System.Text.Json.JsonSerializer]::Deserialize(
        [string]$request.RuntimeProfilesJson,
        [TechToolbox.Agent.Configuration.AgentRuntimeProfilesConfiguration],
        $jsonDeserializeOptions
    )
    if ($null -ne $resolvedRuntimeProfiles) {
        $config.RuntimeProfiles = $resolvedRuntimeProfiles
    }
}
if (-not [string]::IsNullOrWhiteSpace([string]$request.ResiliencePolicyJson)) {
    $resolvedResiliencePolicy = [System.Text.Json.JsonSerializer]::Deserialize(
        [string]$request.ResiliencePolicyJson,
        [TechToolbox.Agent.Configuration.AgentResilienceConfiguration],
        $jsonDeserializeOptions
    )
    if ($null -ne $resolvedResiliencePolicy) {
        $config.ResiliencePolicy = $resolvedResiliencePolicy
    }
}
if (-not [string]::IsNullOrWhiteSpace([string]$request.RetrievalConfigJson)) {
    $resolvedRetrievalConfig = [System.Text.Json.JsonSerializer]::Deserialize(
        [string]$request.RetrievalConfigJson,
        [TechToolbox.Agent.Configuration.AgentRetrievalConfiguration],
        $jsonDeserializeOptions
    )
    if ($null -ne $resolvedRetrievalConfig) {
        $config.Retrieval = $resolvedRetrievalConfig
    }
}
if (-not [string]::IsNullOrWhiteSpace([string]$request.McpConfigJson)) {
    $resolvedMcpConfig = [System.Text.Json.JsonSerializer]::Deserialize(
        [string]$request.McpConfigJson,
        [TechToolbox.Agent.Configuration.McpConfiguration],
        $jsonDeserializeOptions
    )
    if ($null -ne $resolvedMcpConfig) {
        $config.Mcp = $resolvedMcpConfig
    }
}
$config.DestructiveConfirmed = $false
$config.DestructiveApprovalCallback = $destructiveApprovalCallback

$result = [TechToolbox.Agent.Core.AgentCore]::RunAgent($config, [string]$request.Prompt)
[Console]::Write($result)
'@

        $encodedChildScript = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($childScript))
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $childPwsh
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
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
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS'        = '30000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS'                    = '30000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '12000'
        }
        $adaptiveFrontierDefaults = @{
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS'        = '90000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS'                    = '90000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '30000'
            'TT_AGENT_LLM_MAX_OUTPUT_TOKENS'                    = '8192'
        }
        $adaptiveFrontierXlDefaults = @{
            'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS'        = '120000'
            'TT_AGENT_MAX_TOOL_RESULT_CHARS'                    = '120000'
            'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS' = '45000'
            'TT_AGENT_LLM_MAX_OUTPUT_TOKENS'                    = '12000'
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
                    'readFileSummaryThresholdChars'       = 'TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS'
                    'maxToolResultChars'                  = 'TT_AGENT_MAX_TOOL_RESULT_CHARS'
                    'readFilePromptCompactThresholdChars' = 'TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS'
                    'llmMaxOutputTokens'                  = 'TT_AGENT_LLM_MAX_OUTPUT_TOKENS'
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

        $allowedRoots = [System.Collections.Generic.List[string]]::new()
        $seenAllowedRoots = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $addAllowedRoot = {
            param([string]$Candidate)

            if ([string]::IsNullOrWhiteSpace($Candidate)) {
                return
            }

            try {
                $fullRoot = [System.IO.Path]::GetFullPath($Candidate)
            }
            catch {
                return
            }

            if (-not $seenAllowedRoots.Add($fullRoot)) {
                return
            }

            $allowedRoots.Add($fullRoot)
        }

        $configuredAllowedRootsRaw = [Environment]::GetEnvironmentVariable('TT_AGENT_ALLOWED_PATH_ROOTS')
        if (-not [string]::IsNullOrWhiteSpace($configuredAllowedRootsRaw)) {
            foreach ($root in ($configuredAllowedRootsRaw -split [System.IO.Path]::PathSeparator)) {
                & $addAllowedRoot -Candidate $root
            }
        }
        else {
            $defaultAllowedRoots = @()
            foreach ($candidate in @($env:TT_ModuleRoot, $env:TT_Home, (Get-Location).Path)) {
                if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                    $defaultAllowedRoots += $candidate
                }
            }

            foreach ($root in ($defaultAllowedRoots | Select-Object -Unique)) {
                & $addAllowedRoot -Candidate $root
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($expectedOutputPath)) {
            try {
                $expectedOutputDirectory = Split-Path -Path $expectedOutputPath -Parent
                if (-not [string]::IsNullOrWhiteSpace($expectedOutputDirectory)) {
                    & $addAllowedRoot -Candidate $expectedOutputDirectory
                }
            }
            catch {
                # Best-effort: if expected path cannot be normalized, keep baseline authorized roots.
            }
        }

        $effectiveWriteDirectoryPolicy = Resolve-TTAgentWriteDirectorySettings -WriteDirectory $WriteDirectory
        foreach ($root in $effectiveWriteDirectoryPolicy.AllowedRoots) {
            & $addAllowedRoot -Candidate $root
        }

        if ($allowedRoots.Count -gt 0) {
            $startInfo.Environment['TT_AGENT_ALLOWED_PATH_ROOTS'] = [string]::Join([System.IO.Path]::PathSeparator, $allowedRoots)
        }
        if (-not [string]::IsNullOrWhiteSpace($effectiveWriteDirectoryPolicy.FilesystemRoot)) {
            $startInfo.Environment['TT_AGENT_FILESYSTEM_ROOT'] = $effectiveWriteDirectoryPolicy.FilesystemRoot
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
        foreach ($mcpCredentialEntry in $resolvedMcpBearerCredentials.GetEnumerator()) {
            if (-not [string]::IsNullOrWhiteSpace([string]$mcpCredentialEntry.Key) -and -not [string]::IsNullOrWhiteSpace([string]$mcpCredentialEntry.Value)) {
                $startInfo.Environment[[string]$mcpCredentialEntry.Key] = [string]$mcpCredentialEntry.Value
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($serializedMcpConfigForChild)) {
            $startInfo.Environment['TT_AGENT_MCP_CONFIG_JSON'] = $serializedMcpConfigForChild
        }
        if (-not [string]::IsNullOrWhiteSpace($retrievalConfigJson)) {
            $startInfo.Environment['TT_AGENT_RETRIEVAL_CONFIG_JSON'] = $retrievalConfigJson
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

            $approvalRequestPrefix = '__TT_APPROVAL_REQUEST__:'
            $approvalDecisionCache = [System.Collections.Generic.Dictionary[string, bool]]::new([System.StringComparer]::Ordinal)
            $processAgentStdOutLine = {
                param([string]$line)

                if ([string]::IsNullOrEmpty($line) -or -not $line.StartsWith($approvalRequestPrefix, [System.StringComparison]::Ordinal)) {
                    return $false
                }

                $toolName = '(unknown)'
                $argumentSummary = '[no arguments]'
                $payloadJson = $line.Substring($approvalRequestPrefix.Length)
                $approvalCacheKey = if ([string]::IsNullOrWhiteSpace($payloadJson)) { $line } else { $payloadJson }
                [bool]$cachedApprovalDecision = $false
                $hasCachedDecision = $approvalDecisionCache.TryGetValue($approvalCacheKey, [ref]$cachedApprovalDecision)

                try {
                    $approvalRequest = $payloadJson | ConvertFrom-Json -Depth 16 -ErrorAction Stop
                    if ($null -ne $approvalRequest -and $approvalRequest.PSObject.Properties['toolName']) {
                        $resolvedToolName = [string]$approvalRequest.toolName
                        if (-not [string]::IsNullOrWhiteSpace($resolvedToolName)) {
                            $toolName = $resolvedToolName
                        }
                    }

                    if ($null -ne $approvalRequest -and $approvalRequest.PSObject.Properties['arguments']) {
                        $pairs = [System.Collections.Generic.List[string]]::new()
                        $argumentsObject = $approvalRequest.arguments
                        if ($null -ne $argumentsObject) {
                            foreach ($prop in $argumentsObject.PSObject.Properties) {
                                $key = [string]$prop.Name
                                $value = $prop.Value
                                $serializedValue = if ($null -eq $value) { '<null>' } else { $value | ConvertTo-Json -Compress -Depth 8 }
                                $pairs.Add(("{0}={1}" -f $key, $serializedValue))
                            }
                        }

                        if ($pairs.Count -gt 0) {
                            $argumentSummary = $pairs -join '; '
                        }
                    }
                }
                catch {
                    Write-Log -Level Warn -Message ("Failed to parse destructive approval payload from child process: {0}" -f $_.Exception.Message)
                }

                $allowApproval = $cachedApprovalDecision
                if (-not $hasCachedDecision) {
                    $allowApproval = $false
                    $canPromptForApproval = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
                    if ($canPromptForApproval) {
                        $response = Read-Host -Prompt (
                            "Destructive action approval required.`n" +
                            "Tool: {0}`nArgs: {1}`nType 'yes' or 'authorized' to approve this single-use destructive action. Anything else denies it." -f $toolName, $argumentSummary
                        )
                        $normalized = if ($null -ne $response) { $response.Trim() } else { '' }
                        $allowApproval = ($normalized -match '^(?:y|yes|authorized|allow|approve)$') -or ($normalized -ieq 'authorized')
                    }
                    else {
                        Write-Warning "Destructive action denied because interactive approval is unavailable in non-interactive host mode."
                    }

                    $approvalDecisionCache[$approvalCacheKey] = $allowApproval
                }

                $responseText = if ($allowApproval) { 'authorized' } else { 'denied' }
                try {
                    $agentProc.StandardInput.WriteLine($responseText)
                    $agentProc.StandardInput.Flush()
                }
                catch {
                    throw ("Tech agent failed while sending destructive approval response: {0}" -f $_.Exception.Message)
                }

                return $true
            }

            # Initialize agent state tracking
            $agentState = @{
                currentIteration       = 0
                totalIterations        = $resolvedMaxIterations
                foundValidDecision     = $false
                lastResponseLength     = 0
                lastStoppedEarly       = $false
                consecutiveLlmFailures = 0
                lastToolName           = ''
                toolNames              = [System.Collections.Generic.List[string]]::new()
                processExited          = $false
                exitCode               = -1
            }

            # Read stdout/stderr incrementally so iteration status can advance while waiting.
            $stdoutLines = [System.Collections.Generic.List[string]]::new()
            $stderrLines = [System.Collections.Generic.List[string]]::new()
            $streamReadState = @{
                stdoutReadTask = $agentProc.StandardOutput.ReadLineAsync()
                stderrReadTask = $agentProc.StandardError.ReadLineAsync()
            }

            # Define the poll script that drives the internal terminal-state loop.
            $pollScript = {
                while ($true) {
                    $advanced = $false

                    if ($null -ne $streamReadState['stdoutReadTask'] -and $streamReadState['stdoutReadTask'].IsCompleted) {
                        $line = $streamReadState['stdoutReadTask'].GetAwaiter().GetResult()
                        if ($null -ne $line) {
                            if (-not (& $processAgentStdOutLine -line ([string]$line))) {
                                $stdoutLines.Add([string]$line)
                                Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                            }
                            $streamReadState['stdoutReadTask'] = $agentProc.StandardOutput.ReadLineAsync()
                        }
                        else {
                            $streamReadState['stdoutReadTask'] = $null
                        }

                        $advanced = $true
                    }

                    if ($null -ne $streamReadState['stderrReadTask'] -and $streamReadState['stderrReadTask'].IsCompleted) {
                        $line = $streamReadState['stderrReadTask'].GetAwaiter().GetResult()
                        if ($null -ne $line) {
                            Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                            if ($line -notmatch '^__TT_ITERATION__:\d+/\d+$') {
                                $stderrLines.Add([string]$line)
                            }
                            $streamReadState['stderrReadTask'] = $agentProc.StandardError.ReadLineAsync()
                        }
                        else {
                            $streamReadState['stderrReadTask'] = $null
                        }

                        $advanced = $true
                    }

                    if (-not $advanced) {
                        break
                    }
                }

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
                    Message = 'Tech agent completed.'
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

            # Drain any remaining async line reads after process completion.
            $drainRemainderSynchronously = $false
            while ($null -ne $streamReadState['stdoutReadTask'] -or $null -ne $streamReadState['stderrReadTask']) {
                $pendingTasks = [System.Collections.Generic.List[System.Threading.Tasks.Task]]::new()
                if ($null -ne $streamReadState['stdoutReadTask']) { $pendingTasks.Add([System.Threading.Tasks.Task]$streamReadState['stdoutReadTask']) }
                if ($null -ne $streamReadState['stderrReadTask']) { $pendingTasks.Add([System.Threading.Tasks.Task]$streamReadState['stderrReadTask']) }

                if ($pendingTasks.Count -eq 0) {
                    break
                }

                [void][System.Threading.Tasks.Task]::WaitAny($pendingTasks.ToArray(), 250)
                $madeProgress = $false

                if ($null -ne $streamReadState['stdoutReadTask'] -and $streamReadState['stdoutReadTask'].IsCompleted) {
                    $line = $streamReadState['stdoutReadTask'].GetAwaiter().GetResult()
                    if ($null -ne $line) {
                        if (-not (& $processAgentStdOutLine -line ([string]$line))) {
                            $stdoutLines.Add([string]$line)
                            Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                        }
                        $streamReadState['stdoutReadTask'] = $agentProc.StandardOutput.ReadLineAsync()
                    }
                    else {
                        $streamReadState['stdoutReadTask'] = $null
                    }

                    $madeProgress = $true
                }

                if ($null -ne $streamReadState['stderrReadTask'] -and $streamReadState['stderrReadTask'].IsCompleted) {
                    $line = $streamReadState['stderrReadTask'].GetAwaiter().GetResult()
                    if ($null -ne $line) {
                        Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                        if ($line -notmatch '^__TT_ITERATION__:\d+/\d+$') {
                            $stderrLines.Add([string]$line)
                        }
                        $streamReadState['stderrReadTask'] = $agentProc.StandardError.ReadLineAsync()
                    }
                    else {
                        $streamReadState['stderrReadTask'] = $null
                    }

                    $madeProgress = $true
                }

                if (-not $madeProgress -and $agentProc.HasExited -and ($null -ne $streamReadState['stdoutReadTask'] -or $null -ne $streamReadState['stderrReadTask'])) {
                    $drainRemainderSynchronously = $true
                    break
                }
            }

            if ($drainRemainderSynchronously) {
                # Avoid calling ReadToEnd() while a prior ReadLineAsync is still active on the same stream,
                # which can race after process exit and produce the noisy "stream is currently in use" warnings.
                if ($null -eq $streamReadState['stdoutReadTask']) {
                    try {
                        $stdoutTail = $agentProc.StandardOutput.ReadToEnd()
                        if (-not [string]::IsNullOrEmpty($stdoutTail)) {
                            foreach ($line in ($stdoutTail -split "`r?`n")) {
                                if ($null -ne $line -and -not (& $processAgentStdOutLine -line ([string]$line))) {
                                    $stdoutLines.Add([string]$line)
                                    Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                                }
                            }
                        }
                    }
                    catch {
                        # Ignore these as a benign race after process shutdown; the stream is already drained by the line-loop.
                    }
                }

                if ($null -eq $streamReadState['stderrReadTask']) {
                    try {
                        $stderrTail = $agentProc.StandardError.ReadToEnd()
                        if (-not [string]::IsNullOrEmpty($stderrTail)) {
                            foreach ($line in ($stderrTail -split "`r?`n")) {
                                if ($null -ne $line) {
                                    Update-TTAgentTraceStateFromLine -TraceLine $line -AgentState $agentState
                                    if ($line -notmatch '^__TT_ITERATION__:\d+/\d+$') {
                                        $stderrLines.Add([string]$line)
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        # Ignore these as a benign race after process shutdown; the stream is already drained by the line-loop.
                    }
                }
            }

            $capturedStdOut = ($stdoutLines -join [Environment]::NewLine)
            $capturedStdErr = ($stderrLines -join [Environment]::NewLine)

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

        if (-not [string]::IsNullOrWhiteSpace($message)) {
            try {
                $metadataEnvelope = $message | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $metadataEnvelope -and $metadataEnvelope.PSObject.Properties['Output']) {
                    $agentMetadataParsed = $true
                    $message = [string]$metadataEnvelope.Output

                    $metadataObject = $metadataEnvelope.PSObject.Properties['Metadata'].Value
                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['UsedTools']) {
                        $agentMetadataToolNames = @($metadataObject.UsedTools | ForEach-Object {
                                if ($null -ne $_) { [string]$_ }
                            })
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagUsed']) {
                        $markdownRagUsed = [bool]$metadataObject.RagUsed
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagStatus']) {
                        $resolvedRagStatus = [string]$metadataObject.RagStatus
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagStatus)) {
                            $markdownRagStatus = $resolvedRagStatus
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagModelEffective']) {
                        $resolvedRagModel = [string]$metadataObject.RagModelEffective
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagModel)) {
                            $markdownRagModelEffective = $resolvedRagModel
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagModelSource']) {
                        $resolvedRagModelSource = [string]$metadataObject.RagModelSource
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagModelSource)) {
                            $markdownRagModelSource = $resolvedRagModelSource
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagEnabledConfigured']) {
                        $markdownRagEnabledConfigured = [bool]$metadataObject.RagEnabledConfigured
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagAttempted']) {
                        $markdownRagAttempted = [bool]$metadataObject.RagAttempted
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagProviderType']) {
                        $resolvedRagProviderType = [string]$metadataObject.RagProviderType
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagProviderType)) {
                            $markdownRagProviderType = $resolvedRagProviderType
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagExecutionMode']) {
                        $resolvedRagExecutionMode = [string]$metadataObject.RagExecutionMode
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagExecutionMode)) {
                            $markdownRagExecutionMode = $resolvedRagExecutionMode
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagEnvironmentContextIncluded']) {
                        $markdownRagEnvironmentContextIncluded = [bool]$metadataObject.RagEnvironmentContextIncluded
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagEnvironmentContextProfile']) {
                        $resolvedRagEnvironmentContextProfile = [string]$metadataObject.RagEnvironmentContextProfile
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagEnvironmentContextProfile)) {
                            $markdownRagEnvironmentContextProfile = $resolvedRagEnvironmentContextProfile
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagSourcesScanned']) {
                        $markdownRagSourcesScanned = [int]$metadataObject.RagSourcesScanned
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagCandidatesScored']) {
                        $markdownRagCandidatesScored = [int]$metadataObject.RagCandidatesScored
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagCandidatesSelected']) {
                        $markdownRagCandidatesSelected = [int]$metadataObject.RagCandidatesSelected
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagCandidatesPacked']) {
                        $markdownRagCandidatesPacked = [int]$metadataObject.RagCandidatesPacked
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagContextCharacters']) {
                        $markdownRagContextCharacters = [int]$metadataObject.RagContextCharacters
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagModelConfigured']) {
                        $resolvedRagModelConfigured = [string]$metadataObject.RagModelConfigured
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagModelConfigured)) {
                            $markdownRagModelConfigured = $resolvedRagModelConfigured
                        }
                    }

                    if ($null -ne $metadataObject -and $metadataObject.PSObject.Properties['RagStatusReason']) {
                        $resolvedRagStatusReason = [string]$metadataObject.RagStatusReason
                        if (-not [string]::IsNullOrWhiteSpace($resolvedRagStatusReason)) {
                            $markdownRagStatusReason = $resolvedRagStatusReason
                        }
                    }
                }
            }
            catch {
                # Fall back to runtime trace extraction if metadata envelope parsing fails.
            }
        }

        if ($agentMetadataParsed) {
            $markdownToolTrace = Convert-TTAgentToolTrace -ToolNames @($agentMetadataToolNames)
        }
        elseif ($null -ne $agentState -and $agentState.ContainsKey('toolNames')) {
            $markdownToolTrace = Convert-TTAgentToolTrace -ToolNames @($agentState['toolNames'])
        }
        if ($resolvedOutputContract -eq 'markdown' -and -not [string]::IsNullOrWhiteSpace($message)) {
            $message = Remove-TTAgentDuplicateMarkdownHeadings -Markdown $message -WindowLines 40
        }
        if (-not [string]::IsNullOrWhiteSpace($message)) {
            $message = Remove-TTAgentAdjacentDuplicateLines -Text $message -MinimumLineLength 24
        }
        $capturedStdOut = $message
        $markdownResponseLength = $message.Length
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = 'Tech agent completed with no output.'
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
            'Iteration limit reached.',
            '## Agent Iteration Limit Reached',
            'DECISION_NO_PROGRESS_GUARD:'
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

            $outputValidation = Test-TTAgentExpectedOutputFile -Path $expectedOutputPath
            if (-not $outputValidation.IsValid) {
                $parseErrorText = if ([string]::IsNullOrWhiteSpace($outputValidation.Error)) {
                    'unknown validation error'
                }
                else {
                    $outputValidation.Error
                }

                throw ("Tech agent failed: expected output file exists but is not valid PowerShell content at '{0}'. Validation error: {1}" -f $expectedOutputPath, $parseErrorText)
            }
        }
        $markdownExpectedOutputExists = $expectedOutputExists

        if ($knownFailureDetected) {
            if ($expectedOutputExists) {
                $knownFailureMessage = $message
                $markdownRecoveryReason = (
                    "Recovered known orchestrator failure text because expected output file exists at '{0}'. Message: {1}" -f $expectedOutputPath, $knownFailureMessage
                )
                Write-Log -Level Warn -Message (
                    "Tech agent reported orchestrator failure text, but expected output file exists. Treating run as recovered success. Message: {0}" -f $knownFailureMessage
                )

                $recoveredOutputMessage = Resolve-TTAgentRecoveredOutputMessage `
                    -KnownFailureMessage $knownFailureMessage `
                    -ExpectedOutputPath $expectedOutputPath

                if (-not [string]::IsNullOrWhiteSpace($recoveredOutputMessage)) {
                    $message = $recoveredOutputMessage.Trim()
                }

                if ($resolvedOutputContract -eq 'markdown' -and -not [string]::IsNullOrWhiteSpace($message)) {
                    $message = Remove-TTAgentDuplicateMarkdownHeadings -Markdown $message -WindowLines 40
                }

                if (-not [string]::IsNullOrWhiteSpace($message)) {
                    $message = Remove-TTAgentAdjacentDuplicateLines -Text $message -MinimumLineLength 24
                }

                if ([string]::IsNullOrWhiteSpace($message)) {
                    $message = ("Recovered output file was created at {0}." -f $expectedOutputPath)
                }

                $capturedStdOut = $message
                $markdownResponseLength = $message.Length

                $postflightAssessment = Test-TTAgentPostflightGoal -PromptText $Prompt -ResponseText $message -PreflightScore $preflightScore
                $markdownPostflightAchieved = [bool]$postflightAssessment.Achieved
                $markdownPostflightReason = if ([string]::IsNullOrWhiteSpace($postflightAssessment.Reason)) { '' } else { [string]$postflightAssessment.Reason }

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
        # A late failure supersedes any earlier postflight assessment. Keep the
        # markdown record internally consistent rather than implying success.
        $markdownPostflightAchieved = $false
        $lateFailureReason = "Run failed after postflight assessment: $($_.Exception.Message)"
        if ([string]::IsNullOrWhiteSpace($markdownPostflightReason)) {
            $markdownPostflightReason = $lateFailureReason
        }
        else {
            $markdownPostflightReason = "$markdownPostflightReason; $lateFailureReason"
        }
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
                    -IterationLimit $resolvedMaxIterations `
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
                    -ToolTrace @($markdownToolTrace) `
                    -ResponseLength $markdownResponseLength `
                    -KnownFailureDetected $markdownKnownFailureDetected `
                    -ExpectedOutputExists $markdownExpectedOutputExists `
                    -RagUsed $markdownRagUsed `
                    -RagStatus $markdownRagStatus `
                    -RagModelEffective $markdownRagModelEffective `
                    -RagModelSource $markdownRagModelSource `
                    -RagEnabledConfigured $markdownRagEnabledConfigured `
                    -RagAttempted $markdownRagAttempted `
                    -RagProviderType $markdownRagProviderType `
                    -RagExecutionMode $markdownRagExecutionMode `
                    -RagEnvironmentContextIncluded $markdownRagEnvironmentContextIncluded `
                    -RagEnvironmentContextProfile $markdownRagEnvironmentContextProfile `
                    -RagSourcesScanned $markdownRagSourcesScanned `
                    -RagCandidatesScored $markdownRagCandidatesScored `
                    -RagCandidatesSelected $markdownRagCandidatesSelected `
                    -RagCandidatesPacked $markdownRagCandidatesPacked `
                    -RagContextCharacters $markdownRagContextCharacters `
                    -RagModelConfigured $markdownRagModelConfigured `
                    -RagStatusReason $markdownRagStatusReason `
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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCGf8KIunKDI+JE
# UfgLEUL9DcMSPZKHMJ8ummoi+1XoHKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCw
# Y7VK56RUgNVsSuSiuWjJ28mQMVjcCsALL0LzijHoAjANBgkqhkiG9w0BAQEFAASC
# AYCeo4TOXSdE68Y8zYRspUd5dJbeXHTF6Lh9eNRB4NzDhJpuocsU0NeJAWlLZm/C
# TMd0SSzMlPM0tblvTlrmd7IEJsQVHr9ymvHFjw3l1BpMqM5s900jOcUQm1oabgK8
# nKkX0MUXq1QrvZXqBEweqEmfuSu0ALEc+fqFpeppDC5wTKs0yrd4fwlgX0XNzFZW
# DUVURL0Csgad1wPDSC8o9fmhwOkOpDmT5Gh9C6uP2gDImpe1eSBKGVBBw92c3sit
# EtKjpaSzZvcaqzmpjkhSfuJBMHxLKZ3LoM65hd9gxYG6bicjuJdiEy/4vEDX9zE6
# Q8GADm/qps3XPOgkb6YJOoV6dDo682kYVVK5naHJk9AxfPiDreq8wK43gDAKZsvJ
# 0BQp4tjHxat3tP0qUzzILKiKlUL+UONdi9uIIxTmKccN5iGCHtSlFkYlO8yMpcKf
# 0FU7hAHWA/+/zys2S8dIrzAMoeSh97h2aRFYONpxnGWdtEQSCb1Ha5b84HqqLJLK
# amahggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDEwMDUxOTM5WjAvBgkqhkiG
# 9w0BCQQxIgQgmaEDewUHq1AHRwhH59lGcPHyFJEa4s9hl2udFISi/YcwDQYJKoZI
# hvcNAQEBBQAEggIAfV8tCYufmgi6AvCEXTtU5WaHpzkKGfB/zth+w2DcE7HXU/5J
# oDhkvcMidzy4q5JMrIBM/2G2gGY7APzoLrG9cb5FA7YMKtNyO+KrWl9TJ6m/8aU4
# 3YDIZJfgnbWQ6raKE6TDBD90QeW48xW0+CRio/XeAZI7mA8/VeIsBXZjI1vpBEPJ
# AItjL25G2FAROnedlM3//h8RmtFIedC02paeUeJdsn8nXi7NlI3SezFwxbAbqsOZ
# 5ycRrkzYsQzV16UsZP8NqcnFeSU3c4Gn/ttU/Mu1LLtm7AWEqytagGXO4guFkWlv
# Fk4gW1klFbraV3c0WC439JzxHyB7a/uBuFRBq2mdxSDoCuxE+GWq9rH0f48NNlxz
# TnsrUoyhFFOeHLxma2qpiDzRPDTii5oIfBUyQQkydoSNLFMsgwYaV1yeYQwZrj28
# IM25CxGe4DQAxsIyKUzZtcQ+tvJY6MNULNXt8WJBrocLxB2cRGnYaqmombtjLV7H
# hidV1BT8W1GNjwEXrz5Hfuupsh+sO3S4DUTtDSxRyBnjV9DBHZkiCHiCeqHUC9pA
# eoGmJCsmThu6f2GScyGeArUZq/nzZZV9C6DkHs8vok2/sNNvVeVFPJoNh6ny8C2/
# R9MBs2YyBv9qwQYv8nabhAToJ+OXSAde8UOKZDru408nad0ZR3Z0ugeA4f8=
# SIG # End signature block
