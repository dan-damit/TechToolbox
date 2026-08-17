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
        Optional Ollama model name (for example: llama3, mistral,
        qwen2.5-coder).

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
        [switch]$ConfirmDestructive

        ,

        [Parameter()]
        [ValidateSet('ignore', 'strip')]
        [string]$SignedFilePolicy,

        [Parameter()]
        [switch]$AutoRetryOnRecursion

        ,

        [Parameter()]
        [switch]$DisableAutoRetryOnRecursion

        ,

        [Parameter()]
        [bool]$NoTranscript = $true

        ,

        [Parameter()]
        [switch]$AllowMetaTools

        ,

        [Parameter()]
        [pscredential]$ToolCredential

        ,

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

    $resolveExecutionMode = {
        param(
            [string]$ModeFromParam,
            $ConfigObject,
            [bool]$ParamWasBound
        )

        if ($ParamWasBound -and -not [string]::IsNullOrWhiteSpace($ModeFromParam)) {
            return $ModeFromParam.Trim().ToLowerInvariant()
        }

        $configMode = $null
        if ($null -ne $ConfigObject) {
            $modeProperty = $ConfigObject.PSObject.Properties['executionMode']
            if ($null -ne $modeProperty -and -not [string]::IsNullOrWhiteSpace([string]$modeProperty.Value)) {
                $configMode = [string]$modeProperty.Value
            }
        }

        if ([string]::IsNullOrWhiteSpace($configMode)) {
            return 'chat'
        }

        switch ($configMode.Trim().ToLowerInvariant()) {
            'plan' { return 'plan' }
            'analyze' { return 'analyze' }
            'chat' { return 'chat' }
            default { return 'chat' }
        }
    }

    $resolveOutputContract = {
        param(
            [string]$ContractFromParam,
            $ConfigObject,
            [bool]$ParamWasBound
        )

        if ($ParamWasBound -and -not [string]::IsNullOrWhiteSpace($ContractFromParam)) {
            return $ContractFromParam.Trim().ToLowerInvariant()
        }

        $configContract = $null
        if ($null -ne $ConfigObject) {
            $contractProperty = $ConfigObject.PSObject.Properties['outputContract']
            if ($null -ne $contractProperty -and -not [string]::IsNullOrWhiteSpace([string]$contractProperty.Value)) {
                $configContract = [string]$contractProperty.Value
            }
        }

        if ([string]::IsNullOrWhiteSpace($configContract)) {
            return 'markdown'
        }

        switch ($configContract.Trim().ToLowerInvariant()) {
            'plain-text' { return 'plain-text' }
            'json' { return 'json' }
            default { return 'markdown' }
        }
    }

    $resolveQualityProfile = {
        param(
            [string]$ProfileFromParam,
            $ConfigObject,
            [bool]$ParamWasBound
        )

        if ($ParamWasBound -and -not [string]::IsNullOrWhiteSpace($ProfileFromParam)) {
            return $ProfileFromParam.Trim().ToLowerInvariant()
        }

        $configProfile = $null
        if ($null -ne $ConfigObject) {
            $profileProperty = $ConfigObject.PSObject.Properties['qualityProfile']
            if ($null -ne $profileProperty -and -not [string]::IsNullOrWhiteSpace([string]$profileProperty.Value)) {
                $configProfile = [string]$profileProperty.Value
            }
        }

        if ([string]::IsNullOrWhiteSpace($configProfile)) {
            return 'balanced'
        }

        switch ($configProfile.Trim().ToLowerInvariant()) {
            'precise' { return 'precise' }
            'creative' { return 'creative' }
            default { return 'balanced' }
        }
    }

    $invokePromptPreflight = {
        param(
            [string]$PromptText,
            [string]$Mode
        )

        $score = 0
        $warnings = [System.Collections.Generic.List[string]]::new()
        $critical = [System.Collections.Generic.List[string]]::new()

        if ([string]::IsNullOrWhiteSpace($PromptText)) {
            $critical.Add('Prompt is empty.')
            return [ordered]@{ Score = 0; Warnings = @($warnings); Critical = @($critical) }
        }

        $normalizedPrompt = $PromptText.Trim()

        $hasTaskVerb = [regex]::IsMatch(
            $normalizedPrompt,
            '(?i)\b(create|write|update|edit|modify|fix|analy[sz]e|review|refactor|investigate|summari[sz]e|plan|implement|find|fetch|get|retrieve|collect|report|disable|enable|reset|remove|delete|provision|deprovision|offboard)\b')
        if ($hasTaskVerb) { $score += 20 } else { $warnings.Add('Missing clear task verb (for example: update, analyze, fix, plan).') }

        $hasPathOrSystemTarget = [regex]::IsMatch(
            $normalizedPrompt,
            '(?i)([A-Za-z]:\\[^\r\n]+|\b(file|function|class|module|script|command|service|endpoint|api|workflow|active\s*directory|ad\b|account|user|computer|group|ou|organizational\s+unit|exchange\s*online|entra|azure\s*ad)\b)')

        $hasWebTarget = [regex]::IsMatch(
            $normalizedPrompt,
            '(?i)(https?://\S+|\b(url|uri|website|web\s*site|webpage|site|domain|host|weather\.gov)\b)')

        $hasConcreteTarget = $hasPathOrSystemTarget -or $hasWebTarget
        if ($hasConcreteTarget) { $score += 20 } else { $warnings.Add('Missing concrete target (file, function, module, system, URL, website, or path).') }

        $hasExpectedOutcome = [regex]::IsMatch(
            $normalizedPrompt,
            '(?i)\b(expected|outcome|output|result|return|produce|final|success\b|done\b)')
        if ($hasExpectedOutcome) { $score += 20 } else { $warnings.Add('Missing expected outcome details (what successful output should look like).') }

        $hasConstraints = [regex]::IsMatch(
            $normalizedPrompt,
            '(?i)\b(must|should|do not|don''t|avoid|constraint|format|style|security|strict|exact path|preserve|no edits)')
        if ($hasConstraints) { $score += 20 } else { $warnings.Add('Missing explicit constraints or preferences (style, safety, formatting, scope).') }

        if ($normalizedPrompt.Length -ge 80) {
            $score += 20
        }
        else {
            $warnings.Add('Prompt is short; add context (environment, errors, affected behavior).')
        }

        if ($normalizedPrompt.Length -lt 25) {
            $critical.Add('Prompt is too short for reliable execution.')
        }

        if ($Mode -eq 'execute' -and -not $hasConcreteTarget) {
            $critical.Add('Execution mode requires a concrete target to avoid ambiguous changes.')
        }

        if ($Mode -eq 'execute' -and -not $hasExpectedOutcome) {
            $critical.Add('Execution mode requires expected outcome details.')
        }

        return [ordered]@{
            Score    = $score
            Warnings = @($warnings)
            Critical = @($critical)
        }
    }

    $buildAutoPromptHint = {
        param(
            [string]$PromptText,
            [string]$Mode,
            [string]$OutputContract,
            [int]$WarningCount,
            [int]$CriticalCount
        )

        if ([string]::IsNullOrWhiteSpace($PromptText)) {
            return $null
        }

        if ($WarningCount -le 0 -and $CriticalCount -le 0) {
            return $null
        }

        $normalized = $PromptText.Trim()

        $taskVerbMatch = [regex]::Match(
            $normalized,
            '(?i)\b(create|write|update|edit|modify|fix|analy[sz]e|review|refactor|investigate|summari[sz]e|plan|implement|find|fetch|get|retrieve|collect|report)\b')
        $taskVerb = if ($taskVerbMatch.Success) {
            $taskVerbMatch.Value
        }
        elseif ([regex]::IsMatch($normalized, '(?i)\b(weather|forecast)\b')) {
            'fetch'
        }
        else {
            'analyze'
        }

        $urlMatch = [regex]::Match($normalized, '(?i)https?://\S+')
        $pathMatch = [regex]::Match($normalized, '(?i)[A-Za-z]:\\[^\s"''`\r\n]+')
        $locationMatch = [regex]::Match(
            $normalized,
            '(?i)\b(?:for|in|at|near)\s+(?<location>[A-Za-z][A-Za-z0-9''.,/-]*(?:\s+[A-Za-z0-9''.,/-]+){0,6})(?=\s+(?:from|on|using|with|and|return|output|show|summarize|today|tomorrow|next)\b|$)'
        )

        $targetHint = if ($urlMatch.Success) {
            "the data from $($urlMatch.Value)"
        }
        elseif ($pathMatch.Success) {
            "the file at $($pathMatch.Value)"
        }
        elseif ($locationMatch.Success) {
            $locationName = $locationMatch.Groups['location'].Value.Trim().TrimEnd(',', '.')
            "the weather forecast for $locationName from the official weather website"
        }
        elseif ([regex]::IsMatch($normalized, '(?i)\bweather\b')) {
            'the weather forecast for the specified location from the official weather website'
        }
        else {
            'the specific file, service, module, or URL'
        }

        $sourceHint = if ($urlMatch.Success) {
            "Use $($urlMatch.Value) as the primary source."
        }
        elseif ([regex]::IsMatch($normalized, '(?i)\b(website|web\s*site|webpage|url|uri|domain|host|web)\b')) {
            'Use the specified website or URL as the primary source.'
        }
        else {
            'Use only the minimum required tools and keep the scope bounded.'
        }

        $contractHint = switch ($OutputContract) {
            'json' { 'Return valid JSON object or array text only.' }
            'plain-text' { 'Return plain text only (no markdown).' }
            default { 'Return the final answer in markdown.' }
        }

        $modeConstraint = if ($Mode -eq 'execute') {
            'Constraints: execute only bounded steps and avoid unrelated changes.'
        }
        else {
            "Constraints: respect mode '$Mode'."
        }

        return (
            '{0} {1}. {2} {3} {4}' -f $taskVerb, $targetHint, $sourceHint, $contractHint, $modeConstraint
        )
    }

    $evaluatePostflightGoal = {
        param(
            [string]$PromptText,
            [string]$ResponseText,
            [int]$PreflightScore
        )

        if ([string]::IsNullOrWhiteSpace($PromptText)) {
            return @{ Achieved = $false; Reason = 'Prompt was empty.' }
        }

        if ([string]::IsNullOrWhiteSpace($ResponseText)) {
            return @{ Achieved = $false; Reason = 'No response text was produced.' }
        }

        $promptLower = $PromptText.Trim().ToLowerInvariant()
        $responseLower = $ResponseText.Trim().ToLowerInvariant()

        if ([regex]::IsMatch($responseLower, '(?i)(i need more detail|need more information|clarification needed|unable to|could not|failed to|not enough information)')) {
            return @{ Achieved = $false; Reason = 'The response requested more clarification or reported inability to complete the task.' }
        }

        if ($PreflightScore -lt 60 -and $ResponseText.Trim().Length -lt 80) {
            return @{ Achieved = $false; Reason = 'The response was too short to clearly satisfy the prompt.' }
        }

        if ($promptLower.Contains('weather') -or $promptLower.Contains('forecast')) {
            $weatherTerms = @('weather', 'forecast', 'temperature', 'humidity', 'wind', 'rain', 'conditions', 'precipitation')
            $hasWeatherResponseSignal = $false
            foreach ($term in $weatherTerms) {
                if ($responseLower.Contains($term)) {
                    $hasWeatherResponseSignal = $true
                    break
                }
            }

            if (-not $hasWeatherResponseSignal) {
                return @{ Achieved = $false; Reason = 'The response did not include weather or forecast information.' }
            }
        }

        return @{ Achieved = $true; Reason = '' }
    }

    $resolvedExecutionMode = & $resolveExecutionMode -ModeFromParam $Mode -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('Mode')
    $resolvedOutputContract = & $resolveOutputContract -ContractFromParam $OutputContract -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('OutputContract')
    $resolvedQualityProfile = & $resolveQualityProfile -ProfileFromParam $QualityProfile -ConfigObject $cfg -ParamWasBound $PSBoundParameters.ContainsKey('QualityProfile')

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

    $preflight = & $invokePromptPreflight -PromptText $Prompt -Mode $resolvedExecutionMode
    $preflightScore = [int]$preflight.Score
    $preflightWarningCount = @($preflight.Warnings).Count
    $preflightCriticalCount = @($preflight.Critical).Count

    Write-Log -Level Info -Message (
        "`nTech agent prompt preflight: score={0}/100 mode={1} outputContract={2} qualityProfile={3} source={4}" -f $preflightScore, $resolvedExecutionMode, $resolvedOutputContract, $resolvedQualityProfile, $promptSourceLabel
    )

    Write-Log -Level Info -Message (
        "Tech agent reasoning effort settings: override={0} auto={1}" -f $(if ([string]::IsNullOrWhiteSpace($resolvedReasoningEffort)) { '(none)' } else { $resolvedReasoningEffort }), $resolvedReasoningEffortAuto
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
        $hint = & $buildAutoPromptHint `
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
        $rerunHint = & $buildAutoPromptHint `
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

            $preflight = & $invokePromptPreflight -PromptText $Prompt -Mode $resolvedExecutionMode
            $preflightScore = [int]$preflight.Score
            $preflightWarningCount = @($preflight.Warnings).Count
            $preflightCriticalCount = @($preflight.Critical).Count

            Write-Log -Level Info -Message (
                "Invoke-TechAgent auto rerun preflight: score={0}/100 mode={1} outputContract={2} qualityProfile={3} source={4}" -f $preflightScore, $resolvedExecutionMode, $resolvedOutputContract, $resolvedQualityProfile, $promptSourceLabel
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
    $capturedStdOut = ''
    $capturedStdErr = ''
    $runStartedUtc = [DateTime]::UtcNow
    $agentProc = $null
    $stdoutTask = $null
    $stderrTask = $null
    $requestPath = $null
    $resolvedApiKey = $null
    $toolCredentialPath = $null

    $resolveExpectedOutputPath = {
        param(
            [string]$PromptText
        )

        $trimDetectedPath = {
            param([string]$CandidatePath)

            if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
                return $null
            }

            $trimmed = $CandidatePath.Trim().TrimEnd('.', ',', ';', ':', ')', ']', '}')
            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                return $null
            }

            return $trimmed
        }

        $promptIndicatesWriteIntent = {
            param([string]$Text)

            if ([string]::IsNullOrWhiteSpace($Text)) {
                return $false
            }

            return [regex]::IsMatch(
                $Text,
                '(?is)\b(write|rewrite|update|edit|modify|insert|create)\b|\buse\s+write(?:-|=|\s*)file\b|\bwrite(?:-|=|\s*)file\b')
        }

        if ([string]::IsNullOrWhiteSpace($PromptText)) {
            return $null
        }

        $directPathMatches = [regex]::Matches(
            $PromptText,
            '(?i)(?<path>[A-Za-z]:\\[^\s"''`\r\n]*?\.help\.txt)\b')

        if ($directPathMatches.Count -gt 0) {
            $directPath = & $trimDetectedPath -CandidatePath $directPathMatches[$directPathMatches.Count - 1].Groups['path'].Value
            if (-not [string]::IsNullOrWhiteSpace($directPath)) {
                return $directPath
            }
        }

        if (& $promptIndicatesWriteIntent -Text $PromptText) {
            $genericPathMatches = [regex]::Matches(
                $PromptText,
                '(?i)(?<path>[A-Za-z]:\\[^"''`\r\n]*\.[A-Za-z0-9]{1,16})(?=\s|$|[)\],;:])')

            if ($genericPathMatches.Count -gt 0) {
                for ($i = $genericPathMatches.Count - 1; $i -ge 0; $i--) {
                    $candidate = & $trimDetectedPath -CandidatePath $genericPathMatches[$i].Groups['path'].Value
                    if ([string]::IsNullOrWhiteSpace($candidate)) {
                        continue
                    }

                    if ($candidate.EndsWith('\', [System.StringComparison]::Ordinal)) {
                        continue
                    }

                    return $candidate
                }
            }
        }

        $fileNameMatch = [regex]::Match(
            $PromptText,
            '(?is)\b(?:name\s+(?:it|the\s+file)|file\s+should\s+be\s+named|named)\s+["'']?(?<name>[^"''`\r\n]+?\.help\.txt)\b')

        if (-not $fileNameMatch.Success) {
            return $null
        }

        $fileName = $fileNameMatch.Groups['name'].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            return $null
        }

        $pathMatches = [regex]::Matches($PromptText, '(?i)[A-Za-z]:\\[^\s"''`\r\n]+')
        if ($pathMatches.Count -eq 0) {
            return $null
        }

        $candidateDirs = @()
        foreach ($match in $pathMatches) {
            $candidatePath = [string]$match.Value
            if ([string]::IsNullOrWhiteSpace($candidatePath)) {
                continue
            }

            $candidatePath = $candidatePath.Trim().TrimEnd('.', ',', ';')
            if ($candidatePath -match '(?i)\.[A-Za-z0-9]{1,5}$') {
                continue
            }

            $candidateDirs += $candidatePath
        }

        if ($candidateDirs.Count -eq 0) {
            return $null
        }

        $targetDirectory = $candidateDirs |
        Where-Object { $_ -match '(?i)\\en-US$' } |
        Select-Object -Last 1

        if ([string]::IsNullOrWhiteSpace($targetDirectory)) {
            $targetDirectory = $candidateDirs | Select-Object -Last 1
        }

        if ([string]::IsNullOrWhiteSpace($targetDirectory)) {
            return $null
        }

        return (Join-Path -Path $targetDirectory -ChildPath $fileName)
    }

    $expectedOutputPath = & $resolveExpectedOutputPath -PromptText $Prompt

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

    $writeMarkdownLog = {
        param(
            [string]$Path,
            [string]$Status,
            [string]$PromptText,
            [string]$ModelName,
            [int]$IterationLimit,
            [bool]$DestructiveAuthorized,
            [string]$SignedFilePolicyValue,
            [string]$AutoRetryOnRecursionMode,
            [string]$StdOut,
            [string]$StdErr,
            [string]$ErrorText,
            [int]$ExitCode,
            [string]$TranscriptFile,
            [DateTime]$StartedUtc,
            [DateTime]$CompletedUtc
        )

        if ([string]::IsNullOrWhiteSpace($Path)) {
            return
        }

        $dir = Split-Path -Parent $Path
        if (-not [string]::IsNullOrWhiteSpace($dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force
        }

        $renderedOutput = if ([string]::IsNullOrWhiteSpace($StdOut)) {
            '(none)'
        }
        else {
            $StdOut.TrimEnd()
        }

        $rawError = if ([string]::IsNullOrWhiteSpace($StdErr)) {
            '(none)'
        }
        else {
            $StdErr.TrimEnd()
        }

        $rawException = if ([string]::IsNullOrWhiteSpace($ErrorText)) {
            '(none)'
        }
        else {
            $ErrorText.TrimEnd()
        }

        $lines = @(
            '# Tech Agent Run'
            ''
            ('- Status: {0}' -f $Status)
            ('- StartedUtc: {0}' -f $StartedUtc.ToString('o'))
            ('- CompletedUtc: {0}' -f $CompletedUtc.ToString('o'))
            ('- Model: {0}' -f $(if ([string]::IsNullOrWhiteSpace($ModelName)) { '(default)' } else { $ModelName }))
            ('- MaxIterations: {0}' -f $IterationLimit)
            ('- ConfirmDestructive: {0}' -f $DestructiveAuthorized)
            ('- SignedFilePolicy: {0}' -f $(if ([string]::IsNullOrWhiteSpace($SignedFilePolicyValue)) { '(default)' } else { $SignedFilePolicyValue }))
            ('- AutoRetryOnRecursion: {0}' -f $AutoRetryOnRecursionMode)
            ('- ExitCode: {0}' -f $ExitCode)
            ('- TranscriptPath: {0}' -f $(if ([string]::IsNullOrWhiteSpace($TranscriptFile)) { '(none)' } else { $TranscriptFile }))
            ''
            '## Prompt'
            ''
            '```text'
            $PromptText
            '```'
            ''
            '## Output'
            ''
            $renderedOutput
            ''
            '## Error Output'
            ''
            '~~~~text'
            $rawError
            '~~~~'
            ''
            '## Exception'
            ''
            '~~~~text'
            $rawException
            '~~~~'
        )

        Set-Content -Path $Path -Value ($lines -join [Environment]::NewLine) -Encoding utf8BOM
    }

    # Helper function to parse agent trace output and update agent state
    $parseAgentTraceLine = {
        param(
            [string]$TraceLine,
            [hashtable]$AgentState  # Mutable state hashtable passed by reference
        )

        if ([string]::IsNullOrWhiteSpace($TraceLine)) {
            return
        }

        # Detect iteration progress: "Iteration X/Y start messages=N"
        if ($TraceLine -match 'Iteration\s+(\d+)/(\d+)\s+start') {
            $currentIter = [int]$Matches[1]
            $totalIters = [int]$Matches[2]

            $AgentState['currentIteration'] = $currentIter
            $AgentState['totalIterations'] = $totalIters
        }

        # Detect early stop via valid decision found during streaming
        if ($TraceLine -match 'found valid decision during streaming') {
            $AgentState['foundValidDecision'] = $true
        }

        # Detect response received (streaming complete or early stopped)
        if ($TraceLine -match 'response length=(\d+)\s+stoppedEarly=(\w+)') {
            $responseLength = [int]$Matches[1]
            $stoppedEarly = $Matches[2] -eq 'true'

            $AgentState['lastResponseLength'] = $responseLength
            $AgentState['lastStoppedEarly'] = $stoppedEarly
        }

        # Detect LLM failures
        if ($TraceLine -match 'consecutive LLM failures=(\d+)') {
            $failureCount = [int]$Matches[1]
            $AgentState['consecutiveLlmFailures'] = $failureCount
        }

        # Detect tool execution
        if ($TraceLine -match 'executing tool=(\S+)') {
            $toolName = $Matches[1]
            $AgentState['lastToolName'] = $toolName
        }
    }

    try {
        $moduleRoot = Get-ModuleRoot
        $assemblyCandidates = @(
            (Join-Path $moduleRoot 'AgentRuntime\TechToolbox.Agent\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\TechToolbox.Agent.dll'),
            (Join-Path $moduleRoot 'src\TechToolbox.Agent\bin\Debug\net8.0\TechToolbox.Agent.dll')
        )

        $agentAssemblyPath = $assemblyCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1

        if ([string]::IsNullOrWhiteSpace($agentAssemblyPath)) {
            throw "TechToolbox.Agent assembly not found. Install the packaged agent runtime or build/publish src\TechToolbox.Agent."
        }

        Write-Log -Level Info -Message ("Tech agent runtime assembly: {0}" -f $agentAssemblyPath)

        # Load Wait-TerminalState and its dependencies for real-time status animation
        $waitTerminalStateScript = Join-Path $moduleRoot 'Private\System\Utilities\ReusableHelpers\WaitingHeartbeatScripts\Wait-TerminalState.ps1'
        $getDotPulseScript = Join-Path $moduleRoot 'Private\System\Utilities\ReusableHelpers\WaitingHeartbeatScripts\Get-DotPulse.ps1'

        $hasWaitTerminalState = $false
        if ((Test-Path -LiteralPath $waitTerminalStateScript -PathType Leaf) -and (Test-Path -LiteralPath $getDotPulseScript -PathType Leaf)) {
            try {
                . $getDotPulseScript
                . $waitTerminalStateScript
                $hasWaitTerminalState = $true
            }
            catch {
                $hasWaitTerminalState = $false
            }
        }

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
            Write-Log -Level Warn -Message "`nDestructive operations explicitly authorized for this run."
        }

        $autoRetryOnIterationLimit = $false
        if ($AutoRetryOnRecursion.IsPresent) {
            $autoRetryOnIterationLimit = $true
        }
        elseif ($DisableAutoRetryOnRecursion.IsPresent) {
            $autoRetryOnIterationLimit = $false
        }

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

        $resolveStoredAgentSecret = {
            param(
                $configObject,
                [string]$secretKeyName,
                [string]$envVarName
            )

            if (-not [string]::IsNullOrWhiteSpace($envVarName)) {
                $envValue = [Environment]::GetEnvironmentVariable($envVarName)
                if (-not [string]::IsNullOrWhiteSpace($envValue)) {
                    return @{ Key = $envValue; Source = "Environment:$envVarName"; Error = $null }
                }
            }

            $encryptedValue = [string](& $getConfigValue $configObject $secretKeyName)
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

                Write-Log -Level Ok -Message (
                    "Stored DPAPI-encrypted cloud API key in config secrets file: {0}" -f $secretsPath
                )

                if (-not [string]::IsNullOrWhiteSpace($envVarName)) {
                    [Environment]::SetEnvironmentVariable($envVarName, $plainApiKey, 'Process')
                }

                return @{ Key = $plainApiKey; Source = 'Prompt+DPAPI'; Error = $null }
            }
            catch {
                return @{ Key = $null; Source = 'Prompt+DPAPI'; Error = $_.Exception.Message }
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

        if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
            $apiKeyEnvVarValue = & $getConfigValue $cfg 'apiKeyEnvVar'
            if (-not [string]::IsNullOrWhiteSpace([string]$apiKeyEnvVarValue)) {
                $ApiKeyEnvVar = [string]$apiKeyEnvVarValue
            }
        }

        if ([string]::IsNullOrWhiteSpace($ApiKeyEnvVar)) {
            $ApiKeyEnvVar = 'TT_AGENT_LLM_API_KEY'
        }

        if ($Provider -ne 'ollama') {
            $apiKeyResolution = & $resolveCloudApiKey -configObject $cfg -providerName $Provider -envVarName $ApiKeyEnvVar -encryptedOverride $ApiKeyEncryptedBlob -PreferEncryptedOnly:$ApiKeyEncrypted
            $resolvedApiKey = [string]$apiKeyResolution.Key

            if ([string]::IsNullOrWhiteSpace($resolvedApiKey)) {
                $promptResolution = & $promptAndPersistCloudApiKey -providerName $Provider -envVarName $ApiKeyEnvVar
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
                        $llmClientFactoryType = [TechToolbox.Agent.Agent.LlmClientFactory]
                    }
                    catch {
                        $null = Add-Type -Path $agentAssemblyPath -ErrorAction Stop
                        $llmClientFactoryType = [TechToolbox.Agent.Agent.LlmClientFactory]
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

        $memoryPath = $null
        $memoryPathValue = & $getConfigValue $cfg 'memoryPath'
        if (-not [string]::IsNullOrWhiteSpace([string]$memoryPathValue)) {
            $memoryPath = [string]$memoryPathValue
        }

        [int]$resolvedPromptHistoryItems = 2
        if ($PSBoundParameters.ContainsKey('PromptHistoryItems')) {
            $resolvedPromptHistoryItems = [int]$PromptHistoryItems
        }
        else {
            $promptHistoryItemsValue = & $getConfigValue $cfg 'promptHistoryItems'
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
        $diagnosticTracePathValue = & $getConfigValue $cfg 'diagnosticTracePath'
        if (-not [string]::IsNullOrWhiteSpace([string]$diagnosticTracePathValue)) {
            $diagnosticTracePath = [string]$diagnosticTracePathValue
            Write-Log -Level Info -Message ("Tech agent diagnostic trace path: {0}" -f $diagnosticTracePath)
        }

        $allowedFetchHosts = @()
        $fetchConfigValue = & $getConfigValue $cfg 'fetch'
        if ($null -ne $fetchConfigValue) {
            $allowedHostsValue = & $getConfigValue $fetchConfigValue 'allowedHosts'
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
        $searchWebConfigValue = & $getConfigValue $cfg 'searchWeb'
        if ($null -ne $searchWebConfigValue) {
            $searchProviderValue = & $getConfigValue $searchWebConfigValue 'provider'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchProviderValue)) {
                $searchWebProvider = [string]$searchProviderValue
            }

            $searchEndpointValue = & $getConfigValue $searchWebConfigValue 'endpoint'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchEndpointValue)) {
                $searchWebEndpoint = [string]$searchEndpointValue
            }

            $searchApiKeyEnvVarValue = & $getConfigValue $searchWebConfigValue 'apiKeyEnvVar'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchApiKeyEnvVarValue)) {
                $searchWebApiKeyEnvVar = [string]$searchApiKeyEnvVarValue
            }

            $searchCountryValue = & $getConfigValue $searchWebConfigValue 'country'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchCountryValue)) {
                $searchWebCountry = [string]$searchCountryValue
            }

            $searchLanguageValue = & $getConfigValue $searchWebConfigValue 'language'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchLanguageValue)) {
                $searchWebLanguage = [string]$searchLanguageValue
            }

            $searchSafeSearchValue = & $getConfigValue $searchWebConfigValue 'safeSearch'
            if (-not [string]::IsNullOrWhiteSpace([string]$searchSafeSearchValue)) {
                $searchWebSafeSearch = [string]$searchSafeSearchValue
            }

            $searchDefaultCountValue = & $getConfigValue $searchWebConfigValue 'defaultCount'
            if ($null -ne $searchDefaultCountValue) {
                [int]$parsedSearchCount = 0
                if ([int]::TryParse([string]$searchDefaultCountValue, [ref]$parsedSearchCount)) {
                    $searchWebDefaultCount = $parsedSearchCount
                }
            }
        }

        $resolvedSearchWebApiKey = $null
        if (-not [string]::IsNullOrWhiteSpace($searchWebApiKeyEnvVar)) {
            $searchWebApiKeyResolution = & $resolveStoredAgentSecret -configObject $cfg -secretKeyName 'searchWebApiKeyEncrypted' -envVarName $searchWebApiKeyEnvVar
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
Add-Type -Path $env:TT_AGENT_ASSEMBLY_PATH -ErrorAction Stop
$result = [TechToolbox.Agent.Agent.AgentCore]::RunAgent(
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
    [string[]]$request.AllowedFetchHosts,
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
    [int]$request.PromptPreflightCriticalCount)
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

            # Read stderr asynchronously (non-blocking)
            $stderrTask = $agentProc.StandardError.ReadToEndAsync()

            # Create output accumulator
            $stdoutLines = [System.Collections.Generic.List[string]]::new()
            $stdoutReader = $agentProc.StandardOutput

            # Define the poll script that drives Wait-TerminalState
            $pollScript = {
                # Read any available lines from the process
                if ($agentProc.HasExited) {
                    $agentState['processExited'] = $true
                    $agentState['exitCode'] = $agentProc.ExitCode
                    return $agentState
                }

                # Non-blocking read of next line (returns $null if none available immediately)
                if ($stdoutReader.Peek() -gt 0) {
                    $line = $stdoutReader.ReadLine()
                    if ($line -ne $null) {
                        $stdoutLines.Add($line)
                        & $parseAgentTraceLine -TraceLine $line -AgentState $agentState
                    }
                }

                return $agentState
            }

            # Define status extraction from agent state
            $getStatus = {
                param($state)

                if ($state['processExited']) {
                    if ($state['exitCode'] -eq 0) {
                        return 'AGENT_COMPLETED'
                    }
                    else {
                        return 'AGENT_FAILED'
                    }
                }

                # Build status string for polling display
                $status = "Iteration {0}/{1}" -f $state['currentIteration'], $state['totalIterations']
                if ($state['lastToolName']) {
                    $status += " | Tool: {0}" -f $state['lastToolName']
                }
                if ($state['foundValidDecision']) {
                    $status += " | Early stop"
                }
                return $status
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

            # Use Wait-TerminalState to drive the polling loop if available, otherwise fall back to simple blocking read
            if ($hasWaitTerminalState) {
                try {
                    $waitResult = Wait-TerminalState `
                        -Target 'TechToolbox.Agent' `
                        -PollScript $pollScript `
                        -GetStatus $getStatus `
                        -TerminalStates $terminalStates `
                        -TimeoutSeconds $waitTimeoutSeconds `
                        -PollSeconds 1 `
                        -TickMs 250 `
                        -HeartbeatSeconds 5 `
                        -ThrowOnTimeout:$true
                }
                catch {
                    $hasWaitTerminalState = $false

                    # Fall through to the fallback code below
                }
            }

            if (-not $hasWaitTerminalState) {
                # Fallback: simple blocking read without animation
                Write-Log -Level E-Info -Message "`nAgent is running...`n"

                try {
                    while ($true) {
                        if ($agentProc.HasExited) {
                            break
                        }

                        if ($stdoutReader.Peek() -gt 0) {
                            $line = $stdoutReader.ReadLine()
                            if ($line -ne $null) {
                                $stdoutLines.Add($line)
                                & $parseAgentTraceLine -TraceLine $line -AgentState $agentState
                            }
                        }
                        else {
                            Start-Sleep -Milliseconds 100
                        }
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

            # Drain any stdout lines still buffered after process exit.
            # Without this, fast-exiting runs can lose tail lines and appear truncated.
            if ($stdoutReader) {
                try {
                    while (-not $stdoutReader.EndOfStream) {
                        $line = $stdoutReader.ReadLine()
                        if ($line -ne $null) {
                            $stdoutLines.Add($line)
                            & $parseAgentTraceLine -TraceLine $line -AgentState $agentState
                        }
                    }
                }
                catch {
                    Write-Log -Level Warn -Message ("Error draining agent stdout: {0}" -f $_.Exception.Message)
                }
            }

            $capturedStdOut = $stdoutLines -join [Environment]::NewLine
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
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = 'Tech agent completed successfully with no output.'
        }

        $postflightAssessment = & $evaluatePostflightGoal -PromptText $Prompt -ResponseText $message -PreflightScore $preflightScore
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

        $expectedOutputExists = $false
        if (-not [string]::IsNullOrWhiteSpace($expectedOutputPath)) {
            $expectedOutputExists = Test-Path -LiteralPath $expectedOutputPath -PathType Leaf
            if (-not $expectedOutputExists) {
                throw ("Tech agent failed: expected output file was not created: {0}" -f $expectedOutputPath)
            }
        }

        if ($knownFailureDetected) {
            if ($expectedOutputExists) {
                Write-Log -Level Warn -Message (
                    "Tech agent reported orchestrator failure text, but expected output file exists. Treating run as success. Message: {0}" -f $message
                )
            }
            else {
                throw ("Tech agent failed: {0}" -f $message)
            }
        }

        $markdownStatus = 'Success'

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
                $exitCode = if ($markdownStatus -eq 'Success') { 0 } else { -1 }
                & $writeMarkdownLog `
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
                    -StdOut $capturedStdOut `
                    -StdErr $capturedStdErr `
                    -ErrorText $markdownError `
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBv+dZ8DoCC9WNN
# wnwFGp5FLQCEB6ZoUfXVlQd480UcMqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBtkd0ssk2K
# D1jRSIFx9QeCFiJeDq4Ir/RSbjtdUnC45zANBgkqhkiG9w0BAQEFAASCAgB8bLIA
# braWlDvEiuZJpqwZLtK1oSrGzH1QGQr3cJtPqd7U0JQOAu7UwCgKZhPW3QySJM4p
# qE/nF934xbdj2D8sS4WbIpmYD5OJWyy6OmeClxMfg0obXDyDFu29R6JzNkKcsV2e
# JD2uBZ9ebdSa+kIiTqTNkoKMaKi8VIPy3S2e2Qu20vrY3lAKJweEuM4MLC0jZBwx
# VhpDcv/rWhHiVkR1BMSTsKMFqpzc95OXvcV1JI328Lb+0ejk4JhdI6HugxmXYutg
# tdCq2r1dwfUHF73RrkO/aaM++g2fTcE0x5BBj2YEJ9y3cf4Ys4IE2Pvs/FropfF3
# ersarVPswbB5z2KluokbLsFrdCQt7kjJzrZApbmM8PTPP4wH8UZJvQGyrEtxfcz1
# uIEdhIOm83c5gxHU/jw7dMRI9OJJHM8PZG4EQ7xRUV7b898MxxeMyhk8nWzUYFAW
# KHLntSEkBBilEkmnpGv91MwUeQUlp95uewCMKsH9ZK0sYqreC8/jv9Tw5TkVEMBV
# jOzG19LDWxu9xqroHxVcQdXGHRPjfXZnW/MuNiTW3nZfGecRKzBNRkMnmwy6lhQg
# CZzx0XYcRESpJ3jl2dG5CXtwf/Y64Kku0GbqkfQcBDSmt5xXhQDbp+mMvatRmn2h
# kbmxn856cJdPeuAirPEQtGetGp2XmRF1GQ18cqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA4MTcyMDI2MDNaMC8GCSqGSIb3DQEJBDEiBCDVdJnHbnRBLdVO8ux0
# SitH02Ot/KfaJOGv9yLS868vYTANBgkqhkiG9w0BAQEFAASCAgDPpA2tJDrbXrvH
# jwfPF4SIgiT/uT5ulIE9+deOz+PSibNrAgxgwaFBDOJaMkXnpMmszCpYJDaqAD6j
# WJ861T/5K/zfhRpGrZJsIaAfxEeoRrWIAbMJKP2HUOnNKfwmDjejfknmyhXlXhY5
# e95wmy9eQR2nc61t/In9d6v/sPrl+S5vs61yrhb86RXaibc+92MTf36UO1zZ9rvF
# hYa/Am+QmF85tXw2r9iTbr6f/almzYgH2kPxbDK9HyzAUhL+wiNSrvS1ud0aGjw8
# pYSsK73DCtj3M4R8fe2WiLj9RGfTSMc2JgYEg3OSzIusJlHEwFKMvJAGj7TmBclb
# JXxEX5lOsiLyAesp79tH6K3pP0aDcMJFOAnkuQ00UMwTRUTkk6srIovTlZbtN8pY
# F4BcuJnrCQLBZVpGa/XlpaPCCQD6Nd3H7Qqflyv8+XDGvxhw87O5SukFYM3+VcXU
# tfG++QNzwqmZBhzP6YH2Lp3McBtMcGKPmdwDacu+5SIqCk5r9ktxOeUPeA+mMX0i
# AsfwZvdSI2un6Q+HJYgvdBGTnDFVDphQhqNBI1F+ZcPLvxQNsBXk90TD6TgqfPRW
# taDjcYiUAPl8A6UN2ZSIWaMhcUsXtgcZoEqPxBERyrynAoDCAY0cBadqBVbrNluO
# CpUYiYLyGggZ8AoTHwt44dpYUQFRQw==
# SIG # End signature block
