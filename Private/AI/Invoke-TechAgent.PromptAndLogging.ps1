function Resolve-TTAgentExecutionMode {
    [CmdletBinding()]
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

function Resolve-TTAgentOutputContract {
    [CmdletBinding()]
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

function Remove-TTAgentDuplicateMarkdownHeadings {
    [CmdletBinding()]
    param(
        [string]$Markdown,
        [int]$WindowLines = 40
    )

    if ([string]::IsNullOrWhiteSpace($Markdown)) {
        return $Markdown
    }

    if ($WindowLines -lt 1) {
        $WindowLines = 1
    }

    $normalized = ($Markdown -replace "`r`n", "`n") -replace "`r", "`n"
    $lines = $normalized.Split("`n")
    $headingPattern = '^\s*(#{1,6})\s+(.+?)\s*$'
    $lastSeenByHeading = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $keptLines = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = [string]$lines[$i]
        $match = [regex]::Match($line, $headingPattern)
        if (-not $match.Success) {
            $keptLines.Add($line)
            continue
        }

        $level = $match.Groups[1].Value.Length
        $headingText = $match.Groups[2].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($headingText)) {
            $keptLines.Add($line)
            continue
        }

        $key = ('{0}|{1}' -f $level, $headingText)
        [int]$lastSeenLine = 0
        if ($lastSeenByHeading.TryGetValue($key, [ref]$lastSeenLine)) {
            if (($i - $lastSeenLine) -le $WindowLines) {
                $lastSeenByHeading[$key] = $i
                continue
            }
        }

        $lastSeenByHeading[$key] = $i
        $keptLines.Add($line)
    }

    return ($keptLines -join "`n").TrimEnd()
}

function Resolve-TTAgentQualityProfile {
    [CmdletBinding()]
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

function Invoke-TTAgentPromptPreflight {
    [CmdletBinding()]
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
        '(?i)\b(create|write|update|edit|modify|fix|analy[sz]e|review|refactor|investigate|summari[sz]e|plan|implement|find|fetch|get|retrieve|collect|report|check|show|tell|lookup|look\s+up|disable|enable|reset|remove|delete|provision|deprovision|offboard)\b')
    if ($hasTaskVerb) { $score += 20 } else { $warnings.Add('Missing clear task verb (for example: update, analyze, fix, plan).') }

    $hasPathOrSystemTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)([A-Za-z]:\\[^\r\n]+|\b(file|function|class|module|script|command|service|endpoint|api|workflow|active\s*directory|ad\b|account|user|computer|group|ou|organizational\s+unit|exchange\s*online|entra|azure\s*ad)\b)')

    $hasWebTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)(https?://\S+|\b(url|uri|website|web\s*site|webpage|site|domain|host|weather\.gov)\b)')

    $isWeatherIntent = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(weather|forecast|temperature|precipitation|wind|noaa)\b')

    $hasWeatherLocationTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)((?<!\d)\d{5}(?:-\d{4})?(?!\d)|\b[A-Za-z][A-Za-z\-''\.\s]+,\s*[A-Za-z][A-Za-z\-''\.\s]+\b)')

    $hasWeatherLocationPhrase = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(?:for|in|at|near)\s+[A-Za-z][A-Za-z0-9''.,/-]*(?:\s+[A-Za-z0-9''.,/-]+){0,6}(?=\s+(?:from|on|using|with|and|return|output|show|summari[sz]e|today|tomorrow|next|this|tonight|weekend)\b|[.?!]|$)')

    $hasConcreteTarget = $hasPathOrSystemTarget -or $hasWebTarget -or ($isWeatherIntent -and ($hasWeatherLocationTarget -or $hasWeatherLocationPhrase))
    if ($hasConcreteTarget) { $score += 20 } else { $warnings.Add('Missing concrete target (file, function, module, system, URL, website, or path).') }

    $hasExpectedOutcome = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(expected|outcome|output|result|return|produce|final|success\b|done\b)')
    if ($hasExpectedOutcome) { $score += 20 } else { $warnings.Add('Missing expected outcome details (what successful output should look like).') }

    $hasConstraints = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(must|should|do not|don''t|avoid|constraint|format|style|security|strict|exact path|preserve|no edits|markdown|plain[ -]?text|json|yaml|csv|console|terminal|brief|concise|detailed)\b')
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

function New-TTAgentAutoPromptHint {
    [CmdletBinding()]
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
        "the weather forecast for $locationName using the official NOAA API (api.weather.gov)"
    }
    elseif ([regex]::IsMatch($normalized, '(?i)\bweather\b')) {
        'the weather forecast for the specified location using the official NOAA API (api.weather.gov)'
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

function Test-TTAgentPostflightGoal {
    [CmdletBinding()]
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

    $hasCompletionSignal = (
        [regex]::IsMatch($responseLower, '(?im)^\s*##\s*result\b') -or
        [regex]::IsMatch($responseLower, '(?im)^\s*(created|updated|wrote)\s+file\s*:') -or
        [regex]::IsMatch($responseLower, '(?is)```(?:powershell|pwsh)?\s*.+?```') -or
        $responseLower.Contains('script contents') -or
        $responseLower.Contains('successfully')
    )

    $hasUncertaintySignal = [regex]::IsMatch(
        $responseLower,
        '(?i)(\bi need more (?:detail|information)\b|\bclarification needed\b|\bnot enough information\b|\bi (?:am|''m) unable to\b|\bi could not\b|\bi cannot\b|\bi can''t\b|\bplease provide\b|\brequire (?:more|additional) (?:details|information)\b)'
    )

    if ($hasUncertaintySignal -and -not $hasCompletionSignal) {
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

    $isPowerShellScriptPrompt = (
        ($promptLower.Contains('powershell') -or $promptLower.Contains('.ps1')) -and
        $promptLower.Contains('script')
    )

    if ($isPowerShellScriptPrompt) {
        $responseFenceCount = [regex]::Matches($ResponseText, '```').Count
        if (($responseFenceCount % 2) -ne 0) {
            return @{ Achieved = $false; Reason = 'The response appears to contain an unclosed markdown code fence.' }
        }

        $codeBlockMatch = [regex]::Match($ResponseText, '(?is)```(?:powershell|pwsh)?\s*(?<code>.*?)```')
        $candidateCode = if ($codeBlockMatch.Success) {
            $codeBlockMatch.Groups['code'].Value
        }
        else {
            $ResponseText
        }

        if (($promptLower.Contains('stand alone') -or $promptLower.Contains('standalone') -or $promptLower.Contains('no external helper')) -and
            $candidateCode -match '(?im)^\s*write-comment\b') {
            return @{ Achieved = $false; Reason = 'The script references external helper commands (Write-Comment), which violates standalone/no-helper intent.' }
        }

        if ($promptLower.Contains('syntactically correct')) {
            $openBraceCount = [regex]::Matches($candidateCode, '\{').Count
            $closeBraceCount = [regex]::Matches($candidateCode, '\}').Count
            if ($openBraceCount -ne $closeBraceCount) {
                return @{ Achieved = $false; Reason = 'The script output appears structurally incomplete (mismatched braces).' }
            }

            $openParenCount = [regex]::Matches($candidateCode, '\(').Count
            $closeParenCount = [regex]::Matches($candidateCode, '\)').Count
            if ($openParenCount -ne $closeParenCount) {
                return @{ Achieved = $false; Reason = 'The script output appears structurally incomplete (mismatched parentheses).' }
            }
        }
    }

    return @{ Achieved = $true; Reason = '' }
}

function Expand-TTAgentOptionZipFollowUpPrompt {
    [CmdletBinding()]
    param(
        [string]$PromptText,
        [string]$Mode
    )

    if ([string]::IsNullOrWhiteSpace($PromptText)) {
        return $PromptText
    }

    if ($Mode -ne 'execute') {
        return $PromptText
    }

    $trimmed = $PromptText.Trim()
    $zipOnlyMatch = [regex]::Match(
        $trimmed,
        '(?i)^(?:option\s*)?b\s*[:\-]?\s*(?<zip>\d{5}(?:-\d{4})?)\s*$'
    )

    if (-not $zipOnlyMatch.Success) {
        return $PromptText
    }

    $zip = $zipOnlyMatch.Groups['zip'].Value
    return (
        "Continue the pending weather forecast task using alternate location ZIP code $zip. " +
        "Call GET-NOAA-FORECAST with zipCode='$zip' and include Friday through Sunday night periods. " +
        'Return the final answer in markdown. Constraints: execute only bounded steps and avoid unrelated changes.'
    )
}

function Resolve-TTAgentExpectedOutputPath {
    [CmdletBinding()]
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

                if ($candidate.EndsWith('\\', [System.StringComparison]::Ordinal)) {
                    continue
                }

                return $candidate
            }
        }
    }

    $fileNameMatch = [regex]::Match(
        $PromptText,
        '(?is)\b(?:name\s+(?:it|the\s+file|the\s+script\s+file|script\s+file)|file\s+should\s+be\s+named|named)\s+["'']?(?<name>[^\s"''`\\/:*?<>|]+?\.[A-Za-z0-9]{1,16})\b')

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

function Write-TTAgentMarkdownLog {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Status,
        [string]$PromptText,
        [string]$ModelName,
        [int]$IterationLimit,
        [bool]$DestructiveAuthorized,
        [string]$SignedFilePolicyValue,
        [string]$AutoRetryOnRecursionMode,
        [string]$ExecutionMode,
        [string]$OutputContract,
        [string]$QualityProfile,
        [string]$PromptSource,
        [int]$PreflightScore,
        [string[]]$PreflightWarnings,
        [string[]]$PreflightCritical,
        [string]$PromptPreflightSummary,
        [string]$ReasoningEffortSettings,
        [string]$RuntimeAssemblyPath,
        [string]$AdaptiveLimitsPreflight,
        [string]$ExpectedOutputPath,
        [string]$StdOut,
        [string]$StdErr,
        [string]$ErrorText,
        [string]$RecoveryReason,
        [bool]$PostflightAchieved,
        [string]$PostflightReason,
        [int]$ResponseLength,
        [bool]$KnownFailureDetected,
        [bool]$ExpectedOutputExists,
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

    $rawRecoveryReason = if ([string]::IsNullOrWhiteSpace($RecoveryReason)) {
        '(none)'
    }
    else {
        $RecoveryReason.TrimEnd()
    }

    $rawPostflightReason = if ([string]::IsNullOrWhiteSpace($PostflightReason)) {
        '(none)'
    }
    else {
        $PostflightReason.TrimEnd()
    }

    $preflightWarnings = @($PreflightWarnings)
    $preflightCritical = @($PreflightCritical)
    $preflightWarningsText = if ($preflightWarnings.Count -gt 0) {
        ($preflightWarnings -join [Environment]::NewLine)
    }
    else {
        '(none)'
    }

    $preflightCriticalText = if ($preflightCritical.Count -gt 0) {
        ($preflightCritical -join [Environment]::NewLine)
    }
    else {
        '(none)'
    }

    $expectedOutputPathText = if ([string]::IsNullOrWhiteSpace($ExpectedOutputPath)) {
        '(none)'
    }
    else {
        $ExpectedOutputPath
    }

    $adaptiveLimitsPreflightText = if ([string]::IsNullOrWhiteSpace($AdaptiveLimitsPreflight)) {
        '(none)'
    }
    else {
        $AdaptiveLimitsPreflight.TrimEnd()
    }

    $promptPreflightSummaryText = if ([string]::IsNullOrWhiteSpace($PromptPreflightSummary)) {
        '(none)'
    }
    else {
        $PromptPreflightSummary.TrimEnd()
    }

    $reasoningEffortSettingsText = if ([string]::IsNullOrWhiteSpace($ReasoningEffortSettings)) {
        '(none)'
    }
    else {
        $ReasoningEffortSettings.TrimEnd()
    }

    $runtimeAssemblyPathText = if ([string]::IsNullOrWhiteSpace($RuntimeAssemblyPath)) {
        '(none)'
    }
    else {
        $RuntimeAssemblyPath.TrimEnd()
    }

    $postflightStatus = if ($PostflightAchieved) { 'Achieved' } else { 'NotAchieved' }
    $expectedOutputExistsText = if ([string]::IsNullOrWhiteSpace($ExpectedOutputPath)) {
        '(n/a)'
    }
    else {
        [string]$ExpectedOutputExists
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
        '## Preflight'
        ''
        '~~~~text'
        ('Mode: {0}' -f $ExecutionMode)
        ('OutputContract: {0}' -f $OutputContract)
        ('QualityProfile: {0}' -f $QualityProfile)
        ('PromptSource: {0}' -f $PromptSource)
        ('Score: {0}/100' -f $PreflightScore)
        ('PromptPreflightSummary: {0}' -f $promptPreflightSummaryText)
        ('ReasoningEffortSettings: {0}' -f $reasoningEffortSettingsText)
        ('RuntimeAssemblyPath: {0}' -f $runtimeAssemblyPathText)
        ('WarningsCount: {0}' -f $preflightWarnings.Count)
        'Warnings:'
        $preflightWarningsText
        ('CriticalCount: {0}' -f $preflightCritical.Count)
        'Critical:'
        $preflightCriticalText
        'AdaptiveLimits:'
        $adaptiveLimitsPreflightText
        ('ExpectedOutputPath: {0}' -f $expectedOutputPathText)
        '~~~~'
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
        ''
        '## Postflight'
        ''
        '~~~~text'
        ('Status: {0}' -f $postflightStatus)
        ('ResponseLengthChars: {0}' -f $ResponseLength)
        ('KnownFailurePrefixDetected: {0}' -f $KnownFailureDetected)
        ('ExpectedOutputExists: {0}' -f $expectedOutputExistsText)
        'Reason:'
        $rawPostflightReason
        '~~~~'
        ''
        '## Recovery'
        ''
        '~~~~text'
        $rawRecoveryReason
        '~~~~'
    )

    Set-Content -Path $Path -Value ($lines -join [Environment]::NewLine) -Encoding utf8BOM
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDZyrj6em/MjzVU
# w5KRlDph5xviSvT1VyYh2TkILHq2UqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBGl7PCimJ/
# 8S5tDoWgrai0e5lZVKvdaGpDS2beNFFroDANBgkqhkiG9w0BAQEFAASCAgBbWuLF
# U0mET6tRpoRQTCh3MfrY+4NHPzKy1pefeJU/DCmF0ZaWy6K+SIEmttXDGn/bqd0s
# u8zR8Hn1+4FyEA54utXCEB0oVV1H0r3w+gD7pAFkYxgRWIGs7DFJfiQ/RLS0PmWC
# 6gr42GNM0EOXSs+QBofBvTkblADxzJ0nd6Tr69+AQMkjZUCisfGWUaEfKDlijrnv
# ZxS2ZDRlwEBvJFi84fp3TYN8gQ6aNmCcFXTCiFzicK2JdJFpsXyP+Hyo8Vi9A9Rr
# KyNZNx/784EdlQ2XJSPuKNRXEQtSeOOPK+1psC1TkhpsHwCIaJie3nlwAzIqEZDp
# w1rPuRQ7DOkrwaD46q4Ewd1N8dUh5jVCrdaGzSJnzpGoCeoGAiFd51YKIlprVLMb
# L4q5XwZAYLx8cdQkjjBmD4hdvpDwiUwYJLYi6vIT7O28ukFL+SM21UcLDtkXA86k
# ouOT+88fsiq9RJ72VFAPBu7VL8EDOrOgndFgLPJg3XEK+52g0OCJGIlWBwbAKZuY
# foAwP/dFF9sRf2zXZPr6fPfhUqq5c7as8eJnUM0HzXvAecFVa92BmB2/oYN95bUc
# V5fcpiaJL9GFKpGC6OlPQ3FkiZ45ryib8/Hhmu0N6oFYWXUIFdl496RZGB4+onRf
# HAWkqP3O07md025orD6LdQHVcK+bTVirS1UC6qGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MDkyMzIwMzNaMC8GCSqGSIb3DQEJBDEiBCA/oeqkjG7L8O/1gZOm
# r2FbS40HeFvJPElxQcVTdI+0yDANBgkqhkiG9w0BAQEFAASCAgA3NFWTf1T7AYaJ
# ABm9fi5vHVwyftFj85HdMTH4vmp20l3dAKgpCqostiGWNNrUyvMddxBXDtoZF+fQ
# 1p138cEU+8hzkoQrYmowIkw06yVCGLFmrGMB9tQfOZvKZiRtD+s178X57Q/Q8Qtd
# 1WDapA4oo09JoTwZiCAPOataoYica1nX0aqQIkLa6tds64eVKBAXc0ZXs86qU/ak
# hOlZqmk1RhJaFTVL/4U2nKz8AZySTjitupeyaV9U5oVKB2hhzT6V0rG3GErUSiwC
# XbWO7nhjLqT2HWka4zF2/Zzyp68cEEHbXq2nwNRmsyCmaZWJyZ/lGhGgoI72cEP8
# v+SfAtDgClmU4x4e/06svP6xTHa3gzUU4sUECSCl+fvnU/tj9EXfpwJwgsO2rF7T
# 2Es0oHDhfgwIQxg2IW7Zl5rvE+jpKCOJ49zAaTWAsG+MO7X6NZhhX8SCFeVvVlMa
# COEsK++uSrm7tp4IdnNR9uhSXeAZ+2LZDZ949MAGluR497kxIzNiw+SJbO2ISDoX
# UcWj4BorPr4jrpz+zWBIMau8BwvGI1BF3bcXkpW4pioRu0XEckDoPkZboK69p8tE
# RucKC3IHAyyXJNrqrH/uAThgf+/oKmcqX0TNh8IxW/gM+RAhAYT/LSdlAm4F5WNU
# Jqse5p21Y/I2Lb7j2esMiK1W+gPDSw==
# SIG # End signature block
