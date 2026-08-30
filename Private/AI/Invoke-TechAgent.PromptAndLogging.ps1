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
        '(?i)\b(create|write|update|edit|modify|fix|analy[sz]e|review|refactor|investigate|summari[sz]e|plan|implement|find|fetch|get|retrieve|collect|report|disable|enable|reset|remove|delete|provision|deprovision|offboard)\b')
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

    $hasConcreteTarget = $hasPathOrSystemTarget -or $hasWebTarget -or ($isWeatherIntent -and $hasWeatherLocationTarget)
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
        ('WarningsCount: {0}' -f $preflightWarnings.Count)
        'Warnings:'
        $preflightWarningsText
        ('CriticalCount: {0}' -f $preflightCritical.Count)
        'Critical:'
        $preflightCriticalText
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC1wp7PxLgt3o0D
# keZWPLtoy3gCTsNOpe2feqa3fzsH6qCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCFBtx6Pcng
# szxofkY8CPS53Pv/JNVjNjjnKMq2dlAXkTANBgkqhkiG9w0BAQEFAASCAgBTbvtw
# w8Q8A1cJE5LZ7d96uYlbmY9gFByd4b/lLDZLucQa4uKSJZZ2tTkOV4DpBOHB01UM
# b64K24FUalo2f/W3qHJJQ1u/FGzo8EWqwDWrT7iWaOn7+13ezHWM6Mn8F9GgAsxh
# 0m6K7nB8pEOZJfOmbRrdUpr6SaRNguuXG24nJsT8453qgdUUUlax+n8UnVKhL5UE
# rgr/opS9LnCjxDxbExAwYVJhaWbLMtipxZTUbUtDXpm1/yd5vES2HoMUQVXoMSZE
# RS7VLib6NkIpLSnBiR5kU5uKlObKuSHnh7tmGpyl4qgxbm5KKqNOV3zAUTyJONf0
# QQqn0wlIlpNrDgBQwl5WDd+DrtD4bCjF+H7VTcc2JI1siucbZ4pcGGMyEuleYQbX
# mdIH9hUEftMMH+aOBijDoQKB/4VFhxzzbOSxKQ1Hi8T0W1NTiAG93N6E19yEuztD
# SIhw8KKRSdl1stB2H16P/yUaZpmsLsl+e+lJih/zASlqNP8BcneqTHr+Rt/IYQY/
# zPsRhmuEVQf90d4AsDA3e+D3D8giSAmEhK4JaOMYPOwY1lY6E8659WNb1TPTY6wo
# /FDInURFTrampo+wAcUUp4oYJoAPC18bKiZtXK2O4LGHfDBS2223ygkWbSOgCF1K
# HQuNK67ev/2yeExO30n6jUffxnRTFpA+W5OVcKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA4MzAwMTIyMDhaMC8GCSqGSIb3DQEJBDEiBCBqg6kaltJZ3qHOKu8p
# ni5Wo5OaiN5jbKQVVeSCeDDP9zANBgkqhkiG9w0BAQEFAASCAgB5jEFRuVMGWlOl
# ibYu2r9kamlPB66tN8HxGDBZKv/a2+UY56WZ+sGBtUHjSnfVx4j1x2PmIyclZbYy
# b1hoGq75cEUm/ZzimiGZeFJ20pYUKIIF7Gu3HYWu2yIa8zl7r3Ax/1aNzBLEZIV5
# JcAohMgKkeDFzgmIk34JXoIlRrPjdF2Cd0lQ3uCFSL3XDkEsGqUZfDwAwzMpvc0H
# QCK0baYdYH/xXoniE9oai9wsunU7qpErDDI0M85lTpaACUKTU8RWZIpNUf2eac55
# sYaWs8l2VYGEvytQz4O7ygrSWD3ZKf37HDET4/EWybz5gEaMq9FvMtQJNSwji6Wb
# E9cT7IgeceXWE/XCj1CsM7hvUSau62wztR9usFYJnxWXeynomSIe9E9smPTzIAG1
# BM9nCBXTcEfNYHwZS7SFj/6kREVuhPZ/7HSFjkAGlLel4eLf+3fRo8ct6T9fTeoT
# ew3YgfBLp29Z4L3BztC8livsESLGQ17EXkXlrOaU5pNRPck9RBjrgH9jkAFojWDP
# JOK31FbGwXK44zPO48DjupsvvkLyUha+THCHmQLnu2mBGqmLN9oBkkaQCqZL0Iam
# OZ0dTwg4fu4WQesOtlvaA34AXKrLnTC86a21LYfrU+mWZJr0sQtfZv9u778g74vK
# o79JXx2tpHoeQNAfWVt/LJF/8narrg==
# SIG # End signature block
