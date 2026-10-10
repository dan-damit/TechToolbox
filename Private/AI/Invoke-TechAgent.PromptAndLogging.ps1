function Resolve-TTAgentExecutionMode {
    [CmdletBinding()]
    param(
        [string]$ModeFromParam,
        $ConfigObject,
        [bool]$ParamWasBound
    )

    if ($ParamWasBound -and -not [string]::IsNullOrWhiteSpace($ModeFromParam)) {
        $normalizedMode = $ModeFromParam.Trim().ToLowerInvariant()
        if ($normalizedMode -eq 'chat') {
            Write-Warning "`nInvoke-TechAgent: Execution mode 'chat' is deprecated and maps to 'analyze'."
            return 'analyze'
        }

        return $normalizedMode
    }

    $configMode = $null
    if ($null -ne $ConfigObject) {
        $modeProperty = $ConfigObject.PSObject.Properties['executionMode']
        if ($null -ne $modeProperty -and -not [string]::IsNullOrWhiteSpace([string]$modeProperty.Value)) {
            $configMode = [string]$modeProperty.Value
        }
    }

    if ([string]::IsNullOrWhiteSpace($configMode)) {
        return 'execute'
    }

    switch ($configMode.Trim().ToLowerInvariant()) {
        'execute' { return 'execute' }
        'plan' { return 'plan' }
        'analyze' { return 'analyze' }
        'chat' {
            Write-Warning "`nInvoke-TechAgent: Config executionMode 'chat' is deprecated and maps to 'analyze'."
            return 'analyze'
        }
        default { return 'execute' }
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

function Remove-TTAgentAdjacentDuplicateLines {
    [CmdletBinding()]
    param(
        [string]$Text,
        [int]$MinimumLineLength = 24
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    if ($MinimumLineLength -lt 1) {
        $MinimumLineLength = 1
    }

    $normalized = ($Text -replace "`r`n", "`n") -replace "`r", "`n"
    $lines = $normalized.Split("`n")
    $keptLines = [System.Collections.Generic.List[string]]::new()
    $previousComparable = $null

    foreach ($line in $lines) {
        $comparable = [string]$line
        if ($null -ne $comparable) {
            $comparable = $comparable.Trim()
        }

        $isDuplicate = $false
        if (-not [string]::IsNullOrWhiteSpace($comparable) -and $comparable.Length -ge $MinimumLineLength -and -not [string]::IsNullOrWhiteSpace($previousComparable)) {
            $isDuplicate = [string]::Equals($comparable, $previousComparable, [System.StringComparison]::Ordinal)
        }

        if (-not $isDuplicate) {
            $keptLines.Add([string]$line)
        }

        if ([string]::IsNullOrWhiteSpace($comparable)) {
            $previousComparable = $null
        }
        else {
            $previousComparable = $comparable
        }
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
        '(?i)\b(create|write|update|edit|modify|fix|analy[sz]e|review|refactor|investigate|research|summari[sz]e|plan|implement|find|fetch|get|retrieve|collect|report|check|show|tell|lookup|look\s+up|print|disable|enable|reset|remove|delete|provision|deprovision|offboard)\b')
    if ($hasTaskVerb) { $score += 20 } else { $warnings.Add('Missing clear task verb (for example: update, analyze, fix, plan).') }

    $hasMutationVerb = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(create|write|update|edit|modify|fix|disable|enable|reset|remove|delete|provision|deprovision|offboard|install|uninstall|rename|move|copy|save|upload|download|patch|apply)\b')

    $hasPathOrSystemTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)([A-Za-z]:\\[^\r\n]+|\b(file|function|class|module|script|command|service|endpoint|api|workflow|active\s*directory|ad\b|account|user|computer|group|ou|organizational\s+unit|exchange\s*online|entra|azure\s*ad)\b)')

    $hasWebTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)(https?://\S+|\b(url|uri|website|web\s*site|webpage|site|domain|host|weather\.gov)\b)')

    $hasReadOnlyResearchIntent = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(research|lookup|look\s+up|search|find|fetch|get|retrieve|check|review|inspect|summari[sz]e|report|show|tell|collect)\b')

    $hasReadOnlyResearchTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(official|schedule|roster|player|team|standing|game|event|news|forecast|weather|report|status|service|document|site|website|webpage|conference|calendar|season)\b')

    $isWeatherIntent = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(weather|forecast|temperature|precipitation|wind|noaa)\b')

    $hasWeatherLocationTarget = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)((?<!\d)\d{5}(?:-\d{4})?(?!\d)|\b[A-Za-z][A-Za-z\-''\.\s]+,\s*[A-Za-z][A-Za-z\-''\.\s]+\b)')

    $hasWeatherLocationPhrase = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(?:for|in|at|near)\s+[A-Za-z][A-Za-z0-9''.,/-]*(?:\s+[A-Za-z0-9''.,/-]+){0,6}(?=\s+(?:from|on|using|with|and|return|output|show|summari[sz]e|today|tomorrow|next|this|tonight|weekend)\b|[.?!]|$)')

    $hasReadOnlyResearchTargetPhrase = $hasReadOnlyResearchIntent -and $hasReadOnlyResearchTarget -and -not $hasMutationVerb
    $hasConcreteTarget = $hasPathOrSystemTarget -or $hasWebTarget -or $hasReadOnlyResearchTargetPhrase -or ($isWeatherIntent -and ($hasWeatherLocationTarget -or $hasWeatherLocationPhrase))
    if ($hasConcreteTarget) { $score += 20 } else { $warnings.Add('Missing concrete target (file, function, module, system, URL, website, or path).') }

    $hasExpectedOutcome = [regex]::IsMatch(
        $normalizedPrompt,
        '(?i)\b(expected|outcome|output|result|return|produce|final|success\b|done\b|summary|print|display|console|markdown|output\s+to\s+console)')
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

    $normalizeWildcardDirectoryPath = {
        param([string]$CandidatePath)

        if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
            return $null
        }

        $match = [regex]::Match(
            $CandidatePath,
            '(?is)^(?<dir>[A-Za-z]:\\.*?)(?:\\|/)?\*(?:\\|/)?(?<name>[^\\/:*?<>|]+?\.[A-Za-z0-9]{1,16})$')

        if (-not $match.Success) {
            return $null
        }

        $targetDirectory = $match.Groups['dir'].Value.Trim().TrimEnd('\', '/')
        $fileName = $match.Groups['name'].Value.Trim().Trim('"', "'", '`')

        if ([string]::IsNullOrWhiteSpace($targetDirectory) -or [string]::IsNullOrWhiteSpace($fileName)) {
            return $null
        }

        return (Join-Path -Path $targetDirectory.TrimEnd('\', '/') -ChildPath $fileName)
    }

    $tryNormalizeDirectoryAndNamedFileInstruction = {
        param([string]$CandidatePath)

        if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
            return $null
        }

        $match = [regex]::Match(
            $CandidatePath,
            '(?is)^(?<dir>[A-Za-z]:\\[^\r\n]*?)\s+and\s+(?:name\s+(?:it|the\s+file|the\s+script\s+file|script\s+file)|call\s+(?:it|the\s+file|the\s+script\s+file|script\s+file)|file\s+should\s+be\s+named|named)\s+["'']?(?<name>[^\s"''`\\/:*?<>|]+?\.[A-Za-z0-9]{1,16})\b')

        if (-not $match.Success) {
            return $null
        }

        $targetDirectory = $match.Groups['dir'].Value.Trim().TrimEnd('.', ',', ';', ':', ')', ']', '}')
        $fileName = $match.Groups['name'].Value.Trim().Trim('"', "'").TrimEnd('.', ',', ';', ':', ')', ']', '}')

        if ([string]::IsNullOrWhiteSpace($targetDirectory) -or [string]::IsNullOrWhiteSpace($fileName)) {
            return $null
        }

        $normalizedDirectory = $targetDirectory.TrimEnd('\', '/')
        if ([string]::IsNullOrWhiteSpace($normalizedDirectory)) {
            return $null
        }

        return (Join-Path -Path $normalizedDirectory -ChildPath $fileName)
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

    # Prefer deterministic directory-plus-name parsing so sentence prose cannot be
    # swallowed into the directory token before a later filename extension.
    $directoryAndNamedFileMatch = [regex]::Match(
        $PromptText,
        '(?is)\b(?:output|save|write)\s+(?:the\s+)?(?:script|file|output)\s+to\s+(?<dir>[A-Za-z]:\\[^\r\n.?!]*?)(?:\.|\s+and\s+)(?:\s*)?(?:name\s+(?:the\s+)?(?:script|file)|the\s+(?:script|file)\s+is\s+named|named)\s+["''`]*(?<name>[^\s"''`\\/:*?<>|]+?\.[A-Za-z0-9]{1,16})\b'
    )

    if ($directoryAndNamedFileMatch.Success) {
        $directory = $directoryAndNamedFileMatch.Groups['dir'].Value.Trim().TrimEnd('.', ',', ';', ':', ')', ']', '}')
        $directory = $directory.TrimEnd('*')
        $name = $directoryAndNamedFileMatch.Groups['name'].Value.Trim().Trim('"', "'", '`').TrimEnd('.', ',', ';', ':', ')', ']', '}')
        if (-not [string]::IsNullOrWhiteSpace($directory) -and -not [string]::IsNullOrWhiteSpace($name)) {
            return (Join-Path -Path $directory.TrimEnd('\', '/') -ChildPath $name)
        }
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
            '(?i)(?<path>[A-Za-z]:\\[^"''`\r\n]*?\.[A-Za-z0-9]{1,16})(?=\s|$|[)\],;:.!?])')

        if ($genericPathMatches.Count -gt 0) {
            for ($i = $genericPathMatches.Count - 1; $i -ge 0; $i--) {
                $candidate = & $trimDetectedPath -CandidatePath $genericPathMatches[$i].Groups['path'].Value
                if ([string]::IsNullOrWhiteSpace($candidate)) {
                    continue
                }

                $normalizedNamedPath = & $tryNormalizeDirectoryAndNamedFileInstruction -CandidatePath $candidate
                if (-not [string]::IsNullOrWhiteSpace($normalizedNamedPath)) {
                    return $normalizedNamedPath
                }

                $normalizedWildcardPath = & $normalizeWildcardDirectoryPath -CandidatePath $candidate
                if (-not [string]::IsNullOrWhiteSpace($normalizedWildcardPath)) {
                    return $normalizedWildcardPath
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

        $candidatePath = $candidatePath.TrimEnd('\', '/')
        if ($candidatePath.EndsWith('*', [System.StringComparison]::Ordinal)) {
            $candidatePath = $candidatePath.TrimEnd('*')
        }

        $candidateDirs += $candidatePath.TrimEnd('\', '/')
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

    return (Join-Path -Path $targetDirectory.TrimEnd('\', '/') -ChildPath $fileName)
}

function Test-TTAgentExpectedOutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $trimmedPath = $Path.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmedPath)) {
        return [pscustomobject]@{
            Path = $Path
            IsValid = $false
            Error = 'Expected output path is empty.'
        }
    }

    if (-not (Test-Path -LiteralPath $trimmedPath -PathType Leaf)) {
        return [pscustomobject]@{
            Path = $trimmedPath
            IsValid = $false
            Error = 'Expected output file does not exist.'
        }
    }

    $extension = [System.IO.Path]::GetExtension($trimmedPath)
    $psExtensions = @('.ps1', '.psm1', '.psd1', '.ps1xml', '.pssc', '.psrc')
    if ($psExtensions -notcontains $extension.ToLowerInvariant()) {
        return [pscustomobject]@{
            Path = $trimmedPath
            IsValid = $true
            Error = $null
        }
    }

    try {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $trimmedPath,
            [ref]$tokens,
            [ref]$errors
        ) | Out-Null

        if ($null -ne $errors -and $errors.Count -gt 0) {
            $messages = @($errors | ForEach-Object { $_.Message })
            $combinedMessage = ($messages | Select-Object -Unique) -join '; '

            return [pscustomobject]@{
                Path = $trimmedPath
                IsValid = $false
                Error = $combinedMessage
            }
        }

        return [pscustomobject]@{
            Path = $trimmedPath
            IsValid = $true
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Path = $trimmedPath
            IsValid = $false
            Error = $_.Exception.Message
        }
    }
}

function Resolve-TTAgentRecoveredOutputMessage {
    [CmdletBinding()]
    param(
        [string]$KnownFailureMessage,
        [string]$ExpectedOutputPath
    )

    if ([string]::IsNullOrWhiteSpace($KnownFailureMessage)) {
        return $null
    }

    $message = $KnownFailureMessage.Trim()
    $invalidJsonEnvelopeMatch = [regex]::Match(
        $message,
        '(?is)^\s*Agent returned invalid JSON twice\.\s*Last response:\s*(?<json>\{.*\})\s*$')

    if ($invalidJsonEnvelopeMatch.Success) {
        $jsonCandidate = $invalidJsonEnvelopeMatch.Groups['json'].Value
        if (-not [string]::IsNullOrWhiteSpace($jsonCandidate)) {
            try {
                $decision = $jsonCandidate | ConvertFrom-Json -ErrorAction Stop
                $finalAnswer = [string]$decision.finalAnswer
                if (-not [string]::IsNullOrWhiteSpace($finalAnswer)) {
                    return $finalAnswer.Trim()
                }
            }
            catch {
                # Keep fallback behavior when the envelope cannot be parsed.
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExpectedOutputPath)) {
        return (
            "## Run Recovered`n`n" +
            "- Output file created successfully at $ExpectedOutputPath.`n" +
            "- The planner emitted recovery diagnostics during execution; see the Recovery section in the markdown log for details."
        )
    }

    return $null
}

function Convert-TTAgentToolTrace {
    [CmdletBinding()]
    param(
        [string[]]$ToolNames
    )

    $normalizedTools = @()
    foreach ($toolName in @($ToolNames)) {
        if ($null -eq $toolName) {
            continue
        }

        $value = [string]$toolName
        if ([string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $trimmed = $value.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $normalizedTools += $trimmed
    }

    if ($normalizedTools.Count -eq 0) {
        return @('No tool calls recorded.')
    }

    $formatted = [System.Collections.Generic.List[string]]::new()
    foreach ($tool in $normalizedTools) {
        $toolName = [string]$tool
        if ($toolName -match '^(?:mcp\.|MCP\.)') {
            $formatted.Add(('{0} [MCP]' -f $toolName))
            continue
        }

        switch ($toolName.ToUpperInvariant()) {
            'SEARCH-WEB' { $formatted.Add('SEARCH-WEB [Built-in web tool]'); continue }
            'FETCH-URL' { $formatted.Add('FETCH-URL [Built-in fetch tool]'); continue }
            'READ-FILE' { $formatted.Add('READ-FILE [Built-in file/system tool]'); continue }
            'WRITE-FILE' { $formatted.Add('WRITE-FILE [Built-in file/system tool]'); continue }
            'APPEND-FILE' { $formatted.Add('APPEND-FILE [Built-in file/system tool]'); continue }
            'REPLACE-IN-FILE' { $formatted.Add('REPLACE-IN-FILE [Built-in file/system tool]'); continue }
            'RUN-SHELL' { $formatted.Add('RUN-SHELL [Built-in shell tool]'); continue }
            default {
                if ($toolName -match '(?i)(?:^|\.)tavily\b|(?:^|\.)search\b') {
                    $formatted.Add(('{0} [MCP]' -f $toolName))
                }
                else {
                    $formatted.Add(('{0} [Unknown tool source]' -f $toolName))
                }
            }
        }
    }

    return @($formatted)
}

function Write-TTAgentMarkdownLog {
    [CmdletBinding()]
    param(
        [string]$Path,
        [string]$Status,
        [string]$PromptText,
        [string]$ModelName,
        [int]$IterationLimit,
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
        [string[]]$ToolTrace,
        [int]$ResponseLength,
        [bool]$KnownFailureDetected,
        [bool]$ExpectedOutputExists,
        [bool]$RagUsed,
        [string]$RagStatus,
        [string]$RagModelEffective,
        [string]$RagModelSource,
        [bool]$RagEnabledConfigured,
        [bool]$RagAttempted,
        [string]$RagProviderType,
        [string]$RagExecutionMode,
        [bool]$RagEnvironmentContextIncluded,
        [string]$RagEnvironmentContextProfile,
        [int]$RagSourcesScanned,
        [int]$RagCandidatesScored,
        [int]$RagCandidatesSelected,
        [int]$RagCandidatesPacked,
        [int]$RagContextCharacters,
        [string]$RagModelConfigured,
        [string]$RagStatusReason,
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

    $toolTraceText = if ($null -ne $ToolTrace -and $ToolTrace.Count -gt 0) {
        ($ToolTrace | ForEach-Object { $_.TrimEnd() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join [Environment]::NewLine
    }
    else {
        '(none)'
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
    $ragStatusText = if ([string]::IsNullOrWhiteSpace($RagStatus)) {
        'Unknown'
    }
    else {
        $RagStatus.TrimEnd()
    }
    $ragModelEffectiveText = if ([string]::IsNullOrWhiteSpace($RagModelEffective)) {
        '(none)'
    }
    else {
        $RagModelEffective.TrimEnd()
    }
    $ragModelSourceText = if ([string]::IsNullOrWhiteSpace($RagModelSource)) {
        'none'
    }
    else {
        $RagModelSource.TrimEnd()
    }
    $ragProviderTypeText = if ([string]::IsNullOrWhiteSpace($RagProviderType)) {
        '(unknown)'
    }
    else {
        $RagProviderType.TrimEnd()
    }
    $ragExecutionModeText = if ([string]::IsNullOrWhiteSpace($RagExecutionMode)) {
        'unknown'
    }
    else {
        $RagExecutionMode.TrimEnd()
    }
    $ragEnvironmentContextProfileText = if ([string]::IsNullOrWhiteSpace($RagEnvironmentContextProfile)) {
        'standard'
    }
    else {
        $RagEnvironmentContextProfile.TrimEnd()
    }
    $ragModelConfiguredText = if ([string]::IsNullOrWhiteSpace($RagModelConfigured)) {
        '(none)'
    }
    else {
        $RagModelConfigured.TrimEnd()
    }
    $ragStatusReasonText = if ([string]::IsNullOrWhiteSpace($RagStatusReason)) {
        '(none)'
    }
    else {
        $RagStatusReason.TrimEnd()
    }

    $lines = @(
        '# Tech Agent Run'
        ''
        ('- Status: {0}' -f $Status)
        ('- StartedUtc: {0}' -f $StartedUtc.ToString('o'))
        ('- CompletedUtc: {0}' -f $CompletedUtc.ToString('o'))
        ('- Model: {0}' -f $(if ([string]::IsNullOrWhiteSpace($ModelName)) { '(default)' } else { $ModelName }))
        ('- MaxIterations: {0}' -f $IterationLimit)
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
        ('RagUsed: {0}' -f $RagUsed)
        ('RagStatus: {0}' -f $ragStatusText)
        ('RagModelEffective: {0}' -f $ragModelEffectiveText)
        ('RagModelSource: {0}' -f $ragModelSourceText)
        ('RagEnabledConfigured: {0}' -f $RagEnabledConfigured)
        ('RagAttempted: {0}' -f $RagAttempted)
        ('RagProviderType: {0}' -f $ragProviderTypeText)
        ('RagExecutionMode: {0}' -f $ragExecutionModeText)
        ('RagEnvironmentContextIncluded: {0}' -f $RagEnvironmentContextIncluded)
        ('RagEnvironmentContextProfile: {0}' -f $ragEnvironmentContextProfileText)
        ('RagSourcesScanned: {0}' -f $RagSourcesScanned)
        ('RagCandidatesScored: {0}' -f $RagCandidatesScored)
        ('RagCandidatesSelected: {0}' -f $RagCandidatesSelected)
        ('RagCandidatesPacked: {0}' -f $RagCandidatesPacked)
        ('RagContextCharacters: {0}' -f $RagContextCharacters)
        ('RagModelConfigured: {0}' -f $ragModelConfiguredText)
        ('RagStatusReason: {0}' -f $ragStatusReasonText)
        'ToolTrace:'
        $toolTraceText
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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQ9rWIjg5nDSKh
# MsM7J2OflP4Tg0gHUfbjc/zTjbmpy6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCj
# Tf+HbPqFTLfMZhOK2VjP3o+2mD7sUdS1Pt3OaRjmWDANBgkqhkiG9w0BAQEFAASC
# AYCvVB3q0eRZp7gJmHkAV6qS+Z1Knta+v5ayr7T3VYuVl5ZWOuz+mfPtdo3npQ16
# qNK6y8fzAH2/1AbMkfU+buRp7NL/8HbaDX3cwLSlZBixLHX2l37y0rftpT7JXJ8k
# IXxc/pKj8BVRWDZD4gKvBMNnDRgR3J/UrFHsVpIOAVbOqBdA7zwVTJN6uauirxus
# zY718FN3GQa4qA+JQSjX867qciTiHHPFU3P/cBIFwGtAqTZWYQqdPsEciNiKQUd8
# VIQlfdlwl2kglsHMgxD0B7c/j43iEYG/fhMgeW8bFDZUfrGjE+VvQeUeUElomK9H
# uEq1lxKJD/AA52UhISM7RqvkQh2t5SqIOewMiIMwNQP/L3/dFpTL4gOyom4fuYtS
# 5qT5H9YbsUtYet1c7VyDgTqRhmn8cTLhJfapvSyziuY2NP6mKiKs6UIz0a6pEye/
# 9/zHBRS4NpMmJyUjVtRGRYLr39VFzzASUNbNKrD04YdL949OvuyuF3L2ULtQ33K9
# EvihggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDEwMDUxOTM1WjAvBgkqhkiG
# 9w0BCQQxIgQgCLKAwurBq5f46k3rkPLnMF+zQbocNFi0A5x2erF4504wDQYJKoZI
# hvcNAQEBBQAEggIAT/JTH6UiEK+k3dJsXJf5Ku7FtJ4EiahOcsCT8gk3+uGJ1hSv
# 9vJBQCtjt9EPSB/hTrm6sPS6AGAIeriqj0VHNZpQ83VIj3v0W5ZEVKhX3JfVdA4/
# HExLlI3fgQqIv/i4izennm/bSeKNf1eddKgQv8q8bF0bG2EeD7eYroFaIQblXHbg
# XgZx9Z7vbCkK2swTZG+VfJ3VJseCXGl+wnrccX/vUVd4Ek05GL7NvEPcgC7jpTkQ
# JA3um9j/YQUqtgP4KGDm4Pkd9OBIIoP3R+CDEVR/QyLD+1OfMoZSfVLxYoAmsVRC
# +de2zR8i9jyMpHEfEHkXqYJMA3RY2e0eNiMDjaX4ZOqXxsJouAFgk2GD5JtPNU/9
# VLoC6tYr2Pj8jKL/uGYZK7Wzt3xWw7+U8JmFS66+C7rrUxqijvrZTQ0NVX5NuwCR
# QtbaKbimSXWZcaq4CshXdSa0cbEYoylzXXsZI7dvDy2Wc5PvOOhAzg7/W35qn5kq
# zh+lbAfHQBfGHgZR4KRMfSigw/HA0HaFO44157mXl1Jqc32ptOkglyBtBrXJHBwX
# OsQYk+l1zbLdzzDsO1unpJmVEJ2G9meIWSO4m/5zCuZqcsKhmdPuJx8Asxcuk3hV
# vhsOn1NmDMt6ZJ5x1qJpI7S/w3MLomdPs07rNZOYoOJ6YtEJoqVsk45cVPQ=
# SIG # End signature block
