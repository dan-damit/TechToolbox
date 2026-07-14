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

    .PARAMETER MaxIterations
        Maximum number of tool/reasoning iterations before the agent concludes.

    .PARAMETER PromptHistoryItems
        Number of recent memory history entries to inject into prompt context.
        Set to 0 to disable recent history injection for this run.

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
        Allows higher-order meta tools (for example Invoke-CodeAssistant,
        Invoke-CodeAssistantFolder, Invoke-CodeAssistantWrapper, Invoke-TechAgent)
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
        [ValidateRange(1, 500)]
        [int]$MaxIterations = 15,

        [Parameter()]
        [ValidateRange(0, 20)]
        [int]$PromptHistoryItems,

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
    )

    # Initialize the TechToolbox runtime and load agent configuration
    Initialize-TechToolboxRuntime
    $cfg = $script:cfg.settings.agent
    if ([string]::IsNullOrWhiteSpace($Model) -and $cfg -and -not [string]::IsNullOrWhiteSpace($cfg.model)) {
        $Model = $cfg.model
    }

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

    Write-Host ("Invoke-TechAgent prompt source: {0}" -f $promptSourceLabel)
    Write-Log -Level Info -Message ("Invoke-TechAgent prompt source resolved from: {0}" -f $promptSourceLabel)

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

        if (-not [string]::IsNullOrWhiteSpace($Model)) {
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
                Write-Host ("Tech agent transcript: {0}" -f $transcriptPath)
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
                Write-Host ("Tech agent markdown log: {0}" -f $markdownPath)
            }
            catch {
                $markdownPath = $null
                Write-Log -Level Warn -Message ("Tech agent markdown log could not be initialized: {0}" -f $_.Exception.Message)
            }
        }

        if ($ConfirmDestructive.IsPresent) {
            Write-Log -Level Warn -Message 'Destructive operations explicitly authorized for this run.'
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

        Write-Log -Level Info -Message ("Invoking local tech agent via C# assembly: {0}" -f $agentAssemblyPath)

        $request = [ordered]@{
            Prompt               = $effectivePrompt
            Model                = $(if ([string]::IsNullOrWhiteSpace($Model)) { 'llama3' } else { $Model })
            Verbose              = $false
            MaxIterations        = $MaxIterations
            PromptHistoryItems   = $resolvedPromptHistoryItems
            ConfirmDestructive   = $ConfirmDestructive.IsPresent
            MemoryPath           = $memoryPath
            AutoRetryOnRecursion = $autoRetryOnIterationLimit
            ReturnMetadata       = $false
            SignedFilePolicy     = $(if ([string]::IsNullOrWhiteSpace($SignedFilePolicy)) { 'ignore' } else { $SignedFilePolicy })
            DiagnosticTracePath  = $diagnosticTracePath
            ExpectedOutputPath   = $expectedOutputPath
            AllowedFetchHosts    = @($allowedFetchHosts)
            AllowMetaTools       = $AllowMetaTools.IsPresent
        }

        $requestPath = Join-Path ([System.IO.Path]::GetTempPath()) ("techtoolbox-agent-request-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        $request | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $requestPath -Encoding utf8

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
    [bool]$request.AllowMetaTools)
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
                Write-Log -Level E-Info -Message "`nAgent is running..."
                
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

            Write-Log -Level Info -Message ("Tech agent created expected output file: {0}" -f $expectedOutputPath)
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
                    -ModelName $Model `
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

        if ($agentProc) {
            try { $agentProc.Dispose() } catch { }
        }

    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDkuJPSVp+q1b//
# 8edIVDgJyDtEiI4Mfbu5Kw+ebS/SNKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBaL3AfOt/f
# E48H9tzETaBd88TX4PlV5WQvkCOtavXV2zANBgkqhkiG9w0BAQEFAASCAgA5P8Y7
# P07oDRByYKL2ayJW6LCUl7pLb+JWUwtn9hQPL4O/iKz9I9wFq+T4xAZlbvKlXjWf
# q0bSC/nKuZPf2W6F652jPg2G6jbtQP5lGFGDvHz3nM0lUjpc08af0Xvg3clV6h6u
# DJBXZpmva6md+DuqczmQ+Ty1wZoJoXf9dVV6VMT7hJuRcthjnitUtnnYk/f38uLY
# mQi7zVawZQxHb91d4a9MBWBVENrKPgrRzBInySBiDB6VEbYr8JEGx/Wnv10kWYbX
# 4gOG4LFJY1ko7rnAu5uJgIRQI1/AfJTwp5Fm0pUuks9wUXDrcl93HsZRfNhCroZV
# M9SZqQwQY5CSBn4XU7sjuuSRoEpIVc3jv3mF22PZOAsAURwms70Hbq1OYRqUcl84
# 5NUjuxftPqHufc9ifqRJb57JaYQYoXtSUye1nx28GwdcjQS70sPAWEXdjDxMWhJ2
# RWNg2pXlkAOVj5+LnHWxN8z7o1YpXTeU5Pxm7cclDfAufpMFYWFtpbGJfYzG8y5u
# 9Th7CSHzRn4Kq9E3IB029bW11SU38e3ERDOJfh4ovVGPrCcaIVGx30Jgk4QfI+Dh
# Y6i2scSkvRWXpHCUWmsEoNOHbWK8CF0XrSPZ9vXOk5J1Wy8Wxxfq6Il52KZCUZyM
# oqb1441aesySGVWITsI2YlL5dK8HWspkzUbezKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MTQwNDQ4MDRaMC8GCSqGSIb3DQEJBDEiBCCWxLP38Yvf33Remwnx
# 4KoKTEyNobZH+Z0eNjzYU6wOdzANBgkqhkiG9w0BAQEFAASCAgCqKyHsl3Uy47jA
# 5ZCw+ancRN7FRXcQTskY/8QpWhxocMnEryH9gbh09C1sYiZ9mL6qTWlNvXAjwAgA
# 3xApoTg00sNvo2jKB+zncdi5W1qvRZXrwfkH6yFHTkRwLGSeZ0ODafEabqhypwJg
# wHIEZCvyQvtRbqlD6jF3npddQdMwUQVo9rHkDU0Y8gI/zA0BNSImOaRlBi6Vo//9
# 8dWLPn72/HOzNYKrUrCPlar4jsTSKTyP371ufmUx5GaWW3KI4Y9yp3t09lmqNReG
# E+9KmvPmO5fXbkMfJw4YBWNvHYwo+rGj2xwoIJc77fa1TD5X0gsZNNu4+6Inr8pu
# UKnZKr0tDWG2LyYKxZlkOl3ZFCOfvYwfnlyHooGOxwXD155FNbJYIRwPXScaCnT1
# VQDfet7GcOf3qrrExENHd+UYbT1tFrHYPy8/EFsYaaCRs7rxtsY4xCX2fJlydeYz
# y9Lyt1OAif67++9X3AHSSsat1q9khrzPK6duVclzHnxWlrn40cz4XHDxOXASos/A
# Z33qHJnt9bq/uZ7RT4n5WyLpoUBzbkuggCQmPvUaqF2qjpFMYPk5AohS5rKDf9pZ
# IOnX4tieNx9848wxI2LQ1rwxQfhFbuhiynz7cnZTo3CLhS7nPHuDZdrpVCuV8VpP
# 2tXjoEWzuw4LpjVS+mLZ4b7vn3/LDg==
# SIG # End signature block
