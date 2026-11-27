function Get-FilesUsingKeywords {
    <#
    .SYNOPSIS
        Searches files in a directory for one or more keywords.

    .DESCRIPTION
        Recursively searches files under a given directory for lines matching
        any of the supplied keywords.  The search always runs asynchronously: a
        PowerShell runspace is used for local execution and Invoke-Command
        -AsJob is used for remote execution.  Either way Wait-TerminalState
        drives the poll/spinner loop until completion.

    .PARAMETER Path
        The directory to search.  Required.

    .PARAMETER Keywords
        One or more keywords (or regex patterns) to search for within file
        contents.  Required.

    .PARAMETER ComputerName
        Remote computer to run the search on.  When omitted the search runs
        locally.

    .PARAMETER Credential
        Credentials used when connecting to the remote machine or accessing a
        protected directory path.

    .PARAMETER FileFilter
        Wildcard filter applied to file names (e.g. '*.log', '*.txt'). Defaults
        to '*' (all files).

    .PARAMETER NoRecurse
        When specified, only the top-level directory is searched instead of
        recursing into subdirectories.

    .PARAMETER CaseSensitive
        Treat keyword matching as case-sensitive.

    .PARAMETER SimpleMatch
        Treat keywords as literal strings rather than regular expressions.

    .PARAMETER UseSsh
        Use SSH transport when establishing the remote PSSession.

    .PARAMETER UseCredSSP
        Enable CredSSP authentication when establishing the remote PSSession.

    .PARAMETER SshPort
        SSH port to use when -UseSsh is specified.  Defaults to 22.

    .PARAMETER TimeoutSeconds
        Maximum seconds to wait for the search to complete.  Defaults to 1200.

    .PARAMETER PollSeconds
        How often Wait-TerminalState re-checks job/runspace state.  Defaults to
        30.

    .PARAMETER HeartbeatSeconds
        How often a "still searching" log line is emitted while waiting.
        Defaults to 120.

    .PARAMETER ExportCsv
        When specified, exports match results to CSV. If -CsvPath is not
        provided, a file name is created using
        settings.fileSearch.singleFileNamePattern (when
        settings.fileSearch.appendToSingleFile=true) or
        settings.fileSearch.exportFileNamePattern in
        settings.fileSearch.exportDirectory when configured, otherwise in the
        current directory with a built-in fallback naming pattern.

    .PARAMETER CsvPath
        Path to write CSV results. Implies CSV export.

    .PARAMETER IncludeBinary
        When specified, searches binary and non-text files. By default, binary
        files (detected via encoding) are skipped.

    .OUTPUTS
        PSCustomObject summary with metadata, match counts, file summary,
        and match detail records.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-FilesUsingKeywords
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Keywords,

        [string]$ComputerName,
        [pscredential]$Credential,

        [string]$FileFilter = '*',
        [switch]$NoRecurse,
        [switch]$CaseSensitive,
        [switch]$SimpleMatch,

        [switch]$UseSsh,
        [switch]$UseCredSSP,
        [int]$SshPort = 22,

        [ValidateRange(10, 86400)][int]$TimeoutSeconds = 1200,
        [ValidateRange(1, 3600)] [int]$PollSeconds = 30,
        [ValidateRange(0, 3600)] [int]$HeartbeatSeconds = 120,

        [switch]$ExportCsv,
        [string]$CsvPath,
        [switch]$IncludeBinary
    )

    Set-StrictMode -Version Latest
    Initialize-TechToolboxRuntime

    # Core search logic – a self-contained scriptblock with no module-level
    # dependencies so it executes cleanly in a fresh runspace or remote session.
    $searchBlock = {
        param(
            [string]  $SearchPath,
            [string[]]$SearchKeywords,
            [string]  $Filter,
            [bool]    $Recurse,
            [bool]    $IsCaseSensitive,
            [bool]    $IsSimpleMatch,
            [bool]    $SearchBinary
        )

        $gciParams = @{
            LiteralPath = $SearchPath
            Filter      = $Filter
            ErrorAction = 'SilentlyContinue'
        }
        if ($Recurse) { $gciParams.Recurse = $true }

        # Use PSIsContainer filtering instead of -File for compatibility with older hosts.
        $files = @(Get-ChildItem @gciParams | Where-Object { -not $_.PSIsContainer })
        $hits = New-Object System.Collections.Generic.List[object]

        foreach ($file in $files) {
            # Skip binary files unless explicitly requested
            if (-not $SearchBinary) {
                try {
                    $encoding = [System.Text.Encoding]::UTF8
                    $reader = [System.IO.StreamReader]::new($file.FullName, $encoding, $true)
                    $firstLine = $reader.ReadLine()
                    $reader.Dispose()
                    if ($null -eq $firstLine) { continue } # Empty file, skip
                    # If detected encoding is not UTF8 or contains null bytes, likely binary
                    if ($firstLine -match '[\x00-\x08\x0E-\x1F]') {
                        continue # Skip binary
                    }
                }
                catch {
                    continue # Skip files we can't read as text
                }
            }

            foreach ($kw in $SearchKeywords) {
                $ssParams = @{
                    LiteralPath = $file.FullName
                    Pattern     = $kw
                    ErrorAction = 'SilentlyContinue'
                }
                if ($IsCaseSensitive) { $ssParams.CaseSensitive = $true }
                if ($IsSimpleMatch) { $ssParams.SimpleMatch = $true }

                $ssMatches = Select-String @ssParams
                foreach ($m in $ssMatches) {
                    # Sanitize line: remove control characters but keep printable ones
                    $sanitizedLine = $m.Line -replace '[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]', ''
                    $hits.Add([PSCustomObject]@{
                            FilePath   = $m.Path
                            LineNumber = $m.LineNumber
                            Line       = $sanitizedLine.Trim()
                            Keyword    = $kw
                        })
                }
            }
        }

        return $hits
    }

    # Shared arg list keeps both paths in sync.
    $invokeArgs = @(
        $Path,
        $Keywords,
        $FileFilter,
        (-not $NoRecurse),
        $CaseSensitive.IsPresent,
        $SimpleMatch.IsPresent,
        $IncludeBinary.IsPresent
    )

    $runRemote = (-not [string]::IsNullOrWhiteSpace($ComputerName))
    $resolvedComputerName = if ($runRemote) { $ComputerName } else { $env:COMPUTERNAME }
    $searchStartedAt = Get-Date
    $allMatches = @()

    # -----------------------------------------------------------------------
    # REMOTE PATH  –  Invoke-Command -AsJob + Wait-TerminalState
    # -----------------------------------------------------------------------
    if ($runRemote) {
        Write-Log -Level Info -Message "Searching files on $ComputerName under '$Path' for keyword(s): $($Keywords -join ', ')"

        $creds = $Credential
        if ($script:cfg.settings.defaults.promptForCredentials -and -not $creds) {
            $creds = Get-Credential -Message "Enter credentials for $ComputerName"
        }

        $session = $null
        $job = $null
        try {
            $session = Start-NewPSRemoteSession `
                -ComputerName $ComputerName `
                -Credential   $creds `
                -UseSsh:      $UseSsh `
                -UseCredSSP:  $UseCredSSP `
                -Port         $SshPort

            $job = Invoke-Command -Session $session -ScriptBlock $searchBlock `
                -ArgumentList $invokeArgs -AsJob

            # -- Poll scriptblock closes over $job --
            $poll = {
                @{ State = $job.State; Job = $job }
            }

            $getStatus = {
                param($obj)
                $obj.State   # NotStarted / Running / Completed / Failed / Stopped
            }

            $terminal = @{
                'Completed' = @{
                    Level   = 'Ok'
                    Message = "File search on $ComputerName completed."
                    Return  = $true
                }
                'Failed'    = @{
                    Level   = 'Error'
                    Message = {
                        param($obj, $status)
                        $reason = try { ($obj.Job.ChildJobs[0].JobStateInfo.Reason.Message) } catch { 'unknown error' }
                        "File search job failed on ${ComputerName}: $reason"
                    }
                    Return  = $true
                }
                'Stopped'   = @{
                    Level   = 'Warn'
                    Message = "File search job was stopped on $ComputerName."
                    Return  = $true
                }
            }

            $final = Wait-TerminalState `
                -Target           "FileSearch:$ComputerName" `
                -PollScript       $poll `
                -GetStatus        $getStatus `
                -TerminalStates   $terminal `
                -TimeoutSeconds   $TimeoutSeconds `
                -PollSeconds      $PollSeconds `
                -HeartbeatSeconds $HeartbeatSeconds `
                -WaitingMessage   "Searching $ComputerName "

            if ($final.State -ne 'Completed') { return }

            $results = Receive-Job -Job $final.Job -ErrorAction Stop
            $allMatches = @($results | ForEach-Object {
                    [PSCustomObject]@{
                        ComputerName = $ComputerName
                        FileName     = Split-Path -Leaf $_.FilePath
                        FilePath     = $_.FilePath
                        LineNumber   = $_.LineNumber
                        Line         = $_.Line
                        Keyword      = $_.Keyword
                    }
                })
        }
        catch {
            Write-Log -Level Error -Message "Get-FilesUsingKeywords failed on ${ComputerName}: $($_.Exception.Message)"
            throw
        }
        finally {
            if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
            if ($session) { Stop-PSRemoteSession -Session $session -Confirm:$false }
        }
    }
    # -----------------------------------------------------------------------
    # LOCAL PATH  –  PowerShell runspace + BeginInvoke + Wait-TerminalState
    # -----------------------------------------------------------------------
    else {
        Write-Log -Level Info -Message "Searching files locally under '$Path' for keyword(s): $($Keywords -join ', ')"

        $rs = $null
        $ps = $null
        $asyncResult = $null
        try {
            $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $rs.Open()

            $ps = [powershell]::Create()
            $ps.Runspace = $rs

            # AddScript + positional AddArgument to match the param() declaration.
            [void]$ps.AddScript($searchBlock.ToString())
            foreach ($arg in $invokeArgs) { [void]$ps.AddArgument($arg) }

            $asyncResult = $ps.BeginInvoke()

            # -- Poll scriptblock closes over $asyncResult and $ps --
            $poll = {
                @{ Completed = $asyncResult.IsCompleted; PS = $ps }
            }

            $getStatus = {
                param($obj)
                if ($obj.Completed) { 'Completed' } else { 'Running' }
            }

            $terminal = @{
                'Completed' = @{
                    Level   = 'Ok'
                    Message = 'Local file search completed.'
                    Return  = $true
                }
            }

            $null = Wait-TerminalState `
                -Target           "FileSearch:$env:COMPUTERNAME" `
                -PollScript       $poll `
                -GetStatus        $getStatus `
                -TerminalStates   $terminal `
                -TimeoutSeconds   $TimeoutSeconds `
                -PollSeconds      $PollSeconds `
                -HeartbeatSeconds $HeartbeatSeconds `
                -WaitingMessage   'Searching '

            $results = $ps.EndInvoke($asyncResult)

            $runspaceErrors = @($ps.Streams.Error | Where-Object { $_ })
            $runspaceErrorMessages = @(
                $runspaceErrors |
                ForEach-Object {
                    if ($_.Exception -and -not [string]::IsNullOrWhiteSpace($_.Exception.Message)) {
                        $_.Exception.Message
                    }
                    else {
                        $_.ToString()
                    }
                } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )

            if (@($runspaceErrorMessages).Count -gt 0) {
                $errMsg = $runspaceErrorMessages -join '; '
                throw "Local search runspace reported errors: $errMsg"
            }

            if ($ps.HadErrors) {
                Write-Verbose 'Local search runspace signaled HadErrors, but no actionable error details were present.'
            }

            $allMatches = @($results | ForEach-Object {
                    [PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        FileName     = Split-Path -Leaf $_.FilePath
                        FilePath     = $_.FilePath
                        LineNumber   = $_.LineNumber
                        Line         = $_.Line
                        Keyword      = $_.Keyword
                    }
                })
        }
        catch {
            Write-Log -Level Error -Message "Get-FilesUsingKeywords failed locally: $($_.Exception.Message)"
            throw
        }
        finally {
            if ($ps -and $asyncResult -and -not $asyncResult.IsCompleted) {
                $ps.Stop()
            }
            if ($ps) { $ps.Dispose() }
            if ($rs) { $rs.Dispose() }
        }
    }

    $searchCompletedAt = Get-Date
    $duration = New-TimeSpan -Start $searchStartedAt -End $searchCompletedAt

    $files = @(
        $allMatches |
        Group-Object -Property FilePath |
        Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = { Split-Path -Leaf $_.Name }; Descending = $false }, @{ Expression = 'Name'; Descending = $false } |
        ForEach-Object {
            $firstItem = @($_.Group)[0]
            [PSCustomObject]@{
                FileName   = if ($firstItem -and $firstItem.FileName) { $firstItem.FileName } else { Split-Path -Leaf $_.Name }
                FilePath   = $_.Name
                MatchCount = $_.Count
                Keywords   = ($_.Group.Keyword | Sort-Object -Unique) -join ', '
            } | Add-Member -MemberType ScriptMethod -Name ToString -Value {
                '{0}: {1} match(es) [{2}]' -f (Split-Path -Leaf $this.FilePath), $this.MatchCount, $this.Keywords
            } -Force -PassThru
        }
    )

    $csvOutputPath = $null
    if ($ExportCsv -or -not [string]::IsNullOrWhiteSpace($CsvPath)) {
        $targetPath = $CsvPath
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $defaultExportDir = (Get-Location).Path
            $defaultFileNamePattern = 'Get-FilesUsingKeywords-{computer}-{yyyyMMdd_HHmmss}.csv'
            $singleFileNamePattern = 'Get-FilesUsingKeywords-{computer}.csv'
            $appendToSingleFile = $false
            if ($script:cfg -and $script:cfg.settings -and $script:cfg.settings.fileSearch) {
                $cfgExportDir = [string]$script:cfg.settings.fileSearch.exportDirectory
                if (-not [string]::IsNullOrWhiteSpace($cfgExportDir)) {
                    $defaultExportDir = $cfgExportDir
                }

                $cfgFileNamePattern = [string]$script:cfg.settings.fileSearch.exportFileNamePattern
                if (-not [string]::IsNullOrWhiteSpace($cfgFileNamePattern)) {
                    $defaultFileNamePattern = $cfgFileNamePattern
                }

                $cfgSingleFileNamePattern = [string]$script:cfg.settings.fileSearch.singleFileNamePattern
                if (-not [string]::IsNullOrWhiteSpace($cfgSingleFileNamePattern)) {
                    $singleFileNamePattern = $cfgSingleFileNamePattern
                }

                if ($null -ne $script:cfg.settings.fileSearch.appendToSingleFile) {
                    $appendToSingleFile = [bool]$script:cfg.settings.fileSearch.appendToSingleFile
                }
            }

            if ($appendToSingleFile) {
                $defaultFileNamePattern = $singleFileNamePattern
            }

            $resolvedFileName = $defaultFileNamePattern.
            Replace('{computer}', $resolvedComputerName).
            Replace('{yyyyMMdd}', (Get-Date).ToString('yyyyMMdd')).
            Replace('{yyyyMMdd_HHmmss}', (Get-Date).ToString('yyyyMMdd_HHmmss')).
            Replace('{yyyyMMdd-HHmmss}', (Get-Date).ToString('yyyyMMdd-HHmmss'))

            # Sanitize invalid Windows filename characters from configured patterns.
            foreach ($badChar in [System.IO.Path]::GetInvalidFileNameChars()) {
                $resolvedFileName = $resolvedFileName.Replace([string]$badChar, '_')
            }

            # Windows does not allow trailing spaces/periods in file names.
            $resolvedFileName = $resolvedFileName.Trim().TrimEnd('.')

            if (-not $resolvedFileName.EndsWith('.csv', [System.StringComparison]::OrdinalIgnoreCase)) {
                $resolvedFileName = "$resolvedFileName.csv"
            }

            if ([string]::IsNullOrWhiteSpace($resolvedFileName)) {
                $resolvedFileName = "Get-FilesUsingKeywords-{0}-{1}.csv" -f $resolvedComputerName, (Get-Date -Format 'yyyyMMdd_HHmmss')
            }

            $targetPath = Join-Path -Path $defaultExportDir -ChildPath (
                $resolvedFileName
            )
        }

        $targetDir = Split-Path -Parent $targetPath
        if (-not [string]::IsNullOrWhiteSpace($targetDir) -and -not (Test-Path -LiteralPath $targetDir)) {
            $null = New-Item -ItemType Directory -Path $targetDir -Force
        }

        $exportRows = @($allMatches) | Select-Object ComputerName, FileName, FilePath, LineNumber, Keyword, Line
        $appendMode = Test-Path -LiteralPath $targetPath

        if ($appendMode) {
            $exportRows | Export-Csv -LiteralPath $targetPath -NoTypeInformation -Encoding UTF8 -Append
        }
        else {
            $exportRows | Export-Csv -LiteralPath $targetPath -NoTypeInformation -Encoding UTF8
        }

        $csvOutputPath = try { (Resolve-Path -LiteralPath $targetPath).Path } catch { $targetPath }
        if ($appendMode) {
            Write-Log -Level Info -Message "Appended $(@($allMatches).Count) match(es) to CSV: $csvOutputPath"
        }
        else {
            Write-Log -Level Info -Message "Exported $(@($allMatches).Count) match(es) to CSV: $csvOutputPath"
        }
    }

    [PSCustomObject]@{
        ComputerName    = $resolvedComputerName
        SearchPath      = $Path
        Keywords        = ($Keywords -join ', ')
        FileFilter      = $FileFilter
        Recurse         = (-not $NoRecurse.IsPresent)
        CaseSensitive   = $CaseSensitive.IsPresent
        SimpleMatch     = $SimpleMatch.IsPresent
        IncludeBinary   = $IncludeBinary.IsPresent
        StartedAt       = $searchStartedAt
        CompletedAt     = $searchCompletedAt
        DurationSeconds = [math]::Round($duration.TotalSeconds, 3)
        MatchCount      = @($allMatches).Count
        FileCount       = @($files).Count
        CsvPath         = $csvOutputPath
        Files           = @($files)
        Matches         = @($allMatches)
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzxB8QxS6R6eXp
# QvDOMtp0IEV4N71DoTBO4921HFvdJKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDT
# I4ZdS19gmyGp02LG7wZRLIobbcLRFHtAp9pn9oS3HjANBgkqhkiG9w0BAQEFAASC
# AYBOvheS+GpVdppdHDLZiY2ewH6kR6FXt7hR8p2onqNgIpM0KqtokEs1so0DHx8X
# Gf8Wjp/gxTwAAwH5WD7+4kbcHFwzPJBvn20fZHGKwwrbiA9dDoaSMf5QIzQ51qNV
# XyGv7b8Hv5ZFufBFeyHkERKisPT+ergd7tTNSfpt6mwjOR1X0Harcd8p2nYPHjBa
# PWldGPiqq6j1dzm92LQ27TBMPi2MjKdwgEMh84HKQaCJdNJIl6Zw6W4oW2k8VC3D
# 58vyhVGYLIU+o0NTQIvCPU3q623l26X19WPEkA+9kteBhHMz7WRSkhgYhySF5dq0
# EFO3CJXu31Bgo9lYC65SbVWl4xHsl922mxVwoYsEOwybgC/pc7xSE7oyxMbtjxRX
# VOvZkNL3UOrzQb6/WR85znGK37PyvRohIWGYL+DjBpHssw5m3NEIJfOcKwKzUS1K
# CKNmDZ6UIwh+Zqvp/HSu2M+98MkJRhXfqzaJC5C1yf/JrZ20FZE/ScXWUDm4xgHG
# xPqhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDI4WjAvBgkqhkiG
# 9w0BCQQxIgQgfGpTaXPjb1id0A3D3vA/AZSpo/7p/07suzS1zu0AKnowDQYJKoZI
# hvcNAQEBBQAEggIArOvgsxAzIctLcChTebJPK8TaOBuMvrGrPDYoLoJ3CfQjzyrU
# QHwz41QGQKTRkG1v3c8+n/vT6ekKSFSqP0W0VZyEF7Bu/n2PhBLp2ldHp+vUzYvj
# 7hXwSvw4ArHd2yUkg2/Qc90BpVm0IbqoHCDHCFPC4RcLr2YbuJP1AXRwRYqD8LeO
# gxAQGTpaedB5oi5z5+E77Eab6iDKQ2CwYDex4mHKMkcUp+9ys2a915tfEclkRBqF
# ei8iahZot2Qj1teiB52DxA0PimoUptSo5CJH2YiluBqyYZlE14akbcxSnvGx/oKv
# mY6UXxc0Zn2yviNvuOH6YoakpIZNilD812S0SXbTAvUhGO0hC1L23pFbgt/MwZRG
# RiVIa+JgeAc39/8hmgOxM2WD+gp5MygVI7hcWjC3xVrYYTAdQP6hiLdVkV2PCew4
# vvG1zae6wIGZHgBeOWlqdHtG7qf56/EbdjvT0WQpC4x0c0XcIhv2fJTTcSNR0624
# gFD9sDziSQGosHkKMgK8ihMA/xP0ETVB/acdLJVnuNpKKX5bJSLBTh5Z0YOi3cUs
# GfCU6SZCaHt9+YI8rdG8mvw9sUqE7cq3t63NOPt2dVXh6lQ8OBjZ5V6yBsIIImbh
# 18zCMrYlcTi9+/xk+q9NnpomFXjb3XuKZ6c5CWLXXF4zDQT5MVi6WtgcreA=
# SIG # End signature block
