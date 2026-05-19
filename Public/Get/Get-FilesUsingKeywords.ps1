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
        provided, a timestamped file name is created in the current directory.

    .PARAMETER CsvPath
        Path to write CSV results. Implies CSV export.

    .OUTPUTS
        PSCustomObject summary with metadata, match counts, file summary,
        and match detail records.
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
        [string]$CsvPath
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
            [bool]    $IsSimpleMatch
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
                    $hits.Add([PSCustomObject]@{
                            FilePath   = $m.Path
                            LineNumber = $m.LineNumber
                            Line       = $m.Line.Trim()
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
        $SimpleMatch.IsPresent
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
        Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false } |
        ForEach-Object {
            [PSCustomObject]@{
                FilePath   = $_.Name
                MatchCount = $_.Count
                Keywords   = @($_.Group.Keyword | Sort-Object -Unique)
            }
        }
    )

    $csvOutputPath = $null
    if ($ExportCsv -or -not [string]::IsNullOrWhiteSpace($CsvPath)) {
        $targetPath = $CsvPath
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            $targetPath = Join-Path -Path (Get-Location).Path -ChildPath (
                "Get-FilesUsingKeywords-{0}-{1}.csv" -f $resolvedComputerName, (Get-Date -Format 'yyyyMMdd_HHmmss')
            )
        }

        $targetDir = Split-Path -Parent $targetPath
        if (-not [string]::IsNullOrWhiteSpace($targetDir) -and -not (Test-Path -LiteralPath $targetDir)) {
            $null = New-Item -ItemType Directory -Path $targetDir -Force
        }

        @($allMatches) |
            Select-Object ComputerName, FilePath, LineNumber, Keyword, Line |
            Export-Csv -LiteralPath $targetPath -NoTypeInformation -Encoding UTF8

        $csvOutputPath = try { (Resolve-Path -LiteralPath $targetPath).Path } catch { $targetPath }
        Write-Log -Level Info -Message "Exported $(@($allMatches).Count) match(es) to CSV: $csvOutputPath"
    }

    [PSCustomObject]@{
        ComputerName   = $resolvedComputerName
        SearchPath     = $Path
        Keywords       = @($Keywords)
        FileFilter     = $FileFilter
        Recurse        = (-not $NoRecurse.IsPresent)
        CaseSensitive  = $CaseSensitive.IsPresent
        SimpleMatch    = $SimpleMatch.IsPresent
        StartedAt      = $searchStartedAt
        CompletedAt    = $searchCompletedAt
        DurationSeconds = [math]::Round($duration.TotalSeconds, 3)
        MatchCount     = @($allMatches).Count
        FileCount      = @($files).Count
        CsvPath        = $csvOutputPath
        Files          = @($files)
        Matches        = @($allMatches)
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDpxsNCJ1PHdPSs
# t736HBY8ZcfSdQQRCF0dBclt99qp3qCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAJycIOZcrW
# a4+1bTwhzYElJIYphWrhEbCkO/56BKGKZDANBgkqhkiG9w0BAQEFAASCAgCYsy2c
# w5z3RId/FkJZu+0PucIbxyda0Wq0I9UsLSLvOkaYXdIgdeQWR7pJKi8SFwdUFLkl
# m8OTIodcbTgozA8iPm6ZQc6zhcldRCXV84K+F6Rwq+GgC1ey9ilfDKcL5iM9+KPl
# SiE3OsSy+lueKxtcq8z54JZDm4DPCev7oiN8yyByAsYRKLAfOLApB/Yzde51OuTZ
# xB0qxmApG4VJ02O2xgX8K2hrYw88L3lBUea2WS7ByhUjMmdmgUUA+6RVf00m6y0z
# OsIcUKiqheU8snOCM5dJzF+y4oW1frHcGpJHCJLYUx8T3H8nvP6MXfi1ZwKOFYzd
# OPSMQn6k/aPpYeL1qWzNo4f5a0DtTUq/m6mGbyWITEWMLIPRs5kYz1L4vk+GdAVp
# I+tuGheaRw9iH0N2li3dHV5gUEmPO5wLAOy8jVsrLgYHpHY5XxBGrrQBHAhcTfB6
# z+FYFelWHOCur4l+9SMJp44x9+Gvkxs8FjOPdIXa/Yi4W9gfnqn1+NJMw12rZebr
# TH42xTR9r+zTMXGCopyvbGW8HZi1jfX+qHui7qkFywED7LclczQgh/eolduIufMn
# 3bDktg/2+ADCm3mWtRdL5h+N7OBMff3hxWpkz1UmstDeYpyY1cd+tlrJpbVSFKbf
# iYMQuCcO7zVk9Hy6xtna+mVXA19Ejtu80oxMbqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA1MTkxNjE4MjRaMC8GCSqGSIb3DQEJBDEiBCA2sToHfBT7fdbxvLR0
# nS9eG+lnmLNQkEG1i4VsRYal9TANBgkqhkiG9w0BAQEFAASCAgBVjL+74srGs1ts
# q33ZLjisIwn9xsw7MnULT6gyVjJrcnP7WHySDrmYQcBX7EKArGhL/tnLbvt02Kia
# /hU0ZsHe9IQNkB9R/GJW+ePZ8qN1VEmsWKqeT8XNfGknzRBq1fDKLxBiijZHJw1N
# y5j2IPvU3xAKXN51VN57Ic2tLEUYArEu9HGR8j7hfEjk+YGUxHp9xphv/PFTb2Qy
# OQ9NjViUqwDHRf4W4wEWmUMt0/JMxEasZw3AV7uizsyVUEDI+QtGDf0Z5l97j1SP
# 21ZIH3dA0mZMDA2QKVZ5JfTDWm9ZHIvmY6yUmXZ73068OhM8AB2X9dQJo3kpeY/3
# hccCMB0F3QnQlH+vLaTatFDbgYnHvmVhw1ZcFzAwaVUNK38vgUjw7KZgS/h9AcGp
# aW2xGK4SM/WZ54zv9Zkz27i0+20KResCM8IIykyND17/jzMwZh/IiCeDIJ+u8QFx
# AQMgr+0IEY5kntoAGMICGE84whVXVhfdeHygrFsj5pfPEgQcgAHRxKIVRw4TDf36
# 1S9Yn+tB2K2b0OJzLqGL703wzg7qC2EJ9wTNNnlI3J1HCgxlR3bRT1XDv/Q0p570
# mrd/OZFHcio8EGKJKN8pb2RONWAiMXWwutIeH/GJ/KfFd8rS0SRy4k812gqjyyiK
# Q/Knyee9lm3fmDuiX1+Lp83rPi+sNg==
# SIG # End signature block
