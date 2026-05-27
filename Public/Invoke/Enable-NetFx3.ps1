function Enable-NetFx3 {
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [System.Management.Automation.PSCredential]$Credential,
        [string]$Source,
        [switch]$UseCredSSP,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 60,
        [switch]$Validate
    )

    Initialize-TechToolboxRuntime

    # ----------------------------
    # Remote mode
    # ----------------------------
    if ($ComputerName -and $ComputerName.Count -gt 0) {
        if (-not $Credential -and $script:domainAdminCred) {
            $Credential = $script:domainAdminCred
        }

        if ($Source -and -not ($Source.StartsWith('\\'))) {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] -Source '$Source' is not a UNC path. Ensure it exists on EACH target."
        }

        if ($Source -and $Source.StartsWith('\\') -and -not $UseCredSSP) {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] UNC source detected without -UseCredSSP. If the share requires delegated credentials, remote DISM can fail with access denied."
        }

        Write-Log -Level 'Info' -Message "[Enable-NetFx3] Remote mode → targets: $($ComputerName -join ', ')"

        $moduleRoot = Get-ModuleRoot
        $workerLocal = Join-Path $moduleRoot 'Workers\Enable-NetFx3.worker.ps1'

        $pkg = New-HelpersPackage -HelperLibs @() -WorkerFiles @( $workerLocal )

        function Get-Tail {
            param(
                [string]$Text,
                [int]$Lines = 8
            )

            if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
            $parts = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($parts.Count -eq 0) { return $null }
            ($parts | Select-Object -Last $Lines) -join "`n"
        }

        $results = @()

        foreach ($cn in $ComputerName) {
            $session = $null
            try {
                $session = Start-NewPSRemoteSession -ComputerName $cn -Credential $Credential -UseCredSSP:$UseCredSSP

                $r = Invoke-RemoteWorker `
                    -Session          $session `
                    -HelpersZip       $pkg.ZipPath `
                    -HelpersZipHash   $pkg.ZipHash `
                    -WorkerRemotePath 'IGNORED' `
                    -WorkerLocalPath  $workerLocal `
                    -EntryPoint       'Enable-NetFx3Core' `
                    -EntryParameters  @{
                    Source         = $Source
                    TimeoutMinutes = $TimeoutMinutes
                    Validate       = $Validate
                    NoRestart      = $NoRestart
                    Quiet          = $Quiet
                }

                if ($r -and $r.SystemTaskPending) {
                    $taskName = [string]$r.SystemTaskName
                    $resultPath = [string]$r.SystemTaskResultPath
                    $workDir = [string]$r.SystemTaskWorkDir

                    if ($r.SystemTaskReused) {
                        Write-Log -Level 'Info' -Message "[Enable-NetFx3][$cn] Reusing existing pending SYSTEM fallback task '$taskName'."
                    }

                    Wait-TerminalState `
                        -Target "SYSTEM fallback $cn" `
                        -PollScript {
                        $statusObj = Invoke-Command -Session $session -ScriptBlock {
                            param($tn, $rp)

                            if (Test-Path -LiteralPath $rp) {
                                return [pscustomobject]@{ Status = 'ResultReady' }
                            }

                            $statusOut = & schtasks.exe /Query /TN $tn /FO LIST /V 2>$null
                            if (-not $statusOut) {
                                return [pscustomobject]@{ Status = 'Unknown' }
                            }

                            $stateLine = @($statusOut | Where-Object { $_ -match '^\s*Status\s*:\s*' } | Select-Object -First 1)
                            $state = if ($stateLine) { ($stateLine -replace '^\s*Status\s*:\s*', '').Trim() } else { 'Unknown' }

                            if ($state -match 'Could not start|Could not run') {
                                return [pscustomobject]@{ Status = 'TaskFinishedNoResult' }
                            }

                            [pscustomobject]@{ Status = 'Waiting' }
                        } -ArgumentList $taskName, $resultPath

                        $statusObj
                    } `
                        -GetStatus { param($o) $o.Status } `
                        -TerminalStates @{
                        ResultReady = @{ Level = 'Ok'; Message = "[Enable-NetFx3][$cn] SYSTEM fallback result ready." }
                        TaskFinishedNoResult = @{ Level = 'Warn'; Message = "[Enable-NetFx3][$cn] SYSTEM task finished without result file." }
                    } `
                        -TimeoutSeconds ([int][TimeSpan]::FromMinutes([Math]::Max(1, $TimeoutMinutes)).TotalSeconds) `
                        -PollSeconds 15 `
                        -HeartbeatSeconds 120 `
                        -NotFoundToken 'Waiting' `
                        -NotFoundMessage 'Waiting for SYSTEM DISM task result...' `
                        -WaitingMessage "Waiting SYSTEM DISM task [$cn] " `
                        -ThrowOnTimeout:$false `
                        -ReturnLastOnTimeout `
                        -ContextFormatter { param($lastObj, $lastStatus) "Computer=$cn Task=$taskName LastStatus=$lastStatus" } | Out-Null

                    $fallback = Invoke-Command -Session $session -ScriptBlock {
                        param($tn, $rp, $wd)

                        $exitCode = 1
                        $stdOut = $null
                        $stdErr = $null

                        try {
                            if (Test-Path -LiteralPath $rp) {
                                $raw = Get-Content -LiteralPath $rp -Raw -Encoding UTF8
                                $parsed = $raw | ConvertFrom-Json
                                $exitCode = [int]$parsed.ExitCode
                                $stdOut = [string]$parsed.StdOut
                                $stdErr = [string]$parsed.StdErr
                            }
                            else {
                                $stdErr = 'SYSTEM fallback task did not produce result.json before timeout or completion.'
                            }
                        }
                        catch {
                            $stdErr = $_.Exception.Message
                        }

                        [pscustomobject]@{
                            ExitCode = $exitCode
                            StdOut = $stdOut
                            StdErr = $stdErr
                        }
                    } -ArgumentList $taskName, $resultPath, $workDir

                    $r.SystemTaskPending = $false
                    $r.SystemFallbackUsed = $true
                    $r.ExitCode = [int]$fallback.ExitCode
                    $r.Success = ($r.ExitCode -in 0, 3010)
                    $r.RebootRequired = ($r.ExitCode -eq 3010)
                    $r.DismStdOutTail = Get-Tail -Text $fallback.StdOut -Lines 8
                    $r.DismStdErrTail = Get-Tail -Text $fallback.StdErr -Lines 8

                    if ($r.Success) {
                        $r.Message = $null
                    }
                    else {
                        $r.Message = "DISM failed with exit code $($r.ExitCode) after SYSTEM fallback."
                        if ($r.DismStdErrTail -match '(?im)^.*(0x[0-9a-f]{8}|access is denied|error:|failed).*$') {
                            $r.DismErrorHint = ($Matches[0]).Trim()
                        }
                        elseif ($r.DismStdOutTail -match '(?im)^.*(0x[0-9a-f]{8}|error:|failed).*$') {
                            $r.DismErrorHint = ($Matches[0]).Trim()
                        }
                    }
                }

                if ($r) { $results += $r }
            }
            catch {
                $results += [pscustomobject]@{
                    ComputerName   = $cn
                    ExitCode       = 1
                    Success        = $false
                    RebootRequired = $false
                    State          = $null
                    Message        = $_.Exception.Message
                }
            }
            finally {
                if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
            }
        }

        foreach ($r in $results) {
            if ($r.Success) {
                if ($r.SystemFallbackUsed) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Completed via SYSTEM fallback path."
                }

                if ($r.RebootRequired) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Success (reboot required)."
                }
                else {
                    Write-Log -Level 'Ok' -Message "[Enable-NetFx3][$($r.ComputerName)] Success."
                }
            }
            else {
                $tail = if ($r.Message) { " - $($r.Message)" } else { "" }
                Write-Log -Level 'Error' -Message "[Enable-NetFx3][$($r.ComputerName)] Failed (Exit $($r.ExitCode))$tail"

                if ($r.ExitCode -eq 5) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Exit 5 typically means access denied. Confirm elevated token on target and use -Source with -UseCredSSP for UNC media when required."
                }

                if ($r.DismErrorHint) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] DISM hint: $($r.DismErrorHint)"
                }

                if ($r.DismLogErrorHint) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] DISM log hint: $($r.DismLogErrorHint)"
                }

                $hasServicingLockHint = ($r.DismErrorHint -match '(?i)0x8000ffff|0x80070020') -or ($r.DismLogErrorHint -match '(?i)0x8000ffff|0x80070020')
                if ($hasServicingLockHint) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Servicing contention detected (0x8000ffff/0x80070020). Reboot target to clear pending locks, then retry."
                }

                if ($r.ExitCode -eq 5 -and -not $Source) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Try again with -Source \\server\share\sources\sxs (matching OS build) plus -UseCredSSP."
                }
            }
        }

        return $results
    }

    # ----------------------------
    # Local mode (direct DISM, no ExternalCommand)
    # ----------------------------
    Write-Log -Level 'Info' -Message "[Enable-NetFx3] Starting enablement (local)."

    $system32 = Join-Path $env:SystemRoot 'System32'
    $dism = Join-Path $system32 'dism.exe'

    $argsList = @('/online', '/enable-feature', '/featurename:NetFx3', '/All')
    if ($Quiet) { $argsList += '/Quiet' }
    if ($NoRestart) { $argsList += '/NoRestart' }

    # If Source provided, use LimitAccess
    if ($PSBoundParameters.ContainsKey('Source') -and $Source) {
        $argsList += "/Source:$Source"
        $argsList += '/LimitAccess'
    }

    $overallSuccess = $false
    $dismExit = $null
    $state = $null
    $msg = $null

    try {
        $result = Invoke-TTExe -FilePath $dism -Arguments $argsList -TimeoutMinutes $TimeoutMinutes
        $dismExit = $result.ExitCode

        if ($result.TimedOut) {
            $msg = "Timeout after $TimeoutMinutes minutes."
            Write-Log -Level 'Error' -Message "[Enable-NetFx3] $msg"
            $overallSuccess = $false
        }
        elseif ($dismExit -in 0, 3010) {
            $overallSuccess = $true
            if ($dismExit -eq 3010) {
                Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Reboot required to complete NetFx3 enablement."
            }
            else {
                Write-Log -Level 'Ok' -Message "[Enable-NetFx3] DISM completed successfully."
            }
        }
        else {
            $msg = "DISM failed with exit code $dismExit."
            Write-Log -Level 'Error' -Message "[Enable-NetFx3] $msg"
            $overallSuccess = $false
        }
    }
    catch {
        $overallSuccess = $false
        $msg = $_.Exception.Message
        Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed: $msg"
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
            Write-Log -Level 'Info' -Message "[Enable-NetFx3] Feature state: $state"
            if ($state -in 'Enabled', 'EnablePending', 'EnabledPending') {
                Write-Log -Level 'Ok' -Message "[Enable-NetFx3] NetFx3 enablement validated."
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] NetFx3 state not enabled after operation."
                $overallSuccess = $false
            }
        }
        catch {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Validation skipped: $($_.Exception.Message)"
        }
    }

    $exitCode = if ($overallSuccess) { if ($dismExit) { $dismExit } else { 0 } } else { 1 }

    [pscustomobject]@{
        ComputerName   = $env:COMPUTERNAME
        ExitCode       = $exitCode
        Success        = [bool]$overallSuccess
        RebootRequired = ($exitCode -eq 3010)
        State          = $state
        Message        = $msg
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0BTwQyIv8p1cp
# eR2uXUGI3ylOutmFZNtb9pdPPGW8iKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBbQI40kBe8
# OMPc6o2GTJ81i9c7Ikd83m441kpvfy4gwDANBgkqhkiG9w0BAQEFAASCAgDGSaCb
# dKuS8FnoKjZ8GV4e3CQPwodc9YWMZyv72opm3bCVn2ooKzwhR2dwnQ/r6kaPgdc2
# qccby0iMEKMrnBKeoY0NN8Eukgfz4X47adt70doSwtsYT2CqA5yLhVdKpYH+30Re
# 1sURHbhEtJGnZc2poAHOXiacfzdzHgvilzUR3vFJYoJNf6USVHpduplHt2gqrhR9
# FWznIi8FGzK3ntNgUGWEWnLXJ3zGlBDR6VvKZFPe29cgvehqytDG1FnyRIx0Sx/6
# kYELPO7ApafQ8T5Vcz4z+WLotckyDS5DsPdDYmhZPu9cRyD2SirUULWaZgYV+IQP
# vT6E3trbPC3ALuU9+Rl6JVJZ+czCnTSvzAzGIefVGx3qgyNkfQi+zWtdiF87fplI
# 2an4ev8ea92ZCWd6RDQNQ1mkLdqv1tiBB8GC2Crprv6pzZ+bTO2DYKTFLykEsL1N
# 1abLK30FOpD6yjSP9HUgCQhFKFG5ILpo2Mbly3Y+dcwhS9y/o3C2ZZscGd7QAaP7
# XHz2dU6h1z92KQRw9RTH1rmDSfiXluoD9DCY9a2W2uwDKTD2PnQFq/pHLYrTXzJO
# vzr/Vl/ShwF0p9dB2l8S9GtWMfKeGJbpDFxoQj0vjS/ehrX3LW1huxZ7381OmxRb
# qZZSYtN2vZIjuvV/SruOZKG9fqd627kxyznK3aGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA1MjcyMDI3MDNaMC8GCSqGSIb3DQEJBDEiBCAfmgvE6qezWIdxKe3l
# oDkiD7y3iZOYhzZoYQzDIDqLWjANBgkqhkiG9w0BAQEFAASCAgCEONOmqiYxcJ4K
# 6oOX3C0BMGliigiQ3vxNcqhwmxuD879CTFfx8EdJUGEY914t6e/vFaqQEJ1WWdB0
# nks0Q2YorH6hKPp7OdYNjmjSDkbgKyTFdz/S6xcRz/8CO4c/bfnGIzoRz2134/zD
# PL/VaP5Sf9UBLOcxizHynFazJPh2R+OWFDPSORZ1/8rIsf2X2cO2e3ZhB1AvEQoW
# K2KJveNuqhMXjQ3MXuPGB2QZ7jTR7uCA0IIz3lpANHIEF9EuqTLd7x+7QjkH4mDa
# QHSXcxMu0J708Ypcykjv6pT7OmYrUMvWvsKrcGfgTsnm4vrb5MDaJ+0v4gI3rNc5
# DQL7b74jKG8OXlXNGbCKF0Vzo+ahfUJvWyCb4PZ8EnmAwYVLIdUw4ybPXlo19to8
# II2YJuJDVIVtI+8TE8w9kVlSetNWoMDbUKzwfRnKB+2dg0jEduiYs1lc6wDWFaia
# gAOnJiTMPsKbv3rpqDa72tmGfm6D4yBKyYD6zakDGW0h7y9XT1vTc1TFHJxsHOK/
# FQrKDQYbHoJajykcjHYCP1jf0H7eadvl7zGXKPuihgxUp8M+Z91RDgWLak/xHZpV
# kF/id7sWavL9aTPqzrjTs8boK8alFlQLsrGRgoQBYWx6ysjtt9+pWk6oo3h+dpBy
# wx7fI8gO4ep0WjwfJaopLzNSL/p2zg==
# SIG # End signature block
