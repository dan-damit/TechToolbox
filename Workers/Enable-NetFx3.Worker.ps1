function Enable-NetFx3Core {
    [CmdletBinding()]
    param(
        [string]$Source,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 60,
        [switch]$Validate
    )

    $system32 = Join-Path $env:SystemRoot 'System32'
    $dism = Join-Path $system32 'dism.exe'

    if (-not (Get-Command -Name Write-Log -ErrorAction SilentlyContinue)) {
        function Write-Log {
            [CmdletBinding()]
            param(
                [string]$Level = 'Info',
                [Parameter(Mandatory)][string]$Message
            )

            $line = "[{0}] {1}" -f $Level, $Message
            Write-Information -MessageData $line -InformationAction Continue
        }
    }

    function Join-TTArgs {
        param([string[]]$TTArgs)
        ($TTArgs | ForEach-Object {
            if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
        }) -join ' '
    }

    function Get-TTTextTail {
        param(
            [string]$Text,
            [int]$MaxLines = 8
        )

        if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

        $lines = @($Text -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($lines.Count -eq 0) { return $null }

        return ($lines | Select-Object -Last $MaxLines) -join "`n"
    }

    function Get-TTFileTail {
        param(
            [string]$Path,
            [int]$MaxLines = 120
        )

        if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
        if (-not (Test-Path -LiteralPath $Path)) { return $null }

        try {
            $lines = Get-Content -LiteralPath $Path -Tail $MaxLines -ErrorAction Stop
            if (-not $lines -or $lines.Count -eq 0) { return $null }
            return ($lines -join "`n")
        }
        catch {
            return $null
        }
    }

    function Get-TTTokenIntegrityLevel {
        # Returns 'Low', 'Medium', 'High', 'System', or the raw SID string.
        # DISM /online requires High or System. WinRM sessions (including CredSSP) commonly
        # run wsmprovhost.exe at Medium integrity when the PSSessionConfiguration was not
        # registered with -RunAsAdministrator — even if the connecting user is a domain admin.
        try {
            $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups |
            Where-Object { $_.Value -match '^S-1-16-' } |
            Select-Object -First 1
            if ($null -eq $sid) { return 'Unknown' }
            switch ($sid.Value) {
                'S-1-16-4096' { return 'Low' }
                'S-1-16-8192' { return 'Medium' }
                'S-1-16-12288' { return 'High' }
                'S-1-16-16384' { return 'System' }
                default { return $sid.Value }
            }
        }
        catch { return 'Unknown' }
    }

    function Invoke-TTExe {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [string[]]$Arguments = @(),
            [int]$TimeoutMinutes = 60
        )

        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "Invoke-TTExe: File not found: $FilePath"
        }

        $argLine = Join-TTArgs $Arguments

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $argLine
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $null = $proc.Start()

        # Start async reads BEFORE WaitForExit to prevent pipe-buffer deadlock.
        # If both stdout and stderr are redirected and the child writes enough output
        # to fill the OS pipe buffer (~4 KB), it blocks on write while the parent
        # blocks on WaitForExit — resulting in a deadlock and eventual timeout.
        $stdOutTask = $proc.StandardOutput.ReadToEndAsync()
        $stdErrTask = $proc.StandardError.ReadToEndAsync()

        $timedOut = $false
        if ($TimeoutMinutes -gt 0) {
            $timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, $TimeoutMinutes)).TotalMilliseconds
            if (-not $proc.WaitForExit($timeoutMs)) {
                $timedOut = $true
                try { $proc.Kill() } catch {}
            }
        }
        else {
            $proc.WaitForExit()
        }

        $exitCode = if ($timedOut) { -1 } else { $proc.ExitCode }
        $stdOut = $null
        $stdErr = $null

        try { $stdOut = $stdOutTask.GetAwaiter().GetResult() } catch {}
        try { $stdErr = $stdErrTask.GetAwaiter().GetResult() } catch {}

        [pscustomobject]@{
            ExitCode = $exitCode
            TimedOut = $timedOut
            Success  = (-not $timedOut -and $exitCode -in 0, 3010)
            StdOut   = $stdOut
            StdErr   = $stdErr
        }
    }

    function Invoke-TTDismAsSystem {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$DismPath,
            [Parameter(Mandatory)][string[]]$Arguments,
            [int]$TimeoutMinutes = 60
        )

        $taskName = "TT_EnableNetFx3_{0}" -f ([guid]::NewGuid().ToString('N'))
        $workDir = Join-Path $env:TEMP ("TT_EnableNetFx3_{0}" -f ([guid]::NewGuid().ToString('N')))
        $runnerPath = Join-Path $workDir 'run-dism.ps1'
        $argsPath = Join-Path $workDir 'dism-args.json'
        $resultPath = Join-Path $workDir 'result.json'

        # Guard: reuse an existing pending fallback task when possible.
        try {
            $existingTasks = Get-ScheduledTask -TaskName 'TT_EnableNetFx3_*' -ErrorAction SilentlyContinue | Sort-Object TaskName -Descending
            foreach ($et in @($existingTasks)) {
                $action = @($et.Actions | Select-Object -First 1)
                if (-not $action) { continue }

                $actionArgs = [string]$action.Arguments
                $existingRunner = $null
                if ($actionArgs -match '-File\s+"([^"]+run-dism\.ps1)"') {
                    $existingRunner = $Matches[1]
                }
                elseif ($actionArgs -match "-File\s+'([^']+run-dism\.ps1)'") {
                    $existingRunner = $Matches[1]
                }

                if (-not $existingRunner) { continue }

                $existingWorkDir = Split-Path $existingRunner -Parent
                $existingResultPath = Join-Path $existingWorkDir 'result.json'
                $hasResult = Test-Path -LiteralPath $existingResultPath
                $state = [string]$et.State

                # Reuse only actively running tasks with no result file yet.
                if (($state -eq 'Running') -and -not $hasResult) {
                    return [pscustomobject]@{
                        Attempted  = $true
                        Pending    = $true
                        ReusedTask = $true
                        TaskName   = [string]$et.TaskName
                        ResultPath = $existingResultPath
                        WorkDir    = $existingWorkDir
                    }
                }
            }
        }
        catch {
            # Best effort guard only; continue with new task creation.
        }

        try {
            New-Item -ItemType Directory -Path $workDir -Force | Out-Null

            $Arguments | ConvertTo-Json -Compress | Set-Content -LiteralPath $argsPath -Encoding UTF8

            $runnerScript = @"
`$ErrorActionPreference = 'Continue'
`$dismPath = '$($DismPath -replace "'", "''")'
`$argsPath = '$($argsPath -replace "'", "''")'
`$resultPath = '$($resultPath -replace "'", "''")'
`$timeoutMinutes = $([Math]::Max(1, $TimeoutMinutes))

try {
    `$raw = Get-Content -LiteralPath `$argsPath -Raw -Encoding UTF8
    `$args = @()
    if (-not [string]::IsNullOrWhiteSpace(`$raw)) {
        `$parsed = ConvertFrom-Json -InputObject `$raw
        if (`$parsed -is [System.Array]) { `$args = @(`$parsed) }
        elseif (`$null -ne `$parsed) { `$args = @([string]`$parsed) }
    }

    `$psi = New-Object System.Diagnostics.ProcessStartInfo
    `$psi.FileName = `$dismPath
    `$psi.Arguments = ([string]::Join(' ', (`$args | ForEach-Object {
        if (`$_ -match '[\s"]') { '"' + (`$_ -replace '"', '\\"') + '"' } else { `$_ }
    })))
    `$psi.UseShellExecute = `$false
    `$psi.CreateNoWindow = `$true
    `$psi.RedirectStandardOutput = `$true
    `$psi.RedirectStandardError = `$true

    `$proc = New-Object System.Diagnostics.Process
    `$proc.StartInfo = `$psi
    `$null = `$proc.Start()

    # Start async reads BEFORE WaitForExit to prevent pipe-buffer deadlock.
    `$stdOutTask = `$proc.StandardOutput.ReadToEndAsync()
    `$stdErrTask = `$proc.StandardError.ReadToEndAsync()

    `$timedOut = `$false
    `$timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, `$timeoutMinutes)).TotalMilliseconds
    if (-not `$proc.WaitForExit(`$timeoutMs)) {
        `$timedOut = `$true
        try { `$proc.Kill() } catch {}
    }

    `$output = [pscustomobject]@{
        ExitCode = (if (`$timedOut) { -1 } else { `$proc.ExitCode })
        StdOut   = try { `$stdOutTask.GetAwaiter().GetResult() } catch { '' }
        StdErr   = (if (`$timedOut) {
            "Timed out after `$timeoutMinutes minute(s) waiting for DISM in SYSTEM fallback task."
        }
        else {
            try { `$stdErrTask.GetAwaiter().GetResult() } catch { '' }
        })
    }
}
catch {
    `$output = [pscustomobject]@{
        ExitCode = 1
        StdOut   = ''
        StdErr   = `$_.Exception.Message
    }
}

`$output | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `$resultPath -Encoding UTF8
"@

            Set-Content -LiteralPath $runnerPath -Value $runnerScript -Encoding UTF8

            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $taskCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $psExe, $runnerPath

            # Use a near-future trigger and let Task Scheduler launch it, rather than
            # forcing on-demand run (which can be blocked by policy with 0x800710E0).
            $startTime = (Get-Date).AddMinutes(2).ToString('HH:mm')

            & schtasks.exe /Create /TN $taskName /SC ONCE /ST $startTime /RU SYSTEM /RL HIGHEST /TR $taskCommand /F | Out-Null
            return [pscustomobject]@{
                Attempted  = $true
                Pending    = $true
                ReusedTask = $false
                TaskName   = $taskName
                ResultPath = $resultPath
                WorkDir    = $workDir
            }
        }
        catch {
            return [pscustomobject]@{
                Attempted = $true
                Pending   = $false
                ExitCode  = 1
                StdOut    = $null
                StdErr    = $_.Exception.Message
            }
        }
        finally {
            # Cleanup is handled by the local caller after it reads result.json.
        }
    }

    $argsList = @('/online', '/enable-feature', '/featurename:NetFx3', '/All')
    if ($Quiet) { $argsList += '/Quiet' }
    if ($NoRestart) { $argsList += '/NoRestart' }

    if ($Source) {
        $argsList += "/Source:$Source"
        $argsList += '/LimitAccess'
    }

    $overallSuccess = $false
    $dismExit = $null
    $state = $null
    $msg = $null
    $runAsUser = $null
    $isAdmin = $false
    $dismStdOutTail = $null
    $dismStdErrTail = $null
    $dismErrorHint = $null
    $dismLogTail = $null
    $dismLogErrorHint = $null
    $systemFallbackUsed = $false
    $systemTaskPending = $false
    $systemTaskName = $null
    $systemTaskResultPath = $null
    $systemTaskWorkDir = $null
    $systemTaskReused = $false
    $integrityLevel = 'Unknown'

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $runAsUser = $id.Name
        $principal = [Security.Principal.WindowsPrincipal]$id
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        # Keep defaults; this is only diagnostic context.
    }

    $integrityLevel = Get-TTTokenIntegrityLevel

    if (-not $isAdmin) {
        $dismExit = 5
        $msg = 'DISM requires an elevated administrator token on the target machine.'
    }
    elseif ($integrityLevel -eq 'Medium' -and $runAsUser -ne 'NT AUTHORITY\SYSTEM') {
        # WinRM sessions (including CredSSP) run wsmprovhost.exe at Medium integrity when the
        # PSSessionConfiguration was not registered with -RunAsAdministrator.  The $isAdmin check
        # above passes (it tests group membership, not token elevation), but DISM /online requires
        # a High-integrity process and will return exit code 5 immediately.  Skip the wasted DISM
        # call and jump straight to the SYSTEM task fallback with an actionable remediation message.
        #
        # To eliminate the SYSTEM fallback entirely, re-register the endpoint on the target:
        #   Register-PSSessionConfiguration -Name PowerShell.7 -RunAsAdministrator -Force
        #   (or Microsoft.PowerShell for Windows PowerShell)
        Write-Log -Level 'Warn' -Message "[Enable-NetFx3Core] Session is running at Medium integrity as '$runAsUser'. DISM /online requires High integrity. Re-register the WinRM PSSessionConfiguration with -RunAsAdministrator to use the direct DISM path. Proceeding with SYSTEM task fallback."
        $dismExit = 5
        $msg = 'Session token at Medium integrity — DISM requires High integrity. Re-register the WinRM endpoint with -RunAsAdministrator to eliminate this fallback.'
        $fallback = Invoke-TTDismAsSystem -DismPath $dism -Arguments $argsList -TimeoutMinutes $TimeoutMinutes
        if ($fallback -and $fallback.Attempted) {
            if ($fallback.Pending) {
                $systemFallbackUsed = $true
                $systemTaskPending = $true
                $systemTaskName = [string]$fallback.TaskName
                $systemTaskResultPath = [string]$fallback.ResultPath
                $systemTaskWorkDir = [string]$fallback.WorkDir
                $systemTaskReused = [bool]$fallback.ReusedTask
                $msg = 'SYSTEM fallback task started; waiting is handled by caller.'
            }
            else {
                $dismExit = if ($fallback.ExitCode) { [int]$fallback.ExitCode } else { 1 }
                $dismStdErrTail = Get-TTTextTail -Text $fallback.StdErr -MaxLines 8
                $msg = "Failed to start SYSTEM fallback task (Exit $dismExit)."
                if ($dismStdErrTail -match '(?im)^.*(0x[0-9a-f]{8}|access is denied|error:|failed).*$') {
                    $dismErrorHint = ($Matches[0]).Trim()
                }
            }
        }
    }

    if (-not $msg) {
        try {
            $result = Invoke-TTExe -FilePath $dism -Arguments $argsList -TimeoutMinutes $TimeoutMinutes
            $dismExit = $result.ExitCode
            $dismStdOutTail = Get-TTTextTail -Text $result.StdOut -MaxLines 8
            $dismStdErrTail = Get-TTTextTail -Text $result.StdErr -MaxLines 8

            if ($result.TimedOut) {
                $msg = "Timeout after $TimeoutMinutes minutes."
                $overallSuccess = $false
            }
            elseif ($dismExit -in 0, 3010) {
                $overallSuccess = $true
            }
            else {
                $isAccessDenied = ($dismExit -eq 5)
                $isCatastrophicFailure = (($dismStdErrTail -match '(?i)0x8000ffff') -or ($dismStdOutTail -match '(?i)0x8000ffff'))
                $isSharingViolation = (($dismStdErrTail -match '(?i)0x80070020') -or ($dismStdOutTail -match '(?i)0x80070020'))

                if ($isAccessDenied) {
                    $msg = 'DISM failed with exit code 5 (Access denied). Ensure the remote session is elevated and, for UNC installation media, use delegated credentials (CredSSP).'
                }
                elseif ($isCatastrophicFailure -or $isSharingViolation) {
                    $msg = 'DISM failed due to servicing contention (0x8000ffff/0x80070020). Another servicing operation or lock is active. Reboot the target and retry NetFx3 enablement.'
                }
                else {
                    $msg = "DISM failed with exit code $dismExit."
                }

                if ($dismStdErrTail -match '(?im)^.*(0x[0-9a-f]{8}|access is denied|error:|failed).*$') {
                    $dismErrorHint = ($Matches[0]).Trim()
                }
                elseif ($dismStdOutTail -match '(?im)^.*(0x[0-9a-f]{8}|error:|failed).*$') {
                    $dismErrorHint = ($Matches[0]).Trim()
                }

                $dismLogPath = Join-Path $env:WINDIR 'Logs\DISM\dism.log'
                $dismLogTail = Get-TTFileTail -Path $dismLogPath -MaxLines 120
                if ($dismLogTail -match '(?im)^.*(error|0x80070005|0x80070020|0x8000ffff|access is denied).*$') {
                    $dismLogErrorHint = ($Matches[0]).Trim()
                }

                if ($dismLogTail -match '(?i)0x80070020') {
                    $isSharingViolation = $true
                }

                if ($dismLogTail -match '(?i)0x8000ffff') {
                    $isCatastrophicFailure = $true
                }

                if (-not $isAccessDenied -and ($isCatastrophicFailure -or $isSharingViolation)) {
                    $msg = 'DISM failed due to servicing contention (0x8000ffff/0x80070020). Another servicing operation or lock is active. Reboot the target and retry NetFx3 enablement.'
                }

                # Some systems deny finalize under admin token but succeed as SYSTEM.
                if ($dismExit -eq 5 -and $runAsUser -ne 'NT AUTHORITY\SYSTEM') {
                    $fallback = Invoke-TTDismAsSystem -DismPath $dism -Arguments $argsList -TimeoutMinutes $TimeoutMinutes
                    if ($fallback -and $fallback.Attempted) {
                        if ($fallback.Pending) {
                            $systemFallbackUsed = $true
                            $systemTaskPending = $true
                            $systemTaskName = [string]$fallback.TaskName
                            $systemTaskResultPath = [string]$fallback.ResultPath
                            $systemTaskWorkDir = [string]$fallback.WorkDir
                            $systemTaskReused = [bool]$fallback.ReusedTask
                            $msg = 'SYSTEM fallback task started; waiting is handled by caller.'
                        }
                        else {
                            $dismExit = if ($fallback.ExitCode) { [int]$fallback.ExitCode } else { 1 }
                            $dismStdOutTail = Get-TTTextTail -Text $fallback.StdOut -MaxLines 8
                            $dismStdErrTail = Get-TTTextTail -Text $fallback.StdErr -MaxLines 8
                            $msg = "Failed to start SYSTEM fallback task (Exit $dismExit)."
                            if ($dismStdErrTail -match '(?im)^.*(0x[0-9a-f]{8}|access is denied|error:|failed).*$') {
                                $dismErrorHint = ($Matches[0]).Trim()
                            }
                            elseif ($dismStdOutTail -match '(?im)^.*(0x[0-9a-f]{8}|error:|failed).*$') {
                                $dismErrorHint = ($Matches[0]).Trim()
                            }
                        }
                    }
                }

                if (-not $overallSuccess) {
                    $overallSuccess = $false
                }
            }
        }
        catch {
            $overallSuccess = $false
            $msg = $_.Exception.Message
            $dismExit = 1
        }
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
            if ($state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                $overallSuccess = $false
                $msg = "NetFx3 state not enabled after operation (State=$state)."
            }
        }
        catch {
            # Don’t flip success just because validation failed
        }
    }

    $exitCode = if ($overallSuccess) {
        $dismExit
    }
    else {
        if ($dismExit) { $dismExit } else { 1 }
    }

    [pscustomobject]@{
        ComputerName         = $env:COMPUTERNAME
        ExitCode             = $exitCode
        Success              = [bool]$overallSuccess
        RebootRequired       = ($dismExit -eq 3010)
        State                = $state
        Message              = $msg
        Source               = $Source
        NoRestart            = [bool]$NoRestart
        Quiet                = [bool]$Quiet
        Validate             = [bool]$Validate
        RunAsUser            = $runAsUser
        IsAdmin              = [bool]$isAdmin
        TokenIntegrityLevel  = $integrityLevel
        DismStdOutTail       = $dismStdOutTail
        DismStdErrTail       = $dismStdErrTail
        DismErrorHint        = $dismErrorHint
        DismLogTail          = $dismLogTail
        DismLogErrorHint     = $dismLogErrorHint
        SystemFallbackUsed   = [bool]$systemFallbackUsed
        SystemTaskPending    = [bool]$systemTaskPending
        SystemTaskName       = $systemTaskName
        SystemTaskResultPath = $systemTaskResultPath
        SystemTaskWorkDir    = $systemTaskWorkDir
        SystemTaskReused     = [bool]$systemTaskReused
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBlZgxOUwz4Oul1
# by34+Wiy4rwcR6p0yB4xyIIZ0UYO0KCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA1riH7RIiL
# FelQ7SmPFqVkK/AOsjsal6Znxc3WUfTLMTANBgkqhkiG9w0BAQEFAASCAgAXb5A8
# z5vh5ej5klUA/34uKK51ywFsGT1/qF9WeUZggRRidT0nAhguotUV1y2DGi/zxkmF
# HNQjsyMBljGZKEZrcMAxV3wje71jhHyCgeBSv1GShFv/pyc6B6dpEC1rjTUyZlmB
# EOsqE7BLCw2X1suuMkr+ZYHDTOvnPG74pvEpJcpuPgGcxV1iPCFEKQgcErK/tXDt
# xl3s9npeT7siclHUTXRp3v7nl2sDuDmROLphfLhZfUsCm4Iqc82pawL+PnIbJFB0
# dFBhJcrI3ihkz6ezgu7xt1wQnej7y44+I0ojKUB/PGvZ/c4TGPK//bdQA8qXr9V4
# Yl1p3aimrzPhKKx2babK9UXH/ZkiYJvL2sVamXDvj5FKRbjI/mcXqKHwFY3ahsPt
# dZvHknS0pGEN3o1nsgGvlPY0+1jtfiTZNQ+Wu4Y+1bSHrFxL+774yVo8WiSmTnk2
# 17CvAOgJCSFsDF7smepqudFZid3I1fhu06k8/rAr4Vkcl89mksqUWxq4vuepbunr
# jvG00RizOttf3lT82djZu8dloLCTdcPNEyL0rUN0VKS+k7qzIiHgw8EmnpORseak
# t+gIg42kLRLSahrxMTMT9fFupGm/97J/8/B9laZ2Mqlz9M6ZZJZY2IzE+Yabbzfs
# +52ZTD2MGmjOlO6s9SBaoHfuFwoDvq1oGtza4KGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA1MjcyMTI4NTFaMC8GCSqGSIb3DQEJBDEiBCAKJpOfTRJ62raiS3Ar
# MNO+ELEsZZ6w6ARGqrXIJ6ODQjANBgkqhkiG9w0BAQEFAASCAgCR59Uwp5boZiGH
# cRnirXMfckYo1GiSUmKoSnezWdRJQn3IWc+mna0FgJbFn2aLi0zuPF5chPYm0KGa
# 7G6WarnHodwQOiqRMq42RwEIF4P0XobEobXdPHh0fDq0l6y4Bn5RXgFa0YJcsCZo
# pJqC9hNYIsTFz/MyxiPKDtL21ICaNOCqg8L89B7L1iIv9AeeOF6W+2bBqsHgllwW
# T57MPnUPy3wlCfm1IK7H5PhIhC6tXaAUqNeWzact0L7MfN0pJQy358YJvy4PLGid
# 9q43IQ9wg45AeAJIXFd+N/7pJRRusG9o+Z035Bd0i6Q6CDomTZ/UjD5FgKFIhsmW
# h/QP4l4V+cdV0/3FBqSKPWdGxSD3OYFIZEpwTouEBYsIk04Pe3YNwmNzYXjjdlka
# siTF5PZtoVXHrEbmfsfDCh1aKDJwUDDbPQbD1j4JZHoFJdrg+KSTmH/pLvvy7CFG
# TXQqHzVXyMv2nr29QVH070g+G2qQg9YparI8XIKWvJrEuAW0ZwyWg4ZFP69EDsTy
# oohb3J8/dZoaOvV0h0K0fqTMaAuj/GuCLXZzP1HACc+9NX1Y38afXhu0aMHnTZu/
# iNqJnykX13pnXWrJgY3lJvmU8m6mPOr84LDc44I6tkNK0gOUcHZB/6guNJk6Lt0n
# JwMFex4LNF9Qpy6XoEiZzg8qEycpxA==
# SIG # End signature block
