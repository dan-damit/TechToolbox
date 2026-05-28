function Enable-NetFx3Core {
    [CmdletBinding()]
    param(
        [string]$Source,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 60,
        [switch]$Validate
    )

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

    function Get-TTTokenIntegrityLevel {
        # Returns 'Low', 'Medium', 'High', 'System', or the raw SID string.
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

    function Invoke-TTFeatureAsSystem {
        [CmdletBinding()]
        param(
            [string]$Source,
            [switch]$Quiet,
            [switch]$NoRestart,
            [switch]$Validate,
            [int]$TimeoutMinutes = 60
        )

        $taskName = "TT_EnableNetFx3_{0}" -f ([guid]::NewGuid().ToString('N'))
        $workDir = Join-Path $env:TEMP ("TT_EnableNetFx3_{0}" -f ([guid]::NewGuid().ToString('N')))
        $runnerPath = Join-Path $workDir 'run-netfx3.ps1'
        $payloadPath = Join-Path $workDir 'payload.json'
        $resultPath = Join-Path $workDir 'result.json'

        # Guard: reuse an existing pending fallback task when possible.
        try {
            $existingTasks = Get-ScheduledTask -TaskName 'TT_EnableNetFx3_*' -ErrorAction SilentlyContinue | Sort-Object TaskName -Descending
            foreach ($et in @($existingTasks)) {
                $action = @($et.Actions | Select-Object -First 1)
                if (-not $action) { continue }

                $actionArgs = [string]$action.Arguments
                $existingRunner = $null
                if ($actionArgs -match '-File\s+"([^"]+run-netfx3\.ps1)"') {
                    $existingRunner = $Matches[1]
                }
                elseif ($actionArgs -match "-File\s+'([^']+run-netfx3\.ps1)'") {
                    $existingRunner = $Matches[1]
                }

                if (-not $existingRunner) { continue }

                $existingWorkDir = Split-Path $existingRunner -Parent
                $existingResultPath = Join-Path $existingWorkDir 'result.json'
                $hasResult = Test-Path -LiteralPath $existingResultPath
                $state = [string]$et.State

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

            [pscustomobject]@{
                Source         = $Source
                Quiet          = [bool]$Quiet
                NoRestart      = [bool]$NoRestart
                Validate       = [bool]$Validate
                TimeoutMinutes = [int][Math]::Max(1, $TimeoutMinutes)
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $payloadPath -Encoding UTF8

            $runnerScript = @"
`$ErrorActionPreference = 'Continue'
`$payloadPath = '$($payloadPath -replace "'", "''")'
`$resultPath = '$($resultPath -replace "'", "''")'

`$out = [pscustomobject]@{
    ExitCode       = 1
    Success        = `$false
    RebootRequired = `$false
    State          = `$null
    Message        = `$null
}

try {
    `$raw = Get-Content -LiteralPath `$payloadPath -Raw -Encoding UTF8
    `$cfg = ConvertFrom-Json -InputObject `$raw

    `$invokeParams = @{
        Online      = `$true
        FeatureName = 'NetFx3'
        All         = `$true
        ErrorAction = 'Stop'
    }
    if (`$cfg.NoRestart) { `$invokeParams.NoRestart = `$true }
    if (-not [string]::IsNullOrWhiteSpace([string]`$cfg.Source)) {
        `$invokeParams.Source = [string]`$cfg.Source
        `$invokeParams.LimitAccess = `$true
    }

    `$savedProgressPreference = `$null
    if (`$cfg.Quiet) {
        `$savedProgressPreference = `$ProgressPreference
        `$ProgressPreference = 'SilentlyContinue'
    }

    try {
        `$result = Enable-WindowsOptionalFeature @invokeParams
        `$state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop).State
        `$restartNeeded = [bool]`$result.RestartNeeded -or (`$state -in 'EnablePending', 'EnabledPending')

        if (`$state -in 'Enabled', 'EnablePending', 'EnabledPending') {
            `$out.Success = `$true
            `$out.ExitCode = if (`$restartNeeded) { 3010 } else { 0 }
            `$out.RebootRequired = (`$out.ExitCode -eq 3010)
            `$out.State = `$state
        }
        else {
            `$out.ExitCode = 1
            `$out.State = `$state
            `$out.Message = "NetFx3 state not enabled after operation (State=`$state)."
        }

        if (`$out.Success -and `$cfg.Validate) {
            `$state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop).State
            `$out.State = `$state
            if (`$state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                `$out.Success = `$false
                `$out.ExitCode = 1
                `$out.RebootRequired = `$false
                `$out.Message = "NetFx3 state not enabled after operation (State=`$state)."
            }
        }
    }
    catch {
        `$rawMessage = `$_.Exception.Message
        if (`$_.Exception -is [System.UnauthorizedAccessException] -or `$rawMessage -match '(?i)access is denied|0x80070005') {
            `$out.ExitCode = 5
            `$out.Message = 'Access is denied while running SYSTEM fallback feature task.'
        }
        else {
            `$out.ExitCode = 1
            `$out.Message = `$rawMessage
        }
    }
    finally {
        if (`$cfg.Quiet -and `$null -ne `$savedProgressPreference) {
            `$ProgressPreference = `$savedProgressPreference
        }
    }
}
catch {
    `$out.ExitCode = 1
    `$out.Success = `$false
    `$out.RebootRequired = `$false
    `$out.Message = `$_.Exception.Message
}

`$out | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath `$resultPath -Encoding UTF8
"@

            Set-Content -LiteralPath $runnerPath -Value $runnerScript -Encoding UTF8

            $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $taskCommand = '"{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $psExe, $runnerPath

            # Use a near-future trigger and let Task Scheduler launch it.
            $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')

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
                Message   = $_.Exception.Message
            }
        }
    }

    $invokeParams = @{
        Online      = $true
        FeatureName = 'NetFx3'
        All         = $true
        ErrorAction = 'Stop'
    }
    if ($NoRestart) { $invokeParams.NoRestart = $true }
    if ($Source) {
        $invokeParams.Source = $Source
        $invokeParams.LimitAccess = $true
    }

    $overallSuccess = $false
    $exitCode = 1
    $restartNeeded = $false
    $state = $null
    $msg = $null
    $runAsUser = $null
    $isAdmin = $false
    $integrityLevel = 'Unknown'
    $systemFallbackUsed = $false
    $systemTaskPending = $false
    $systemTaskName = $null
    $systemTaskResultPath = $null
    $systemTaskWorkDir = $null
    $systemTaskReused = $false

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
        $exitCode = 5
        $msg = 'Feature enablement requires an elevated administrator token on the target machine.'
    }
    else {
        $savedProgressPreference = $null
        if ($Quiet) {
            $savedProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
        }

        try {
            $result = Enable-WindowsOptionalFeature @invokeParams
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop).State
            $restartNeeded = [bool]$result.RestartNeeded -or ($state -in 'EnablePending', 'EnabledPending')

            if ($state -in 'Enabled', 'EnablePending', 'EnabledPending') {
                $overallSuccess = $true
                $exitCode = if ($restartNeeded) { 3010 } else { 0 }
            }
            else {
                $overallSuccess = $false
                $exitCode = 1
                $msg = "NetFx3 state not enabled after operation (State=$state)."
            }
        }
        catch {
            $overallSuccess = $false
            $rawMessage = $_.Exception.Message
            $isAccessDenied = ($_.Exception -is [System.UnauthorizedAccessException]) -or ($rawMessage -match '(?i)access is denied|0x80070005')
            if ($isAccessDenied) {
                if ($isAdmin -and $runAsUser -ne 'NT AUTHORITY\SYSTEM') {
                    $fallback = Invoke-TTFeatureAsSystem -Source $Source -Quiet:$Quiet -NoRestart:$NoRestart -Validate:$Validate -TimeoutMinutes $TimeoutMinutes
                    if ($fallback -and $fallback.Attempted) {
                        if ($fallback.Pending) {
                            $systemFallbackUsed = $true
                            $systemTaskPending = $true
                            $systemTaskName = [string]$fallback.TaskName
                            $systemTaskResultPath = [string]$fallback.ResultPath
                            $systemTaskWorkDir = [string]$fallback.WorkDir
                            $systemTaskReused = [bool]$fallback.ReusedTask
                            $msg = 'SYSTEM fallback feature task started; waiting is handled by caller.'
                            $exitCode = 5
                        }
                        else {
                            $exitCode = if ($fallback.ExitCode) { [int]$fallback.ExitCode } else { 1 }
                            $msg = if ($fallback.Message) { [string]$fallback.Message } else { 'Failed to start SYSTEM fallback feature task.' }
                        }
                    }
                    else {
                        $exitCode = 5
                        $msg = 'Access is denied. Remote session token likely not elevated for servicing operations. Configure the target WinRM endpoint with -RunAsCredential (an admin account), then retry.'
                    }
                }
                else {
                    $exitCode = 5
                    $msg = 'Access is denied. Feature enablement requires an elevated administrator token on the target machine.'
                }
            }
            else {
                $msg = $rawMessage
                $exitCode = 1
            }
        }
        finally {
            if ($Quiet -and $null -ne $savedProgressPreference) {
                $ProgressPreference = $savedProgressPreference
            }
        }
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction Stop).State
            if ($state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                $overallSuccess = $false
                $msg = "NetFx3 state not enabled after operation (State=$state)."
                $exitCode = 1
            }
        }
        catch {
            # Keep command outcome when validation check fails.
        }
    }

    [pscustomobject]@{
        ComputerName         = $env:COMPUTERNAME
        ExitCode             = $exitCode
        Success              = [bool]$overallSuccess
        RebootRequired       = ($exitCode -eq 3010)
        State                = $state
        Message              = $msg
        Source               = $Source
        NoRestart            = [bool]$NoRestart
        Quiet                = [bool]$Quiet
        Validate             = [bool]$Validate
        RunAsUser            = $runAsUser
        IsAdmin              = [bool]$isAdmin
        TokenIntegrityLevel  = $integrityLevel
        DismStdOutTail       = $null
        DismStdErrTail       = $null
        DismErrorHint        = $null
        DismLogTail          = $null
        DismLogErrorHint     = $null
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDMojcXizvZHr4G
# i+j/fhEjg7nDwINmi7H1btlnkb3XJaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAeURYOscuG
# ozdjg2WjYxpzXU+//Lw5lxHwb8cl+4BaOTANBgkqhkiG9w0BAQEFAASCAgCkPmxD
# inE0jXL8icwOJROpyQrtdwsqyt7zXn/CjIbKuUUI7ouZs7HhfH2+yyWHR1SURnFM
# ssLgxESoDZTDtc3FYY7xSAaqqO7gJ1eM0vWkCEHrT3wh8PpNi4b4pJqCrbC70YaE
# mSqF74ihNAh2E+f7UYcxt4S0kDUrFS9dgscicTrRvfbsVEjjMCUMDWYBy8ry46Ps
# Odg7yczVn/Mfqb5llgA5fV79YDlwy+o1Jx7Z7wYG7+rwtsLViQU7p8FcsySUUAts
# TrRVfit6rZlfGSqxN056Uhz1CVshafgllhxtmD/CITeGGf05SlDV0zum1OHZZWWi
# XoyzFzg+Jr+lGSiPr2WZfE29kJ7a5gLZKwsy3aLSIf5taYBie2h2LBIm9n7S2hhv
# NU9HFIbBI2RorVoJD4qCuKlpCGSN7wr9jS7d0hhune5X+2kURYhARg7Yfi/f7/E9
# IVOGrBlv+5cvzDaWSN/FeXhV/d1JNS5zsrbpAzNjYOVJiT8tkAlWB54T5iyaicRy
# ghVCkKkmnRlv2cw8lrKlT+YtB9XlL8hlyb2A0ToBmNVhc80ddK/bfeBqxFysckfG
# EABUyxa2CHOes0ISdBNOhKWjtYkr0UuCPEp0cgVku05f1HAzsMND6xWd68d5jxO6
# NnGmqB/8rFS9pHojZWMtjhoK7iO8acpp8OqxzaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA1MjgxMzUwMDZaMC8GCSqGSIb3DQEJBDEiBCDnExJvkbWmN92FUsWM
# 9kYhEzctQA4fNSWY81tg/l6DxzANBgkqhkiG9w0BAQEFAASCAgBvoHnBGCQVO1D+
# C7F4fbjx1uZ/v7EPMZ04v14pBzIxAQ7sM1PNRmZ4tOAPnhM6EWXYmi2K7K8Ihdkn
# O38OCbVS8fZ0dM69Bu1itb2rDx9CFtHA01MENCZXRxMyNX+JUwDJLx0GKHH1Ccyv
# WHw63yThnwEHcNR5t4ZEb9OgeUvyiBrcZA79gCPQb8hGtCHgeYXTHqS1S5YAvA57
# 619io8bnqjRBR2uzxFZLBJnXE3DgNTayJ2EsasXDlTwI6vhAggkDTxpwmh4U5wZo
# JBH426JeVRE+BNWMLQ/n5dWzpIHnjAXyqOugBx/h9iJ8s1Co5G6bL+z97H7aCa86
# KA246TVN6R27229BwJax/9EmL3y5XuVTuLM/dO/4G1+8f/15woSJeu7yY5RXZbeY
# IIv9PaAGqtZit+ddlQo+lxC9DLP+xAkGKMhobMdmE/1JD9uvf48BZNHmvOiH7rTC
# kMdK5LL5MjpfcZq1zfJ+TFgU2+E1V2dYvJsljR7XO2MumOzTzY1Ozi1rUe6k9NGe
# FaOCvzwyBlCH/aPocOOSZTHts/emQBIkyY7Z7im2E+ltfPn+CPV6vELyaw3RByeS
# 6ffxup5NkGbzHsnFmF3JNsh8oTj7vUQ7UpVrXv17j06L7HSy7zZYX9Sxwouduyiq
# jGB1pAe+zdSvpsphGnzNbmkMXWXctg==
# SIG # End signature block
