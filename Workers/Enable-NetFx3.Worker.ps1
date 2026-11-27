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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDMojcXizvZHr4G
# i+j/fhEjg7nDwINmi7H1btlnkb3XJaCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAe
# URYOscuGozdjg2WjYxpzXU+//Lw5lxHwb8cl+4BaOTANBgkqhkiG9w0BAQEFAASC
# AYAFp0mSbmY+Z2zvtdyQguZBWnrXE4Wubu9PXzeVlfbLrMAit2g0e9j53FgklsqM
# GOUK773JWsVDppUjRZman6nwaYuaCMvFOJkFj5uYXQMNg3xN+Q+X54+IxlxAbGgA
# NuZs5i4H1JGoxXcxZZJ3T9hB3mxSizKsDRuPM3zS60qIxkAd9JG9Hj58DK59YYbP
# qk6EcQVhuSPaGBAgfzCyxk/Z5c2kxvuQj6xuyRpdk2oBrf2zWhKq3YHIMnC++kOM
# mwZj/hlvYj0UAsKQaQipRG2Pai63ppmbMG0JKpfiiZzPx+icOMJ1JwOGpqP4z69K
# ELbXEa6yhMsGRGAnRjGAkjdQG8kXqy/TVvq3dABRrrp5XFkDPdiUy4EyOhfj14kj
# wkasqmMDiuJPgQo3MUYocIMLePmo+o6YHWizg25ePfUroLUvrwq6a0H7LV6T/Avr
# 1RQPMukXLH4V+Wz/dVBB48H3+N/1Xm4mkWXVF8Lpb95IvVQoHP+HGuH0Lk1Z0Q8U
# rCShggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNTU0WjAvBgkqhkiG
# 9w0BCQQxIgQgeS80T956FcL90BpGScqZ2JLq5cz2do3wGNwtPpUe07IwDQYJKoZI
# hvcNAQEBBQAEggIAfBzZQICxN3FMN3yEukGEhtwiDP+bcFtqjrIMU9BOw46BkFev
# qfoF+ebELxcu6Uisarw7uA23Hlj7XO0oavOOV6koEOikiOkL+kwrBHluAgNoYWSQ
# glAdSbtRoAE+8vX7rcGvKajRzhfgVexb0Q/PHmPDxopk0V2tcxNTqN+rFb2zRpSd
# E7J3FjeTpmQ4ar/6BUQ2ujPj1bYg0USOKLZPExdmygpN0rB6cFGLyWvBEFRzcU8H
# S+qIk7MHAp9Hpziv2iqe9tGopR2cF4SLxIrQgn9X69EGWtczUtMmiH500RhKzqqp
# CTZ+/ZpjHFIHZWqiml0rgEUCi2PrISot5M0LNEyV8hjr4gCqkb/GS0iPBcu+wzCg
# 8uC65tHOvKn1gdrkPo4hAEtDO2MDJdCFOsDgkkYcr9nvHyz09bf/gwgnKyflqeVD
# OveEvmry1i8RLW3wUeMkq+X9MK8lNbcKASRcfllRPZPOoKyqMUhrbh/YkS8HzzSs
# VgcGHHxzGaDlWfW5CrO9yBiI4tsAS4uK43+w5kRTIJWw4Q4irD2FfYmMAdLPzGpd
# nFdJFdiioSMMEgliDTlcBdR2UdfUAgY3tcR1edjQwX+D1Ryflati93k1//875l+d
# 2cal/nenYca6zUL606rUBve9gB9Dz+s7UTKA1d+pa0RPDwlsgVxY3MbHVLs=
# SIG # End signature block
