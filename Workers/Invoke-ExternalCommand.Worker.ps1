param(
    [Parameter(Mandatory)]
    [string]$Payload
)

# ----------------------------
# Decode payload
# ----------------------------
$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload))
$data = $json | ConvertFrom-Json

$FilePath = [string]$data.FilePath
$ArgumentsArray = @($data.Arguments)              # should be string[]
$OutputPath = [string]$data.OutputPath
$RequiresElevation = [bool]($data.RequiresElevation)
$TimeoutMinutes = if ($data.TimeoutMinutes) { [int]$data.TimeoutMinutes } else { 30 }

# normalize args into a single string (preserve your existing worker behavior)
$Arguments = ($ArgumentsArray -join ' ')

# ----------------------------
# META logging helper
# ----------------------------
function Write-Meta {
    param([string]$Line)
    try { $Line | Out-File -LiteralPath $OutputPath -Append -Encoding UTF8 } catch {}
}

Write-Meta "[META] WorkerStarted=$(Get-Date -Format o)"
Write-Meta "[META] RequiresElevation=$RequiresElevation"
Write-Meta "[META] FilePath=$FilePath"

# ----------------------------
# Safety checks
# ----------------------------
if ([string]::IsNullOrWhiteSpace($FilePath)) {
    Write-Meta "[META] ExitCode=1"
    Write-Meta "[META] Error=FilePath was null/empty in payload"
    Write-Meta "[META] WorkerFinished=$(Get-Date -Format o)"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($Payload)) {
    Write-Meta "[META] ExitCode=1"
    Write-Meta "[META] Error=Payload was empty."
    Write-Meta "[META] WorkerFinished=$(Get-Date -Format o)"
    exit 1
}

# ----------------------------
# Admin test
# ----------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]$id
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ----------------------------
# Normal lane: run process directly (inherits token)
# ----------------------------
function Invoke-NormalProcess {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string]$Args,
        [int]$TimeoutMinutes = 30
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = $Args
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError = $false

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    $null = $proc.Start()

    if ($TimeoutMinutes -gt 0) {
        $timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, $TimeoutMinutes)).TotalMilliseconds
        if (-not $proc.WaitForExit($timeoutMs)) {
            try { $proc.Kill() } catch {}
            return @{ ExitCode = -1; TimedOut = $true }
        }
    }
    else {
        $proc.WaitForExit()
    }

    return @{ ExitCode = $proc.ExitCode; TimedOut = $false }
}

# ----------------------------
# Elevated lane: Scheduled Task as SYSTEM (Highest)
# Works remotely over WSMan without UAC prompts.
# ----------------------------
function Invoke-ElevatedScheduledTask {
    param(
        [Parameter(Mandatory)][string]$Exe,
        [Parameter(Mandatory)][string]$Args,
        [int]$TimeoutMinutes = 30
    )

    $taskName = "TT_External_{0}" -f ([guid]::NewGuid().ToString("N"))

    # Use the built-in ScheduledTasks module when available (Win 8+/Server 2012+)
    # Fallback to schtasks.exe otherwise.
    $useCmdlets = [bool](Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue)

    $started = Get-Date
    $deadline = $started.AddMinutes([Math]::Max(1, $TimeoutMinutes))

    # We record exit code by writing it to a small file the worker can read.
    $exitFile = Join-Path $env:TEMP ("{0}.exitcode" -f $taskName)

    # Build a command that runs the exe, captures $LASTEXITCODE, writes it to exitFile.
    # Use cmd.exe to avoid quoting edge cases between PowerShell/ScheduledTask.
    $cmd = @"
"$Exe" $Args
set ec=%errorlevel%
echo %ec%>"$exitFile"
exit /b %ec%
"@

    $cmdFile = Join-Path $env:TEMP ("{0}.cmd" -f $taskName)
    $cmd | Out-File -LiteralPath $cmdFile -Encoding ASCII -Force

    try {
        if ($useCmdlets) {
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$cmdFile`""
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
        }
        else {
            # schtasks fallback
            # /RU SYSTEM + /RL HIGHEST, run once "now", then start it.
            $time = (Get-Date).AddMinutes(1).ToString("HH:mm")
            schtasks.exe /Create /TN $taskName /SC ONCE /ST $time /RU "SYSTEM" /RL HIGHEST /TR "cmd.exe /c `"$cmdFile`"" /F | Out-Null
            schtasks.exe /Run /TN $taskName | Out-Null
        }

        # Poll for exitFile (task completion signal)
        while ((Get-Date) -lt $deadline) {
            if (Test-Path -LiteralPath $exitFile) { break }
            Start-Sleep -Seconds 1
        }

        if (-not (Test-Path -LiteralPath $exitFile)) {
            # timeout; try to stop task
            try {
                if ($useCmdlets) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null }
                else { schtasks.exe /End /TN $taskName | Out-Null }
            }
            catch {}

            return @{ ExitCode = -1; TimedOut = $true }
        }

        $exitCodeText = Get-Content -LiteralPath $exitFile -ErrorAction SilentlyContinue | Select-Object -First 1
        $exitCode = 0
        if (-not [int]::TryParse($exitCodeText, [ref]$exitCode)) { $exitCode = 1 }

        return @{ ExitCode = $exitCode; TimedOut = $false }
    }
    finally {
        # Cleanup task + temp files
        try {
            if ($useCmdlets) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
            else { schtasks.exe /Delete /TN $taskName /F | Out-Null }
        }
        catch {}

        try { Remove-Item -LiteralPath $cmdFile -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $exitFile -Force -ErrorAction SilentlyContinue } catch {}
    }
}

# ----------------------------
# Execute
# ----------------------------
$timedOut = $false
$exitCode = 1

try {
    if ($RequiresElevation) {
        # Local rule: if not admin, fail fast with a clear message.
        if (-not (Test-IsAdmin)) {
            $exitCode = 740  # common "requires elevation" style code (informational)
            Write-Meta "[META] Error=Requires elevation. Run PowerShell as Administrator."
        }
        else {
            $r = Invoke-ElevatedScheduledTask -Exe $FilePath -Args $Arguments -TimeoutMinutes $TimeoutMinutes
            $exitCode = $r.ExitCode
            $timedOut = $r.TimedOut
        }
    }
    else {
        $r = Invoke-NormalProcess -Exe $FilePath -Args $Arguments -TimeoutMinutes $TimeoutMinutes
        $exitCode = $r.ExitCode
        $timedOut = $r.TimedOut
    }
}
catch {
    $exitCode = 1
    Write-Meta "[META] Error=$($_.Exception.Message)"
}

Write-Meta "[META] TimedOut=$timedOut"
Write-Meta "[META] WorkerFinished=$(Get-Date -Format o)"
Write-Meta "[META] ExitCode=$exitCode"

exit $exitCode

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBfF/2+P3neOpnt
# Vtan2D/k4PPRx6AlpWKWzEK7FOhZMqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCVYwDDhthe
# v9axzMYXx92/F7/Y+7jUhZaUeOIIdVJCUDANBgkqhkiG9w0BAQEFAASCAgBLYaps
# T9GhvaujCJqbiR5BepSefirU2rQqlepPpnEwmKgKUC9un4nV9Dr1tYOE6F9PlhOf
# pVTkkjkGTdWtKHrwqGtyMU8kumsVHe4BIDuLW+wTFW52UuZ03LLxGNC8Y8py7aCG
# m+wm3CG6WEa48GBS+YZWPR1WUin9xUF0RAu6oLLW0kIOAXEvSYVoHiyslOmTFYOy
# W7ZqBIJ20EkFtGfwalFq3e8N0kwly2q1zH2FFM09Ya+MQJoMkxXCxkAXIk7vhD3K
# JVg47wqnUQ4hXQQawg2wMms8Rxas1rINy8Pnn41HBiUXVpq1vCU4AuKjwiImLGNR
# q19/uvmLSHLT6XkxLfOHZdFTbe3GR5+a6HsPhjebIQgZYHBJ12XMycKBl1gJe9AD
# WHJQA6SDkI5vEXuGgdOQi/jrcXJH+XguJQ7oa74gMvZOMYdLG9aD3X6Ft3g7m1ob
# v750/ZgbErFcfAwVYaXn3HKVAbwzGuqdOorjntoj/RemLZWaQS5OpBhhnW+4qtPg
# 37m3T/F0E9IIVfJcyoh+KgbhbvEkIHofNXAC84faB6NhHXXkH+AZjD4YFQYugILq
# mi82A7mWp9465Vw5Njnqae3aNpDmLVfSGohrvHH4V1ChM1KSnvB3Y3DRVaUZMofS
# jNx0F7+AIuXb/2QIhRyoG3mflciLXVrHZfjIv6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMDkxNzI3MzdaMC8GCSqGSIb3DQEJBDEiBCAIM4BtSqrVQC3vlo5B
# C0peFXDRR0JiL9wXsxt1v1TFUzANBgkqhkiG9w0BAQEFAASCAgB94cXwzZb0Virc
# W3M1RE4NsOSOYB9YzIRQYh5q/cygjmsMXEKEChrb4YdBmQ1vunLrgSYI9tJU/pl4
# SUQ42RBsdIHBNNR+m7R4WInyOuSXZClyZsPcMNWyhmzk7hIguzG/uRbyRy1J80SA
# l7tAR9NBA0EDlYVjHK71S+MWbp7kPmCrNLmmUSj+RNRmDwgondsrnMsM79poUA6F
# L0W9RPCsdmQOvky1J7ip4G/+wU/Tfhh2dR7cr1SFSJi0nH5dWtnW2R7Wcd2hHhH6
# HWzkhxtOBL3DpcdfsnIA/SiIm6ivG8yC0K3F0dKgAoRq39wDEjFx4WB9jes6VzDv
# 34C9vr60bf8DNmncTAgAFHAQVmBlg1R1OvyIEM6WR63fmcfuNI51856n2YVYLm/z
# Vr13/8oCuWMeZNeJA9K1ro/okX6Pffo4wlxquua05tdwC/6vTGGcImgPkj4eInUr
# gjUAEGC0gf2PYmHXJnV9VHyq6GrjjcXK3MB14PD/YD/zg/n1yzKi60JD3fkxVGum
# o2db3byZMoPq731a/e6GxFaVmhl4GR2VYGrORJt53I0G4wruxE56Wp21B9E23EPE
# 0ik1tmoOnuxb6xwiliomghIIFMtQNHX3b82wTnS6PDzAYhIJy07x9CgSFyq1zdwb
# 1EjKTjUy3kr00h72bJvjAKKkMDb39A==
# SIG # End signature block
