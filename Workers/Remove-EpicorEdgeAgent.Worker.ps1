<#
.SYNOPSIS
    Worker script to fully scrub Epicor Edge Agent from a computer.

.DESCRIPTION
    Deep removal including:
      - Stop processes/services
      - MSI uninstall via registry Uninstall keys (avoids Win32_Product)
      - Remove scheduled tasks
      - Delete program/appdata folders
      - Remove registry keys

.PARAMETER AnalyzeOnly
    When supplied, perform a dry-run and DO NOT change the system.
#>

param(
    [switch]$AnalyzeOnly
)

# ----------------------------
# INITIALIZATION
# ----------------------------

$Result = [ordered]@{
    ComputerName        = $env:COMPUTERNAME
    AnalyzeOnly         = $AnalyzeOnly.IsPresent
    Status              = "Started"
    StartTime           = (Get-Date)
    DurationS           = $null
    ServicesStopped     = New-Object System.Collections.Generic.List[string]
    ProcessesKilled     = New-Object System.Collections.Generic.List[string]
    PackagesUninstalled = New-Object System.Collections.Generic.List[string]
    TasksRemoved        = New-Object System.Collections.Generic.List[string]
    DirsRemoved         = New-Object System.Collections.Generic.List[string]
    RegKeysRemoved      = New-Object System.Collections.Generic.List[string]
    Warnings            = New-Object System.Collections.Generic.List[string]
    Errors              = New-Object System.Collections.Generic.List[string]
    Actions             = New-Object System.Collections.Generic.List[string]
}

function Write-Action($msg) {
    Write-Host "[+] $msg" -ForegroundColor Cyan
    $Result.Actions.Add($msg) | Out-Null
}
function Write-Err($msg) {
    Write-Host "[!] $msg" -ForegroundColor Red
    $Result.Errors.Add($msg) | Out-Null
}
function Write-Warn($msg) {
    Write-Warning $msg
    $Result.Warnings.Add($msg) | Out-Null
}

# Require elevation for actual changes (not for AnalyzeOnly)
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin -and -not $AnalyzeOnly) {
    Write-Err "Administrator privileges are required. Re-run elevated or use -AnalyzeOnly."
    $Result.Status = "Failed"
    $Result.EndTime = Get-Date
    $Result.DurationS = [math]::Round(($Result.EndTime - $Result.StartTime).TotalSeconds, 2)
    return [pscustomobject]$Result
}

# ----------------------------
# STOP SERVICES (best-effort)
# ----------------------------

Write-Action "Stopping Epicor / Edge Agent services..."
$svcCandidates = Get-Service | Where-Object { $_.Name -match "Epicor|Edge|Kinetic" }

foreach ($svc in $svcCandidates) {
    try {
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would stop service: $($svc.Name)"
            continue
        }
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            Write-Action "Stopped service: $($svc.Name)"
            $Result.ServicesStopped.Add($svc.Name) | Out-Null
        }
    }
    catch {
        Write-Err "Failed to stop service: $($svc.Name) :: $($_.Exception.Message)"
    }
}

# ----------------------------
# KILL PROCESSES
# ----------------------------

Write-Action "Killing Epicor / Edge Agent processes..."
$processTargets = @(
    "Epicor.EA.Tray",
    "Epicor.EA.Agent",
    "EdgeAgent",
    "Epicor"          # broad catch; safe as try/catch + SilentlyContinue
)

foreach ($p in $processTargets) {
    $procs = Get-Process -Name $p -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        try {
            if ($AnalyzeOnly) {
                Write-Action "[ANALYZE] Would kill process: $($proc.ProcessName) (PID=$($proc.Id))"
                continue
            }
            $proc | Stop-Process -Force
            Write-Action "Killed process: $($proc.ProcessName) (PID=$($proc.Id))"
            $Result.ProcessesKilled.Add("$($proc.ProcessName)[$($proc.Id)]") | Out-Null
        }
        catch {
            Write-Err "Failed to kill process: $($proc.ProcessName) :: $($_.Exception.Message)"
        }
    }
}

# ----------------------------
# MSI UNINSTALL via Registry (no Win32_Product)
# ----------------------------

Write-Action "Searching for Epicor Edge Agent uninstall entries..."
$uninstallRoots = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

$entries = foreach ($root in $uninstallRoots) {
    Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
            if ($p.DisplayName -and ($p.DisplayName -match '(?i)Epicor.*Edge.*Agent|^Epicor Edge Agent$')) { $p }
        }
        catch {}
    }
}

function Invoke-SilentUninstall {
    param(
        [Parameter(Mandatory)] [string]$DisplayName,
        [Parameter(Mandatory)] [string]$UninstallString
    )
    $msiGuid = [regex]::Match($UninstallString, '{[0-9A-Fa-f\-]+}').Value
    $isMsiexec = ($UninstallString -match '(?i)msiexec\.exe')

    if ($isMsiexec -and $msiGuid) {
        $cmd = "msiexec.exe"
        $args = "/x $msiGuid /qn /norestart"
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would uninstall MSI: $DisplayName -> $cmd $args"
            return $true
        }
        $p = Start-Process -FilePath $cmd -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
        if ($p.ExitCode -eq 0) { return $true } else {
            Write-Err "MSI uninstall failed ($DisplayName). ExitCode=$($p.ExitCode)"
            return $false
        }
    }

    # Direct MSI path?
    if ($UninstallString -match '(?i)\.msi') {
        # Extract quoted path if present
        $msiPath = $null
        if ($UninstallString -match '"([^"]+\.msi)"') { $msiPath = $matches[1] }
        else {
            # Fallback: split and locate first token ending with .msi
            $token = ($UninstallString -split '\s+') | Where-Object { $_ -match '(?i)\.msi$' } | Select-Object -First 1
            if ($token) { $msiPath = $token }
        }
        if ($msiPath) {
            $cmd = "msiexec.exe"
            $args = "/x `"$msiPath`" /qn /norestart"
            if ($AnalyzeOnly) {
                Write-Action "[ANALYZE] Would uninstall MSI path: $DisplayName -> $cmd $args"
                return $true
            }
            $p = Start-Process -FilePath $cmd -ArgumentList $args -Wait -PassThru -WindowStyle Hidden
            if ($p.ExitCode -eq 0) { return $true } else {
                Write-Err "MSI path uninstall failed ($DisplayName). ExitCode=$($p.ExitCode)"
                return $false
            }
        }
    }

    # Unknown EXE uninstaller: attempt common silent switches (best-effort)
    $exe = $null; $argsExisting = $null
    if ($UninstallString -match '^\s*"([^"]+\.exe)"\s*(.*)$') {
        $exe = $matches[1]; $argsExisting = $matches[2]
    }
    elseif ($UninstallString -match '^\s*(\S+\.exe)\s*(.*)$') {
        $exe = $matches[1]; $argsExisting = $matches[2]
    }

    if ($exe) {
        $silentSwitches = @('/S', '/silent', '/quiet', '/VERYSILENT')
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would try EXE uninstall: $DisplayName -> `"$exe`" $argsExisting + (one of $($silentSwitches -join ', '))"
            return $true
        }
        foreach ($sw in $silentSwitches) {
            try {
                $proc = Start-Process -FilePath $exe -ArgumentList "$argsExisting $sw" -Wait -PassThru -WindowStyle Hidden
                if ($proc.ExitCode -eq 0) { return $true }
            }
            catch {}
        }
        Write-Warn "EXE uninstall may require vendor-specific silent switch: ${DisplayName}"
        return $false
    }

    Write-Warn "Unrecognized uninstall string for ${DisplayName}: $UninstallString"
    return $false
}

foreach ($e in $entries) {
    if (-not $e.UninstallString) { continue }
    $name = $e.DisplayName
    $ok = Invoke-SilentUninstall -DisplayName $name -UninstallString $e.UninstallString
    if ($ok) { $Result.PackagesUninstalled.Add($name) | Out-Null }
}

# ----------------------------
# REMOVE SCHEDULED TASKS
# ----------------------------

Write-Action "Removing Epicor-related scheduled tasks..."
$removedTasks = 0
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskName -match '(?i)Epicor|Edge|Kinetic' -or $_.TaskPath -match '(?i)Epicor|Edge|Kinetic'
    }
}
catch {
    $tasks = @()
}

if (-not $tasks -or $tasks.Count -eq 0) {
    # Fallback to schtasks parsing
    $raw = schtasks /Query /FO LIST 2>$null | Select-String "TaskName:"
    $tasks = foreach ($line in $raw) { $tn = ($line -split ":")[1].Trim(); if ($tn) { [pscustomobject]@{ TaskName = $tn; TaskPath = "" } } }
}

foreach ($t in $tasks) {
    $name = $t.TaskName
    if ($AnalyzeOnly) {
        Write-Action "[ANALYZE] Would delete scheduled task: $name"
        continue
    }
    try {
        if (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
        }
        else {
            schtasks /Delete /TN $name /F | Out-Null
        }
        $Result.TasksRemoved.Add($name) | Out-Null
        $removedTasks++
    }
    catch {
        Write-Err "Failed to delete task: $name :: $($_.Exception.Message)"
    }
}

# ----------------------------
# DELETE PROGRAM FILES + APPDATA
# ----------------------------

Write-Action "Removing Epicor program/AppData directories..."
$paths = @(
    "C:\Program Files\Epicor",
    "C:\Program Files (x86)\Epicor",
    "$Env:LocalAppData\Epicor",
    "$Env:AppData\Epicor"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would remove directory: $path"
            continue
        }
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Action "Removed directory: $path"
            $Result.DirsRemoved.Add($path) | Out-Null
        }
        catch {
            Write-Err "Failed to remove directory: $path :: $($_.Exception.Message)"
        }
    }
}

# ----------------------------
# REMOVE REGISTRY ENTRIES
# ----------------------------

Write-Action "Cleaning Epicor registry keys..."
$regPaths = @(
    "HKLM:\Software\Epicor",
    "HKLM:\Software\WOW6432Node\Epicor",
    "HKCU:\Software\Epicor"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would remove registry key: $regPath"
            continue
        }
        try {
            Remove-Item $regPath -Recurse -Force -ErrorAction Stop
            Write-Action "Removed registry key: $regPath"
            $Result.RegKeysRemoved.Add($regPath) | Out-Null
        }
        catch {
            Write-Err "Failed to remove registry key: $regPath :: $($_.Exception.Message)"
        }
    }
}

# ----------------------------
# FINALIZE
# ----------------------------

$Result.Status = "Completed"
$Result.EndTime = Get-Date
$Result.DurationS = [math]::Round(($Result.EndTime - $Result.StartTime).TotalSeconds, 2)

Write-Action ("Epicor Edge Agent Removal {0}" -f ($(if ($AnalyzeOnly) { 'ANALYZE-ONLY (no changes)' } else { 'COMPLETED' })))

# Return typed object
[pscustomobject]$Result

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1MhX77xg8+Z/J
# iWDsKwroIOmX8Uzd9GRB/QQwY0z2ZKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBUXXgUlCYv
# /d0qREZlg+aB3zQzGsC9YOZ4DxkaCm7lSjANBgkqhkiG9w0BAQEFAASCAgAiKQLr
# e9OHZ1za5mjuOhMyYtgbLT2NA7dVrDdjeqrJ/KE/Dsg7Yvnj2Fo1qHO4GYemmR9K
# IPhjSo2dti2tLoLw1++mZUVQEr6lukXmsyi/sa38RcBvcFvBT10skXkQhwD1RDkD
# 7NOZ8Y+rr69JQzlxm0ja5DP5wFR3gS3n0VXeCClgUtl5lXjkUGZ3uUZ5X/sPoftQ
# ZNmx8Q194x0X+Ma+zdc4ReiI89HPEnBCZbxyzJ4S63yS/BSOl9ROOekZ/pEVe5fH
# kQWkd78vfLavGNgKZsGBptqsjWB9GacW2m9B9uDjzNymwM3jAeW6JtuSO2vQI1aa
# TSs+iB+lrh6EnkRY4HVC7cafexLfpt76cBPgZe/Btx7w+vSpoSQsxzlrV3YR3trl
# SmZ1hBYqRUImaJjbGBBa80v1ETl6xgs6I45Njl4vgFL/USalCOONgfLB0YhlAyI/
# hPtGEtnHPiX/QJsiIv/UgVnZcQ+GHfQG8B1jmmYQ1Z0uPpFGzs0q99SVdAE/Dqwt
# UXjKSsoNSpUfOothftJNCBSldyWukznZTAHdpxWrYOUGPE3qkonkXOkIrhWEx/KF
# ON+3wa9vf7vdAWJgFIfFqeq9wHNfT0nY8FNhd2aXyxTu/8UqqrqANTVsEXf/bOR2
# UGWxcAG8NYDY1RVF1kxPMSC+SbLXgOV5EJOln6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTcxNTM4MzhaMC8GCSqGSIb3DQEJBDEiBCD4qr05j05ULnRkX/k0
# eCsH5smBpOaY23ixKOpLRMPXuzANBgkqhkiG9w0BAQEFAASCAgDLQrylURPfHxtq
# EGCpVC9cabfrsA6GqrHKtBoO4jpug2c+eTvtnWaDc24LiqAo/0fMhFChYndauBQU
# RO0FTBcmLlVrXJfkSNlDfqzaeABIVf/EpOF1EuS2V5aJabLeypM2y9sSb/vZJ+2B
# HKeKal0u4qZmgN3n5+7fP3BGagCSpKLKkBelhrR7RCNkwcXVp717o1dDg4Vkch2R
# GveEjVXpEsJ+I4UXXRr37dk1E16WmsWufEUAKlLCAT93Yf1MNvICAhnA+Bi1lMCp
# X1sokJYlaBqO2fFQxxZRSX882Qo2PGIWc/3IEeZ6SNTWpeCxG1Tghs6ct535JOCP
# Y6sT9mSQCoM8T6QL5boBNKcNpyj29rGyz6cI/8DuO4bA5iwMUcM8rBr8rEL4vlD9
# rvIFd6cqTex7xhEYxVe9alDjkWNUnxv+0oPI5lXZdYi2WV00lfLckQXqp/wujkaW
# SwWZBgdDjquqTqVxzPzDIuPTLYWxnRRJ7i78yV2y0DQkd9eh7OAmrDKqUc+Z1VEq
# dd0jwjUGOJ1t+HnZ+1jT4JkTP05quTNsYZcL98kmifdypJPUlMVIGDk1L7HfCtsG
# SyOtaexrDprR4SqeeOyF8qznIa6Y6pz9SgDXcqWuWxwV2kGLomWVfueaWrGkWm6D
# 687IIliJn9JnfW/+aoSYpY2EoqRuDA==
# SIG # End signature block
