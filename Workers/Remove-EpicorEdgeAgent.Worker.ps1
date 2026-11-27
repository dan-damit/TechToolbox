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
        $MSIExec_Args = "/x $msiGuid /qn /norestart"
        if ($AnalyzeOnly) {
            Write-Action "[ANALYZE] Would uninstall MSI: $DisplayName -> $cmd $MSIExec_Args"
            return $true
        }
        $p = Start-Process -FilePath $cmd -ArgumentList $MSIExec_Args -Wait -PassThru -WindowStyle Hidden
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
            $MSIExec_Args = "/x `"$msiPath`" /qn /norestart"
            if ($AnalyzeOnly) {
                Write-Action "[ANALYZE] Would uninstall MSI path: $DisplayName -> $cmd $MSIExec_Args"
                return $true
            }
            $p = Start-Process -FilePath $cmd -ArgumentList $MSIExec_Args -Wait -PassThru -WindowStyle Hidden
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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCPJcztaoJfyJxh
# 4QoYNlPVUGbEt0u22Eul+8XtsOi+4aCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC0
# A9YA+djvdPGmuZjwXM3C8oJvtXX+EdGuDUx22FBbdzANBgkqhkiG9w0BAQEFAASC
# AYCRKpQDt3xpt5ShmFtsLE2p/pheehF8WHMjzMovPAA7BtQ8CkJzTUTLkGtZG+km
# ufes1IQuS9ziKWIibqMx2+/Br/l3MRHzIbeRvGzhwgKPnpxhcMYQN+tVZ4QVPNQs
# hjgnvIvU08gnzZ+yxWYK55Kdg7vEo0ow1bzrcwxqwvTg17wwphpSAs3vbIm6zlWz
# MTHQzRXTc/JOU67wg1u+HTD+GE2J+0Jj2QMrizOBcjmHQgce3EZ19lsYHlaVA4oc
# M6MBG42X3LIVkGc1zhI0IFixa5pQ7Jg8RvOFX4MNHMzK9d1dDYHktm7s93JOw2WA
# 0GwG4FUsSVafWCf03oVCSKNDndukBz4CJvTDJvLqSxotkNc27X0LBNOLy0ALn8ny
# kmCfoVnPhf+Ww4fJ3bw6MeH8rPNhxIbnpBfOoW1pnpyXeK88dpEXE3X597cPiaKM
# zScFVQ3EsC8d9KDSAN5mBISrAWtDtVVUSzLyEPhXStKDIRBeRJl8l4yQlJ8W5GiQ
# AR+hggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNjEzWjAvBgkqhkiG
# 9w0BCQQxIgQgaZA0gidg1tSKrSpPe2ZUDAMfhQ5UfujLhoTNnfzzfU8wDQYJKoZI
# hvcNAQEBBQAEggIAsbiEA5RK7F4jdA0w+7vZP/x0pZ/vCk56VLj5dXtQizw9DTSR
# ZzX6GJSmVu7c6/9UaKv5yWGeiUiouqEK1XYQrJrHSO27436WUbGs1SXKm1OxbfMk
# grZ7kUmLQhuVF069g28AR8o2ze/Wz1A8dKJlwa7DBQwww7S29GzCLv7VH6AVWc9x
# ZnxiBk3q70uUCHwnHQ9M4XIaRjSk0nfo/HACqxqYkfcrmWuz03L1uikZ+CCEOEPU
# uYmyg8xUmycmTSJrhgNb7hm/2BWdjtusPlBfKA01B6rMzVvgHuQIh0P66DdNaA0s
# 76qRTDQgiDouqKHa+mqkLuwWSvXXXbzVlgbHuRUf4eIgwavsuBAyGwoCEdoEkdB5
# JzpBT/cfgyQWwrmGm0V/ooJsRyBI2V5yJD0hk0mvAXYPfV014ZmhIbowkp8oUTuz
# sgA7kwC6SB0dssJlbqK4gHrxI+Hem6MVvllv6wDX0PBdpjH/Ncxja11zHRHWfG0a
# ASD3r2Vbd2CwH5bSjljSfpSHHUiNnSih7J/lP2QYeyX8HltaGC1ms0/O2kPt9p7V
# 54C/OWEOzwZ2/HlUb9/jT0LuaKWLBJzlZdZ6mo6yDyzlABART8h1460RJmv+sBcO
# 2RrtnlRLAAnewmYm7+mVAFaG3WYllCITn1hYSXZhwDibOXHvA8Q797qD8Xk=
# SIG # End signature block
