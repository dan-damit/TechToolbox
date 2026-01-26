
<# Author: Dan.Damit (https://github.com/dan-damit)
Remote DISM Repair with opt-in CredSSP, UNC validation, timeout control,
fallback repair, structured output, and optional dry-run mode.

Parameters:
-RemoteComputer: Target computer name or FQDN
-RemoteLogDir: Remote directory for DISM logs (default: C:\Temp\DISM-Remote)
-DryRun: Validate connectivity and access without executing DISM
-UseCredSSP: OPT-IN to use CredSSP (only when you need second-hop delegation)
-CopyLogsLocal: Copy remote DISM log to local temp folder
-UseRepairWindowsImageFallback: Use Repair-WindowsImage if DISM fails

Requires: Admin rights on both client and remote, WinRM enabled.
#>

# -----------------------------
# Parameters
# -----------------------------
param(
    [string]$RemoteComputer,
    [string]$RemoteLogDir = "C:\Temp\DISM-Remote",
    [switch]$DryRun,
    [switch]$UseCredSSP,            # <-- opt-in (was SkipCredSSP)
    [switch]$CopyLogsLocal,
    [switch]$UseRepairWindowsImageFallback
)

# -----------------------------
# Transcript
# -----------------------------
$TranscriptLog = Join-Path $env:TEMP "DISM-Remote-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Start-Transcript -Path $TranscriptLog -Force | Out-Null

# -----------------------------
# Prompt for RemoteComputer
# -----------------------------
$RemoteComputer = Read-Host "Enter Remote Computer name (default: $RemoteComputer)"
if ([string]::IsNullOrWhiteSpace($RemoteComputer)) {
    $RemoteComputer = $PSBoundParameters['RemoteComputer'] ?? $RemoteComputer
}

# -----------------------------
# Ask whether to use a local source first
# -----------------------------
do {
    $ans = Read-Host "Use a local repair source first? (Y/N)"
} while ($ans -notmatch '^[YyNn]$')

$UseLocalSource = $ans -match '^[Yy]$'
$SourcePath = $null
if ($UseLocalSource) {
    do {
        $SourcePath = Read-Host "Enter local/UNC source path (e.g., \\server\share\...\sources\sxs or D:\sources\sxs)"
    } while ([string]::IsNullOrWhiteSpace($SourcePath))
}

# -----------------------------
# Credential Prompt
# -----------------------------
$Cred = Get-Credential -Message "Enter credentials with admin rights on $RemoteComputer"

# -----------------------------
# Helper: Preflight WSMan Check
# -----------------------------
function Test-WSManConnection {
    param([string]$Computer)
    try {
        Test-WSMan -ComputerName $Computer -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Throw "WSMan connection to '$Computer' failed: $($_.Exception.Message)"
    }
}

# -----------------------------
# Helper: CredSSP Enable/Disable (used only when -UseCredSSP is set)
# -----------------------------
function Enable-CredSSP {
    param([string]$RemoteComputer)

    Write-Host "Enabling CredSSP..." -ForegroundColor Cyan

    try {
        Enable-WSManCredSSP -Role Client -DelegateComputer $RemoteComputer -Force -ErrorAction Stop
    }
    catch {
        Write-Warning "Client CredSSP enable failed or already enabled: $($_.Exception.Message)"
    }

    try {
        Invoke-Command -ComputerName $RemoteComputer -Credential $Cred -ScriptBlock {
            Enable-WSManCredSSP -Role Server -Force
        } -ErrorAction Stop
    }
    catch {
        Throw "Failed to enable CredSSP on remote server: $($_.Exception.Message)"
    }
}

function Disable-CredSSP {
    param([string]$RemoteComputer)

    Write-Host "Disabling CredSSP..." -ForegroundColor Cyan

    try { Disable-WSManCredSSP -Role Client -ErrorAction Stop }
    catch { Write-Warning "Client CredSSP disable failed: $($_.Exception.Message)" }

    try {
        Invoke-Command -ComputerName $RemoteComputer -Credential $Cred -ScriptBlock {
            Disable-WSManCredSSP -Role Server
        } -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to disable CredSSP on remote server: $($_.Exception.Message)"
    }
}

# -----------------------------
# Helper: Remote DISM Check
# -----------------------------
function Test-RemoteDism {
    param($Session)
    Invoke-Command -Session $Session -ScriptBlock {
        if (-not (Get-Command dism.exe -ErrorAction SilentlyContinue)) {
            Throw "DISM.exe not found on remote system."
        }
    }
}

# -----------------------------
# Helper: Timeout-Safe DISM (flexible: with/without Source & LimitAccess)
# -----------------------------
function Invoke-RemoteDism {
    param(
        $Session,
        [string]$SourcePath,
        [string]$LogFile,
        [bool]$IncludeLimitAccess = $false,
        [int]$TimeoutSeconds = 7200  # 2 hours
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param($SourcePath, $LogFile, $IncludeLimitAccess, $TimeoutSeconds)

        $ags = @(
            "/Online",
            "/Cleanup-Image",
            "/RestoreHealth",
            "/LogPath:$LogFile"
        )

        if ($SourcePath) { $ags += "/Source:`"$SourcePath`"" }
        if ($IncludeLimitAccess) { $ags += "/LimitAccess" }

        $proc = Start-Process -FilePath "dism.exe" -ArgumentList $ags -PassThru -NoNewWindow

        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            $proc.Kill()
            Throw "DISM timed out after $TimeoutSeconds seconds."
        }

        [pscustomobject]@{
            ExitCode = $proc.ExitCode
            LogPath  = $LogFile
        }
    } -ArgumentList $SourcePath, $LogFile, $IncludeLimitAccess, $TimeoutSeconds
}

# -----------------------------
# MAIN EXECUTION
# -----------------------------
try {
    Write-Host "Preflight: Testing WSMan connectivity..." -ForegroundColor Cyan
    Test-WSManConnection -Computer $RemoteComputer

    # Only enable CredSSP if explicitly requested (opt-in)
    if ($UseCredSSP) {
        Enable-CredSSP -RemoteComputer $RemoteComputer
    }

    Write-Host "Creating remote session..." -ForegroundColor Cyan

    # Prefer Kerberos in domain; fallback to Negotiate; include CredSSP only if requested
    $authOrder = @('Kerberos','Negotiate')
    if ($UseCredSSP) { $authOrder += 'CredSSP' }

    $Session = $null
    foreach ($auth in $authOrder) {
        try {
            $Session = New-PSSession -ComputerName $RemoteComputer `
                                     -Credential $Cred `
                                     -Authentication $auth `
                                     -ConfigurationName Microsoft.PowerShell `
                                     -ErrorAction Stop
            Write-Host "Session created using $auth." -ForegroundColor Green
            break
        }
        catch {
            Write-Warning "New-PSSession with '$auth' failed: $($_.Exception.Message)"
        }
    }
    if (-not $Session) { throw "Unable to create PSSession to $RemoteComputer with any mechanism." }

    # Dry-run mode stops here
    if ($DryRun) {
        Write-Host "Dry-run mode: Validating remote access only." -ForegroundColor Yellow

        if ($UseLocalSource) {
            $RemoteSourceTest = Invoke-Command -Session $Session -ScriptBlock {
                param($Path) Test-Path $Path
            } -ArgumentList $SourcePath

            if (-not $RemoteSourceTest) {
                Throw "Remote cannot access source path: $SourcePath"
            }
        }

        Write-Host "Dry-run completed successfully." -ForegroundColor Green
        return
    }

    # Validate remote DISM
    Test-RemoteDism -Session $Session

    # Ensure remote log directory
    Invoke-Command -Session $Session -ScriptBlock {
        param($Dir)
        if (-not (Test-Path $Dir)) { New-Item -Path $Dir -ItemType Directory -Force | Out-Null }
    } -ArgumentList $RemoteLogDir

    $RemoteDismLog = Join-Path $RemoteLogDir "DISM-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

    # -------------------------
    # Run DISM according to choice
    # -------------------------
    $DismResult = $null

    if ($UseLocalSource) {
        Write-Host "Validating remote access to source '$SourcePath'..." -ForegroundColor Cyan
        $RemoteSourceTest = Invoke-Command -Session $Session -ScriptBlock {
            param($Path) Test-Path $Path
        } -ArgumentList $SourcePath

        if (-not $RemoteSourceTest) {
            Write-Warning "Remote computer cannot access source '$SourcePath'. Proceeding with ONLINE repair."
            Write-Host "Running DISM online (no /Source, allows WU/WSUS)..." -ForegroundColor Cyan
            $DismResult = Invoke-RemoteDism -Session $Session -SourcePath $null -LogFile $RemoteDismLog
        }
        else {
            Write-Host "Running DISM with local source (offline-only using /LimitAccess)..." -ForegroundColor Cyan
            $DismResult = Invoke-RemoteDism -Session $Session -SourcePath $SourcePath -LogFile $RemoteDismLog -IncludeLimitAccess $true

            if ($DismResult.ExitCode -ne 0) {
                Write-Warning "DISM with local source failed (ExitCode=$($DismResult.ExitCode)). Retrying ONLINE repair..."
                $DismResult = Invoke-RemoteDism -Session $Session -SourcePath $null -LogFile $RemoteDismLog
            }
        }
    }
    else {
        Write-Host "Running DISM online (no /Source, allows WU/WSUS)..." -ForegroundColor Cyan
        $DismResult = Invoke-RemoteDism -Session $Session -SourcePath $null -LogFile $RemoteDismLog
    }

    Write-Host "DISM exit code: $($DismResult.ExitCode)" -ForegroundColor Yellow

    # -------------------------
    # Optional PowerShell cmdlet fallback
    # -------------------------
    if ($DismResult.ExitCode -ne 0 -and $UseRepairWindowsImageFallback) {
        Write-Warning "DISM failed. Attempting Repair-WindowsImage fallback..."

        $Fallback = Invoke-Command -Session $Session -ScriptBlock {
            param($SourcePathLocal)
            try {
                if ($SourcePathLocal) {
                    # First try with source, offline-only; then fallback online
                    Repair-WindowsImage -Online -RestoreHealth -Source $SourcePathLocal -LimitAccess -ErrorAction Stop
                }
                else {
                    # No source selected; allow online repair
                    Repair-WindowsImage -Online -RestoreHealth -ErrorAction Stop
                }
                "OK"
            }
            catch { $_.Exception.Message }
        } -ArgumentList $SourcePath

        if ($Fallback -ne "OK") {
            Throw "Fallback failed: $Fallback"
        }
    }

    # Optional: copy logs locally
    if ($CopyLogsLocal) {
        $LocalCopy = Join-Path $env:TEMP "Remote-DISM-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Copy-Item -Path $RemoteDismLog -Destination $LocalCopy -FromSession $Session
        Write-Host "Copied remote DISM log to: $LocalCopy" -ForegroundColor Green
    }

    # Tail CBS
    Write-Host "Pulling last 50 lines of CBS.log..." -ForegroundColor Cyan
    $CBS = Invoke-Command -Session $Session -ScriptBlock {
        $Path = "C:\Windows\Logs\CBS\CBS.log"
        if (Test-Path $Path) { Get-Content $Path -Tail 50 }
        else { "CBS.log not found." }
    }

    # Structured return object
    [pscustomobject]@{
        Computer     = $RemoteComputer
        UsedLocal    = $UseLocalSource
        SourcePath   = $SourcePath
        DismExitCode = $DismResult.ExitCode
        DismLog      = $DismResult.LogPath
        Transcript   = $TranscriptLog
        Timestamp    = (Get-Date)
        CBS_Tail     = $CBS
    }

}
catch {
    Write-Error "Error: $($_.Exception.Message)"
}
finally {
    if ($Session) { Remove-PSSession $Session }
    if ($UseCredSSP) { Disable-CredSSP -RemoteComputer $RemoteComputer }   # <-- only if opted-in
    Stop-Transcript | Out-Null
    Write-Host "Transcript saved: $TranscriptLog" -ForegroundColor Yellow
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA3TJEyUxVv9cET
# mkQo9rNpSYgKL50JWa12F3JQjx/kE6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCG3KgoQMiv
# nuyTg38dHDx9t7HIAZN9oMFulVg01n4RmDANBgkqhkiG9w0BAQEFAASCAgC6ZW+n
# tmf3Zqqy3m1C+B6HUXhvOsU6cJLN0RPKsfC62ABQ9JtrIlIqVsOMD14s9hPhyRY6
# OkFct8SKDq7zt8T8PZ/sJv0Fk+14l8XCW3ucv5FP2JwJJ4xQ8OAm8OyJxR5obfXm
# yVcgjNdpFoBjiJwON6332jaDitgq2jwIJOYvNrjPrD/7NVVxalV15dl70xXEZHiy
# LYtZZBQ8VnSsS1bbyydbsQVQGwkfcKJ1M2dwCVgjTlIv7XBJoBbzz9iT41rGO1zk
# BqcntqaAfXjsy1seE5U97/4c62UzgCp85AtF19Vc9/9W024DZxxVCqPjcmj9rjRS
# bD9NprSqlrcDDq7eZ4TymWlmel6UKPSNl2lphHQLHgSd5oX8hUdDsmnzbK2UrZ/n
# GtisoNZxidlQutJmbF0eXGkW75kiNCoEbnD1A6W4SUXjKtQlBfKozmtjH89hsppH
# qg2BJxogSWkFPZgrHdlGWw6Gbvtb6MDDQswCRWlL7sALxz1WHwurFOlX+aFKiPO6
# +stF4xpKZBwZHcuF1j/nPTwkXC1PHeov9iOmLfJlqLGJZStPg+4M71G7KZ0HuIEm
# k3NckuVxTSXRzTgbOd+5DSvAQD3utIZq7fomX57exQh2ptohk4+c8L9kWlEB1aid
# 04AEFcqXQ8RzDxm5Qk+kYIKdBr+PjVoxCIZ+fqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNTEyMjkyMTMyNTRaMC8GCSqGSIb3DQEJBDEiBCDFEHCATkjZiYi59yXP
# 5KTU155RGWVlcx2AUvCjDCk35jANBgkqhkiG9w0BAQEFAASCAgBEqlp2DapCTGXM
# FoUcfbLPglq2+17MMbSFFiZj5CB7uUx4Qfnn+KC+HwkItqK9rrtDzVSfMjc6rdrU
# Eb5bLT7gM7unih5mHSUcduntBdA6PUKFiUrWm3LDfAirQ3x4BTDrUb6LhDf/HWz1
# LH2AkyoKlTQL/bHB3sYKv6ak/qP1BNtIGwoIq0qmSasmpx7FzY0kk2302lnqlrP6
# DTkIZHCg3wNuAuOd5u8RHgpyZVKblPIq+WMRxfEFLu8SMwlOe08uzrR00rucanRh
# UorsB/PTL77Wx0nRR64NRJveMirup7f3b4fOzDSApxcTK6FUQPwVBoshl5x+xdYe
# BHAtrDdmvS2PupBwfakLPc6gHaCk4ln1D/L4gNaYtTsCvU+r9ByLfguNGJx6JJKd
# O73aZjujPW5Vi19UhV+6wkNXAUpTRXRKRYeGFhP3ocD/NQASloIRJ7WTrlAPgCTi
# lWGtuxVbZJe4eewSl9Mtb6kbyau5C3EtW0hTBTMtjma8YlTz+CC78GER8ewo+ot4
# wHrXHW2WMf8mNwNB4WqAkHAyY894tC5G5moXcAG5VmVeGFUOjZCkTkJ8x2seKBoB
# Ax344kUH7DMpXzmNP8lvwrooaai3MyJ3JX3Y9EMP6tGvq23vkSCy4ZBr3CN4FrW5
# Ht2uHw0Q+WHAlsE8O/5IcLL1GEZh5Q==
# SIG # End signature block
