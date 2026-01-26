
#Requires -Version 5.1
<#
Exit codes:
  0 = Success: channel confirmed Monthly Enterprise, update triggered
  10 = Policy enforced Current Channel (cannot change)
  11 = Prereqs missing (setup.exe/config.xml)
  12 = C2R client missing
  13 = Channel did not change
  14 = Update trigger failed
  15 = ODT run fail
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$LogRoot = Join-Path $env:ProgramData 'PDQ\OfficeChannelSwitch'
$null = New-Item -ItemType Directory -Path $LogRoot -Force -ErrorAction SilentlyContinue
$LogFile = Join-Path $LogRoot ("Run_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

function Write-Log([string]$msg) {
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] $msg"
    Write-Output $line
    Add-Content -Path $LogFile -Value $line
}

$MonthlyGuid = '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114'  # Monthly Enterprise
$CurrentGuid = '492350f6-3a01-4f97-b9c0-c7c6ddf67d60'  # Current Channel

function Get-C2RClientPath {
    $paths = @(
        "$env:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe",
        "$env:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    return $null
}

function Get-UpdateChannelUrl {
    try { (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration").UpdateChannel }
    catch { $null }
}

function Get-GuidFromUrl([string]$url) {
    if ([string]::IsNullOrWhiteSpace($url)) { return $null }
    if ($url -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { return $Matches[1] }
    return $null
}

function Get-PolicyState {
    $pol = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate"
    $out = [ordered]@{}
    foreach ($name in 'UpdateBranch','UpdateChannel','UpdatePath','EnableAutomaticUpdates','UpdateDeadline','TargetVersion') {
        try { $out[$name] = (Get-ItemProperty -Path $pol -ErrorAction Stop).$name } catch { $out[$name] = $null }
    }
    return [pscustomobject]$out
}

# Ensure 64-bit host when possible
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    $ps64 = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    Write-Log "Relaunching in 64-bit PowerShell..."
    & $ps64 -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath
    exit $LASTEXITCODE
}

Write-Log "Starting Office channel switch to Monthly Enterprise..."
Write-Log "Log file: $LogFile"

# Prereqs
$setup  = Join-Path (Get-Location) 'setup.exe'
$config = Join-Path (Get-Location) 'config.xml'
if (!(Test-Path $setup) -or !(Test-Path $config)) {
    Write-Log "ERROR: setup.exe or config.xml missing in working directory: $(Get-Location)"
    exit 11
}

# Policy snapshot
$pol = Get-PolicyState
Write-Log "Policy snapshot: UpdateBranch='$($pol.UpdateBranch)' UpdateChannel='$($pol.UpdateChannel)' UpdatePath='$($pol.UpdatePath)' EnableAutomaticUpdates='$($pol.EnableAutomaticUpdates)' TargetVersion='$($pol.TargetVersion)'"

# If policy enforces Current Channel, abort early
$policyLocksCurrent = $false
foreach ($val in @($pol.UpdateChannel,$pol.UpdateBranch)) {
    if ($val) {
        $ch = "$val".ToLower()
        if ($ch -match "current|ctr|broad|$CurrentGuid") { $policyLocksCurrent = $true }
    }
}
if ($policyLocksCurrent) {
    Write-Log "Policy is enforcing Current Channel. Aborting local change."
    exit 10
}

# Pre-check ClickToRun configuration; clear pinning keys if present
$cfgPath = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
$cfg = Get-ItemProperty -Path $cfgPath -ErrorAction SilentlyContinue
if ($cfg) {
    Write-Log ("Pre-check C2R config: UpdateChannel='{0}' CDNBaseUrl='{1}' UpdatePath='{2}' UpdateToVersion='{3}' TargetVersion='{4}' UpdateDeadline='{5}'" -f `
        $cfg.UpdateChannel, $cfg.CDNBaseUrl, $cfg.UpdatePath, $cfg.UpdateToVersion, $cfg.TargetVersion, $cfg.UpdateDeadline)

    $toClear = @('UpdatePath','UpdateToVersion','TargetVersion','UpdateDeadline')
    foreach ($name in $toClear) {
        if ($cfg.PSObject.Properties[$name] -and $cfg.$name) {
            Write-Log "Clearing pinning key '$name' from ClickToRun\\Configuration"
            Remove-ItemProperty -Path $cfgPath -Name $name -ErrorAction SilentlyContinue
        }
    }
}

# 1) Apply XML via ODT
Write-Log "Running ODT: setup.exe /configure config.xml"
$odt = Start-Process -FilePath $setup -ArgumentList '/configure config.xml' -Wait -PassThru
Write-Log "ODT exit code: $($odt.ExitCode)"
if ($odt.ExitCode -ne 0) {
    Write-Log "ERROR: ODT returned non-zero exit code."
    exit 15
}

Start-Sleep -Seconds 5

# 2) Verify channel in registry
$chanUrl  = Get-UpdateChannelUrl
$chanGuid = Get-GuidFromUrl $chanUrl
Write-Log "UpdateChannel after ODT: '$chanUrl'"
Write-Log "Parsed GUID: '$chanGuid'"

# 3) Fallback if needed with C2R
if ($chanGuid -ne $MonthlyGuid) {
    Write-Log "ODT did not set Monthly Enterprise; attempting OfficeC2RClient fallback..."
    $c2r = Get-C2RClientPath
    if (-not $c2r) {
        Write-Log "ERROR: OfficeC2RClient.exe not found."
        exit 12
    }
    & $c2r /changesetting Channel=MonthlyEnterprise
    $changeExit = $LASTEXITCODE
    Write-Log "C2R /changesetting exit code: $changeExit"

    Start-Sleep -Seconds 5
    $chanUrl  = Get-UpdateChannelUrl
    $chanGuid = Get-GuidFromUrl $chanUrl
    Write-Log "UpdateChannel after C2R: '$chanUrl'"
    Write-Log "Parsed GUID: '$chanGuid'"
}

if ($chanGuid -ne $MonthlyGuid) {
    Write-Log "ERROR: Channel still not Monthly Enterprise (GUID=$chanGuid)."
    Write-Log "Check logs in %ProgramData%\Microsoft\Office\ClickToRun\Log and confirm no tenant Cloud Update assignment."
    exit 13
}

Write-Log "Monthly Enterprise channel confirmed (GUID $MonthlyGuid). Triggering update..."
$c2rPath = Get-C2RClientPath
if (-not $c2rPath) {
    Write-Log "ERROR: OfficeC2RClient.exe not found; cannot trigger update."
    exit 12
}

& $c2rPath /update user forceappshutdown=true
$updateExit = $LASTEXITCODE
Write-Log "C2R /update exit code: $updateExit"

if ($updateExit -ne 0) {
    Write-Log "ERROR: Office update trigger failed."
    exit 14
}

Write-Log "Success: Channel switched to Monthly Enterprise and update triggered."
exit 0

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDHA6sgpQZB3EYK
# 1RZ641V+xXRlkXToKOdJFa0eV8EWx6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDJYvXm3mYo
# IFwjj89XiDh+RnVTC0virEpTztMIeiNuezANBgkqhkiG9w0BAQEFAASCAgCtKTiq
# TL4wNz2lhyJt88plxSUjnh2pHTdLTelR2FtaaEjQBQpax3maxi750xcWPB2/vz3I
# FtIwJUkO5gOpMaaD1q3okyemWRYu+uxFwqgzJPFe3XNRkBpz0zdEohewBeGhe4ln
# Dht7S1q+If+PGZ+3fZ3fI+NVEi1wbqQ4Drpld/FfEQMmnXU1DfwNvE8lGZNsKCxF
# Tg2wVzMnGZbk6ws0sDmJTzpp3GrqVhuCmm9gT4XGix4RB0zrkGW3VU7oHJ0NMOam
# Jr4fWdFxZKbeYd6U7h7PViX1eSHeOCizglvQ9N/Xgt8HdskFrxU9nMyD7bECuDkV
# qrZGPWNqZJ9CjpFG2RePG8P4/+ZriqQDSv6xF0aX82nILHbc7iMr3xVcj2coe2Jg
# pFGB501Uuzuxx7c93RuwbIwL9Cu5pZpbiF3mK6pPnFKalNh9rlbXr9TpBD2Crj5X
# vAIfTHVnSbCiDxlLqfmn7I5LoYkbBv4Q5jlvtnT6EctxIVdhhCj77fR3XbVSLuNR
# q6+P0ibA95HRBGcOQqXIUIsbEUONj84erCDDBaECM/X5MikwINLG6CXzFPku0H61
# GYS7Gao/Sj8LIeBwsgwQ6+hPwPQ4WwTJex9dcvnoE2u/UuXN6AxVlKC/bg8Yg2WD
# BeSVFeSSQIjYESabjgsyY+G/oJNa5h1wGVEce6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMDkyMDQyMjBaMC8GCSqGSIb3DQEJBDEiBCCeI9j6V8sUbPklLo0/
# 0Np3gAxH+qrmyFCts07kWr+s+zANBgkqhkiG9w0BAQEFAASCAgAMQWsAZ5vrKP+i
# XhEm4/3gnWNlU5pCNPAG2I9NIN0IO6NTEOzLPRWzaFvNHRgJONAdiOKF424oEJHV
# 3R2pqaiX4RMpvGDdAMF24LX83RpBlTxq3m7JG0WKd91UxpTKexP6rl328rw/dIbU
# SJzLL23ZIZNAQiwmdtAgg1nkM4cxJUvYNh89PCl31m3GLxvsgwXp33Brg4nZFYmU
# 8Ay4E1ltkszOHMSggNVSUlKYYBJqtzJCGVTeJY+WBauiRqh52CUD8QsRr3XWp3Hw
# l+nrQ8OsI+YvvaSwxZ29K/9mi8GixmRYwihyy4X81D+f5nKiRZvB4m+EAis2nXSV
# p/R0S+LZmf1I3Jyj+mwpK85ssXcMii+r9jxcnHFBUoIqqjkj7pz0uKmGv5Y59c3g
# LHOY6wS/qHd1+jSjs/LFiPn73dLP48W/yuMSS3WEsgElkUJfFT8yfxFo/tdX05E0
# nbb/BZY1Sli2E/HcJoo/5/2Xen1Jq7BaTU9cH1TPJyqtcOVu8iLhUymJNXGdKdih
# pf7EHf52EkiM1UQmzj/77H1brLi6gOdz9Q3ZJRyduQTm6jtvrRJB1hunf1nLbFWa
# IaQeV8Sn3BMzaerYNKPaZ8DuZvZYlyNXH+ry2xGWErQJTHnFDLmamp4TuANwWX0d
# I+hkpyZwQFL7WDYlUQN3IvaNApqTsQ==
# SIG # End signature block
