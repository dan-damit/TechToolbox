function Get-SystemWorkerScriptContent {
    @'
param(
  [string]$ArgsPath
)

$ErrorActionPreference = 'Stop'

# Read args
$cfgRaw = if ($ArgsPath -and (Test-Path -LiteralPath $ArgsPath -ErrorAction SilentlyContinue)) {
  Get-Content -LiteralPath $ArgsPath -Raw -Encoding UTF8
} else { $null }

$cfg = if ($cfgRaw) { $cfgRaw | ConvertFrom-Json } else { $null }

# Extract settings
$timestamp       = if ($cfg.Timestamp) { [string]$cfg.Timestamp } else { (Get-Date -Format 'yyyyMMdd-HHmmss') }
$connectPath     = if ($cfg.ConnectDataPath) { [string]$cfg.ConnectDataPath } else { (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent') }
$extra           = @()
if ($cfg.ExtraPaths) {
  # Ensure array type after deserialization
  if ($cfg.ExtraPaths -is [string]) { $extra = @($cfg.ExtraPaths) }
  elseif ($cfg.ExtraPaths -is [System.Collections.IEnumerable]) { $extra = @($cfg.ExtraPaths) }
}

# Paths
$tempRoot = Join-Path $env:windir 'Temp'
$staging  = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME,$timestamp)
$zipPath  = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME,$timestamp)
$doneFlg  = Join-Path $staging 'system_done.flag'

# Clean & create staging
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# Build PDQ paths
$pdqPaths = @(
  'C:\ProgramData\Admin Arsenal\PDQ Deploy\Logs'
  'C:\ProgramData\Admin Arsenal\PDQ Inventory\Logs'
  'C:\Windows\Temp\PDQDeployRunner'
  'C:\Windows\Temp\PDQInventory'
  (Join-Path $env:SystemRoot 'System32\Winevt\Logs\PDQ.com.evtx')  # fallback; we'll export via wevtutil too
)
if ($connectPath) {
  $pdqPaths += (Join-Path $connectPath 'PDQConnectAgent.db')
  $pdqPaths += (Join-Path $connectPath 'Updates\install.log')
}

# Normalize extras (PS 5.1-safe)
$extras = if ($null -eq $extra -or -not $extra) { @() } else { $extra }

# Resilient copy helper (Copy-Item → robocopy /B)
function Copy-PathResilient {
  param([string]$SourcePath,[string]$StagingRoot)

  if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) { return $false }

  $leaf = Split-Path -Leaf $SourcePath
  $dest = Join-Path $StagingRoot $leaf

  try {
    $it = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if ($it -is [IO.DirectoryInfo]) {
      New-Item -ItemType Directory -Path $dest -Force | Out-Null
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Recurse -Force -ErrorAction Stop
    } else {
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
    }
    return $true
  } catch {
    $primary = $_.Exception.Message
    try {
      $rc = Get-Command robocopy.exe -ErrorAction SilentlyContinue
      if (-not $rc) { throw "robocopy.exe not found" }
      $it2 = Get-Item -LiteralPath $SourcePath -ErrorAction SilentlyContinue
      if ($it2 -is [IO.DirectoryInfo]) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $null = & $rc.Source $SourcePath $dest /E /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      } else {
        $srcDir = Split-Path -Parent $SourcePath
        $file   = Split-Path -Leaf   $SourcePath
        New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
        $null = & $rc.Source $srcDir $StagingRoot $file /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      }
      if ($LASTEXITCODE -lt 8) { return $true }
      Add-Content -Path $copyErr -Value ("{0} | robocopy exit {1} | {2}" -f (Get-Date), $LASTEXITCODE, $SourcePath) -Encoding UTF8
      return $false
    } catch {
      Add-Content -Path $copyErr -Value ("{0} | Copy failed: {1} | {2}" -f (Get-Date), $primary, $SourcePath) -Encoding UTF8
      return $false
    }
  }
}

# Merge non-empty paths (no pre-Test-Path to avoid "Access denied" noise)
$all = @($pdqPaths; $extras) | Where-Object { $_ } | Select-Object -Unique
foreach ($p in $all) { try { Copy-PathResilient -SourcePath $p -StagingRoot $staging } catch {} }

# Export event log by name (avoids in-use copy issues)
try {
  $destEvtx = Join-Path $staging 'PDQ.com.evtx'
  if (-not (Test-Path -LiteralPath $destEvtx -ErrorAction SilentlyContinue)) {
    $logName = 'PDQ.com'
    $wevt = Join-Path $env:windir 'System32\wevtutil.exe'
    if ($env:PROCESSOR_ARCHITEW6432 -or $env:ProgramW6432) {
      $sysnative = Join-Path $env:windir 'Sysnative\wevtutil.exe'
      if (Test-Path -LiteralPath $sysnative) { $wevt = $sysnative }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $wevt
    $psi.Arguments = "epl `"$logName`" `"$destEvtx`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [Diagnostics.Process]::Start($psi); $p.WaitForExit()
    if ($p.ExitCode -ne 0) {
      $err = $p.StandardError.ReadToEnd()
      Add-Content -Path $copyErr -Value ("{0} | wevtutil failed ({1}): {2}" -f (Get-Date), $p.ExitCode, $err) -Encoding UTF8
    }
  }
} catch {
  Add-Content -Path $copyErr -Value ("{0} | wevtutil exception: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
}

# Useful metadata
try {
  Get-CimInstance Win32_Service |
    Where-Object { $_.Name -like 'PDQ*' -or $_.DisplayName -like '*PDQ*' } |
    Select-Object Name,DisplayName,State,StartMode |
    Export-Csv -Path (Join-Path $staging 'services.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -match 'PDQ' -or $_.Publisher -match 'Admin Arsenal' } |
    Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
    Export-Csv -Path (Join-Path $staging 'installed.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  $sys = Get-ComputerInfo -ErrorAction SilentlyContinue
  if ($sys) { $sys | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $staging 'computerinfo.json') -Encoding UTF8 }
  $PSVersionTable | Out-String | Set-Content -Path (Join-Path $staging 'psversion.txt') -Encoding UTF8
} catch {}

# Zip
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zipPath -Force

# Done flag
"ZipPath=$zipPath" | Set-Content -Path $doneFlg -Encoding UTF8
'@
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDytrroZRSHAZ/R
# yHct5gr6ZqGSQGWcv4iVk+p6tugItqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAWcJHIlMqa
# itPlBi1Wg1duwZCCGtdyP3V4+J9p7QZLnjANBgkqhkiG9w0BAQEFAASCAgBczPgp
# F/9cvA0RS6u3gS1YMuSgI1hc5++G2Tf+NOWXxwdfP4/m9BnTUjzRtF0o/0H+/pP8
# xsvRorzSHSBtt5LJSzNxNXnroZYMLhUa17ntNrUq1MPa4xhhE5DRnbg1AcadryuQ
# RZoqg2zK6zDu9WtvLjVaPOrpI8/JJFuB61yEu92WvCKZwVpCHthV+adQP3qFM9UO
# tJB5afnVDeWgc3BllTK46vV635HO5w/UAS6a2uMYq8gmf37gChZF+uunW663j2By
# Q/RWZx6P4r/NXxKrIU2mGBWdSjP8aL4CnGO6ChLYJgPv8467oV4kBjk80sRpLkm1
# +OsWmPZoZ7ujvIoGs/NWREVvtQOmjJdqKhqaU6BsrTzoJePF0FbdJgfpMY/Jwtzg
# M/49K/0158EDSwh5qbHVnhXZ8brJolq0geueSYKGGFBguwCjxHMvWb/X0X2loh5f
# za7ArUx1UByFqhFJyIGACyNOguCJITdfIdEiwv775aTHi+JBVVMwagHedH1dNLWY
# 3ZNR6azc1Kh0NgBo8ievrG4PZjnEsUBdx7dvW09kEqng3wk8C5biQvvJOijnRT5A
# 1wgBahLIsy5oAKYImeMLUWTi+ihTHsADMZUnVo7V+p4Ir41z1Lv2Z/OTy+sPgR7z
# OXB6WMEkPdQYnYjePNt26Gke6upFOIE/oB1LEqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMDYxODMwMTdaMC8GCSqGSIb3DQEJBDEiBCDEReURIxS8V3Dgo2iF
# SYqzc8Sb5Nk2J9KU8Tv8HRKtRzANBgkqhkiG9w0BAQEFAASCAgBifcz0DoXvf4cX
# MBgRAdD2ZS76YFKjIGiw/OgeXHCbJagK3fHmZGOX/W/WtYOLzcKpWhpoN47kD+rm
# ntfqpdq41wFCf93+M1BSUlqy1z0uvpRa0e2cSthIjYijQ5ozopADGgS7UQM4z7lT
# A9F0iTHNPuxFfj32brQ3Obm2oZMmDJSMos5XHAenXR2PoDfkXxYmlt2RJqVjRfk2
# 0EiG9yo6AfJIt/J5rvYWMZVOn5+hAUnCNtp46rvA1hH85pGIRvi79gbV+w1f2+1D
# B5dQWlC/4W8u9VXuKJd61hsrrNa/LdP5eafmc4S7RXgziCSiS8ek7A/mZaPiseHJ
# c0Cr8JY+VL0YpI4bv6qUfW6bYznsEVMZGTe80AZyDQSLp8cO5RC3wYjAci0doOmc
# fNwdeMIpknrt4d4SvZtSlPYR3h0YjoXKQlWCQZBouPemITI9GRrd9I1rQPnPz/zo
# +89IogpxpqSSM+kBI6FXazFWl2FTHAW8HnCw2kFSEtE1lPt60lFC8G2/TIiczwes
# 5KSo/IReN3dOYyINM96eiuDve0janndEjqpVuOxpr4k/xX02IU6oih/yjRWd/PPm
# qikiIHuaj0VzZYUyadgryk4b8kFH5B+ImNojJt55hId+ykjDVfPbw1gy89KhXx6L
# uQhKRxAquY4Z577kdtN2mJiRCYZ+7w==
# SIG # End signature block
