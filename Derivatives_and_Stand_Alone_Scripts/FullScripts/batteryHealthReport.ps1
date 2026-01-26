# Author: Dan.Damit
# Requires: Windows PowerShell 5.1 (no external modules)
# Purpose: Extract data under "Installed batteries" from powercfg battery report, output JSON with health metrics

# Paths
$reportPath  = "C:\temp\battery-report.html"
$outputJson  = "C:\temp\installed-batteries.json"
$debugInfo   = "C:\temp\installed-batteries_debug.txt"

# --- Generate report ---
$reportDir = Split-Path -Parent $reportPath
if ($reportDir -and -not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}
powercfg.exe /batteryreport /output "$reportPath" | Out-Null

# Wait briefly for the file to be written and non-empty
$tries = 0
while ($tries -lt 40) {
    if (Test-Path -LiteralPath $reportPath) {
        $size = (Get-Item -LiteralPath $reportPath).Length
        if ($size -gt 0) { break }
    }
    Start-Sleep -Milliseconds 250
    $tries++
}

if (-not (Test-Path -LiteralPath $reportPath)) {
    Write-Error "Battery report not found at: $reportPath"
    exit 1
}

# --- Read HTML and Update ---
$html = Get-Content -LiteralPath $reportPath -Raw
$htmlNorm = $html -replace '&nbsp;', ' ' -replace '\r\n', "`n"

# --- Helpers ---
function Update-Text {
    param([string]$s)
    if (-not $s) { return "" }
    try { $s = [System.Web.HttpUtility]::HtmlDecode($s) } catch { }
    $s = ($s -replace '<[^>]+>', '')
    ($s -replace [char]0xA0, ' ' -replace '\s+', ' ').Trim()
}

function Update-CamelKey {
    param([string]$label)
    $l = Update-Text $label
    $l = ($l.ToLower() -replace '[^a-z0-9 ]','').Trim()
    if ([string]::IsNullOrWhiteSpace($l)) { return "" }
    $parts = $l -split '\s+'
    $key = $parts[0]
    for ($i=1; $i -lt $parts.Length; $i++) {
        $key += ($parts[$i].Substring(0,1).ToUpper() + $parts[$i].Substring(1))
    }
    return $key
}

# Parse capacity strings like "55,000 mWh", "55 Wh", "55,000", etc. into integer mWh
function Get-mWh {
    param([string]$text)
    $t = Update-Text $text
    # Capture number and optional unit
    $m = [regex]::Match($t, '(?i)\b([0-9][0-9,\.]*)\s*(mwh|wh)?\b')
    if (-not $m.Success) { return $null }
    $num = $m.Groups[1].Value
    $unit = $m.Groups[2].Value.ToLower()
    # Update number: remove commas; support decimals (round)
    $num = ($num -replace ',','')
    $val = 0
    if ($num -match '^\d+(\.\d+)?$') {
        $val = [double]$num
    } else {
        return $null
    }
    switch ($unit) {
        'mwh' { return [int][math]::Round($val) }      # already mWh
        'wh'  { return [int][math]::Round($val * 1000) } # convert Wh → mWh
        default {
            # No unit—assume mWh if value is large, else Wh
            if ($val -ge 1000) { return [int][math]::Round($val) } else { return [int][math]::Round($val * 1000) }
        }
    }
}

# --- Find Installed batteries section (any heading level), then first table ---
$installedPattern = '(?is)<h[1-6][^>]*>.*?Installed\W+Batter(?:y|ies).*?</h[1-6]>.*?<table\b[^>]*>(.*?)</table>'
$sectionMatch = [regex]::Match($htmlNorm, $installedPattern)

# Fallback: find a table containing typical battery fields if heading is different/translated
if (-not $sectionMatch.Success) {
    $tableMatches = [regex]::Matches($htmlNorm, '(?is)<table\b[^>]*>(.*?)</table>')
    foreach ($tm in $tableMatches) {
        if ($tm.Value -match '(?is)(Design\s+Capacity|Full\s+Charge\s+Capacity|Chemistry|Serial|Manufacturer)') {
            $sectionMatch = $tm
            break
        }
    }
}

if (-not $sectionMatch.Success) {
    Write-Error "Could not locate the Installed batteries table (by heading or typical fields)."
    $headings = [regex]::Matches($htmlNorm, '(?is)<h[1-6][^>]*>(.*?)</h[1-6]>') | ForEach-Object {
        Update-Text $_.Groups[1].Value
    }
    $headings | Set-Content -LiteralPath $debugInfo -Encoding UTF8
    Write-Warning "Wrote detected headings to $debugInfo"
    exit 2
}

# --- Extract tbody if present; else parse rows directly ---
$tableHtml  = $sectionMatch.Value
$tbodyMatch = [regex]::Match($tableHtml, '(?is)<tbody\b[^>]*>(.*?)</tbody>')
$rowsHtml   = if ($tbodyMatch.Success) { $tbodyMatch.Groups[1].Value } else { $tableHtml }

$rowMatches = [regex]::Matches($rowsHtml, '(?is)<tr\b[^>]*>(.*?)</tr>')
if ($rowMatches.Count -eq 0) {
    Write-Error "Installed batteries table has no <tr> rows."
    exit 3
}

# --- Parse into battery objects and compute health ---
$batteries = New-Object System.Collections.Generic.List[object]
$current   = [ordered]@{}
$startKeys = @('manufacturer','serialNumber','name','batteryName')

foreach ($rm in $rowMatches) {
    $rowInner    = $rm.Groups[1].Value
    $cellMatches = [regex]::Matches($rowInner, '(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>')
    if ($cellMatches.Count -eq 0) { continue }

    if ($cellMatches.Count -eq 2) {
        $label = Update-Text $cellMatches[0].Groups[1].Value
        $value = Update-Text $cellMatches[1].Groups[1].Value

        $key = Update-CamelKey $label
        if ([string]::IsNullOrWhiteSpace($key)) { continue }

        # Start a new battery object if a repeated start key appears (multi-battery heuristic)
        if ($startKeys -contains $key -and $current.Contains($key)) {
            # compute health for current before committing
            $dc = if ($current.Contains('designCapacity')) { Get-mWh $current['designCapacity'] } else { $null }
            $fc = if ($current.Contains('fullChargeCapacity')) { Get-mWh $current['fullChargeCapacity'] } else { $null }
            if ($dc -and $fc -and $dc -gt 0) {
                $current['designCapacity_mWh']     = $dc
                $current['fullChargeCapacity_mWh'] = $fc
                $current['healthRatio']            = [math]::Round($fc / $dc, 4)
                $current['healthPercent']          = [math]::Round(($fc * 100.0) / $dc, 2)
            }
            if ($current.Count -gt 0) { $batteries.Add([PSCustomObject]$current) }
            $current = [ordered]@{}
        }

        $current[$key] = $value
    }
    else {
        # Multi-column rows: capture generically
        $vals = @()
        foreach ($cm in $cellMatches) { $vals += (Update-Text $cm.Groups[1].Value) }
        if ($vals.Count -gt 0) {
            if (-not $current.Contains('rows')) { $current['rows'] = New-Object System.Collections.Generic.List[object] }
            $current['rows'].Add($vals)
        }
    }
}

# compute health for the last battery
if ($current.Count -gt 0) {
    $dc = if ($current.Contains('designCapacity')) { Get-mWh $current['designCapacity'] } else { $null }
    $fc = if ($current.Contains('fullChargeCapacity')) { Get-mWh $current['fullChargeCapacity'] } else { $null }
    if ($dc -and $fc -and $dc -gt 0) {
        $current['designCapacity_mWh']     = $dc
        $current['fullChargeCapacity_mWh'] = $fc
        $current['healthRatio']            = [math]::Round($fc / $dc, 4)
        $current['healthPercent']          = [math]::Round(($fc * 100.0) / $dc, 2)
    }
    $batteries.Add([PSCustomObject]$current)
}

if ($batteries.Count -eq 0) {
    Write-Error "No battery data parsed under Installed batteries."
    exit 4
}

# --- Output JSON ---
$dir = Split-Path -Parent $outputJson
if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$json = $batteries | ConvertTo-Json -Depth 6
Set-Content -LiteralPath $outputJson -Value $json -Encoding UTF8

Write-Host "Exported JSON with health metrics to $outputJson"
Write-Host $json

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAhONnfVWPKugP4
# 57j0f3T1roiBqsMu4/gXeZp/UVofMqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB7HKBKFZt9
# l//a+kVsm+UK5k8M3PNxj9m8n4UGGe3qYDANBgkqhkiG9w0BAQEFAASCAgAvQPQw
# /6kI96sXU/xJW6KZMBJzdkIFqmJH5VZ4htwKTxPgokQ5zuwzV2W7T/oL8EninNBT
# XPLNCqEmDS2z6mCBJZFOuktiCvFwB/uNjbXLMQ3J/eVeSkZkeI5rqUDLHcK5igOo
# lG4xJpRl03zNI3V2jw8CAflkDiKRftkkhu9Q+G/4CSx/LqRJ4nFK7zZGawiLtlH2
# vZlvznk8ll4AzhDnsQ5e4NWAt5FbDf1TLvxhmMqVh1TOQrCNS0M8NBFb6Sa8FQ8Y
# LOhYCIlwipiam8EVBAE4iGGte5hq7iXtMH5qdPFRr6SGLe/77mvEkZ7JC4dhteX2
# g5xU7QMfckDpgyt/pJgwKMqqT7ZIXAwgEZ18hIyBZnQh7pBw6rpTCoC85J0cWZjZ
# H9VsANaz/EB9XnLR8j8An34BisAYSrQNBBOIj9rMyFq6jWmbvJv+CyIIwtAq/aaQ
# NsHl4BnxqeTN11OO2WCneG2P5Yins54adtgmGGpOjmfnxTW9JfSjr4YSBCSycDCv
# mDjtVCEtsHIDBkUpWe1EGuKDCVjORUBgkeWJsNhKFS08ocIhkgRPfiQFq5b6vzdg
# 8b3oynsd8qnOCbVrYE/7rnPsjdlRgTSz4mCzD6LHV2U0HSdRhjewsuwb0RVelyGb
# ZjHtmGTaRqSOfUuGYOgo66kll+ThAwHn/5HeCKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNTEyMjIyMTIxNDFaMC8GCSqGSIb3DQEJBDEiBCBQOnCj3G/w0UzvuBYF
# /cdhppTyp5XRnoK2W890pE1unjANBgkqhkiG9w0BAQEFAASCAgABuJ9RxvTJDoKe
# ynvlimBhaStfOH+dMIQxwQUukLofR7MQyb9SkXkNFnkkgoImG+RLq83rWmpSZQtH
# MW9Ujo8NUBRDgdEdKhUFqU8yBvKl52tXKqrSgUBRuYTIA8wlqRndfdoQ8MhUveHd
# 3aJc7mIajSzPFQeGNvL+Of0zEO0c+UuyRHLBdX/nNHSxhJY5G6L/TJt2nLrUkS75
# +vaZsJsFKqsL1Z3SeYUehkPIMqCZj8M8jJQvPbrphip+OHAuRhfmC6dd5HK3is6l
# wJKaOAYACrgt/bfrTEjekSQ+8d271yC7ihlJ08PrMTy6Nj/LxKV93hxDbgiw6jTN
# P7LT1sk/6UxjBuUo+1AZewqH3FaEzsZMGKsbZ7ePwVyXjKpFxnOClp834T28/EqN
# CXje6yKdK8+yPzwwcHT5wfT3ARKzKSJQfsJFVFiYeuj+7rBHrr+vG1GD+/lQeykW
# B8ie/LT5XOLorbDMkyKXNrw9WqgdTTr18avpbsBj6IG+Sqmd1VRkIMDwONnjYuWJ
# V/JZx1CMIEdOvdJHc7CQ4BePQYFFHc3wmyjUD1ziTdNAs4zXaKbZteZ17kJQ+Z/B
# mfhO//mkbUyuoYcu4jE/E/cM203ZIqVaKYPaHKTpPIEKbH1eQCC4B6QPhItFR2iH
# m0YpDayz4qeK16IAj7IMMyhRPsCyPQ==
# SIG # End signature block
