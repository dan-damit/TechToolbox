param()

Write-Host "=== TechToolbox Badge Builder ===" -ForegroundColor Cyan

# -----------------------------
# Helper: Format numbers nicely
# -----------------------------
function Format-Number {
    param([long]$n)
    if ($null -eq $n) { return "0" }
    return "{0:N0}" -f $n
}

function Get-SectionDownloadCount {
    param(
        [string]$Html,
        [string]$SectionPattern
    )

    $total = 0
    foreach ($match in [regex]::Matches($Html, $SectionPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
        foreach ($rowMatch in [regex]::Matches($match.Groups['body'].Value, '<td>\s*(?<downloads>[\d,]+)\s*</td>', [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
            $total += [long](($rowMatch.Groups['downloads'].Value) -replace ',', '')
        }
    }

    return $total
}

# -----------------------------
# Fetch PSGallery Data
# -----------------------------
Write-Host "`n[1/4] Fetching PSGallery data..." -ForegroundColor Yellow

$psVersion = "N/A"
$psDownloads = 0
$apiDownloads = 0

try {
    $module = Find-Module -Name "TechToolbox" -ErrorAction Stop

    # Version
    $psVersion = $module.Version.ToString()

    # API Downloads (property may not exist)
    if ($module.PSObject.Properties.Match('TotalDownloads')) {
        $value = $module.TotalDownloads
        if ($null -ne $value -and [long]::TryParse($value.ToString(), [ref]$apiDownloads) -and $apiDownloads -ge 0) {
            $psDownloads = $apiDownloads
        }
    }
}
catch {
    Write-Warning "Failed to fetch PSGallery data: $_"
}

# Primary source: sum per-version downloads from PSGallery HTML.
# Fallbacks: package total in HTML, then API total if available.
Write-Host "  Fetching per-version download totals from package HTML..." -ForegroundColor DarkYellow
try {
    $pageHtml = (Invoke-WebRequest -Uri "https://www.powershellgallery.com/packages/TechToolbox/" -UseBasicParsing -ErrorAction Stop).Content

    $versionHistoryTotal = Get-SectionDownloadCount -Html $pageHtml -SectionPattern '<tbody class="[^"]*\bno-border\b[^"]*"[^>]*>(?<body>.*?)</tbody>'
    if ($versionHistoryTotal -gt 0) {
        $psDownloads = $versionHistoryTotal
        Write-Host "  Using per-version total: $psDownloads" -ForegroundColor DarkGreen
    }
    elseif ($pageHtml -match '<li class="package-details-info-main">\s*([\d,]+)\s*<br\s*/?>\s*<text[^>]*>\s*Downloads\s*</text>') {
        $psDownloads = [long]($Matches[1] -replace ',', '')
        Write-Host "  Per-version rows unavailable; using package total: $psDownloads" -ForegroundColor DarkGreen
    }
    elseif ($apiDownloads -gt 0) {
        $psDownloads = $apiDownloads
        Write-Host "  HTML scrape unavailable; using API total: $psDownloads" -ForegroundColor DarkGreen
    }
    else {
        Write-Warning "Could not determine PSGallery download count from version rows, package total, or API."
    }
}
catch {
    if ($apiDownloads -gt 0) {
        $psDownloads = $apiDownloads
        Write-Warning "HTML scrape failed; using API total downloads instead: $apiDownloads"
    }
    else {
        Write-Warning "Failed to fetch PSGallery HTML and no API total was available: $_"
    }
}

<#
# Fallback: scrape the PSGallery package page if the API returned 0
if ($psDownloads -eq 0) {
    Write-Host "  API returned 0 downloads — attempting HTML scrape fallback..." -ForegroundColor DarkYellow
    try {
        $pageHtml = (Invoke-WebRequest -Uri "https://www.powershellgallery.com/packages/TechToolbox/" -UseBasicParsing -ErrorAction Stop).Content

        # Regex that tolerates spans, whitespace, <br>, and commas
        $regex = '<li class="package-details-info-main">.*?([\d,]+).*?<br\s*/?>\s*<text[^>]*>\s*Downloads\s*</text>'

        if ($pageHtml -match $regex) {
            $scraped = [long]($Matches[1] -replace ',', '')
            if ($scraped -gt 0) {
                $psDownloads = $scraped
                Write-Host "  Scraped downloads: $psDownloads" -ForegroundColor DarkGreen
            }
        }
        else {
            Write-Warning "Scrape fallback: could not locate download count in PSGallery HTML."
        }
    }
    catch {
        Write-Warning "Scrape fallback failed: $_"
    }
}
#>

# Format for badges
$psDownloadsFormatted = Format-Number $psDownloads

Write-Host "  Version: $psVersion"
Write-Host "  Downloads: $psDownloadsFormatted"

# -----------------------------
# Fetch GitHub Release Data
# -----------------------------
Write-Host "`n[2/4] Fetching GitHub release data..." -ForegroundColor Yellow

try {
    $gh = Invoke-RestMethod "https://api.github.com/repos/dan-damit/TechToolbox/releases/latest" -ErrorAction Stop

    $ghVersion = $gh.tag_name
    $ghDownloads = ($gh.assets | Measure-Object -Property download_count -Sum).Sum
    $ghDownloadsFormatted = Format-Number $ghDownloads
}
catch {
    Write-Warning "Failed to fetch GitHub release data: $_"
    $ghVersion = "N/A"
    $ghDownloadsFormatted = "0"
}

Write-Host "  GitHub Release: $ghVersion"
Write-Host "  GitHub Downloads: $ghDownloadsFormatted"
Write-Host "  Required PowerShell: 7.4+"

# -----------------------------
# Build Replacement Table
# -----------------------------
Write-Host "`n[3/4] Preparing badge data..." -ForegroundColor Yellow

$badgeData = @{
    VERSION             = $psVersion
    PSGALLERY_DOWNLOADS = $psDownloadsFormatted
    GH_RELEASE          = $ghVersion
    GH_DOWNLOADS        = $ghDownloadsFormatted
    REQUIRED_PWSH       = "7.4+"
}

$badgeData.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key) = $($_.Value)"
}

# -----------------------------
# Process Templates
# -----------------------------
Write-Host "`n[4/4] Generating SVG badges..." -ForegroundColor Yellow

$templatePath = "assets/badges/templates"
$outputPath = "assets/badges"

$templates = Get-ChildItem $templatePath -Filter *.template -ErrorAction SilentlyContinue

if (-not $templates) {
    Write-Error "No template files found in $templatePath"
    exit 1
}

foreach ($file in $templates) {
    Write-Host "  Processing $($file.Name)..."

    $template = Get-Content $file.FullName -Raw

    # Validate placeholders
    foreach ($key in $badgeData.Keys) {
        if ($template -notmatch "{{$key}}") {
            Write-Warning "Template '$($file.Name)' does not contain placeholder {{$key}}"
        }
    }

    # Replace placeholders
    foreach ($key in $badgeData.Keys) {
        $value = $badgeData[$key]
        $template = $template -replace "{{$key}}", $value
    }

    # Output final SVG
    $outFile = Join-Path $outputPath ($file.BaseName.Replace(".svg", "") + ".svg")
    Set-Content -Path $outFile -Value $template -Encoding UTF8

    Write-Host "    → Generated $outFile" -ForegroundColor Green
}

Write-Host "`n=== Badge Build Complete ===" -ForegroundColor Cyan

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRmC5qxGsqFy5G
# FgaxBxQDYN369aWW0IktGjU9x0ftgaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAWvY/q7XVS
# gDivotBJe2IMhrwEze0PNzfQkooW0d4mvTANBgkqhkiG9w0BAQEFAASCAgCDlY8c
# a3oLAdjGJdOWG1Ci42Bi0YHshsLC+4s4pRWDs4QYE+DDcV3VD8rVKS0P6/c0rGvs
# /5D0cZZSkWGhJLM/zfQpM7cCgM80uf5Ni5W4UCmnN/cwSJGh0QcogCY6kXSQw42P
# /8pZ6LsBtttbl/d6nk3OpU1DatQwoMistPPnaJvO1k5npNV7jk3jKpe4f/XA7d6O
# y2N+q1BGbvjVLG+iGK8UFfXhnuPm+mnfXHvvZIj49TciW6aTOMeeYXxs91UaTT9+
# mHaIocS1vZRzWe+dlbmh0E57yz0acrH7OFnfDiqIyGotNFSc6RF4pNSq1yw1yjsp
# qOVLxkl2VNlOffiMkZ0MbImKBsbhVmlXP5cXU/UDZuZM7OR30dSn5h/dR4Ykr8ka
# vyBtUDm6zTULeiHnczwDF6hBlYBCjmt3D4/O/VNgSC/ba7Y6l+c6S8uFY3mLVbz/
# dfjdL3k16lvQelSe8HWE+kvdHNaXoaGFYc/767/7hAGCp3wmdGWDC4ajVfPNIo0v
# DVggmyJ4WYd8gEecsbx5+0jcRhIIyrDuIv35c1xPipl2fFpeS73UEUQp/TFlN/SM
# eeFbkGPPFPlM1vgql9aNMhNW1mLR83KFZ8ONidPpzgqrScmgbE/Lk/d2/zmSI6Xj
# TVwnbOhP3OPVdU1Cnd+howT4JEawXMJ5t9uuT6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MjAxNjQ0MDJaMC8GCSqGSIb3DQEJBDEiBCBdeGaeWuGFVpRErmne
# S7WXA2pJOujPNr1c+Ut0fI+bbTANBgkqhkiG9w0BAQEFAASCAgAWMVHQdVJS8oQ6
# Bi/pCd+k5wR/sywWM6KynJG7Vanrl8IL5dHirJIOyw/rYClv0KQk7kXAJkAmCqOO
# DSGI4CODSo++v1cPXNtm+btAIF+xSAhzZx5JZYBsy0Wh3weGeoL4vaNYO8KU4Kqf
# O1d8iWfxaP6nKdpIiQTARTV8+/YoqPgZNM9xOXUZR7/3OoDVtQp9SeHb+TgNJtP9
# kWXvSa3kMNB51+ZgeXe7ATWlB+bSF/shmqCe2E6wu0EaCsKAyYRq2NGV9yHypQpF
# SJjtfF4EGQUMlQ9eSCb8meC1YIvos/N+d1UhV49CkqIng5LUJMJN6L+5WTOX2m1t
# 49oK+tNPy0TINo6B+xSQybfv/4L8mcTOtLbLt63yI5q7iKsPot83+UUFjBXQkUru
# P+Yi3yuj41KCL5+BFDt517JLZ5GGyxCgAsVaXfSgwujt0dmxvb5u6OvovU+BTsBI
# FfP0tjdwF+C6VlJx8VotFqftu3Y5LMyMxeRncK9M7x9DXqqls+sTpQhJa5x/vzTT
# REsiV1DO5tjdmmYwRthXriD6oV9wjwp1Fk2Hyy0/b3HvIV6zwcVVpm1NoN038zit
# 7MDSuVg/kuecp4UfzlUa0GZkOL0hOHmcV0b+YjRffejoI6YolR2uC3LRlQ9GRoJ0
# 0QH2XZZ7sg58OnLv4x7m9EJnr7HloA==
# SIG # End signature block
