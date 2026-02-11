<#
.SYNOPSIS
  One-shot build for TechToolbox (rooted at C:\TechToolbox):
  - Update manifest (version & GUID)
  - (Optional) Run PSSA analysis
  - Sign module files
  - (Optional) Package artifacts

.NOTES
  - Prefers PS7+ but works on Windows PowerShell 5.1+
  - Non-interactive by default; prompts only with -Interactive
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AutoVersionPatch,
    [switch]$RegenerateGuid,
    [switch]$SkipValidSigs = $true,
    [switch]$Recurse,
    [switch]$Analyze,         # Run PSSA (PowerShell ScriptAnalyzer)
    [switch]$FailOnPssa,      # Fail build if PSSA finds issues
    [switch]$ExportPublic,    # Export only functions discovered in Public\ (else '*')
    [switch]$Pack,            # Zip to .\Out\TechToolbox_<version>.zip
    [switch]$Interactive,     # Allow prompts when data is missing
    [string]$ModuleRoot = $PSScriptRoot,             # C:\TechToolbox
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'Config\build.config.json'),
    [string]$TimestampServer,
    [string]$Thumbprint
)

# ---------------- 01. Load config --------------------------------------------
$cfg = $null
if (Test-Path -LiteralPath $ConfigPath) {
    $cfg = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
}

$TimestampServer = $cfg.signing.timestamp ?? 'http://timestamp.digicert.com'
$Thumbprint = $cfg.signing.thumbprint
$outDir = $cfg.artifacts.outDir ?? (Join-Path $ModuleRoot 'Out')
$pssaSettings = $cfg.quality.pssaSettings ?? (Join-Path $ModuleRoot 'PSScriptAnalyzerSettings.psd1')
$analyzeEnabled = $Analyze.IsPresent -or ($cfg.quality.analyze -eq $true)
$failOnPssa = $FailOnPssa.IsPresent -or ($cfg.quality.failOnPssa -eq $true)

# ---------------- 02. Validate environment -----------------------------------
$manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Manifest not found: $manifestPath"
}

# ---------------- Helper: Import manifest ------------------------------------
$manifest = Import-PowerShellDataFile -Path $manifestPath

# ---------------- 03. Compute new values -------------------------------------
$oldGuid = $manifest.Guid
$newGuid = if ($RegenerateGuid) { [guid]::NewGuid().Guid } else { $oldGuid }

$oldVersion = [version]$manifest.ModuleVersion
$newVersion = if ($AutoVersionPatch) {
    $build = if ($oldVersion.Build -ge 0) { $oldVersion.Build } else { 0 }
    [version]::new($oldVersion.Major, $oldVersion.Minor, $build + 1)
}
else { $oldVersion }

# Paths
$publicFolder = Join-Path $ModuleRoot 'Public'
$manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'

# Collect public function names from file basenames
$publicFiles = Get-ChildItem -LiteralPath $publicFolder -Filter *.ps1 -File -Recurse
$publicFuns = $publicFiles.BaseName | Sort-Object -Unique

# Fall back to '*' only if nothing found (e.g., dev shell without Public yet)
$functionsToExport = if ($publicFuns.Count -gt 0) { $publicFuns } else { @('*') }

# Keep aliases explicit (avoid '*') for faster module analysis
$aliasesToExport = @()  # set to concrete alias names when you have them

# Preserve existing PrivateData.PSData
$psdata = [ordered]@{}
if ($manifest.PrivateData -and $manifest.PrivateData.PSData) {
    $psdata = [ordered]@{} + $manifest.PrivateData.PSData
}
$privateData = if ($psdata.Count -gt 0) { [ordered]@{ PSData = $psdata } } else { @{} }

# Update manifest once
Update-ModuleManifest -Path $manifestPath `
    -FunctionsToExport $functionsToExport `
    -AliasesToExport   $aliasesToExport `
    -PrivateData       $privateData

# ---------------- 04. Dirty check & update manifest --------------------------
$manifestChanged = $false
$exportsChanged = ($manifest.FunctionsToExport -join ',') -ne ($functionsToExport -join ',')

if ($oldGuid -ne $newGuid -or $oldVersion -ne $newVersion -or $exportsChanged) {
    if ($PSCmdlet.ShouldProcess($manifestPath, "Update manifest")) {
        Update-ModuleManifest -Path $manifestPath `
            -ModuleVersion $newVersion `
            -Guid $newGuid `
            -FunctionsToExport $functionsToExport `
            -PrivateData $privateData
        $manifestChanged = $true
        Write-Host "Manifest updated → Version: $oldVersion → $newVersion; Guid: $oldGuid → $newGuid" -ForegroundColor Cyan
    }
}
else {
    Write-Host "Manifest unchanged (no updates needed)." -ForegroundColor DarkCyan
}

# ---------------- 05. (Optional) PSSA analysis --------------------------------
$pssaIssues = @()
if ($analyzeEnabled) {
    try {
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            Write-Warning "PSScriptAnalyzer module not found. Skipping analysis."
        }
        else {
            Import-Module PSScriptAnalyzer -ErrorAction Stop
            Write-Host "Running PSSA (ScriptAnalyzer)..." -ForegroundColor Cyan
            $pssaIssues = Invoke-ScriptAnalyzer -Path $ModuleRoot `
                -Settings $pssaSettings -Recurse
            if ($pssaIssues.Count -gt 0) {
                # Store a machine-readable report under CodeAnalysis\
                $caDir = Join-Path $ModuleRoot 'CodeAnalysis'
                New-Item -ItemType Directory -Force -Path $caDir | Out-Null
                $reportPath = Join-Path $caDir ("PSSA-Report_{0:yyyyMMdd_HHmmss}.json" -f (Get-Date))
                $pssaIssues | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $reportPath -Encoding UTF8
                Write-Host "PSSA found $($pssaIssues.Count) issue(s). Report: $reportPath" -ForegroundColor Yellow
                if ($failOnPssa -and -not $Interactive) {
                    throw "Build failed due to ScriptAnalyzer findings."
                }
            }
            else {
                Write-Host "PSSA clean." -ForegroundColor Green
            }
        }
    }
    catch {
        throw "PSSA run failed: $($_.Exception.Message)"
    }
}

# ---------------- 06. Signing -------------------------------------------------
function Get-CodeSigningCert {
    param([Parameter(Mandatory)] [string]$Thumb)
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($store in $stores) {
        $found = Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }
        if ($found -and $found.HasPrivateKey) { return $found }
    }
    return $null
}

if (-not $Thumbprint) {
    if ($Interactive) { $Thumbprint = Read-Host "Enter code signing thumbprint" }
    else { throw "Thumbprint not provided (set Config\build.config.json signing.thumbprint or pass -Thumbprint)." }
}
$cert = Get-CodeSigningCert -Thumb $Thumbprint
if (-not $cert) { throw "Code signing cert not found or missing private key for thumbprint $Thumbprint." }

# What to sign
$search = @{ Path = $ModuleRoot; Include = '*.ps1', '*.psm1', '*.psd1'; File = $true; Recurse = $true }
$files = Get-ChildItem @search | Where-Object {
    $_.FullName -notmatch '\\(Out|Bin|CodeAnalysis|\.git)\\'
}

$ok = 0; $skip = 0; $warn = 0
Write-Host "Signing $(($files|Measure-Object).Count) file(s)..." -ForegroundColor Cyan
foreach ($f in $files) {
    try {
        if ($SkipValidSigs) {
            $sig = Get-AuthenticodeSignature -FilePath $f.FullName
            if ($sig.Status -eq 'Valid') { $skip++; continue }
        }
        $params = @{
            FilePath      = $f.FullName
            Certificate   = $cert
            HashAlgorithm = 'SHA256'
        }
        if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }
        $r = Set-AuthenticodeSignature @params
        if ($r.Status -eq 'Valid') { $ok++ } else { $warn++ }
    }
    catch {
        $warn++
    }
}
Write-Host "Signing complete → OK: $ok  Skipped: $skip  Warnings/Errors: $warn" -ForegroundColor Cyan

# ---------------- 07. (Optional) Package -------------------------------------
$artifact = $null
if ($Pack) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $zip = Join-Path $outDir ("TechToolbox_{0}.zip" -f $newVersion)
    if (Test-Path $zip) { Remove-Item $zip -Force }
    # Zip only module assets
    $items = @(
        (Join-Path $ModuleRoot 'TechToolbox.psd1'),
        (Join-Path $ModuleRoot 'TechToolbox.psm1'),
        (Join-Path $ModuleRoot 'Public\*'),
        (Join-Path $ModuleRoot 'Private\*'),
        (Join-Path $ModuleRoot 'Config\*')
    )
    Compress-Archive -Path $items -DestinationPath $zip
    $artifact = $zip
    Write-Host "Packaged → $artifact" -ForegroundColor Green
}

# ---------------- 08. Emit summary -------------------------------------------
$result = [pscustomobject]@{
    ManifestPath    = $manifestPath
    Version         = [pscustomobject]@{ Old = $oldVersion; New = $newVersion }
    Guid            = [pscustomobject]@{ Old = $oldGuid; New = $newGuid }
    ManifestUpdated = $manifestChanged
    PssaIssues      = $pssaIssues.Count
    FilesSigned     = $ok
    FilesSkipped    = $skip
    FilesWarned     = $warn
    ArtifactPath    = $artifact
}
$result

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrE29Vu3DvnQhX
# xloYHoZVF6qfVLqI/jKQRt0JhhwcdqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDxUiP5x2Ko
# PjVTmtJYd8wl3sYvGUPWyMzbBuYY3NVWuzANBgkqhkiG9w0BAQEFAASCAgBhRDCJ
# 1u8WznDrLAE9a/CobH0MzP9TDeBUMTJ2QvAhoyMlHrbhjADcSAw6LqBynn8yiNSo
# qSW5HAh1O6n8MGwmFiZGPpDi63XF5bFzzaAiblCTiOYZppVl4pwzEH4bOx7BMuTd
# vYBE1SJi7PITYJcHrzadM7JNQiFyXI+Hg1QjYszH9TRFXiC+efcmeVaSl9k1qLHy
# D+Bq+7J9V5u7YX4BMSw4oVd6GFJ0TEv+xtnqrd9BhdnVFROjpldmbz6q8WMmH0mp
# jpYDjVBJRBJHW6sxTSmhPzlvaUxxPpwDJT88kUt+9AYFwV29/F0JeYsft8rfQ1YV
# e3G1t6wjHg4MKW6Z2Yw5P5hLkg/w8M32IGpHiwoQXbt9XyeUo8xQHy5Da2YeoGRK
# Pu3vJYVwmUnxfS3CGBCx8s8kBb7phhcuvjvX5OzQ5mWciQhIzDSFnGrmcGKaDi2Y
# yFWyHJkt4fGvvc5g8dNZKWQmny1Bgp/3oTPTUO9LoybDKnhkQkZMI92j9FfSuF5N
# FVNshKAYgMkyCDHmGUDSzjUTmFlnw0AfJ0Km8/GfmkvWpGuSNYuHfSP837nEiwHQ
# 4F4yFsVkVurXe+X3TNb0Uu6aiRx1nYHIAGzZQ/CP/BKQsrmPnDJz4/w7s9xu8gUc
# LXjGKzS0zdqOQNS7RjvCCzaTI7uvPb/8VDunhqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTEwMDQ3MTlaMC8GCSqGSIb3DQEJBDEiBCBDrcP/sIxBirXEmSn2
# 3UXcCoL+xzaRhJ/ZjWXtegRCiDANBgkqhkiG9w0BAQEFAASCAgCWNzz7hWVnoqQe
# CfEh+6n7o22f5Iln/Hj2OeQIc/jonCc7rcKp8uhZE+wKK1qWWULJmaSCbzfmkR1A
# jMZbTv70uPl7Ogz3JXFDRqVQfTFTrsUKTSVhvID8lYHaHmqMK7EYsrSjlWTrb7iI
# DOsJEMflD5ML7wT7eYeALIN6C1P/yHcD+k5NC1b8D2nHUj6f/EV59ZSckXNEDVNx
# T7Z4EEh4dIaQSsyuR+effbBhuEHHXlVz6v8GYGITJ/Mw8ONUmZR1nh4N7DAuhSKN
# SylTM8uN2RZbYc2Oa75a/vAWMgTbMRcCEq4VQbesJ94L6bOMUCoujvWi8F2U2TxF
# ewoA49enjBbtbvyZB31DBmE3s7XdrWQ4Ok76SecUbQkMQ5TEnVf5MHlHMTgYY4tT
# cUQZY+IwQswO52TYoczGNv80PuMscElEXCp8WQvLz93x90BXgO2NkaQdbIIsbrBf
# WGvOs3077/JFr80PJ3pheDDpwwiHN4XH5Fl7iH9M6k6K+1Gu1UyPOXBScXkFy3BJ
# kvH3Lx7qiXev9ibbbvbMJem5WnF/ULZCrwcD0oeron2DQXQuWF2MJ2++uIeITDq8
# 4bhVC4yyFn+rElUsRuBbKbLGViazRTEmbctZ4JUTXqX22wmggSk516qECy0nBhTo
# m17/aBFaHRnHcOeiBhgN2BeugUCQ+Q==
# SIG # End signature block
