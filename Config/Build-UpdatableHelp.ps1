[CmdletBinding()]
param(
    [string]$ModuleManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'TechToolbox.psd1'),
    [string]$SourceHelpPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'en-US'),
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Out\UpdatableHelp'),
    [string]$Culture = 'en-US',
    [string]$HelpVersion,
    [string]$HelpContentUri,
    [string]$ExternalHelpPath,
    [switch]$Clean
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-AbsolutePath {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Get-HelpVersionString {
    param([Parameter(Mandatory)][string]$RawVersion)

    $v = [version]$RawVersion

    $major = $v.Major
    $minor = $v.Minor
    $build = if ($v.Build -lt 0) { 0 } else { $v.Build }
    $revision = if ($v.Revision -lt 0) { 0 } else { $v.Revision }

    return '{0}.{1}.{2}.{3}' -f $major, $minor, $build, $revision
}

function New-HelpCabinet {
    param(
        [Parameter(Mandatory)][string]$CabinetName,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [Parameter(Mandatory)][string[]]$InputFiles
    )

    $makecab = Get-Command -Name 'makecab.exe' -ErrorAction SilentlyContinue
    if (-not $makecab) {
        throw "makecab.exe was not found. Install the Windows cabinet tools or run from Windows with makecab available."
    }

    $token = [guid]::NewGuid().ToString('N')
    $ddfPath = Join-Path $env:TEMP ("tt-help-{0}.ddf" -f $token)
    $infPath = Join-Path $env:TEMP ("tt-help-{0}.inf" -f $token)
    $rptPath = Join-Path $env:TEMP ("tt-help-{0}.rpt" -f $token)

    try {
        $ddfLines = @(
            '.OPTION EXPLICIT'
            ".Set CabinetNameTemplate=$CabinetName"
            ".Set DiskDirectoryTemplate=$DestinationDirectory"
            ".Set InfFileName=$infPath"
            ".Set RptFileName=$rptPath"
            '.Set Cabinet=on'
            '.Set Compress=on'
            '.Set CompressionType=MSZIP'
            '.Set UniqueFiles=on'
        )

        foreach ($file in $InputFiles) {
            $ddfLines += ('"{0}"' -f $file)
        }

        Set-Content -LiteralPath $ddfPath -Value $ddfLines -Encoding ASCII

        $null = & $makecab.Source '/F' $ddfPath
        if ($LASTEXITCODE -ne 0) {
            throw "makecab.exe failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if (Test-Path -LiteralPath $ddfPath) {
            Remove-Item -LiteralPath $ddfPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $infPath) {
            Remove-Item -LiteralPath $infPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $rptPath) {
            Remove-Item -LiteralPath $rptPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$manifestPath = Resolve-AbsolutePath -Path $ModuleManifestPath
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Module manifest not found: $manifestPath"
}

$sourceHelpPath = Resolve-AbsolutePath -Path $SourceHelpPath
if (-not (Test-Path -LiteralPath $sourceHelpPath)) {
    throw "Source help folder not found: $sourceHelpPath"
}

$outputRoot = Resolve-AbsolutePath -Path $OutputPath
$manifest = Import-PowerShellDataFile -Path $manifestPath

$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($manifestPath)
$moduleGuid = [string]$manifest.GUID
if ([string]::IsNullOrWhiteSpace($moduleGuid)) {
    throw "Manifest GUID is missing in $manifestPath"
}

$resolvedHelpVersion = if ([string]::IsNullOrWhiteSpace($HelpVersion)) {
    [string]$manifest.ModuleVersion
}
else {
    $HelpVersion
}

if ([string]::IsNullOrWhiteSpace($resolvedHelpVersion)) {
    throw "Help version could not be resolved from manifest ModuleVersion."
}

$resolvedHelpContentUri = if ([string]::IsNullOrWhiteSpace($HelpContentUri)) {
    [string]$manifest.HelpInfoURI
}
else {
    $HelpContentUri
}

if ([string]::IsNullOrWhiteSpace($resolvedHelpContentUri)) {
    throw "HelpContentUri was not provided and HelpInfoURI is missing in manifest."
}

if (-not ($resolvedHelpContentUri -match '^https?://')) {
    throw "HelpContentUri must be an absolute http/https URI. Received: $resolvedHelpContentUri"
}

$helpVersionString = Get-HelpVersionString -RawVersion $resolvedHelpVersion

$stagingPath = Join-Path $outputRoot ("staging-{0}" -f $Culture)
$feedPath = Join-Path $outputRoot $Culture

if ($Clean) {
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $feedPath) {
        Remove-Item -LiteralPath $feedPath -Recurse -Force
    }
}

$null = New-Item -ItemType Directory -Path $stagingPath -Force
$null = New-Item -ItemType Directory -Path $feedPath -Force

$copiedFiles = New-Object System.Collections.Generic.List[string]

$aboutFiles = Get-ChildItem -LiteralPath $sourceHelpPath -File -Filter '*.help.txt'
foreach ($file in $aboutFiles) {
    $destination = Join-Path $stagingPath $file.Name
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    [void]$copiedFiles.Add($destination)
}

if (-not [string]::IsNullOrWhiteSpace($ExternalHelpPath)) {
    $externalPath = Resolve-AbsolutePath -Path $ExternalHelpPath
    if (-not (Test-Path -LiteralPath $externalPath)) {
        throw "ExternalHelpPath does not exist: $externalPath"
    }

    $xmlFiles = Get-ChildItem -LiteralPath $externalPath -File -Filter '*-help.xml'
    foreach ($file in $xmlFiles) {
        $destination = Join-Path $stagingPath $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
        [void]$copiedFiles.Add($destination)
    }
}

if ($copiedFiles.Count -eq 0) {
    throw "No help files were staged. Add *.help.txt to $sourceHelpPath and optionally *-help.xml via -ExternalHelpPath."
}

$cabName = '{0}_{1}_{2}_HelpContent.cab' -f $moduleName, $moduleGuid, $Culture
$helpInfoName = '{0}_{1}_HelpInfo.xml' -f $moduleName, $moduleGuid

New-HelpCabinet -CabinetName $cabName -DestinationDirectory $feedPath -InputFiles $copiedFiles

$cabPath = Join-Path $feedPath $cabName
if (-not (Test-Path -LiteralPath $cabPath)) {
    throw "CAB build succeeded but output file was not found: $cabPath"
}

$helpInfoPath = Join-Path $feedPath $helpInfoName

$helpInfoXml = @"
<?xml version="1.0" encoding="utf-8"?>
<HelpInfo xmlns="http://schemas.microsoft.com/powershell/help/2010/05">
  <HelpContentURI>$resolvedHelpContentUri</HelpContentURI>
  <SupportedUICultures>
    <UICulture>
      <UICultureName>$Culture</UICultureName>
      <UICultureVersion>$helpVersionString</UICultureVersion>
    </UICulture>
  </SupportedUICultures>
</HelpInfo>
"@

Set-Content -LiteralPath $helpInfoPath -Value $helpInfoXml -Encoding UTF8

Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue

[pscustomobject]@{
    ModuleName        = $moduleName
    ModuleGuid        = $moduleGuid
    Culture           = $Culture
    HelpVersion       = $helpVersionString
    HelpContentUri    = $resolvedHelpContentUri
    FeedPath          = $feedPath
    HelpInfoXmlPath   = $helpInfoPath
    HelpCabPath       = $cabPath
    StagedFileCount   = $copiedFiles.Count
    StagedFileSamples = @($copiedFiles | Select-Object -First 10 | ForEach-Object { [System.IO.Path]::GetFileName($_) })
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCr89oMHHqLaPUC
# /ZN+Sy0IRh1c6AItZtshFHqDnFujZaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDQhGfn2UyV
# EAG4DeYdiO/TEvc2ElzGVQtBpPJCd7A/uzANBgkqhkiG9w0BAQEFAASCAgAuuKMN
# SKx4U7hRDd6yZut3li0z3/qXcKlLh1I0Jw/grOBbEgQMoEOt1f9hQIDgZ9gZPiO6
# PC7BPd8Iynacxsgga2FNp3diJjSHWnh4qp618XMcF7iON9NnSl4AL9pFizWQeJZ/
# FYctQPeH6j95ab8HHe2pXblXrFI/kE4gvIU2QcVkNYRXUHJ/6dDH5CC+RN4ddLKI
# biTKaptZmlIDT9C2v1sk8WQB0VmBLpZnNIdxdN2afVq/8nQpQcmdN5eZsWzI6JUD
# xOKvksLHRL5Gt82hCrtxucT/35/jykAGsRnglhBEt7tJ5zHUgn2O78d3nFJNHwvk
# TM7FWfYSwRMn2W5kJCeYBXTblIQLiNVj01Mx2LwTFISa3y1ObbmxgQA31dFcU3qK
# 19yc5xWauXRuXYJY5XG13ZBgw8CZVWTgF8MfSTiaCGlFiM9KhH5BvWt9HwDyXEkJ
# 4nOTd+m0cOzVqoJKK4fH5EhNeCzkoSN8Ub/ut6t/v0UvfsCOH8kU6V4WDmsh4L9w
# RnduX8WBlTWWl1fNIDphQy8UOyv84dBm5HbVEzaC78X/Dd2pmiZ5RqNVCcJLb6pY
# wb5DGajtAS89xkixQ+t7z4J4ULKsxw5l4HWTmU2PVqK+9X8P0rDOcHucEALpPSVI
# X6mhSnISAA8r/e4rdxwf9MLf/dYLN5aGaLmwHqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjEwMDExNzQ4MzdaMC8GCSqGSIb3DQEJBDEiBCCegca9FOKl3b2Va327
# PPonycXAW1t/1zxnN1DR8e4ZVTANBgkqhkiG9w0BAQEFAASCAgBJ47wVLuL24MaX
# /H/FbOBJSYF4BA4BVd74VUZVOB357embfrOfhgC753yB8bmD7QrJjEiYZ2Z021Cb
# QxLKWoODsB+zjcMYr/HWk5/G/koFQriaw466ekEKOZX3lMArn45PgKOI6TpaXrf+
# hmGfHFNPLgcXWjgVyA8pGJFlZtqULm5f4rrDuPEl+KP6Ltpkgbv/V7fYOHn9UAJ+
# JNKu+CBAEE0Z4UOt+rryLONSHhRyvakllgHkzZrfCUtbxW+0920ml6932ian8/p8
# dcI5bPyX/SL62Vtux45aHJ3YPqdCN8CIerBHPDt+I0XwTO7eLi99LgxOXhsUxu1E
# wz0L0M14DB8TtKP8Zcb7IE067vXsSsziirs7w2/hCy/HZgEl4wM7IcRIMa5OTIxA
# j0cGC99gKasr9ZdYpChCISfDEUxiWklGhugAomewRGgL/pOvXxTGvw7ru7+hlpMY
# 65zRVYVNBd3rbPprNTTjJEHn9Gv9NomRXo+9Quj6bVF2MyD4cS1zcJLa3yHblkJT
# y4BPIHEjqeZyY0aUpWin8rde1tOtehS5qR1+Yz/KbBBCbPlO5RYCMKML7TMwzqwz
# MIYP502AiK9Hhbq038TgHgOtWPTMG6p5mD14RoD2jUbkmUbxxKYLGMyVlbSo7od3
# AhhZIyiFRB8ac78McO1pdreD7e2XHA==
# SIG # End signature block
