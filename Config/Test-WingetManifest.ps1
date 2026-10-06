[CmdletBinding()]
param(
    [string]$ManifestRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'packaging\winget'),
    [string]$PackageIdentifier = 'TechToolbox.TechShell',
    [Parameter(Mandatory)]
    [string]$PackageVersion,
    [switch]$SkipWingetCliValidation
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

$errors = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

$resolvedRoot = Resolve-AbsolutePath -Path $ManifestRoot
$versionPath = Join-Path (Join-Path $resolvedRoot $PackageIdentifier) $PackageVersion

$manifestFile = Join-Path $versionPath ("{0}.yaml" -f $PackageIdentifier)
$installerFile = Join-Path $versionPath ("{0}.installer.yaml" -f $PackageIdentifier)
$localeFile = Join-Path $versionPath ("{0}.locale.en-US.yaml" -f $PackageIdentifier)

foreach ($path in @($manifestFile, $installerFile, $localeFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $errors.Add("Missing required manifest file: $path")
    }
}

if (Test-Path -LiteralPath $installerFile -PathType Leaf) {
    $installerText = Get-Content -LiteralPath $installerFile -Raw

    if ($installerText -notmatch '(?m)^\s*InstallerUrl\s*:\s*https://') {
        $errors.Add("InstallerUrl must be present and use https in $installerFile")
    }

    $hashMatch = [regex]::Match($installerText, '(?m)^\s*InstallerSha256\s*:\s*(?<hash>[A-Fa-f0-9]{64})\s*$')
    if (-not $hashMatch.Success) {
        $errors.Add("InstallerSha256 is missing or invalid in $installerFile (must be 64 hex chars)")
    }

    if ($installerText -notmatch '(?m)^\s*InstallerType\s*:\s*(msix|msi|exe|zip)\s*$') {
        $warnings.Add("InstallerType not found or outside common values (msix/msi/exe/zip) in $installerFile")
    }

    if ($installerText -match '(?m)^\s*InstallerType\s*:\s*msix\s*$' -and
        $installerText -notmatch '(?m)^\s*PackageFamilyName\s*:\s*.+\S\s*$') {
        $errors.Add("PackageFamilyName is required for msix installers in $installerFile")
    }
}

if (Test-Path -LiteralPath $manifestFile -PathType Leaf) {
    $manifestText = Get-Content -LiteralPath $manifestFile -Raw
    if ($manifestText -notmatch '(?m)^\s*PackageIdentifier\s*:\s*' + [regex]::Escape($PackageIdentifier) + '\s*$') {
        $errors.Add("PackageIdentifier mismatch in $manifestFile")
    }
    if ($manifestText -notmatch '(?m)^\s*PackageVersion\s*:\s*' + [regex]::Escape($PackageVersion) + '\s*$') {
        $errors.Add("PackageVersion mismatch in $manifestFile")
    }
}

$wingetValidationExitCode = $null
if (-not $SkipWingetCliValidation) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        $warnings.Add('winget CLI not found; skipped winget validate.')
    }
    else {
        $wingetOutput = & winget validate --manifest $versionPath 2>&1
        $wingetOutputText = ($wingetOutput | Out-String)
        if (-not [string]::IsNullOrWhiteSpace($wingetOutputText)) {
            Write-Host $wingetOutputText.TrimEnd()
        }

        $wingetValidationExitCode = $LASTEXITCODE
        if ($wingetValidationExitCode -ne 0) {
            if ($wingetOutputText -match 'Manifest validation succeeded with warnings\.') {
                $warnings.Add("winget validate succeeded with warnings (exit code $wingetValidationExitCode).")
            }
            else {
                $errors.Add("winget validate failed with exit code $wingetValidationExitCode")
            }
        }
    }
}

$result = [pscustomobject]@{ ManifestRoot = $resolvedRoot; ManifestVersionPath = $versionPath; PackageIdentifier = $PackageIdentifier; PackageVersion = $PackageVersion; CheckedFiles = @($manifestFile, $installerFile, $localeFile); ErrorCount = $errors.Count; WarningCount = $warnings.Count; Errors = @($errors); Warnings = @($warnings); WingetValidationExitCode = $wingetValidationExitCode }

$result

if ($errors.Count -gt 0) {
    throw "Winget manifest validation failed with $($errors.Count) error(s)."
}

# SIG # Begin signature block
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnpWBUo5lY/bmR
# dsiuZVotM9FYJexwy3TLdYC/wFFoGqCCFmgwggMqMIICEqADAgECAhAUclYcLlB0
# o0+hlxGb32/OMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMMIlRlY2hUb29sYm94
# IFRlY2hTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYxMDAzMDE0MjMyWhcNMjgxMDAz
# MDE1MjMxWjAtMSswKQYDVQQDDCJUZWNoVG9vbGJveCBUZWNoU2hlbGwgQ29kZSBT
# aWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXcCV9CPSwPJ
# 42duP85fSh0jCkJWIov+AYymeKQzBLgsz6jCkhuuKBf7gpsStULwAJuBtFztT/XI
# 0jK0e+3SIzYCaG+1nn0rzBsB4YisBtMykS+EtRgmjcu2h1YMGiQ/FScDak5h707Z
# hQ/VBXZ/+rZ7Wd08wUnWHAsNRz75wz/kiWGEoCDIuLsl4uy+gQmXlQVBFn8ALEh0
# AtJk0B7c6qzz1y0So8y4Lq1IXvCEnN61HYSJ5zaopOMvNo3pNsrr0sM7m9DyEzu4
# Ci3EWtuyXbPegoV62qC62MRllrFJNzV6dJBUuXqCAhgMFGaT6Mj2/qRlBiVVmTFe
# FXTX9pHvxQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFB8+5HahBP9rHFC1mG3OWbTh3WwxMA0GCSqGSIb3DQEB
# CwUAA4IBAQAOdqNp/5ce+dpVcp2FivGK7FpYroSWaeOoEDEDLnxq58mDEZKBwfYM
# SduDQ4AHZQ3U1WRrvHWyiPpFI5lOt1utiw9WHrA4sHuvxGmFkcfH4J8AsRtlVK94
# yUX16UZhLPXWItGM75rUz/uRSBcyXQWOzq5gfwNL22F5Z8AljAicEBAZLUhuQBpd
# 9rE3JWZ0rZzbRZNd4Hb4/DP53KaiA7zfZyXmuEfLCCwyGtcPn3Mqxu6IsCU8LmzH
# 2fClU7OGxte+VxaczuFaPqmIBtChvxj4ZoluHWgWOIXqyOsSc9v9qzYeHM6i4pY4
# pRkjpGU/2NWfwVbOkyJxQlE9XdhO3IXGMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG
# 9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVz
# dGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+
# PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxe
# Lho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2D
# Z0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJB
# YgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7G
# b5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS
# 3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7C
# coKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUm
# s+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN
# +nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqE
# G1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhG
# NKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQY
# MBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUE
# DDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDww
# OjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0G
# CSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/D
# m1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO4
# 1P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFS
# goR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSL
# ANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJ
# DMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cva
# iIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+
# U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6
# bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+
# Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhL
# ULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3
# XDCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
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
# /YMxggUdMIIFGQIBATBBMC0xKzApBgNVBAMMIlRlY2hUb29sYm94IFRlY2hTaGVs
# bCBDb2RlIFNpZ25pbmcCEBRyVhwuUHSjT6GXEZvfb84wDQYJYIZIAWUDBAIBBQCg
# gYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0B
# CQQxIgQghuX3hZNP8xe19C+vK4tD+l3uxc9oqiWF55mSgazlKOgwDQYJKoZIhvcN
# AQEBBQAEggEAjbPv9JsAWaEyp7e5JfBLyzafUDJc+jj9S8M2J08rL2Eu/B8tF7TQ
# g90gBX/lZ7X9q00vOaQLaK7dWm6eD7VniSd6gSlhVqiZFmHng/cSvd75u9gFY7Oi
# JU8OJuO/wWKFRvqAEkE0JaMQjfPPkJiUcPV/TVQz4VWjsFpdRdBhSYE6AGprL+cP
# NJ0eQma7xEZG3rp6TVBOrw5qA/GSm9pl3AcfHx3hp8Sf9frZlPnh+O3OXr0OJ+Wa
# F6bgKtm5h9bIdWEbur4zx9NZ5TYYIotQ7aD3s+O5l4jHFdeFSUc07qE5zvWolkgE
# Iv0nfCzCg1qRUWxfVUwMMRpkDL9TzzdmOqGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDMyMDQwNDRaMC8GCSqGSIb3DQEJBDEiBCCQDVorSsW8dNCPRfIWKGAq
# zTHqOhG664Uz5pAW6shFczANBgkqhkiG9w0BAQEFAASCAgAcCH/sJ1mh9eV1lN+1
# 2papq8AhVXHyYBRNr1+3rq/g6Ojb6V1cz9ayBzn6sl8HrCtoXrIWkuSc0K6ZaOmj
# GVPWoawp+f2HpIuXtfqdBAELBb1YVE6okVAZAaBvE1bJAdytOP92X46OZDNDqIxa
# CeqE9kP6sgr152xIbjqCq/b2H3I7c90meu10JTEwrA3ODkYxMLwpu2+9Pw+q9AWm
# 9qrGFlKfGzIWZQ9J/25PWwe3xrUqMkDXSH4hvoKi5jULIYBY6NIs5ZrYHZAYkC+0
# itdyiWeqiXXxEjWwgCGLTDRWsqUkpWfnzGKXHRE2NV1kt17eIvjtqwI+8q7n87xK
# R26/0Pw4wK7VDAfvKDdOzn6AELDUY+XKu+DrzvJjfXX3b5XnAcHfvFhWSrY3akX+
# g0o1K2g61p8TpNrbFH1G583ihwIeP7UFc+rCLNxIGygYaLveiIvtJOzhkBvRPwmo
# cO6oA4rzn1Z/n19T1f95jh+K7OpCJXSheON3W66fJ+YWkFYbzjFlWSHWAU+1CAkO
# Kjz84Hpza5OWoJrneKJ9KXbxLCsuUKmqajWl9hU2cxBag2jqT7QkpXd6G2lqWCsq
# 2XH73nZukpo3w0HkVsBn+AmLrnG/RWDL+7Fda5Nd177L2mD91TeCO0BDaz7sMw6g
# 4mJeGykdc2pCDZXnYvp3oXa4bg==
# SIG # End signature block
