[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]$TechShellPackageRegex = 'C7E250C2|TechShell',
    [string]$RuntimeNamePattern = 'Microsoft.WindowsAppRuntime.2*',
    [string]$RuntimeDependencyMsixPath,
    [string]$TechShellMsixPath,
    [switch]$AttemptRuntimeRemoval,
    [switch]$SkipRuntimeRemoval,
    [switch]$SkipReinstall,
    [switch]$SkipDependencyInstall,
    [switch]$ForceDependencyInstall,
    [switch]$RequireReboot,
    [switch]$StrictRuntimeRemoval,
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-LatestArtifactPath {
    param(
        [Parameter(Mandatory)] [string]$RepoRoot,
        [Parameter(Mandatory)] [string]$Filter,
        [switch]$PreferInstaller
    )

    $searchRoots = @(
        (Join-Path $RepoRoot 'Out\\TechShell'),
        (Join-Path $RepoRoot 'src\\TechShell\\src\\TechShell.UI\\artifacts\\TechShell')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }

    $matches = foreach ($root in $searchRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -File -Filter $Filter -ErrorAction SilentlyContinue
    }

    if (-not $matches) {
        return $null
    }

    if ($PreferInstaller) {
        $installerMatch = $matches |
            Where-Object { $_.FullName -match '\\Installer\\|_x64_Test\\' } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1

        if ($installerMatch) {
            return $installerMatch.FullName
        }
    }

    return ($matches | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

function Remove-PackagesByFilter {
    param(
        [Parameter(Mandatory)] [ScriptBlock]$Filter,
        [Parameter(Mandatory)] [string]$Label,
        [switch]$PassForce,
        [switch]$BestEffortWhenInUse
    )

    function Stop-LockingProcesses {
        param(
            [Parameter(Mandatory)] [string[]]$Names
        )

        foreach ($name in $Names) {
            $processes = Get-Process -Name $name -ErrorAction SilentlyContinue
            if (-not $processes) { continue }

            Write-Host "Stopping process(es) holding $Label package: $($processes.ProcessName -join ', ')" -ForegroundColor Yellow
            $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

    $packages = Get-AppxPackage -AllUsers | Where-Object $Filter | Sort-Object Version -Descending
    if (-not $packages) {
        Write-Host "No installed packages matched: $Label" -ForegroundColor DarkYellow
        return
    }

    foreach ($pkg in $packages) {
        Write-Host "Removing $Label package: $($pkg.PackageFullName)" -ForegroundColor Cyan
        if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Remove-AppxPackage')) {
            $processNames = @()
            if ($Label -match 'TechShell') {
                $processNames = @('TechShell.UI', 'TechShell')
            }
            elseif ($Label -match 'Windows App Runtime') {
                $processNames = @('BackgroundTaskHost', 'SearchApp', 'ShellExperienceHost', 'StartMenuExperienceHost', 'RuntimeBroker')
            }

            for ($attempt = 1; $attempt -le 3; $attempt++) {
                try {
                    if ($processNames.Count -gt 0) {
                        Stop-LockingProcesses -Names $processNames
                    }

                    if ($PassForce) {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    }
                    else {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    }

                    break
                }
                catch {
                    if ($attempt -lt 3 -and $_.Exception.Message -match 'currently in use|in use') {
                        Write-Warning "Package is still in use; retrying removal attempt $($attempt + 1) of 3..."
                        Start-Sleep -Seconds 3
                        continue
                    }

                    if ($BestEffortWhenInUse -and $_.Exception.Message -match 'currently in use|in use') {
                        Write-Warning "Could not remove $Label package because it is still in use. Continuing in best-effort mode."
                        break
                    }

                    if ($BestEffortWhenInUse -and $_.Exception.Message -match 'dependency or conflict validation|failed updates') {
                        Write-Warning "Could not remove $Label package because dependency/conflict validation failed. Continuing in best-effort mode."
                        break
                    }

                    throw
                }
            }
        }
    }
}

function Install-AppxSafely {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Label,
        [switch]$BestEffortWhenInUse
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label path was not found: $Path"
    }

    Write-Host ("Installing {0}: {1}" -f $Label, $Path) -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($Path, 'Add-AppxPackage')) {
        try {
            Add-AppxPackage -Path $Path -ForceApplicationShutdown -ErrorAction Stop
        }
        catch {
            $errorMessage = $_.Exception.Message
            $errorRecordText = ($_ | Out-String)
            $errorText = "$errorMessage`n$errorRecordText"
            $activityId = $null
            if ($errorText -match '\[ActivityId\]\s*([0-9a-fA-F\-]{36})') {
                $activityId = $Matches[1]
            }

            if ($errorText -match '0x80073CF9|0x80070020|currently in use|Creating file .*WindowsAppRuntime') {
                Write-Warning "Install failed due to in-use files for $Label."
                Write-Warning 'Recommendation: reboot Windows, then re-run this script before launching other apps.'
                if ($activityId) {
                    Write-Warning "Collect deployment details with: Get-AppPackageLog -ActivityID $activityId"
                }

                if ($Label -eq 'Windows App Runtime dependency') {
                    $runtimeStillInstalled = @(Get-AppxPackage -AllUsers | Where-Object { $_.Name -like 'Microsoft.WindowsAppRuntime.2*' }).Count -gt 0
                    if ($runtimeStillInstalled) {
                        Write-Warning 'Windows App Runtime is already installed; continuing without dependency reinstall.'
                        return
                    }
                }

                if ($BestEffortWhenInUse) {
                    Write-Warning "Continuing in best-effort mode for $Label because files are currently in use."
                    return
                }
            }

            throw
        }
    }
}

function Repair-WindowsAppRuntimeIfNeeded {
    param([Parameter(Mandatory)] [string]$RuntimePattern)

    $runtimePackages = @(Get-AppxPackage | Where-Object { $_.Name -like $RuntimePattern })
    if (-not $runtimePackages) {
        return
    }

    foreach ($pkg in $runtimePackages) {
        $statusText = [string]$pkg.Status
        if ($statusText -match 'NeedsRemediation|Modified') {
            Write-Warning "Windows App Runtime package requires remediation: $($pkg.PackageFullName) (Status: $statusText)"
            if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Reset-AppxPackage')) {
                try {
                    Reset-AppxPackage -Package $pkg.PackageFullName -ErrorAction Stop
                    Write-Host "Reset-AppxPackage completed for $($pkg.PackageFullName)." -ForegroundColor Green
                }
                catch {
                    Write-Warning "Reset-AppxPackage failed for $($pkg.PackageFullName): $($_.Exception.Message)"
                    Write-Warning 'A reboot is recommended before rerunning this script.'
                }
            }
        }
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-IsAdministrator)) {
    throw 'This script must be run from an elevated PowerShell session (Run as Administrator).'
}

Write-Host 'Step 1: Stop running TechShell process if present...' -ForegroundColor Green
Get-Process -Name 'TechShell.UI' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host 'Step 2: Remove installed TechShell app packages...' -ForegroundColor Green
Remove-PackagesByFilter -Label 'TechShell' -PassForce:$Force -Filter {
    $_.Name -match $TechShellPackageRegex -or $_.PackageFullName -match $TechShellPackageRegex
}

if ($SkipRuntimeRemoval -or -not $AttemptRuntimeRemoval) {
    Write-Host 'Step 3: Skipping runtime removal.' -ForegroundColor DarkYellow
    if (-not $AttemptRuntimeRemoval) {
        Write-Host 'Reason: Windows App Runtime host processes are aggressively respawned by the shell, so reinstall/repair is the default strategy.' -ForegroundColor DarkYellow
        Write-Host 'Use -AttemptRuntimeRemoval (and optionally -StrictRuntimeRemoval) only when intentionally doing a full removal pass.' -ForegroundColor DarkYellow
    }
}
else {
    Write-Host 'Step 3: Remove installed Windows App Runtime 2 packages...' -ForegroundColor Green
    Remove-PackagesByFilter -Label 'Windows App Runtime' -PassForce:$Force -BestEffortWhenInUse:(-not $StrictRuntimeRemoval) -Filter {
        $_.Name -like $RuntimeNamePattern
    }

    if (-not $StrictRuntimeRemoval) {
        Write-Host 'Runtime removal is running in best-effort mode because framework packages are frequently locked by the shell.' -ForegroundColor DarkYellow
    }
}

if ($RequireReboot) {
    Write-Warning 'A reboot is required now to fully release package state. Re-run this script after reboot for reinstall steps.'
    return
}

Write-Host 'Step 3.5: Verify Windows App Runtime package health...' -ForegroundColor Green
Repair-WindowsAppRuntimeIfNeeded -RuntimePattern $RuntimeNamePattern

if (-not $SkipReinstall) {
    if ([string]::IsNullOrWhiteSpace($RuntimeDependencyMsixPath) -and -not $SkipDependencyInstall) {
        $RuntimeDependencyMsixPath = Resolve-LatestArtifactPath -RepoRoot $repoRoot -Filter 'Microsoft.WindowsAppRuntime.2.msix'
    }

    if ([string]::IsNullOrWhiteSpace($TechShellMsixPath)) {
        $TechShellMsixPath = Resolve-LatestArtifactPath -RepoRoot $repoRoot -Filter 'TechShell.msix' -PreferInstaller
        if (-not $TechShellMsixPath) {
            $TechShellMsixPath = Resolve-LatestArtifactPath -RepoRoot $repoRoot -Filter 'TechShell.UI_*.msix' -PreferInstaller
        }
    }

    if (-not $SkipDependencyInstall) {
        $runtimeInstalled = @(Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $RuntimeNamePattern })
        if ($runtimeInstalled.Count -gt 0 -and -not $ForceDependencyInstall) {
            $runtimeVersions = ($runtimeInstalled | Sort-Object Version -Descending | Select-Object -ExpandProperty Version | Select-Object -Unique) -join ', '
            Write-Host 'Step 4: Skipping Windows App Runtime dependency install (already present).' -ForegroundColor DarkYellow
            Write-Host "Installed runtime version(s): $runtimeVersions" -ForegroundColor DarkYellow
            Write-Host 'Use -ForceDependencyInstall to explicitly reinstall the dependency package.' -ForegroundColor DarkYellow
        }
        else {
            Write-Host 'Step 4: Install Windows App Runtime dependency package...' -ForegroundColor Green
            Install-AppxSafely -Path $RuntimeDependencyMsixPath -Label 'Windows App Runtime dependency' -BestEffortWhenInUse:(-not $ForceDependencyInstall)
        }
    }
    else {
        Write-Host 'Step 4: Skipping dependency install by request.' -ForegroundColor DarkYellow
    }

    Write-Host 'Step 5: Install TechShell package...' -ForegroundColor Green
    Install-AppxSafely -Path $TechShellMsixPath -Label 'TechShell package'
}
else {
    Write-Host 'Reinstall steps skipped by request.' -ForegroundColor DarkYellow
}

Write-Host 'Step 6: Verification snapshot...' -ForegroundColor Green
$runtimePackages = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $RuntimeNamePattern } |
    Select-Object Name, Version, PackageFullName
$techshellPackages = Get-AppxPackage -AllUsers | Where-Object {
    $_.Name -match $TechShellPackageRegex -or $_.PackageFullName -match $TechShellPackageRegex
} | Select-Object Name, Version, PackageFullName

Write-Host 'Windows App Runtime packages:' -ForegroundColor Cyan
$runtimePackages | Format-Table -AutoSize

Write-Host 'TechShell packages:' -ForegroundColor Cyan
$techshellPackages | Format-Table -AutoSize

Write-Host 'Repair flow completed.' -ForegroundColor Green

# SIG # Begin signature block
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCFDEIb3P6SB1cx
# LBvvEOvwVG/+oL6fTghDX/FqhaMYa6CCFmgwggMqMIICEqADAgECAhAUclYcLlB0
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
# CQQxIgQgL/Eiv8cEHsvfWFnS3uWsQYA5ovqjIOh/ns0yQxMDepcwDQYJKoZIhvcN
# AQEBBQAEggEAYlNPNQRG+MOm+M6d/zKGi7wXaVEr299W+Uv8Um3loU2qZcb285IE
# xBTbd3sglAMQ9UqmiC6UPJkf2mFJos10j9Q8qp6hGsg9+mUdbVm3lJe5bpHIcS9w
# Mz4avHzM0FdZDh0swVj6nPy7N3RCimumbZCG2L422O0dMwitrGm6s86LlPVOBPDi
# u0uAnaZdUr2zdLySrnDDNZhEwjwbB2bR3vzbXVFOkmR82bZV7vDgu5gkbNzojN4r
# //4sOODOIni55xvdRadSQ35f5wdBMFRAEXAMH0qqmQ48o2kbCO1B2MtctvVBqUyQ
# +iMfJsrTAnCztKDqBMKcRJrStfs6+CtZaKGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDMyMDE3MjVaMC8GCSqGSIb3DQEJBDEiBCAXU6BeOFQRQH6BYghHyXKX
# qOqSeSxw84++JxJ1SLmi5TANBgkqhkiG9w0BAQEFAASCAgAIr78/LcenrlLdJL2A
# tisSSJCyRho8850HWMJrT/Mq7XWezmGx8cv6i7MQcFroZU0Ajotraqhx7IFsOPpY
# 4M6IWhTUKbLjrcWHbuzW9UG1WSEKauXAT+IDo4PNio8zMAbEdU3Oxygkhot+KrWi
# 8mAjf6KZg2BH/l9hMRJ4j76gSZp15S96yg/OMIuUcDQW9ijozedP29msXQb7TbNz
# Xhc2nsFunEEUxheRhVlqYtj7a7+NDhoXZhl+T+UsVpCwTtqJZ8lqU05iBBsokw7y
# tX8rjPZ6wXyzBtz9ToIfubiMoLLoYN+vsk1ZY6jEyrWMUVwP0ScUVOo7r2yT9q5m
# +WB96y7vNSJDGKpCLeYXSfBHUPY7fIaYwDNLlwUvJ/0feYbaJNKZtN2kQ4IJSmFG
# cg3ywEfZAtKs0rQmip7dZnrLhTlaTq1QNjx3iKlsDI5FQ0QgffL24lh3zVZIbEYs
# vFH+HAiYCQIdKwYl3Zx7JkRD0NpZE6IwX7dr0nCBz6RPfD/NpxsK2h6qRyl7CnYV
# +8Id+0z/SCNk/zgUuKXo2p1NLWUV0r7AUa791U8SZ+1zFnvaz8MRyMA0qVYkKzdh
# K4WzZ95QSPnmnTF+8JT2dc5ojLP2puXyHB5IDzoNy0bOLd2MFxH1mPDTtSOdkdJX
# niH3I2PEngCpcLlielSizLi9fA==
# SIG # End signature block
