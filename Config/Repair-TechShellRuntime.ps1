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
