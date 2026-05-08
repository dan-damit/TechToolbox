<#
.SYNOPSIS
  Closes Edge/Chrome and clears cache only (keeps cookies) for the current user.
.NOTES
  Author: (https://github.com/dan-damit)
#>

[CmdletBinding()]
param()

function Stop-Browsers {
    $names = @("msedge", "chrome")

    # Try graceful close first
    Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $names -contains $_.Name } |
    ForEach-Object { try { $_.CloseMainWindow() | Out-Null } catch {} }

    Start-Sleep -Seconds 2

    # Force close remaining
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Remove-PathSafe {
    param([Parameter(Mandatory)][string[]]$Paths)

    foreach ($path in $Paths) {
        if (Test-Path -LiteralPath $path) {
            try {
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
                Write-Host "Removed: $path"
            }
            catch {
                Write-Host "WARN: Failed to remove $path :: $($_.Exception.Message)"
            }
        }
    }
}

function Get-ChromiumProfiles {
    param([Parameter(Mandatory)][string]$BasePath)

    if (-not (Test-Path -LiteralPath $BasePath)) { return @() }

    Get-ChildItem -LiteralPath $BasePath -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^(Default|Profile \d+)$' }
}

# Cache locations (NO cookies)
$cacheRelPaths = @(
    "Cache",
    "Code Cache",
    "GPUCache",
    "Service Worker\CacheStorage",
    "Service Worker\ScriptCache"
)

Stop-Browsers

# --- EDGE ---
$edgeBase = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data"
$edgeProfiles = Get-ChromiumProfiles -BasePath $edgeBase

foreach ($prof in $edgeProfiles) {
    $profilePath = [string]$prof.FullName

    $toRemove = foreach ($rel in $cacheRelPaths) {
        Join-Path -Path $profilePath -ChildPath $rel
    }

    Remove-PathSafe -Paths $toRemove
}

# --- CHROME ---
$chromeBase = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data"
$chromeProfiles = Get-ChromiumProfiles -BasePath $chromeBase

foreach ($prof in $chromeProfiles) {
    $profilePath = [string]$prof.FullName

    $toRemove = foreach ($rel in $cacheRelPaths) {
        Join-Path -Path $profilePath -ChildPath $rel
    }

    Remove-PathSafe -Paths $toRemove
}

Write-Host "Done."
