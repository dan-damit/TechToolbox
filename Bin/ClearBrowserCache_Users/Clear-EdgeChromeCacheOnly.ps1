<#
.SYNOPSIS
  Closes Edge/Chrome and clears cache only (keeps cookies) for the current user.
.DESCRIPTION
  - Shows a confirmation prompt (Yes/No).
  - Closes Edge + Chrome.
  - Clears common cache locations including Service Worker caches.
  - Does NOT delete cookie databases.
.NOTES
  Author: (https://github.com/dan-damit)
#>

[CmdletBinding()]
param()

# --- UI Prompt (Confirmation) ---
function Show-Confirm {
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        $msg = @"
This will CLOSE Microsoft Edge and Google Chrome,
then clear browser cache (cookies will be kept).

Continue?
"@
        $choice = [System.Windows.Forms.MessageBox]::Show(
            $msg,
            "Fix Epicor (Browser Cache Reset)",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return ($choice -eq [System.Windows.Forms.DialogResult]::Yes)
    }
    catch {
        # If forms isn't available, default to "true" (run) or make it "false" (safe).
        return $false
    }
}

function Show-Done {
    param([string]$Text = "Epicor fix complete`n`nBrowser cache cleared (cookies kept).`nReopen Edge/Chrome and try again.")
    try {
        Add-Type -AssemblyName System.Windows.Forms | Out-Null
        [System.Windows.Forms.MessageBox]::Show(
            $Text,
            "Fix Epicor",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
    catch {}
}

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
            }
            catch {
                # Don't fail the run because a single file is locked
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

# --- Confirm with user first ---
if (-not (Show-Confirm)) {
    # User clicked No (or popup couldn’t display)
    Show-Done -Text "Cancelled. No changes were made."
    return
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

# Edge
$edgeBase = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Edge\User Data"
foreach ($prof in (Get-ChromiumProfiles -BasePath $edgeBase)) {
    $profilePath = [string]$prof.FullName
    $toRemove = foreach ($rel in $cacheRelPaths) { Join-Path -Path $profilePath -ChildPath $rel }
    Remove-PathSafe -Paths $toRemove
}

# Chrome
$chromeBase = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Google\Chrome\User Data"
foreach ($prof in (Get-ChromiumProfiles -BasePath $chromeBase)) {
    $profilePath = [string]$prof.FullName
    $toRemove = foreach ($rel in $cacheRelPaths) { Join-Path -Path $profilePath -ChildPath $rel }
    Remove-PathSafe -Paths $toRemove
}

Show-Done
