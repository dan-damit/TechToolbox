#Requires -Version 7.0
<#
.SYNOPSIS
    Sets up the TechToolbox environment with required tools in the current PowerShell session.

.DESCRIPTION
    Configures PATH and environment variables for .NET SDK, Node.js, and uv in the current session.
    This is automatically applied when PowerShell starts via the profile, but can be run manually
    if needed.

.EXAMPLE
    .\Setup-Environment.ps1

.NOTES
    This script is part of the TechToolbox environment setup.
    Required tools must be installed first (see ENVIRONMENT_SETUP.md).
#>

$dotnetRoot = "$env:LOCALAPPDATA\dotnet"
$toolPaths = @(
    "$env:LOCALAPPDATA\nodejs",
    "$env:LOCALAPPDATA\uv"
)

Write-Host "TechToolbox Environment Setup" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

$allFound = $true
if (Test-Path $dotnetRoot) {
    Write-Host "✓ Found: $dotnetRoot" -ForegroundColor Green
    $env:PATH = "$dotnetRoot;$env:PATH"
    $env:DOTNET_ROOT = $dotnetRoot
    $env:DOTNET_ROOT_X64 = $dotnetRoot
    if ([string]::IsNullOrWhiteSpace($env:DOTNET_MULTILEVEL_LOOKUP)) {
        $env:DOTNET_MULTILEVEL_LOOKUP = '1'
    }
    if ([string]::IsNullOrWhiteSpace($env:DOTNET_ROLL_FORWARD)) {
        $env:DOTNET_ROLL_FORWARD = 'LatestMajor'
    }
}
else {
    Write-Host "✗ Missing: $dotnetRoot" -ForegroundColor Red
    $allFound = $false
}

foreach ($path in $toolPaths) {
    if (Test-Path $path) {
        Write-Host "✓ Found: $path" -ForegroundColor Green
        $env:PATH = "$path;$env:PATH"
    }
    else {
        Write-Host "✗ Missing: $path" -ForegroundColor Red
        $allFound = $false
    }
}

if ($allFound) {
    Write-Host "`n✓ All tools ready!" -ForegroundColor Green
    Write-Host "`nVerifying tool availability:"
    Write-Host "  .NET:   $(dotnet --version)"
    Write-Host "  DOTNET_ROOT: $env:DOTNET_ROOT"
    Write-Host "  DOTNET_ROLL_FORWARD: $env:DOTNET_ROLL_FORWARD"
    Write-Host "  Node:   $(node --version)"
    Write-Host "  npm:    $(npm --version)"
    Write-Host "  uv:     $(uv --version)"
}
else {
    Write-Host "`n✗ Some tools are missing. See ENVIRONMENT_SETUP.md for installation instructions." -ForegroundColor Red
}
