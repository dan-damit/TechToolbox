# TechToolbox.psm1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Show logo on module import
$logo = @"
 _____         _       _____           _ _               
|_   _|__  ___| |__   |_   _|__   ___ | | |__   _____  __
  | |/ _ \/ __| '_ \    | |/ _ \ / _ \| | '_ \ / _ \ \/ /
  | |  __/ (__| | | |   | | (_) | (_) | | |_) | (_) >  < 
  |_|\___|\___|_| |_|   |_|\___/ \___/|_|_.__/ \___/_/\_\

                 Technician-Grade Toolkit
"@

Write-Host $logo -ForegroundColor Cyan

# Set module root and config path
$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:ConfigPath = Join-Path $script:ModuleRoot '\Config\config.json'

# Load Private first
Get-ChildItem "$PSScriptRoot\Private" -Recurse -Filter *.ps1 |
ForEach-Object { . $_.FullName }

# Load Public and export only those
$publicFunctions = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Recurse -Filter *.ps1 -File |
ForEach-Object {
    . $_.FullName
    $_.BaseName
}

# Load all C# interop classes recursively
$interopRoot = Join-Path $PSScriptRoot 'Private\Interop'

if (Test-Path $interopRoot) {
    Get-ChildItem -Path $interopRoot -Filter '*.cs' -Recurse | ForEach-Object {
        Add-Type -Path $_.FullName -ErrorAction Stop
    }
}

# Attempt to preload and cache the config for interactive convenience
try {
    $script:TechToolboxConfig = Get-TechToolboxConfig -Path $script:ConfigPath
}
catch {
    Write-Host "TechToolbox: config preload failed: $($_.Exception.Message)"
    # keep $script:TechToolboxConfig as $null so callers can detect and handle missing config
    $script:TechToolboxConfig = $null
}

Export-ModuleMember -Function $publicFunctions
