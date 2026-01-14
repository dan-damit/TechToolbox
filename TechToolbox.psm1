Set-StrictMode -Version Latest

# Show logo
Write-Host @"
 _____         _       _____           _ _
|_   _|__  ___| |__   |_   _|__   ___ | | |__   _____  __
  | |/ _ \/ __| '_ \    | |/ _ \ / _ \| | '_ \ / _ \ \/ /
  | |  __/ (__| | | |   | | (_) | (_) | | |_) | (_) >  <
  |_|\___|\___|_| |_|   |_|\___/ \___/|_|_.__/ \___/_/\_\

                 Technician-Grade Toolkit
"@ -ForegroundColor Cyan

# Predefine module-level variables
$script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase
$script:log = $null
$script:ConfigPath = $null
$script:ModuleDependencies = $null
# Load all private functions
$privateRoot = Join-Path $script:ModuleRoot 'Private'
Get-ChildItem -Path $privateRoot -Recurse -Filter *.ps1 -File |
ForEach-Object { . $_.FullName }
# Load all public functions
$publicRoot = Join-Path $script:ModuleRoot 'Public'
$publicFunctionFiles = Get-ChildItem -Path $publicRoot -Recurse -Filter *.ps1 -File
$publicFunctionNames = foreach ($file in $publicFunctionFiles) {
    . $file.FullName
    $file.BaseName
}
# Run initialization pipeline
Initialize-Config
Initialize-Logging
# Module dependency resolution
$script:ModuleDependencies = Get-ModuleDependencies
Initialize-Modules -Dependencies $script:ModuleDependencies
# Interop
Initialize-Interop
# Export public functions + aliases
Export-ModuleMember -Function $publicFunctionNames