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

# Module root
$script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase
$loaderRoot = Join-Path $script:ModuleRoot 'Private\Loader'

# Dot-source loader helpers
Get-ChildItem -Path $loaderRoot -Filter *.ps1 | ForEach-Object {
    . $_.FullName
}

# Run initialization pipeline
Initialize-Config
Initialize-Logging

# Module dependency resolution
$script:ModuleDependencies = Get-ModuleDependencies

Initialize-Modules -Dependencies $script:ModuleDependencies

# Aliases + Public functions
$exportableAliases = Initialize-Aliases
Resolve-Aliases -Aliases $exportableAliases

$publicFunctionNames = Initialize-PublicFunctions

# Interop
Initialize-Interop

# Export public functions + aliases
Export-ModuleMember -Function $publicFunctionNames -Alias $exportableAliases

# Auto-init
Initialize-Toolbox