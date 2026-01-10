# TechToolbox.psm1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleRoot = Split-Path -Parent $PSCommandPath
$script:ConfigPath = Join-Path $script:ModuleRoot '..\Config\config.json'
$script:Config = $null

# Load Private first
Get-ChildItem "$PSScriptRoot\Private" -Recurse -Filter *.ps1 |
ForEach-Object { . $_.FullName }

# Load Public and export only those
$publicFunctions = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Filter *.ps1 -File -ErrorAction SilentlyContinue |
ForEach-Object {
    . $_.FullName
    $_.BaseName
}

$script:TechToolboxConfig = $null # Clear any cached config

Export-ModuleMember -Function $publicFunctions
