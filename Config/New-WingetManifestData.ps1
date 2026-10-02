[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InstallerPath,

    [Parameter(Mandatory)]
    [string]$PackageVersion,

    [string]$PackageIdentifier = 'TechToolbox.TechShell',
    [string]$InstallerUrl = 'https://github.com/dan-damit/TechToolbox/releases/download/v<version>/TechShell.msix',
    [string]$Publisher = 'VADTEK',
    [string]$PackageName = 'TechShell',
    [string]$ShortDescription = 'TechToolbox Windows shell experience.',
    [string]$MinimumOSVersion = '10.0.17763.0',
    [ValidateSet('msix', 'exe', 'msi', 'zip')]
    [string]$InstallerType = 'msix',
    [ValidateSet('x64', 'x86', 'arm64', 'neutral')]
    [string]$Architecture = 'x64',
    [ValidateSet('machine', 'user')]
    [string]$Scope = 'machine',
    [switch]$AsJson,
    [switch]$WriteManifestFiles,
    [string]$ManifestRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'packaging\winget')
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

$resolvedInstallerPath = Resolve-AbsolutePath -Path $InstallerPath
if (-not (Test-Path -LiteralPath $resolvedInstallerPath -PathType Leaf)) {
    throw "Installer file not found: $resolvedInstallerPath"
}

$sha256 = (Get-FileHash -LiteralPath $resolvedInstallerPath -Algorithm SHA256).Hash.ToUpperInvariant()
$installerFileName = [System.IO.Path]::GetFileName($resolvedInstallerPath)

if ($InstallerUrl -match '<version>') {
    $InstallerUrl = $InstallerUrl -replace '<version>', $PackageVersion
}

if ($InstallerUrl -match '<file>') {
    $InstallerUrl = $InstallerUrl -replace '<file>', $installerFileName
}

$result = [pscustomobject]@{
    PackageIdentifier = $PackageIdentifier
    PackageVersion    = $PackageVersion
    InstallerPath     = $resolvedInstallerPath
    InstallerFileName = $installerFileName
    InstallerUrl      = $InstallerUrl
    InstallerType     = $InstallerType
    Architecture      = $Architecture
    Scope             = $Scope
    InstallerSha256   = $sha256
    Publisher         = $Publisher
    PackageName       = $PackageName
    ShortDescription  = $ShortDescription
    MinimumOSVersion  = $MinimumOSVersion
    GeneratedAtUtc    = (Get-Date).ToUniversalTime().ToString('o')
}

$installerYaml = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $PackageVersion
MinimumOSVersion: $MinimumOSVersion
Installers:
  - Architecture: $Architecture
    InstallerType: $InstallerType
    Scope: $Scope
    InstallerUrl: $InstallerUrl
    InstallerSha256: $sha256
ManifestType: installer
ManifestVersion: 1.10.0
"@

$versionYaml = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $PackageVersion
ManifestType: version
ManifestVersion: 1.10.0
"@

$localeYaml = @"
PackageIdentifier: $PackageIdentifier
PackageVersion: $PackageVersion
PackageLocale: en-US
Publisher: $Publisher
PackageName: $PackageName
ShortDescription: $ShortDescription
ManifestType: defaultLocale
ManifestVersion: 1.10.0
"@

$manifestOutput = $null
if ($WriteManifestFiles) {
    $resolvedManifestRoot = Resolve-AbsolutePath -Path $ManifestRoot
    $versionFolder = Join-Path (Join-Path $resolvedManifestRoot $PackageIdentifier) $PackageVersion
    New-Item -ItemType Directory -Path $versionFolder -Force | Out-Null

    $versionManifestPath = Join-Path $versionFolder ("{0}.yaml" -f $PackageIdentifier)
    $installerManifestPath = Join-Path $versionFolder ("{0}.installer.yaml" -f $PackageIdentifier)
    $localeManifestPath = Join-Path $versionFolder ("{0}.locale.en-US.yaml" -f $PackageIdentifier)

    Set-Content -LiteralPath $versionManifestPath -Value ($versionYaml.Trim() + [Environment]::NewLine) -Encoding utf8
    Set-Content -LiteralPath $installerManifestPath -Value ($installerYaml.Trim() + [Environment]::NewLine) -Encoding utf8
    Set-Content -LiteralPath $localeManifestPath -Value ($localeYaml.Trim() + [Environment]::NewLine) -Encoding utf8

    $manifestOutput = [pscustomobject]@{
        ManifestRoot = $resolvedManifestRoot
        ManifestVersionPath = $versionFolder
        VersionManifestPath = $versionManifestPath
        InstallerManifestPath = $installerManifestPath
        LocaleManifestPath = $localeManifestPath
    }
}

if ($AsJson) {
    [pscustomobject]@{
        Metadata = $result
        InstallerYaml = $installerYaml.Trim()
        VersionYaml = $versionYaml.Trim()
        DefaultLocaleYaml = $localeYaml.Trim()
        ManifestFiles = $manifestOutput
    } | ConvertTo-Json -Depth 5
}
else {
    [pscustomobject]@{
        Metadata = $result
        InstallerYaml = $installerYaml.Trim()
        VersionYaml       = $versionSnippet.Trim()
        DefaultLocaleYaml = $localeYaml.Trim()
        ManifestFiles = $manifestOutput
    }
}
