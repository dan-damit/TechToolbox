[CmdletBinding()]
param(
    [string]$ManifestRoot = (Join-Path (Split-Path -Parent $PSScriptRoot) 'packaging\winget'),
    [string]$PackageIdentifier = 'TechToolbox.TechShell',
    [Parameter(Mandatory)]
    [string]$PackageVersion,
    [switch]$SkipWingetCliValidation
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

$errors = New-Object System.Collections.Generic.List[string]
$warnings = New-Object System.Collections.Generic.List[string]

$resolvedRoot = Resolve-AbsolutePath -Path $ManifestRoot
$versionPath = Join-Path (Join-Path $resolvedRoot $PackageIdentifier) $PackageVersion

$manifestFile = Join-Path $versionPath ("{0}.yaml" -f $PackageIdentifier)
$installerFile = Join-Path $versionPath ("{0}.installer.yaml" -f $PackageIdentifier)
$localeFile = Join-Path $versionPath ("{0}.locale.en-US.yaml" -f $PackageIdentifier)

foreach ($path in @($manifestFile, $installerFile, $localeFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $errors.Add("Missing required manifest file: $path")
    }
}

if (Test-Path -LiteralPath $installerFile -PathType Leaf) {
    $installerText = Get-Content -LiteralPath $installerFile -Raw

    if ($installerText -notmatch '(?m)^\s*InstallerUrl\s*:\s*https://') {
        $errors.Add("InstallerUrl must be present and use https in $installerFile")
    }

    $hashMatch = [regex]::Match($installerText, '(?m)^\s*InstallerSha256\s*:\s*(?<hash>[A-Fa-f0-9]{64})\s*$')
    if (-not $hashMatch.Success) {
        $errors.Add("InstallerSha256 is missing or invalid in $installerFile (must be 64 hex chars)")
    }

    if ($installerText -notmatch '(?m)^\s*InstallerType\s*:\s*(msix|msi|exe|zip)\s*$') {
        $warnings.Add("InstallerType not found or outside common values (msix/msi/exe/zip) in $installerFile")
    }
}

if (Test-Path -LiteralPath $manifestFile -PathType Leaf) {
    $manifestText = Get-Content -LiteralPath $manifestFile -Raw
    if ($manifestText -notmatch '(?m)^\s*PackageIdentifier\s*:\s*' + [regex]::Escape($PackageIdentifier) + '\s*$') {
        $errors.Add("PackageIdentifier mismatch in $manifestFile")
    }
    if ($manifestText -notmatch '(?m)^\s*PackageVersion\s*:\s*' + [regex]::Escape($PackageVersion) + '\s*$') {
        $errors.Add("PackageVersion mismatch in $manifestFile")
    }
}

$wingetValidationExitCode = $null
if (-not $SkipWingetCliValidation) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        $warnings.Add('winget CLI not found; skipped winget validate.')
    }
    else {
        & winget validate --manifest $versionPath
        $wingetValidationExitCode = $LASTEXITCODE
        if ($wingetValidationExitCode -ne 0) {
            $errors.Add("winget validate failed with exit code $wingetValidationExitCode")
        }
    }
}

$result = [pscustomobject]@{ ManifestRoot = $resolvedRoot; ManifestVersionPath = $versionPath; PackageIdentifier = $PackageIdentifier; PackageVersion = $PackageVersion; CheckedFiles = @($manifestFile, $installerFile, $localeFile); ErrorCount = $errors.Count; WarningCount = $warnings.Count; Errors = @($errors); Warnings = @($warnings); WingetValidationExitCode = $wingetValidationExitCode }

$result

if ($errors.Count -gt 0) {
    throw "Winget manifest validation failed with $($errors.Count) error(s)."
}
