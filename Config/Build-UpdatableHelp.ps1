[CmdletBinding()]
param(
    [string]$ModuleManifestPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'TechToolbox.psd1'),
    [string]$SourceHelpPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'en-US'),
    [string]$OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Out\UpdatableHelp'),
    [string]$Culture = 'en-US',
    [string]$HelpVersion,
    [string]$HelpContentUri,
    [string]$ExternalHelpPath,
    [switch]$Clean
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

function Get-HelpVersionString {
    param([Parameter(Mandatory)][string]$RawVersion)

    $v = [version]$RawVersion

    $major = $v.Major
    $minor = $v.Minor
    $build = if ($v.Build -lt 0) { 0 } else { $v.Build }
    $revision = if ($v.Revision -lt 0) { 0 } else { $v.Revision }

    return '{0}.{1}.{2}.{3}' -f $major, $minor, $build, $revision
}

function New-HelpCabinet {
    param(
        [Parameter(Mandatory)][string]$CabinetName,
        [Parameter(Mandatory)][string]$DestinationDirectory,
        [Parameter(Mandatory)][string[]]$InputFiles
    )

    $makecab = Get-Command -Name 'makecab.exe' -ErrorAction SilentlyContinue
    if (-not $makecab) {
        throw "makecab.exe was not found. Install the Windows cabinet tools or run from Windows with makecab available."
    }

    $token = [guid]::NewGuid().ToString('N')
    $ddfPath = Join-Path $env:TEMP ("tt-help-{0}.ddf" -f $token)
    $infPath = Join-Path $env:TEMP ("tt-help-{0}.inf" -f $token)
    $rptPath = Join-Path $env:TEMP ("tt-help-{0}.rpt" -f $token)

    try {
        $ddfLines = @(
            '.OPTION EXPLICIT'
            ".Set CabinetNameTemplate=$CabinetName"
            ".Set DiskDirectoryTemplate=$DestinationDirectory"
            ".Set InfFileName=$infPath"
            ".Set RptFileName=$rptPath"
            '.Set Cabinet=on'
            '.Set Compress=on'
            '.Set CompressionType=MSZIP'
            '.Set UniqueFiles=on'
        )

        foreach ($file in $InputFiles) {
            $ddfLines += ('"{0}"' -f $file)
        }

        Set-Content -LiteralPath $ddfPath -Value $ddfLines -Encoding ASCII

        $null = & $makecab.Source '/F' $ddfPath
        if ($LASTEXITCODE -ne 0) {
            throw "makecab.exe failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        if (Test-Path -LiteralPath $ddfPath) {
            Remove-Item -LiteralPath $ddfPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $infPath) {
            Remove-Item -LiteralPath $infPath -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path -LiteralPath $rptPath) {
            Remove-Item -LiteralPath $rptPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$manifestPath = Resolve-AbsolutePath -Path $ModuleManifestPath
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Module manifest not found: $manifestPath"
}

$sourceHelpPath = Resolve-AbsolutePath -Path $SourceHelpPath
if (-not (Test-Path -LiteralPath $sourceHelpPath)) {
    throw "Source help folder not found: $sourceHelpPath"
}

$outputRoot = Resolve-AbsolutePath -Path $OutputPath
$manifest = Import-PowerShellDataFile -Path $manifestPath

$moduleName = [System.IO.Path]::GetFileNameWithoutExtension($manifestPath)
$moduleGuid = [string]$manifest.GUID
if ([string]::IsNullOrWhiteSpace($moduleGuid)) {
    throw "Manifest GUID is missing in $manifestPath"
}

$resolvedHelpVersion = if ([string]::IsNullOrWhiteSpace($HelpVersion)) {
    [string]$manifest.ModuleVersion
}
else {
    $HelpVersion
}

if ([string]::IsNullOrWhiteSpace($resolvedHelpVersion)) {
    throw "Help version could not be resolved from manifest ModuleVersion."
}

$resolvedHelpContentUri = if ([string]::IsNullOrWhiteSpace($HelpContentUri)) {
    [string]$manifest.HelpInfoURI
}
else {
    $HelpContentUri
}

if ([string]::IsNullOrWhiteSpace($resolvedHelpContentUri)) {
    throw "HelpContentUri was not provided and HelpInfoURI is missing in manifest."
}

if (-not ($resolvedHelpContentUri -match '^https?://')) {
    throw "HelpContentUri must be an absolute http/https URI. Received: $resolvedHelpContentUri"
}

$helpVersionString = Get-HelpVersionString -RawVersion $resolvedHelpVersion

$stagingPath = Join-Path $outputRoot ("staging-{0}" -f $Culture)
$feedPath = Join-Path $outputRoot $Culture

if ($Clean) {
    if (Test-Path -LiteralPath $stagingPath) {
        Remove-Item -LiteralPath $stagingPath -Recurse -Force
    }
    if (Test-Path -LiteralPath $feedPath) {
        Remove-Item -LiteralPath $feedPath -Recurse -Force
    }
}

$null = New-Item -ItemType Directory -Path $stagingPath -Force
$null = New-Item -ItemType Directory -Path $feedPath -Force

$copiedFiles = New-Object System.Collections.Generic.List[string]

$aboutFiles = Get-ChildItem -LiteralPath $sourceHelpPath -File -Filter '*.help.txt'
foreach ($file in $aboutFiles) {
    $destination = Join-Path $stagingPath $file.Name
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
    [void]$copiedFiles.Add($destination)
}

if (-not [string]::IsNullOrWhiteSpace($ExternalHelpPath)) {
    $externalPath = Resolve-AbsolutePath -Path $ExternalHelpPath
    if (-not (Test-Path -LiteralPath $externalPath)) {
        throw "ExternalHelpPath does not exist: $externalPath"
    }

    $xmlFiles = Get-ChildItem -LiteralPath $externalPath -File -Filter '*-help.xml'
    foreach ($file in $xmlFiles) {
        $destination = Join-Path $stagingPath $file.Name
        Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
        [void]$copiedFiles.Add($destination)
    }
}

if ($copiedFiles.Count -eq 0) {
    throw "No help files were staged. Add *.help.txt to $sourceHelpPath and optionally *-help.xml via -ExternalHelpPath."
}

$cabName = '{0}_{1}_{2}_HelpContent.cab' -f $moduleName, $moduleGuid, $Culture
$helpInfoName = '{0}_{1}_HelpInfo.xml' -f $moduleName, $moduleGuid

New-HelpCabinet -CabinetName $cabName -DestinationDirectory $feedPath -InputFiles $copiedFiles

$cabPath = Join-Path $feedPath $cabName
if (-not (Test-Path -LiteralPath $cabPath)) {
    throw "CAB build succeeded but output file was not found: $cabPath"
}

$helpInfoPath = Join-Path $feedPath $helpInfoName

$helpInfoXml = @"
<?xml version="1.0" encoding="utf-8"?>
<HelpInfo xmlns="http://schemas.microsoft.com/powershell/help/2010/05">
  <HelpContentURI>$resolvedHelpContentUri</HelpContentURI>
  <SupportedUICultures>
    <UICulture>
      <UICultureName>$Culture</UICultureName>
      <UICultureVersion>$helpVersionString</UICultureVersion>
    </UICulture>
  </SupportedUICultures>
</HelpInfo>
"@

Set-Content -LiteralPath $helpInfoPath -Value $helpInfoXml -Encoding UTF8

Remove-Item -LiteralPath $stagingPath -Recurse -Force -ErrorAction SilentlyContinue

[pscustomobject]@{
    ModuleName        = $moduleName
    ModuleGuid        = $moduleGuid
    Culture           = $Culture
    HelpVersion       = $helpVersionString
    HelpContentUri    = $resolvedHelpContentUri
    FeedPath          = $feedPath
    HelpInfoXmlPath   = $helpInfoPath
    HelpCabPath       = $cabPath
    StagedFileCount   = $copiedFiles.Count
    StagedFileSamples = @($copiedFiles | Select-Object -First 10 | ForEach-Object { [System.IO.Path]::GetFileName($_) })
}
