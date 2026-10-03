[CmdletBinding()]
param(
    [string]$ManifestPath,
    [string]$ProjectRoot
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Resolve-AbsolutePath {
    param([Parameter(Mandatory)] [string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $repoRoot 'src\TechShell\src\TechShell.UI\Package.appxmanifest'
}

if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = Split-Path -Parent $ManifestPath
}

$manifestPathResolved = Resolve-AbsolutePath -Path $ManifestPath
$projectRootResolved = Resolve-AbsolutePath -Path $ProjectRoot

if (-not (Test-Path -LiteralPath $manifestPathResolved -PathType Leaf)) {
    throw "Manifest not found: $manifestPathResolved"
}

if (-not (Test-Path -LiteralPath $projectRootResolved -PathType Container)) {
    throw "Project root not found: $projectRootResolved"
}

[xml]$manifestXml = Get-Content -LiteralPath $manifestPathResolved -Raw
$ns = New-Object System.Xml.XmlNamespaceManager($manifestXml.NameTable)
$ns.AddNamespace('pkg', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
$ns.AddNamespace('uap', 'http://schemas.microsoft.com/appx/manifest/uap/windows10')

$assetCandidates = @()

$propertiesLogoNode = $manifestXml.SelectSingleNode('/pkg:Package/pkg:Properties/pkg:Logo', $ns)
if ($propertiesLogoNode -and -not [string]::IsNullOrWhiteSpace($propertiesLogoNode.InnerText)) {
    $assetCandidates += $propertiesLogoNode.InnerText.Trim()
}

$visualNodes = $manifestXml.SelectNodes('//uap:VisualElements', $ns)
foreach ($visualNode in $visualNodes) {
    foreach ($attrName in @('Square150x150Logo', 'Square44x44Logo')) {
        $attr = $visualNode.Attributes[$attrName]
        if ($attr -and -not [string]::IsNullOrWhiteSpace($attr.Value)) {
            $assetCandidates += $attr.Value.Trim()
        }
    }
}

$defaultTileNodes = $manifestXml.SelectNodes('//uap:DefaultTile', $ns)
foreach ($tileNode in $defaultTileNodes) {
    $wideAttr = $tileNode.Attributes['Wide310x150Logo']
    if ($wideAttr -and -not [string]::IsNullOrWhiteSpace($wideAttr.Value)) {
        $assetCandidates += $wideAttr.Value.Trim()
    }
}

$splashNodes = $manifestXml.SelectNodes('//uap:SplashScreen', $ns)
foreach ($splashNode in $splashNodes) {
    $imageAttr = $splashNode.Attributes['Image']
    if ($imageAttr -and -not [string]::IsNullOrWhiteSpace($imageAttr.Value)) {
        $assetCandidates += $imageAttr.Value.Trim()
    }
}

$protocolLogoNodes = $manifestXml.SelectNodes('//uap:Protocol/uap:Logo', $ns)
foreach ($protocolLogoNode in $protocolLogoNodes) {
    if (-not [string]::IsNullOrWhiteSpace($protocolLogoNode.InnerText)) {
        $assetCandidates += $protocolLogoNode.InnerText.Trim()
    }
}

$assetPaths = $assetCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique
if (-not $assetPaths) {
    throw "No manifest asset references found in: $manifestPathResolved"
}

$missing = @()
$present = @()

foreach ($assetPath in $assetPaths) {
    $fullPath = Join-Path $projectRootResolved ($assetPath -replace '/', '\\')
    if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
        $present += [pscustomobject]@{ AssetPath = $assetPath; FullPath = $fullPath }
    }
    else {
        $missing += [pscustomobject]@{ AssetPath = $assetPath; FullPath = $fullPath }
    }
}

Write-Host 'Manifest assets present:' -ForegroundColor Green
$present | Sort-Object AssetPath | Format-Table AssetPath, FullPath -AutoSize

if ($missing.Count -gt 0) {
    Write-Host 'Manifest assets missing:' -ForegroundColor Red
    $missing | Sort-Object AssetPath | Format-Table AssetPath, FullPath -AutoSize
    throw "Manifest asset validation failed: $($missing.Count) asset file(s) are missing."
}

Write-Host 'Manifest asset validation passed.' -ForegroundColor Green
