[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceImagePath,

    [string]$SplashSourceImagePath,

    [string]$AssetsDirectory,

    [switch]$SkipValidation
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Drawing

function Resolve-AbsolutePath {
    param([Parameter(Mandatory)] [string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function New-ScaledImage {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image]$Source,
        [Parameter(Mandatory)] [int]$Width,
        [Parameter(Mandatory)] [int]$Height,
        [ValidateSet('crop', 'fit')] [string]$Mode = 'crop'
    )

    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $bitmap.SetResolution(96, 96)

    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality

        $sourceRatio = $Source.Width / [double]$Source.Height
        $targetRatio = $Width / [double]$Height

        if ($Mode -eq 'crop') {
            if ($sourceRatio -gt $targetRatio) {
                $drawHeight = $Height
                $drawWidth = [int][Math]::Round($Height * $sourceRatio)
            }
            else {
                $drawWidth = $Width
                $drawHeight = [int][Math]::Round($Width / $sourceRatio)
            }
        }
        else {
            if ($sourceRatio -gt $targetRatio) {
                $drawWidth = $Width
                $drawHeight = [int][Math]::Round($Width / $sourceRatio)
            }
            else {
                $drawHeight = $Height
                $drawWidth = [int][Math]::Round($Height * $sourceRatio)
            }
        }

        $offsetX = [int][Math]::Floor(($Width - $drawWidth) / 2)
        $offsetY = [int][Math]::Floor(($Height - $drawHeight) / 2)
        $graphics.DrawImage($Source, $offsetX, $offsetY, $drawWidth, $drawHeight)
    }
    finally {
        $graphics.Dispose()
    }

    return $bitmap
}

function Save-PngVariant {
    param(
        [Parameter(Mandatory)] [System.Drawing.Image]$Source,
        [Parameter(Mandatory)] [string]$OutputPath,
        [Parameter(Mandatory)] [int]$Width,
        [Parameter(Mandatory)] [int]$Height,
        [ValidateSet('crop', 'fit')] [string]$Mode = 'crop'
    )

    $directory = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $scaled = New-ScaledImage -Source $Source -Width $Width -Height $Height -Mode $Mode
    try {
        $scaled.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $scaled.Dispose()
    }
}

function Get-DetachedImage {
    param([Parameter(Mandatory)] [string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $memoryStream = New-Object System.IO.MemoryStream(,$bytes)
    try {
        $loaded = [System.Drawing.Image]::FromStream($memoryStream)
        try {
            return New-Object System.Drawing.Bitmap($loaded)
        }
        finally {
            $loaded.Dispose()
        }
    }
    finally {
        $memoryStream.Dispose()
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($AssetsDirectory)) {
    $AssetsDirectory = Join-Path $repoRoot 'src\TechShell\src\TechShell.UI\Assets'
}

$resolvedSourceImagePath = Resolve-AbsolutePath -Path $SourceImagePath
if (-not (Test-Path -LiteralPath $resolvedSourceImagePath -PathType Leaf)) {
    throw "Source image not found: $resolvedSourceImagePath"
}

$resolvedSplashSourcePath = if ([string]::IsNullOrWhiteSpace($SplashSourceImagePath)) {
    $resolvedSourceImagePath
}
else {
    Resolve-AbsolutePath -Path $SplashSourceImagePath
}

if (-not (Test-Path -LiteralPath $resolvedSplashSourcePath -PathType Leaf)) {
    throw "Splash source image not found: $resolvedSplashSourcePath"
}

$resolvedAssetsDirectory = Resolve-AbsolutePath -Path $AssetsDirectory
if (-not (Test-Path -LiteralPath $resolvedAssetsDirectory -PathType Container)) {
    New-Item -ItemType Directory -Path $resolvedAssetsDirectory -Force | Out-Null
}

$iconMap = @(
    @{ Name = 'StoreLogo.png'; Width = 50; Height = 50; Mode = 'crop' },
    @{ Name = 'Square44x44Logo.png'; Width = 44; Height = 44; Mode = 'crop' },
    @{ Name = 'Square150x150Logo.png'; Width = 150; Height = 150; Mode = 'crop' },
    @{ Name = 'Wide310x150Logo.png'; Width = 310; Height = 150; Mode = 'fit' },
    @{ Name = 'SplashScreen.png'; Width = 620; Height = 300; Mode = 'fit'; Splash = $true },
    @{ Name = 'Square150x150Logo.scale-200.png'; Width = 300; Height = 300; Mode = 'crop' },
    @{ Name = 'Square44x44Logo.scale-200.png'; Width = 88; Height = 88; Mode = 'crop' },
    @{ Name = 'Wide310x150Logo.scale-200.png'; Width = 620; Height = 300; Mode = 'fit' },
    @{ Name = 'SplashScreen.scale-200.png'; Width = 1240; Height = 600; Mode = 'fit'; Splash = $true },
    @{ Name = 'LockScreenLogo.scale-200.png'; Width = 48; Height = 48; Mode = 'crop' },
    @{ Name = 'Square44x44Logo.targetsize-24_altform-unplated.png'; Width = 24; Height = 24; Mode = 'crop' },
    @{ Name = 'Square44x44Logo.targetsize-48_altform-lightunplated.png'; Width = 48; Height = 48; Mode = 'crop' }
)

$iconSource = Get-DetachedImage -Path $resolvedSourceImagePath
$splashSource = Get-DetachedImage -Path $resolvedSplashSourcePath
try {
    foreach ($entry in $iconMap) {
        $source = if ($entry.ContainsKey('Splash') -and $entry.Splash) { $splashSource } else { $iconSource }
        $outputPath = Join-Path $resolvedAssetsDirectory $entry.Name
        Save-PngVariant -Source $source -OutputPath $outputPath -Width $entry.Width -Height $entry.Height -Mode $entry.Mode
        Write-Host ("Generated {0} ({1}x{2})" -f $entry.Name, $entry.Width, $entry.Height) -ForegroundColor Cyan
    }
}
finally {
    $iconSource.Dispose()
    $splashSource.Dispose()
}

if (-not $SkipValidation) {
    $validatorScript = Join-Path $PSScriptRoot 'Test-TechShellManifestAssets.ps1'
    if (-not (Test-Path -LiteralPath $validatorScript -PathType Leaf)) {
        throw "Validator script not found: $validatorScript"
    }

    & $validatorScript
}

Write-Host "TechShell asset generation completed." -ForegroundColor Green
