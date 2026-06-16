param()

Write-Host "=== TechToolbox Badge Builder ===" -ForegroundColor Cyan

# -----------------------------
# Helper: Format numbers nicely
# -----------------------------
function Format-Number {
    param([long]$n)
    if ($null -eq $n) { return "0" }
    return "{0:N0}" -f $n
}

# -----------------------------
# Fetch PSGallery Data
# -----------------------------
Write-Host "`n[1/4] Fetching PSGallery data..." -ForegroundColor Yellow

$psVersion = "N/A"
$psDownloads = 0

try {
    $module = Find-Module -Name "TechToolbox" -ErrorAction Stop

    # Version
    $psVersion = $module.Version.ToString()

    # Downloads (property may not exist)
    if ($module.PSObject.Properties.Match('TotalDownloads')) {
        $value = $module.TotalDownloads
        if ($null -ne $value -and $value -is [int] -and $value -ge 0) {
            $psDownloads = $value
        }
    }
}
catch {
    Write-Warning "Failed to fetch PSGallery data: $_"
}

# --- Smoothing: prevent PSGallery API regressions ---
$downloadsFile = "./assets/badges/last-downloads.txt"

# Load previous value
$previousDownloads = 0
if (Test-Path $downloadsFile) {
    $previousDownloads = [int](Get-Content $downloadsFile)
}

# Prevent regression if API is stale
if ($psDownloads -lt $previousDownloads) {
    $psDownloads = $previousDownloads
}

# Save updated value
$psDownloads | Out-File $downloadsFile

# Format for badges
$psDownloadsFormatted = Format-Number $psDownloads

Write-Host "  Version: $psVersion"
Write-Host "  Downloads: $psDownloadsFormatted"

# -----------------------------
# Fetch GitHub Release Data
# -----------------------------
Write-Host "`n[2/4] Fetching GitHub release data..." -ForegroundColor Yellow

try {
    $gh = Invoke-RestMethod "https://api.github.com/repos/dan-damit/TechToolbox/releases/latest" -ErrorAction Stop

    $ghVersion = $gh.tag_name
    $ghDownloads = ($gh.assets | Measure-Object -Property download_count -Sum).Sum
    $ghDownloadsFormatted = Format-Number $ghDownloads
}
catch {
    Write-Warning "Failed to fetch GitHub release data: $_"
    $ghVersion = "N/A"
    $ghDownloadsFormatted = "0"
}

Write-Host "  GitHub Release: $ghVersion"
Write-Host "  GitHub Downloads: $ghDownloadsFormatted"
Write-Host "  Required PowerShell: 7.6+"

# -----------------------------
# Build Replacement Table
# -----------------------------
Write-Host "`n[3/4] Preparing badge data..." -ForegroundColor Yellow

$badgeData = @{
    VERSION             = $psVersion
    PSGALLERY_DOWNLOADS = $psDownloadsFormatted
    GH_RELEASE          = $ghVersion
    GH_DOWNLOADS        = $ghDownloadsFormatted
    REQUIRED_PWSH       = "7.6+"
}

$badgeData.GetEnumerator() | ForEach-Object {
    Write-Host "  $($_.Key) = $($_.Value)"
}

# -----------------------------
# Process Templates
# -----------------------------
Write-Host "`n[4/4] Generating SVG badges..." -ForegroundColor Yellow

$templatePath = "assets/badges/templates"
$outputPath = "assets/badges"

$templates = Get-ChildItem $templatePath -Filter *.template -ErrorAction SilentlyContinue

if (-not $templates) {
    Write-Error "No template files found in $templatePath"
    exit 1
}

foreach ($file in $templates) {
    Write-Host "  Processing $($file.Name)..."

    $template = Get-Content $file.FullName -Raw

    # Validate placeholders
    foreach ($key in $badgeData.Keys) {
        if ($template -notmatch "{{$key}}") {
            Write-Warning "Template '$($file.Name)' does not contain placeholder {{$key}}"
        }
    }

    # Replace placeholders
    foreach ($key in $badgeData.Keys) {
        $value = $badgeData[$key]
        $template = $template -replace "{{$key}}", $value
    }

    # Output final SVG
    $outFile = Join-Path $outputPath ($file.BaseName.Replace(".svg", "") + ".svg")
    Set-Content -Path $outFile -Value $template -Encoding UTF8

    Write-Host "    → Generated $outFile" -ForegroundColor Green
}

Write-Host "`n=== Badge Build Complete ===" -ForegroundColor Cyan
