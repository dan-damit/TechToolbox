param()

Write-Host "Fetching PSGallery data..."
$module = Find-Module -Name "TechToolbox"

$psVersion = $module.Version.ToString()
$psDownloads = $module.TotalDownloads

Write-Host "Fetching GitHub release data..."
$gh = Invoke-RestMethod "https://api.github.com/repos/dan-damit/TechToolbox/releases/latest"

$ghVersion = $gh.tag_name

Write-Host "Building badge data..."
$badgeData = @{
    VERSION             = $psVersion
    PSGALLERY_DOWNLOADS = $psDownloads
    GH_RELEASE          = $ghVersion
}

$templatePath = "assets/badges/templates"
$outputPath = "assets/badges"

Get-ChildItem $templatePath -Filter *.template | ForEach-Object {
    $template = Get-Content $_.FullName -Raw
    foreach ($key in $badgeData.Keys) {
        $template = $template -replace "{{$key}}", $badgeData[$key]
    }

    $outFile = Join-Path $outputPath ($_.BaseName.Replace(".svg", "") + ".svg")
    Set-Content -Path $outFile -Value $template -Encoding UTF8

    Write-Host "Generated $outFile"
}
