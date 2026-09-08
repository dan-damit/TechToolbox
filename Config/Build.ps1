<#
.SYNOPSIS
  One-shot build for TechToolbox:
  - Update manifest (version & GUID)
  - (Optional) Run PSSA analysis
  - Sign module files
  - (Optional) Package artifacts
    - (Optional) Release automation (bump/commit/tag/push)

.NOTES
  - Prefers PS7+ but works on Windows PowerShell 5.1+
  - Non-interactive by default; prompts only with -Interactive
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AutoVersionPatch,
    [switch]$Release,
    [switch]$RegenerateGuid,
    [switch]$SkipSigning,
    [bool]$SkipValidSigs = $true,
    [switch]$Recurse,
    [switch]$Analyze,         # Run PSSA (PowerShell ScriptAnalyzer)
    [switch]$FailOnPssa,      # Fail build if PSSA finds issues
    [switch]$ExportPublic,    # Export only functions discovered in Public\ (else '*')
    [switch]$Pack,            # Zip to .\Out\TechToolbox_<version>.zip
    [switch]$Interactive,     # Allow prompts when data is missing
    [string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$ConfigPath,
    [string]$TimestampServer,
    [string]$Thumbprint
)

function Invoke-Git {
    param(
        [Parameter(Mandatory)]
        [string[]]$gitArgs,
        [switch]$IgnoreExitCode
    )

    $output = & git -C $ModuleRoot @gitArgs 2>&1
    if ($LASTEXITCODE -ne 0 -and -not $IgnoreExitCode) {
        $joined = ($output | Out-String).Trim()
        throw "git $($gitArgs -join ' ') failed: $joined"
    }

    return ($output | Out-String).Trim()
}

# ---------------- 01. Load config --------------------------------------------
$defaultConfigDir = Join-Path $ModuleRoot 'Config'
$defaultConfigPath = Join-Path $defaultConfigDir 'build.config.json'
$legacyConfigPath = Join-Path $ModuleRoot 'build.config.json'

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    if (Test-Path -LiteralPath $defaultConfigPath) {
        $ConfigPath = $defaultConfigPath
    }
    elseif (Test-Path -LiteralPath $legacyConfigPath) {
        Write-Warning "Legacy build config found at '$legacyConfigPath'. Move it to '$defaultConfigPath'."
        $ConfigPath = $legacyConfigPath
    }
    else {
        $ConfigPath = $defaultConfigPath
    }
}
elseif (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigPath = Join-Path $ModuleRoot $ConfigPath
}

$cfg = $null
if (Test-Path -LiteralPath $ConfigPath) {
    $cfg = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
}
else {
    throw "Build config not found at '$ConfigPath'. Expected '$defaultConfigPath' or a valid override path."
}

$TimestampServer = $cfg.signing.timestamp ?? 'http://timestamp.digicert.com'
$Thumbprint = $cfg.signing.thumbprint

$rawOutDir = if ($null -ne $cfg.artifacts -and $null -ne $cfg.artifacts.outDir) { [string]$cfg.artifacts.outDir } else { '.\Out' }
$outDir = if ([System.IO.Path]::IsPathRooted($rawOutDir)) { $rawOutDir } else { Join-Path $ModuleRoot $rawOutDir }

$rawPssaSettings = if ($null -ne $cfg.quality -and $null -ne $cfg.quality.pssaSettings) { [string]$cfg.quality.pssaSettings } else { '.\PSScriptAnalyzerSettings.psd1' }
$pssaSettings = if ([System.IO.Path]::IsPathRooted($rawPssaSettings)) { $rawPssaSettings } else { Join-Path $ModuleRoot $rawPssaSettings }

$analyzeEnabled = $Analyze.IsPresent -or ($cfg.quality.analyze -eq $true)
$failOnPssa = $FailOnPssa.IsPresent -or ($cfg.quality.failOnPssa -eq $true)

# Release mode implies patch bump + manifest update flow, then git commit/tag/push.
if ($Release) {
    $AutoVersionPatch = $true

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "git is required for -Release but was not found in PATH."
    }

    $repoRoot = Invoke-Git -gitArgs @('rev-parse', '--show-toplevel')
    if (-not $repoRoot) {
        throw "-Release requires running inside a git repository."
    }

    $preReleaseDirty = Invoke-Git -gitArgs @('status', '--porcelain')
    if (-not [string]::IsNullOrWhiteSpace($preReleaseDirty)) {
        throw "Working tree is not clean. Commit or stash local changes before running -Release."
    }

    $releaseBranch = Invoke-Git -gitArgs @('rev-parse', '--abbrev-ref', 'HEAD')
    if ([string]::Equals($releaseBranch, 'HEAD', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "-Release requires a named branch checkout (detached HEAD is not supported for release pushes)."
    }

    Invoke-Git -gitArgs @('fetch', 'origin', $releaseBranch) | Out-Null
    $behindRaw = Invoke-Git -gitArgs @('rev-list', '--count', "HEAD..origin/$releaseBranch")
    $behindCount = 0
    [void][int]::TryParse($behindRaw, [ref]$behindCount)
    if ($behindCount -gt 0) {
        Write-Host "Release branch '$releaseBranch' is behind origin by $behindCount commit(s); rebasing before release." -ForegroundColor Yellow
        Invoke-Git -gitArgs @('pull', '--rebase', 'origin', $releaseBranch) | Out-Null
    }

    Write-Host "Release mode enabled: auto-version patch + manifest update + git release steps." -ForegroundColor Cyan
}

# ---------------- 02. Validate environment -----------------------------------
$manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Manifest not found: $manifestPath"
}

# ---------------- Helper: Import manifest ------------------------------------
$manifest = Import-PowerShellDataFile -Path $manifestPath
$manifestDescription = [string]$manifest.Description
$manifestReleaseNotes = [string]$manifest.PrivateData.PSData.ReleaseNotes
$manifestPowerShellVersion = '7.6.5'

# ---------------- 03. Compute new values -------------------------------------
$oldGuid = $manifest.Guid
$newGuid = if ($RegenerateGuid) { [guid]::NewGuid().Guid } else { $oldGuid }

$oldVersion = [version]$manifest.ModuleVersion
$newVersion = if ($AutoVersionPatch) {
    $build = if ($oldVersion.Build -ge 0) { $oldVersion.Build } else { 0 }
    [version]::new($oldVersion.Major, $oldVersion.Minor, $build + 1)
}
else { $oldVersion }

# Paths
$publicFolder = Join-Path $ModuleRoot 'Public'
$manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'

# Collect public function names from file basenames
$publicFiles = Get-ChildItem -LiteralPath $publicFolder -Filter *.ps1 -File -Recurse
$publicFuns = $publicFiles.BaseName | Sort-Object -Unique

# Preserve explicit non-Public exports (wrappers/entry points in .psm1)
$nonPublicExports = @()

$mergedExports = @($publicFuns + $nonPublicExports) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

# Fall back to '*' only if nothing found (e.g., dev shell without Public yet)
$functionsToExport = if ($mergedExports.Count -gt 0) { $mergedExports } else { @('*') }

# Keep aliases explicit (avoid '*') for faster module analysis
$aliasesToExport = @()  # set to concrete alias names when you have them

# Preserve existing PrivateData (both top-level keys and PSData)
$privateData = [ordered]@{}
if ($manifest.PrivateData) {
    $privateData = [ordered]@{} + $manifest.PrivateData
}

$psdata = [ordered]@{}
if ($privateData.PSData) {
    $psdata = [ordered]@{} + $privateData.PSData
}

# Normalize tags so gallery metadata remains valid (example: "active directory" -> "active-directory" then filter both deprecated forms).
if (($psdata.Keys -contains 'Tags') -and $null -ne $psdata.Tags) {
    $deprecatedTags = @('active-directory', 'active directory')

    $normalizedTags = @(
        $psdata.Tags | ForEach-Object {
            if ($_ -is [string]) {
                ($_ -replace '\s+', '-').Trim('-')
            }
            else {
                $_
            }
        }
    ) | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_) -and
        ($deprecatedTags -notcontains [string]$_)
    } | Select-Object -Unique

    $psdata['Tags'] = $normalizedTags
}

# Rebuild full PrivateData with normalized PSData
$privateData['PSData'] = $psdata

# Update manifest once (both exports and PrivateData)
Update-ModuleManifest -Path $manifestPath `
    -FunctionsToExport $functionsToExport `
    -AliasesToExport   $aliasesToExport `
    -Description       $manifestDescription `
    -ReleaseNotes      $manifestReleaseNotes `
    -PowerShellVersion $manifestPowerShellVersion `
    -PrivateData       $privateData

# ---------------- 04. Dirty check & update manifest --------------------------
$manifestChanged = $false
$exportsChanged = ($manifest.FunctionsToExport -join ',') -ne ($functionsToExport -join ',')

if ($oldGuid -ne $newGuid -or $oldVersion -ne $newVersion -or $exportsChanged) {
    if ($PSCmdlet.ShouldProcess($manifestPath, "Update manifest")) {
        Update-ModuleManifest -Path $manifestPath `
            -ModuleVersion $newVersion `
            -Guid $newGuid `
            -FunctionsToExport $functionsToExport `
            -AliasesToExport   $aliasesToExport `
            -Description       $manifestDescription `
            -ReleaseNotes      $manifestReleaseNotes `
            -PowerShellVersion $manifestPowerShellVersion `
            -PrivateData $privateData
        $manifestChanged = $true
        Write-Host "Manifest updated → Version: $oldVersion → $newVersion; Guid: $oldGuid → $newGuid" -ForegroundColor Cyan
    }
}
else {
    Write-Host "Manifest unchanged (no updates needed)." -ForegroundColor DarkCyan
}

# ---------------- 05. (Optional) PSSA analysis --------------------------------
$pssaIssues = @()
if ($analyzeEnabled) {
    try {
        if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
            Write-Warning "PSScriptAnalyzer module not found. Skipping analysis."
        }
        else {
            Import-Module PSScriptAnalyzer -ErrorAction Stop
            Write-Host "Running PSSA (ScriptAnalyzer)..." -ForegroundColor Cyan
            $pssaIssues = Invoke-ScriptAnalyzer -Path $ModuleRoot `
                -Settings $pssaSettings -Recurse
            if ($pssaIssues.Count -gt 0) {
                # Store a machine-readable report under CodeAnalysis\
                $caDir = Join-Path $ModuleRoot 'CodeAnalysis'
                New-Item -ItemType Directory -Force -Path $caDir | Out-Null
                $reportPath = Join-Path $caDir ("PSSA-Report_{0:yyyyMMdd_HHmmss}.json" -f (Get-Date))
                $pssaIssues | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $reportPath -Encoding UTF8
                Write-Host "PSSA found $($pssaIssues.Count) issue(s). Report: $reportPath" -ForegroundColor Yellow
                if ($failOnPssa -and -not $Interactive) {
                    throw "Build failed due to ScriptAnalyzer findings."
                }
            }
            else {
                Write-Host "PSSA clean." -ForegroundColor Green
            }
        }
    }
    catch {
        throw "PSSA run failed: $($_.Exception.Message)"
    }
}

# ---------------- 06. Signing -------------------------------------------------
function Get-CodeSigningCert {
    param([Parameter(Mandatory)] [string]$Thumb)
    $stores = @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')
    foreach ($store in $stores) {
        $found = Get-ChildItem $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }
        if ($found -and $found.HasPrivateKey) { return $found }
    }
    return $null
}

$ok = 0; $skip = 0; $warn = 0
if ($SkipSigning) {
    Write-Host "Signing skipped (-SkipSigning)." -ForegroundColor DarkYellow
}
else {
    if (-not $Thumbprint) {
        if ($Interactive) { $Thumbprint = Read-Host "Enter code signing thumbprint" }
        else { throw "Thumbprint not provided (set Config\build.config.json signing.thumbprint or pass -Thumbprint)." }
    }
    $cert = Get-CodeSigningCert -Thumb $Thumbprint
    if (-not $cert) { throw "Code signing cert not found or missing private key for thumbprint $Thumbprint." }

    # What to sign
    $search = @{ Path = $ModuleRoot; Include = '*.ps1', '*.psm1'; File = $true; Recurse = $true }
    $files = Get-ChildItem @search | Where-Object {
        $_.FullName -notmatch '\\(Out|Bin|CodeAnalysis|\.git)\\'
    }

    Write-Host "Signing $(($files|Measure-Object).Count) file(s)..." -ForegroundColor Cyan
    foreach ($f in $files) {
        try {
            if ($SkipValidSigs) {
                $sig = Get-AuthenticodeSignature -FilePath $f.FullName
                if ($sig.Status -eq 'Valid') { $skip++; continue }
            }
            $params = @{
                FilePath      = $f.FullName
                Certificate   = $cert
                HashAlgorithm = 'SHA256'
            }
            if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }
            $r = Set-AuthenticodeSignature @params
            if ($r.Status -eq 'Valid') { $ok++ } else { $warn++ }
        }
        catch {
            $warn++
        }
    }
    Write-Host "Signing complete → OK: $ok  Skipped: $skip  Warnings/Errors: $warn" -ForegroundColor Cyan
}

# ---------------- 06A. Build + publish .NET agent projects ------------------
$dotNetProjects = @(
    [pscustomobject]@{
        Name       = 'TechToolbox.Agent'
        ProjectPath = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.Agent.csproj'
        PublishDir  = Join-Path $ModuleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish'
    },
    [pscustomobject]@{
        Name       = 'TechToolbox.Agent.UI'
        ProjectPath = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.Agent.UI\TechToolbox.Agent.UI.csproj'
        PublishDir  = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.Agent.UI\bin\Release\net8.0-windows\win-x64\publish'
    }
)

foreach ($project in $dotNetProjects) {
    if (-not (Test-Path -LiteralPath $project.ProjectPath)) {
        Write-Host "Skipping .NET build/publish for missing project: $($project.ProjectPath)" -ForegroundColor DarkYellow
        continue
    }

    Write-Host "Building .NET project: $($project.Name)" -ForegroundColor Cyan
    & dotnet build $project.ProjectPath -c Release
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet build failed for $($project.ProjectPath)"
    }

    if (Test-Path -LiteralPath $project.PublishDir) {
        Remove-Item -LiteralPath $project.PublishDir -Recurse -Force
    }

    $publishArgs = @('publish', $project.ProjectPath, '-c', 'Release', '-o', $project.PublishDir)
    if ($project.Name -eq 'TechToolbox.Agent.UI') {
        $publishArgs += @('-r', 'win-x64')
    }

    Write-Host "Publishing .NET project: $($project.Name)" -ForegroundColor Cyan
    & dotnet @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for $($project.ProjectPath)"
    }

    Write-Host "Build + publish complete for $($project.Name) → $($project.PublishDir)" -ForegroundColor Green
}

# ---------------- 07. (Optional) Package -------------------------------------
$artifact = $null
if ($Pack) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $zip = Join-Path $outDir ("TechToolbox_{0}.zip" -f $newVersion)
    if (Test-Path $zip) { Remove-Item $zip -Force }
    # Zip only module assets
    $items = @(
        (Join-Path $ModuleRoot 'TechToolbox.psd1'),
        (Join-Path $ModuleRoot 'TechToolbox.psm1'),
        (Join-Path $ModuleRoot 'Public\*'),
        (Join-Path $ModuleRoot 'Private\*'),
        (Join-Path $ModuleRoot 'Config\*')
    )

    Compress-Archive -Path $items -DestinationPath $zip
    $artifact = $zip
    Write-Host "Packaged → $artifact" -ForegroundColor Green
}

# ---------------- 08. (Optional) Release commit/tag/push ---------------------
$releaseTag = $null
$releaseCommit = $null
$releasePushed = $false
if ($Release) {
    $releaseTag = "v$newVersion"

    $existingTag = Invoke-Git -gitArgs @('tag', '--list', $releaseTag)
    if (-not [string]::IsNullOrWhiteSpace($existingTag)) {
        throw "Tag already exists: $releaseTag"
    }

    $branchName = Invoke-Git -gitArgs @('rev-parse', '--abbrev-ref', 'HEAD')

    Invoke-Git -gitArgs @('add', '-A') | Out-Null
    & git -C $ModuleRoot diff --cached --quiet
    if ($LASTEXITCODE -eq 0) {
        throw "No staged changes detected after release build. Nothing to commit/tag."
    }

    $commitMessage = "release: $releaseTag"
    if ($PSCmdlet.ShouldProcess($ModuleRoot, "Create release commit ($commitMessage)")) {
        Invoke-Git -gitArgs @('commit', '-m', $commitMessage) | Out-Null
        $releaseCommit = Invoke-Git -gitArgs @('rev-parse', '--short', 'HEAD')
        Write-Host "Release commit created: $releaseCommit" -ForegroundColor Green
    }

    if ($PSCmdlet.ShouldProcess($ModuleRoot, "Create git tag $releaseTag")) {
        Invoke-Git -gitArgs @('tag', '-a', $releaseTag, '-m', "Release $releaseTag") | Out-Null
        Write-Host "Tag created: $releaseTag" -ForegroundColor Green
    }

    if ($PSCmdlet.ShouldProcess($ModuleRoot, "Push branch '$branchName' and tag '$releaseTag' to origin")) {
        Invoke-Git -gitArgs @('push', 'origin', $branchName) | Out-Null
        Invoke-Git -gitArgs @('push', 'origin', $releaseTag) | Out-Null
        $releasePushed = $true
        Write-Host "Pushed branch + tag. Tag push should trigger .github/workflows/publish.yml" -ForegroundColor Green
    }
}

# ---------------- 09. Emit summary -------------------------------------------
$result = [pscustomobject]@{
    ManifestPath    = $manifestPath
    Version         = [pscustomobject]@{ Old = $oldVersion; New = $newVersion }
    Guid            = [pscustomobject]@{ Old = $oldGuid; New = $newGuid }
    ManifestUpdated = $manifestChanged
    PssaIssues      = $pssaIssues.Count
    FilesSigned     = $ok
    FilesSkipped    = $skip
    FilesWarned     = $warn
    ArtifactPath    = $artifact
    Release         = [pscustomobject]@{
        Enabled      = [bool]$Release
        Commit       = $releaseCommit
        Tag          = $releaseTag
        Pushed       = $releasePushed
        PipelineHint = if ($releasePushed -and $releaseTag) { "GitHub Actions publish workflow triggers on pushed v* tags." } else { $null }
    }
}
$result

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCPDHkyN5m2cc0P
# DxF0dSj1f617WxDafkMM/jjrIww8JaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCrGFYN9MlI
# fD7VQJccA1auwRc/XkIlkhYbcAdKiRX39zANBgkqhkiG9w0BAQEFAASCAgBYTLWO
# gcZMKiPWy5q0kBtJ3uFJDorpqQROm4Dyie8KZ3PtchLaVfzJAzu6gAY0Z/NLVjjz
# 9BrS4Zz7cBw3iCzNqZNpK9joDHTdrvLDLfiYMh8cEKSWl7Dyf6ulz/c/4Q7sYT7M
# /jp+1XaosHeTRocGUKii1TBLVL6FF02iUmy0U6OydvgaBmqgAQfpohOpB+D1BMVl
# ZU+zvgVrKSE+fdsqy0Ybzi0rfiW0YIQLKtavvBm4w9Y1bKm8jsxg+g/HlXK8Sv7K
# hDnVgrPPgMjAt1Ct5Pu0w8JzQgaEw0yqEmmKqftcoVLf/hrbFgAQ2i79zSwlxz3A
# 7OmDGThKOFtVAI3KoClT8QWPUmhoIy/O4xaeME8IsrLD995IUCjJr35+X6su0TyY
# WO4rqIwIODm+vEpCoWRo0QzX6qsHCu0ckOBkM/aNCaVB6Uj3+nX9NsvsF93OjSMZ
# hvIsAtxm0z0GWsQimW4kEC5AsyxrNsycPiYmG1dt7Sa2YydvUc379FqO+noWJasi
# M7le3hlGk9LilBVjqzdjCqMs+i3svGEmtkwD87HRcWzkBl2BrcUXGkupLGO33KNT
# rm6/1VPsVn2NnSLP2w8a1QDdGBuZNv3B20MgGIVKTIJxEHKpUtgixaO4NVEJqpuV
# GxHEYYKK/E+oLO4pC3HelCsvW8tra9PHSgBCxKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MDgwNDA5MTRaMC8GCSqGSIb3DQEJBDEiBCCyV04lVUda70zY0mMD
# p5lgyDx/ExYglS0m2ZASymg5qTANBgkqhkiG9w0BAQEFAASCAgBSoVsOhVHNwiGf
# NW+ic6G3KzUAK75yio3t1IqMkDNI2evrWKaAXbNmWSfXwrwBJYAusrdId5Q/wzZf
# 6VVQntT53H2KNqLNJBHR+oVDhF2JciS2DN9snHJCVsXM2FJNiRiJYXGdkbYjgxEm
# GQrVPIAKUmizUMPzR/E8bnhHnDCBd4SgHPiFV/Y0zfsHLbg8hCHz6UwcMjmvnGPf
# cU5mKW/lel6Nq66tNnpUVs2fDWVuDwmovuDp+TTfSOls4ke/4HsPaQu4OBRpxvhq
# Eza4vdHb1VZFT48jnlabX/PzDJUUWxXi5BjYF9I3aYY6AVXcKvbOqyM/D9iORg4k
# 3cKqsPGD/B/18Db2xu4Yxm5nALclTzTmc/BsOS4c1eyEdeLWnq+QhZWNlSA0JT0B
# /0xQjJywqT9Sxd+tHGLglG+sOiK4K1qhzToctdLVgFQSWIPvrHIJjJCrVCKqN3Ue
# /BRyPU53okGzEY1OSiRqlByLARvlgOmdvMMM/BwGub/cVgoEtb6ni//Kg+vE78pS
# dvdGT2MLnXLz44hDrh+MS8IVNo5sgcLpFsfr+8bb7cyAiHk/RLfSIZRvf9pfervD
# /k8ikD1z6R0qL+m16o9E9c6CXHwbqXYLc6e2RF9M1I5qq/Y6OHtLvMiE8yRpFoFS
# KxMp9p1O3v+FbdJCpMvaTVleiDfh3g==
# SIG # End signature block
