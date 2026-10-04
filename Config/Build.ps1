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
    [switch]$SkipProjects,    # Skip .NET project build/publish steps
    [switch]$BuildTechShellWinget, # Opt-in: build/sign TechShell MSIX + winget manifests via Config\Build-TechShellWinget.ps1
    [switch]$SkipTechShell,    # Explicitly disable TechShell build/publish even when release or caller opts in
    [string]$TechShellReleaseTag,
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')]
    [string]$TechShellRuntimeIdentifier = 'win-x64',
    [string]$TechShellInstallerFileName = 'TechShell.msix',
    [switch]$SkipTechShellManifestWrite,
    [switch]$SkipTechShellManifestValidation,
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

function Resolve-DotNetInvocation {
    $sdkScopedPattern = '[\\/]sdk[\\/][^\\/]+[\\/]dotnet(?:\.exe)?$'
    $dotnetHost = $null

    $resolved = Get-Command dotnet -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($resolved) {
        $resolvedPath = [string]$resolved.Source
        if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
            $resolvedPath = [string]$resolved.Path
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedPath) -and $resolvedPath -notmatch $sdkScopedPattern) {
            $dotnetHost = $resolvedPath
        }
    }

    $fallbackCandidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:DOTNET_ROOT)) {
        $fallbackCandidates += (Join-Path $env:DOTNET_ROOT 'dotnet.exe')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $fallbackCandidates += (Join-Path $env:ProgramFiles 'dotnet\dotnet.exe')
    }

    foreach ($candidate in ($fallbackCandidates | Select-Object -Unique)) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $dotnetHost = $candidate
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($dotnetHost)) {
        if ($resolved) {
            $resolvedPathForError = [string]$resolved.Source
            if ([string]::IsNullOrWhiteSpace($resolvedPathForError)) {
                $resolvedPathForError = [string]$resolved.Path
            }

            if ($resolvedPathForError -match $sdkScopedPattern) {
                throw "Resolved 'dotnet' to SDK-scoped host path '$resolvedPathForError', which is invalid. Ensure a valid .NET host is available at DOTNET_ROOT\dotnet.exe or Program Files\dotnet\dotnet.exe."
            }
        }

        throw ".NET host executable 'dotnet' could not be resolved. Install/repair .NET SDK and ensure dotnet.exe is available."
    }

    $versionOutput = & $dotnetHost --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        return [pscustomobject]@{
            HostPath       = $dotnetHost
            Prefix         = @()
            DisplayCommand = $dotnetHost
        }
    }

    $listSdkOutput = & $dotnetHost --list-sdks 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ".NET host '$dotnetHost' failed --version and --list-sdks checks. --version output: $($versionOutput -join [Environment]::NewLine)"
    }

    $sdkCandidates = @()
    foreach ($sdkLine in $listSdkOutput) {
        if ($sdkLine -match '^\s*([0-9]+\.[0-9]+\.[0-9]+)\s+\[(.+)\]\s*$') {
            $sdkVersionText = $matches[1]
            $sdkRoot = $matches[2]
            $sdkDotNetDll = Join-Path (Join-Path $sdkRoot $sdkVersionText) 'dotnet.dll'
            if (Test-Path -LiteralPath $sdkDotNetDll -PathType Leaf) {
                $sdkCandidates += [pscustomobject]@{
                    Version    = [version]$sdkVersionText
                    VersionRaw = $sdkVersionText
                    DotNetDll  = $sdkDotNetDll
                }
            }
        }
    }

    foreach ($sdkCandidate in ($sdkCandidates | Sort-Object Version -Descending)) {
        & $dotnetHost exec $sdkCandidate.DotNetDll --version *> $null
        if ($LASTEXITCODE -eq 0) {
            return [pscustomobject]@{
                HostPath       = $dotnetHost
                Prefix         = @('exec', $sdkCandidate.DotNetDll)
                DisplayCommand = "$dotnetHost exec $($sdkCandidate.DotNetDll)"
            }
        }
    }

    throw ".NET host '$dotnetHost' is present but could not execute any installed SDK command host. --version output: $($versionOutput -join [Environment]::NewLine)"
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
$manifestPowerShellVersion = '7.4.0'

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

function Sign-FileSet {
    param(
        [Parameter(Mandatory)] [string[]]$Files,
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [switch]$SkipValidSigs,
        [string]$TimestampServer,
        [ref]$OkCount,
        [ref]$SkippedCount,
        [ref]$WarnCount
    )

    foreach ($f in $Files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }

        try {
            if ($SkipValidSigs) {
                $sig = Get-AuthenticodeSignature -FilePath $f
                if ($sig.Status -eq 'Valid') { $SkippedCount.Value++; continue }
            }

            $params = @{
                FilePath      = $f
                Certificate   = $Certificate
                HashAlgorithm = 'SHA256'
            }
            if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }

            $r = Set-AuthenticodeSignature @params
            if ($r.Status -eq 'Valid') { $OkCount.Value++ } else { $WarnCount.Value++ }
        }
        catch {
            $WarnCount.Value++
        }
    }
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
    Sign-FileSet -Files ($files.FullName) -Certificate $cert -SkipValidSigs:$SkipValidSigs -TimestampServer $TimestampServer -OkCount ([ref]$ok) -SkippedCount ([ref]$skip) -WarnCount ([ref]$warn)
    Write-Host "Signing complete → OK: $ok  Skipped: $skip  Warnings/Errors: $warn" -ForegroundColor Cyan
}

# ---------------- 06A. Build + publish .NET agent projects ------------------
if ($SkipProjects) {
    Write-Host "Skipping .NET project build/publish (-SkipProjects)." -ForegroundColor DarkYellow
}
else {
    $dotnetInvocation = Resolve-DotNetInvocation
    $dotnetExe = $dotnetInvocation.HostPath
    $dotnetPrefix = @($dotnetInvocation.Prefix)
    Write-Host "Using dotnet command: $($dotnetInvocation.DisplayCommand)" -ForegroundColor DarkGray

    $dotNetProjects = @(
        [pscustomobject]@{
            Name        = 'TechToolbox.Agent'
            ProjectPath = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.Agent.csproj'
            PublishDir  = Join-Path $ModuleRoot 'src\TechToolbox.Agent\bin\Release\net8.0\publish'
            Publish     = $true
        },
        [pscustomobject]@{
            Name        = 'TechToolbox.LocalMcpAdapter'
            ProjectPath = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.LocalMcpAdapter\TechToolbox.LocalMcpAdapter.csproj'
            PublishDir  = Join-Path $ModuleRoot 'src\TechToolbox.Agent\TechToolbox.LocalMcpAdapter\bin\Release\net8.0\publish'
            Publish     = $true
        },
        [pscustomobject]@{
            Name        = 'TechShell.UI'
            ProjectPath = Join-Path $ModuleRoot 'src\TechShell\src\TechShell.UI\TechShell.UI.csproj'
            PublishDir  = $null
            Publish     = $false
        }
    )

    foreach ($project in $dotNetProjects) {
        if (-not (Test-Path -LiteralPath $project.ProjectPath)) {
            Write-Host "Skipping .NET build/publish for missing project: $($project.ProjectPath)" -ForegroundColor DarkYellow
            continue
        }

        Write-Host "Building .NET project: $($project.Name)" -ForegroundColor Cyan
        & $dotnetExe @dotnetPrefix build $project.ProjectPath -c Release
        if ($LASTEXITCODE -ne 0) {
            throw "dotnet build failed for $($project.ProjectPath)"
        }

        if ($project.Publish) {
            if (Test-Path -LiteralPath $project.PublishDir) {
                Remove-Item -LiteralPath $project.PublishDir -Recurse -Force
            }

            $publishArgs = @('publish', $project.ProjectPath, '-c', 'Release', '-o', $project.PublishDir)

            Write-Host "Publishing .NET project: $($project.Name)" -ForegroundColor Cyan
            & $dotnetExe @dotnetPrefix @publishArgs
            if ($LASTEXITCODE -ne 0) {
                throw "dotnet publish failed for $($project.ProjectPath)"
            }

            if (-not $SkipSigning) {
                $publishExes = @(Get-ChildItem -LiteralPath $project.PublishDir -Filter *.exe -File -Recurse | Select-Object -ExpandProperty FullName)
                if ($publishExes.Count -gt 0) {
                    Write-Host "Signing published EXE(s) for $($project.Name): $(($publishExes | Measure-Object).Count) file(s)" -ForegroundColor Cyan
                    Sign-FileSet -Files $publishExes -Certificate $cert -SkipValidSigs:$SkipValidSigs -TimestampServer $TimestampServer -OkCount ([ref]$ok) -SkippedCount ([ref]$skip) -WarnCount ([ref]$warn)
                }
            }

            Write-Host "Build + publish complete for $($project.Name) → $($project.PublishDir)" -ForegroundColor Green
        }
        else {
            Write-Host "Build complete for $($project.Name) (publish skipped by policy)." -ForegroundColor Green
        }
    }
}

# ---------------- 06B. (Optional) Build TechShell winget bundle -------------
$techShellWingetResult = $null
if ($BuildTechShellWinget -and -not $SkipTechShell) {
    if ($SkipSigning) {
        throw "TechShell winget build requires signing; remove -SkipSigning or disable -BuildTechShellWinget."
    }

    $techShellWingetScript = Join-Path $defaultConfigDir 'Build-TechShellWinget.ps1'
    if (-not (Test-Path -LiteralPath $techShellWingetScript -PathType Leaf)) {
        throw "TechShell winget build script not found: $techShellWingetScript"
    }

    $resolvedTechShellTag = if ([string]::IsNullOrWhiteSpace($TechShellReleaseTag)) { "v$newVersion" } else { $TechShellReleaseTag }
    $techShellArgs = @{
        PackageVersion         = $newVersion.ToString()
        ReleaseTag             = $resolvedTechShellTag
        RuntimeIdentifier      = $TechShellRuntimeIdentifier
        InstallerFileName      = $TechShellInstallerFileName
        Thumbprint             = $Thumbprint
        TimestampServer        = $TimestampServer
        SkipManifestWrite      = $SkipTechShellManifestWrite
        SkipManifestValidation = $SkipTechShellManifestValidation
    }

    Write-Host "Building TechShell winget bundle for version $($newVersion.ToString()) (tag $resolvedTechShellTag)..." -ForegroundColor Cyan
    $techShellWingetResult = & $techShellWingetScript @techShellArgs
    Write-Host "TechShell winget build complete." -ForegroundColor Green
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
    TechShellWinget = if ($null -ne $techShellWingetResult) {
        [pscustomobject]@{
            Enabled           = $true
            ReleaseTag        = $techShellWingetResult.ReleaseTag
            RuntimeIdentifier = $techShellWingetResult.RuntimeIdentifier
            InstallerPath     = $techShellWingetResult.InstallerPath
            ManifestWritten   = $techShellWingetResult.ManifestWritten
            ManifestValidated = $techShellWingetResult.ManifestValidated
            SigningThumbprint = $techShellWingetResult.SigningThumbprint
        }
    }
    else {
        [pscustomobject]@{ Enabled = $false }
    }
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
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANAQidLRFoIrbo
# mkRkr8NwjiuFG7fuYUNpolODm3C866CCFmgwggMqMIICEqADAgECAhAUclYcLlB0
# o0+hlxGb32/OMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMMIlRlY2hUb29sYm94
# IFRlY2hTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYxMDAzMDE0MjMyWhcNMjgxMDAz
# MDE1MjMxWjAtMSswKQYDVQQDDCJUZWNoVG9vbGJveCBUZWNoU2hlbGwgQ29kZSBT
# aWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXcCV9CPSwPJ
# 42duP85fSh0jCkJWIov+AYymeKQzBLgsz6jCkhuuKBf7gpsStULwAJuBtFztT/XI
# 0jK0e+3SIzYCaG+1nn0rzBsB4YisBtMykS+EtRgmjcu2h1YMGiQ/FScDak5h707Z
# hQ/VBXZ/+rZ7Wd08wUnWHAsNRz75wz/kiWGEoCDIuLsl4uy+gQmXlQVBFn8ALEh0
# AtJk0B7c6qzz1y0So8y4Lq1IXvCEnN61HYSJ5zaopOMvNo3pNsrr0sM7m9DyEzu4
# Ci3EWtuyXbPegoV62qC62MRllrFJNzV6dJBUuXqCAhgMFGaT6Mj2/qRlBiVVmTFe
# FXTX9pHvxQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFB8+5HahBP9rHFC1mG3OWbTh3WwxMA0GCSqGSIb3DQEB
# CwUAA4IBAQAOdqNp/5ce+dpVcp2FivGK7FpYroSWaeOoEDEDLnxq58mDEZKBwfYM
# SduDQ4AHZQ3U1WRrvHWyiPpFI5lOt1utiw9WHrA4sHuvxGmFkcfH4J8AsRtlVK94
# yUX16UZhLPXWItGM75rUz/uRSBcyXQWOzq5gfwNL22F5Z8AljAicEBAZLUhuQBpd
# 9rE3JWZ0rZzbRZNd4Hb4/DP53KaiA7zfZyXmuEfLCCwyGtcPn3Mqxu6IsCU8LmzH
# 2fClU7OGxte+VxaczuFaPqmIBtChvxj4ZoluHWgWOIXqyOsSc9v9qzYeHM6i4pY4
# pRkjpGU/2NWfwVbOkyJxQlE9XdhO3IXGMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG
# 9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVz
# dGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+
# PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxe
# Lho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2D
# Z0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJB
# YgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7G
# b5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS
# 3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7C
# coKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUm
# s+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN
# +nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqE
# G1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhG
# NKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQY
# MBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUE
# DDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDww
# OjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0G
# CSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/D
# m1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO4
# 1P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFS
# goR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSL
# ANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJ
# DMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cva
# iIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+
# U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6
# bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+
# Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhL
# ULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3
# XDCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggUdMIIFGQIBATBBMC0xKzApBgNVBAMMIlRlY2hUb29sYm94IFRlY2hTaGVs
# bCBDb2RlIFNpZ25pbmcCEBRyVhwuUHSjT6GXEZvfb84wDQYJYIZIAWUDBAIBBQCg
# gYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0B
# CQQxIgQgiTrWmkxrwKElD3kUmsTMSJtN5nuJUGYWCGhNc1p0uVowDQYJKoZIhvcN
# AQEBBQAEggEAlGM3r7bvly+wHkVcX+Orm6lTAin5qK6LAkUDAdepiZ7uLrIL9P2f
# fKJ1rqJgtBunnCWJuaY+CtNumQCygQ7FhAkiJhkqSJbVgJyf1QetO1u9kvtQLRwM
# QNjCoXU53B/3bKoE0uS0GHwOr4EgW9zZ1WLGU3gk7Qe/vjm14EvRhTRyKmdf+WIn
# d+3d6DLpFIpPtsjTjExwJO9ID6VQNmB9RhflZucCVUgDoFQo1mAIVWsIbeq+fpWv
# AMZ4+V6063xgLW0NbaMdXHTApO6nj1GHm3tmqn7alPkEKVSSv6n25RycPgU2hqTG
# /QoQzno4xPxLtdJMWYObbTwOuxYBHqgzRqGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDQxNjQ2MDFaMC8GCSqGSIb3DQEJBDEiBCDTU8XxZNdkOamcb3AxDzf7
# UEaankxfVTIqtepsmNcodTANBgkqhkiG9w0BAQEFAASCAgBUqiD4wRWa8dpKK4Mp
# O9Z8FU2aFi0zrcC+/g3qUA47aChdi4sSiz7Da+9EFH9YCrltVIfTtV1iiQU6Ezer
# X1u3FlJqyZ3FN4rI1Qid9pbnYOMwzW8wP6OGzHAqEzRnpLBhX9hak2dKOG8RCcZW
# eqYeHRYuammO8visnrAMiDvepk6dqpnTnM5ZoQPQmw2QjNeFjNypIGWDjpEG4EQY
# /IzdWaUn2ULwlI6USaSvI+g1zV3M6tumq1KsW6+yfWkxMSuyt6VBgF41/H5DWCD5
# aO38F+GAJlJamVANwkmz2SRfnA6QM6iVl5upz6pn9p9jz6K4SJAG5nQfSx1zo4gz
# 8Ymt0f5bdP58QoI3DU8MUjL6VNjAXkwQavKghS99uG34EdBwmk291i4aJDBxybxU
# 4wMekaWT0jyZgO1SzMectR+vCwvyo3GhMyu648Dp9YIq70JOjbsp8rBocOaXk+bc
# foGC7Elx4p1kdF5oMSQ/VXur6ugcMYkeBoiwYLHQqTNzS66Iq4n3NMECzxEEqITe
# KhrIIkq5vF7t6mGthVaHcV3Y4ukFSPCKsBG9n/dizVYKhglRjfRtRq34S3rKtR5u
# QFeIBye3DmFlaj4Af5fdNHD05gsBnk3ob4n5lrPMnE9Ms8Xg3m4VBYojoqprT9DN
# X6vgINX2K2gWnxooOGN/JkCOXw==
# SIG # End signature block
