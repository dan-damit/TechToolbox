[CmdletBinding()]
param(
    [string]$Version,
    [string]$PackageVersion,

    [string]$ReleaseTag,
    [string]$PackageIdentifier = 'TechToolbox.TechShell',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')]
    [string]$RuntimeIdentifier = 'win-x64',
    [string]$Configuration = 'Release',
    [string]$InstallerFileName = 'TechShell.msix',
    [string]$OutputRoot,
    [string]$Thumbprint,
    [string]$TimestampServer,
    [switch]$SkipManifestWrite,
    [switch]$SkipManifestValidation
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
    $PackageVersion = $Version
}

if ([string]::IsNullOrWhiteSpace($PackageVersion)) {
    throw "PackageVersion is required. Pass -PackageVersion or -Version."
}

function Resolve-AbsolutePath {
    param([Parameter(Mandatory)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Path))
}

function Ensure-RustMsvcToolchain {
    $linkCommand = Get-Command link.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $linkCommand) {
        return
    }

    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vsInstallPath = $null
    if (Test-Path -LiteralPath $vswherePath -PathType Leaf) {
        $vsInstallPath = & $vswherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1
    }

    if ([string]::IsNullOrWhiteSpace($vsInstallPath)) {
        $fallbackInstallRoot = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools'
        if (Test-Path -LiteralPath $fallbackInstallRoot -PathType Container) {
            $vsInstallPath = $fallbackInstallRoot
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($vsInstallPath)) {
        $vcToolsDir = Join-Path $vsInstallPath 'VC\Tools\MSVC'
        if (Test-Path -LiteralPath $vcToolsDir -PathType Container) {
            $linkCandidates = Get-ChildItem -LiteralPath $vcToolsDir -Recurse -Filter link.exe -File -ErrorAction SilentlyContinue | Select-Object -First 20
            if ($null -ne $linkCandidates -and $linkCandidates.Count -gt 0) {
                $linkDir = $linkCandidates[0].DirectoryName
                if (-not [string]::IsNullOrWhiteSpace($linkDir)) {
                    $env:PATH = [string]::Join(';', @($linkDir, $env:PATH))
                    return
                }
            }
        }
    }

    throw @"
Rust packaging requires the MSVC linker (`link.exe`), but it is not installed or not on PATH.
Install Visual Studio 2022 Build Tools and select: 'Desktop development with C++' and 'MSVC v143 - VS 2022 C++ x64/x86 build tools'.
Then reopen the terminal and rerun this script.
"@
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

function ConvertTo-AppxPackageVersion {
    param([Parameter(Mandatory)][string]$Version)

    $parts = $Version.Split('.')
    if ($parts.Count -lt 1 -or $parts.Count -gt 4) {
        throw "PackageVersion '$Version' must have between 1 and 4 numeric version segments for MSIX versioning."
    }

    $normalized = @()
    foreach ($part in $parts) {
        if ($part -notmatch '^\d+$') {
            throw "PackageVersion '$Version' contains non-numeric segment '$part', which is not valid for MSIX package versioning."
        }

        $value = [int]$part
        if ($value -lt 0 -or $value -gt 65535) {
            throw "PackageVersion segment '$part' is out of range for MSIX package versioning (0..65535)."
        }

        $normalized += $value
    }

    while ($normalized.Count -lt 4) {
        $normalized += 0
    }

    return ($normalized -join '.')
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$projectPath = Join-Path $repoRoot 'src\TechShell\src\TechShell.UI\TechShell.UI.csproj'
$packageManifestPath = Join-Path $repoRoot 'src\TechShell\src\TechShell.UI\Package.appxmanifest'
$appManifestPath = Join-Path $repoRoot 'src\TechShell\src\TechShell.UI\app.manifest'
$rustProjectPath = Join-Path $repoRoot 'src\TechShell\src\TechShell.Core'
$rustManifestPath = Join-Path $rustProjectPath 'Cargo.toml'
$rustBinaryName = 'techshell-core.exe'
$rustBinaryPath = Join-Path $rustProjectPath (Join-Path 'target\release' $rustBinaryName)
$explorerRegistrationScript = Join-Path $repoRoot 'src\TechShell\Register-TechShellExplorerIntegration.ps1'
$explorerInstallScript = Join-Path $repoRoot 'src\TechShell\Install-TechShellExplorerIntegration.ps1'
$buildConfigPath = Join-Path $PSScriptRoot 'build.config.json'
if (-not (Test-Path -LiteralPath $projectPath -PathType Leaf)) {
    throw "TechShell UI project not found: $projectPath"
}

if (-not (Test-Path -LiteralPath $packageManifestPath -PathType Leaf)) {
    throw "TechShell package manifest not found: $packageManifestPath"
}

if (-not (Test-Path -LiteralPath $explorerRegistrationScript -PathType Leaf)) {
    throw "TechShell Explorer integration helper not found: $explorerRegistrationScript"
}

if (-not (Test-Path -LiteralPath $explorerInstallScript -PathType Leaf)) {
    throw "TechShell Explorer installer helper not found: $explorerInstallScript"
}

if ([string]::IsNullOrWhiteSpace($Thumbprint) -and (Test-Path -LiteralPath $buildConfigPath -PathType Leaf)) {
    $buildConfig = Get-Content -LiteralPath $buildConfigPath -Raw | ConvertFrom-Json
    $Thumbprint = [string]$buildConfig.signing.thumbprint
}

if ([string]::IsNullOrWhiteSpace($TimestampServer) -and (Test-Path -LiteralPath $buildConfigPath -PathType Leaf)) {
    $buildConfig = Get-Content -LiteralPath $buildConfigPath -Raw | ConvertFrom-Json
    $TimestampServer = [string]$buildConfig.signing.timestamp
}

if ([string]::IsNullOrWhiteSpace($TimestampServer)) {
    $TimestampServer = 'http://timestamp.digicert.com'
}

function Get-CodeSigningCert {
    param([Parameter(Mandatory)] [string]$Thumb)

    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $found = Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }

        if ($found -and $found.HasPrivateKey) {
            return $found
        }
    }

    return $null
}

function Test-CodeSigningTrustPreflight {
    param(
        [Parameter(Mandatory)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

    $chainBuildSucceeded = $chain.Build($Certificate)
    $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    $isSelfSigned = [string]::Equals($Certificate.Subject, $Certificate.Issuer, [System.StringComparison]::OrdinalIgnoreCase)
    $hasUntrustedRoot = $statuses -contains 'UntrustedRoot'

    $isPublicTrustReady = $chainBuildSucceeded -and -not $isSelfSigned -and -not $hasUntrustedRoot
    $statusText = if ($statuses.Count -gt 0) { $statuses -join ', ' } else { 'None' }

    [pscustomobject]@{
        IsPublicTrustReady  = $isPublicTrustReady
        IsSelfSigned        = $isSelfSigned
        ChainBuildSucceeded = $chainBuildSucceeded
        ChainStatuses       = $statuses
        StatusText          = $statusText
    }
}

function Get-AppxManifestPublisher {
    param([Parameter(Mandatory)][string]$ManifestPath)

    [xml]$manifestXml = Get-Content -LiteralPath $ManifestPath -Raw
    $identityNode = $manifestXml.Package.Identity
    if ($null -eq $identityNode -or [string]::IsNullOrWhiteSpace([string]$identityNode.Publisher)) {
        throw "Package manifest '$ManifestPath' is missing Package/Identity Publisher."
    }

    return [string]$identityNode.Publisher
}

function Invoke-MsixSigning {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string]$Thumb,
        [Parameter(Mandatory)] [string]$Timestamp
    )

    $certificate = Get-CodeSigningCert -Thumb $Thumb
    if (-not $certificate) {
        throw "The configured signing certificate was not found in CurrentUser\My or LocalMachine\My for thumbprint $Thumb."
    }

    $providerName = $null
    $keyContainerName = $null
    if ($certificate.HasPrivateKey -and $null -ne $certificate.PrivateKey -and $certificate.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
        $cspInfo = $certificate.PrivateKey.CspKeyContainerInfo
        if ($null -ne $cspInfo) {
            $providerName = $cspInfo.ProviderName
            $keyContainerName = $cspInfo.KeyContainerName
        }
    }

    $preferredArchitecture = if (-not [string]::IsNullOrWhiteSpace($providerName) -and $providerName -like '*SimplySign*') { 'x86' } else { 'x64' }
    $signtoolCandidates = @()

    $pathSigntool = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pathSigntool -and -not [string]::IsNullOrWhiteSpace($pathSigntool.Source)) {
        $signtoolCandidates += $pathSigntool.Source
    }

    $kitsBinRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path -LiteralPath $kitsBinRoot -PathType Container) {
        $kitSigntools = @(Get-ChildItem -LiteralPath $kitsBinRoot -Recurse -Filter signtool.exe -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\(x86|x64)\\signtool\.exe$' } |
            Sort-Object FullName -Descending)
        $preferredPattern = [regex]::Escape("\$preferredArchitecture\signtool.exe") + '$'
        $preferredTools = @($kitSigntools | Where-Object { $_.FullName -match $preferredPattern } | ForEach-Object { $_.FullName })
        $fallbackTools = @($kitSigntools | Where-Object { $_.FullName -notmatch $preferredPattern } | ForEach-Object { $_.FullName })
        $signtoolCandidates += $preferredTools
        $signtoolCandidates += $fallbackTools
    }

    $signtoolCandidates = @($signtoolCandidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    if ($signtoolCandidates.Count -eq 0) {
        throw 'signtool.exe was not found in PATH or Windows Kits. Install the Windows SDK signing tools or configure PATH.'
    }

    $signArgs = @('sign', '/fd', 'SHA256', '/td', 'SHA256', '/tr', $Timestamp, '/sha1', $Thumb, '/v')
    if (-not [string]::IsNullOrWhiteSpace($providerName) -and -not [string]::IsNullOrWhiteSpace($keyContainerName)) {
        $signArgs += @('/csp', $providerName, '/kc', $keyContainerName)
    }
    $signArgs += $FilePath

    $attemptFailures = @()
    foreach ($signtoolPath in $signtoolCandidates) {
        Write-Host "Attempting MSIX signing with: $signtoolPath" -ForegroundColor DarkGray
        try {
            & $signtoolPath @signArgs
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0) {
                Write-Host "MSIX signing succeeded using: $signtoolPath" -ForegroundColor Green
                return
            }

            $attemptFailures += "$signtoolPath (exit code $exitCode)"
        }
        catch {
            $attemptFailures += "$signtoolPath (launch failure: $($_.Exception.Message))"
        }
    }

    throw "Signing failed for $FilePath using thumbprint $Thumb. Attempted signtool candidates: $($attemptFailures -join '; ')."
}

if ([string]::IsNullOrWhiteSpace($ReleaseTag)) {
    $ReleaseTag = "techshell-v$PackageVersion"
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot ("Out\TechShell\$PackageVersion\$RuntimeIdentifier")
}

$outputRootResolved = Resolve-AbsolutePath -Path $OutputRoot
$appxOutDir = Join-Path $outputRootResolved 'Appx'
$installerOutDir = Join-Path $outputRootResolved 'Installer'
$appxPackageVersion = ConvertTo-AppxPackageVersion -Version $PackageVersion

New-Item -ItemType Directory -Path $appxOutDir -Force | Out-Null
New-Item -ItemType Directory -Path $installerOutDir -Force | Out-Null

$publishArgs = @(
    'publish',
    $projectPath,
    '-c',
    $Configuration,
    '-r',
    $RuntimeIdentifier,
    '-p:GenerateAppxPackageOnBuild=true',
    "-p:Version=$appxPackageVersion",
    "-p:AssemblyVersion=$appxPackageVersion",
    "-p:FileVersion=$appxPackageVersion",
    "-p:PackageVersion=$appxPackageVersion",
    "-p:AppxPackageDir=$($appxOutDir)\\",
    '-p:AppxBundle=Never',
    '-p:UapAppxPackageBuildMode=SideloadOnly'
)

Write-Host "Building TechShell Rust backend for packaging..." -ForegroundColor Cyan
Ensure-RustMsvcToolchain
& cargo build --manifest-path $rustManifestPath --release
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed for TechShell.Core"
}

if (-not (Test-Path -LiteralPath $rustBinaryPath -PathType Leaf)) {
    throw "Rust backend release binary was not produced: $rustBinaryPath"
}

$packagedRustBinaryDestination = Join-Path $appxOutDir $rustBinaryName
Copy-Item -LiteralPath $rustBinaryPath -Destination $packagedRustBinaryDestination -Force

$originalPackageManifestContent = Get-Content -LiteralPath $packageManifestPath -Raw
$originalAppManifestContent = Get-Content -LiteralPath $appManifestPath -Raw
try {
    [xml]$packageManifestXml = $originalPackageManifestContent
    $nsManager = New-Object System.Xml.XmlNamespaceManager($packageManifestXml.NameTable)
    $nsManager.AddNamespace('pkg', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $identityNode = $packageManifestXml.SelectSingleNode('/pkg:Package/pkg:Identity', $nsManager)
    if ($null -eq $identityNode) {
        throw "Could not find /Package/Identity node in $packageManifestPath."
    }

    [void]$identityNode.SetAttribute('Version', $appxPackageVersion)
    $packageManifestXml.Save($packageManifestPath)

    [xml]$appManifestXml = $originalAppManifestContent
    $appManifestNs = New-Object System.Xml.XmlNamespaceManager($appManifestXml.NameTable)
    $appManifestNs.AddNamespace('asm', 'urn:schemas-microsoft-com:asm.v1')
    $appAssemblyIdentityNode = $appManifestXml.SelectSingleNode('/asm:assembly/asm:assemblyIdentity', $appManifestNs)
    if ($null -eq $appAssemblyIdentityNode) {
        throw "Could not find /assembly/assemblyIdentity node in $appManifestPath."
    }

    [void]$appAssemblyIdentityNode.SetAttribute('version', $appxPackageVersion)
    $appManifestXml.Save($appManifestPath)

    $dotnetInvocation = Resolve-DotNetInvocation
    $dotnetExe = $dotnetInvocation.HostPath
    $dotnetPrefix = @($dotnetInvocation.Prefix)
    Write-Host "Using dotnet command: $($dotnetInvocation.DisplayCommand)" -ForegroundColor DarkGray
    Write-Host "Publishing TechShell MSIX ($RuntimeIdentifier) with package identity version $appxPackageVersion..." -ForegroundColor Cyan
    & $dotnetExe @dotnetPrefix @publishArgs
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet publish failed for TechShell.UI"
    }
}
finally {
    Set-Content -LiteralPath $packageManifestPath -Value $originalPackageManifestContent -Encoding utf8
    Set-Content -LiteralPath $appManifestPath -Value $originalAppManifestContent -Encoding utf8
}

$msix = Get-ChildItem -LiteralPath $appxOutDir -Filter *.msix -File -Recurse |
Sort-Object LastWriteTime -Descending |
Select-Object -First 1

if ($null -eq $msix) {
    throw "No MSIX artifact found under: $appxOutDir"
}

$installerPath = Join-Path $installerOutDir $InstallerFileName
Copy-Item -LiteralPath $msix.FullName -Destination $installerPath -Force

$registrationScriptDestination = Join-Path $installerOutDir 'Register-TechShellExplorerIntegration.ps1'
$installScriptDestination = Join-Path $installerOutDir 'Install-TechShellExplorerIntegration.ps1'

# Keep the generated installer payload aligned with the canonical source scripts.
# The files under Out/TechShell are build artifacts, not editable source-of-truth.
Copy-Item -LiteralPath $explorerRegistrationScript -Destination $registrationScriptDestination -Force
Copy-Item -LiteralPath $explorerInstallScript -Destination $installScriptDestination -Force

if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
    throw 'No code signing thumbprint was provided and none was found in Config\build.config.json.'
}

$signingCertificate = Get-CodeSigningCert -Thumb $Thumbprint
if (-not $signingCertificate) {
    throw "The configured signing certificate was not found in CurrentUser\My or LocalMachine\My for thumbprint $Thumbprint."
}

$trustPreflight = Test-CodeSigningTrustPreflight -Certificate $signingCertificate
if (-not $trustPreflight.IsPublicTrustReady) {
    $preflightMessage = "Code-signing trust preflight detected a non-public trust chain for thumbprint $Thumbprint. SelfSigned=$($trustPreflight.IsSelfSigned); ChainBuildSucceeded=$($trustPreflight.ChainBuildSucceeded); ChainStatuses=$($trustPreflight.StatusText)."
    throw "$preflightMessage Use a publicly trusted code-signing certificate."
}
else {
    Write-Host "Code-signing trust preflight passed for thumbprint $Thumbprint." -ForegroundColor Green
}

$manifestPublisher = Get-AppxManifestPublisher -ManifestPath $packageManifestPath
if (-not [string]::Equals($manifestPublisher, $signingCertificate.Subject, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "MSIX signing certificate subject does not match package identity publisher. Manifest publisher='$manifestPublisher'; cert subject='$($signingCertificate.Subject)'. Update Package.appxmanifest to match the active signing certificate."
}

Write-Host "Signing TechShell installer bundle with certificate thumbprint $Thumbprint..." -ForegroundColor Cyan
Invoke-MsixSigning -FilePath $installerPath -Thumb $Thumbprint -Timestamp $TimestampServer
Set-AuthenticodeSignature -FilePath $registrationScriptDestination -Certificate $signingCertificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer | Out-Null
Set-AuthenticodeSignature -FilePath $installScriptDestination -Certificate $signingCertificate -HashAlgorithm SHA256 -TimestampServer $TimestampServer | Out-Null

$installerUrl = "https://github.com/dan-damit/TechToolbox/releases/download/$ReleaseTag/$InstallerFileName"
$newManifestScript = Join-Path $PSScriptRoot 'New-WingetManifestData.ps1'
$testManifestScript = Join-Path $PSScriptRoot 'Test-WingetManifest.ps1'

$manifestArgs = @{ InstallerPath = $installerPath; PackageVersion = $PackageVersion; PackageIdentifier = $PackageIdentifier; InstallerUrl = $installerUrl; WriteManifestFiles = (-not $SkipManifestWrite) }

$manifestResult = & $newManifestScript @manifestArgs

if (-not $SkipManifestValidation) {
    & $testManifestScript -PackageVersion $PackageVersion -PackageIdentifier $PackageIdentifier
}

[pscustomobject]@{ PackageVersion = $PackageVersion; AppxPackageVersion = $appxPackageVersion; RuntimeIdentifier = $RuntimeIdentifier; ReleaseTag = $ReleaseTag; ProjectPath = $projectPath; PublishedMsixPath = $msix.FullName; InstallerPath = $installerPath; ExplorerRegistrationScriptPath = $registrationScriptDestination; ExplorerInstallScriptPath = $installScriptDestination; InstallerUrl = $installerUrl; SigningThumbprint = $Thumbprint; SigningTimestampServer = $TimestampServer; PublicTrustPreflightPassed = $trustPreflight.IsPublicTrustReady; PublicTrustPreflightSelfSigned = $trustPreflight.IsSelfSigned; PublicTrustPreflightChainStatuses = @($trustPreflight.ChainStatuses); ManifestWritten = (-not $SkipManifestWrite); ManifestValidated = (-not $SkipManifestValidation); ManifestResult = $manifestResult }

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCza1MhEuM8rDo+
# 7tPofeAXJ51PLJDd/+QH0cl1ycATzaCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
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
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBv
# wZS+8JLZLKAPRSm3vc9kjRwbiScUcrFPHVAl4GyXozANBgkqhkiG9w0BAQEFAASC
# AYAT3jWMnjScUShjG11cv+KWiCH5XbPKYW7gVz/taYgZsrh8+btU0uugXvLG9Ufr
# nQ0G2vyPMopHovQfZ4PZstUU/tup0aYvi2sE/IK7J05rs1yBOO8EAvWzNZDtv6Pt
# d+6/OxF/CT3V8uFkqwQ+M4N4AfC6uktz3SaLMe14BHiDYJ7sqiFsp2Gb9Q2agG01
# 3eAwd/G97VtBvDPhBct9lxcWPRCfHplXyhy4K4/u3918hanIwEPelBW0rtminHUV
# F1wjtWmg+YVR/4mmc4oDVMKYEsBu8udultc0GD0F/g3rrLwwtH/3xyQ+DGo/PRcZ
# uBaR3z12Q4XQqMs6zcZTx0zP9gTPwJCt48jQ0PiP81e/Kq+UDLOOiwxqYwjIGxdi
# FSf0QepxMqbycsrc3o7AudkjEETNc0poyxINpegyG/R9GUb/eJY7sjoez/Glqh6h
# masjXAYKN6pJAJ4qaNoXtsIuhh8Ych9g+IXV6X1cEhq/WnU6hPk/bbyNIgdzQAdz
# pRGhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDA1MjAwMDIwWjAvBgkqhkiG
# 9w0BCQQxIgQgvykeOXnycbr7D/xgekFsRN/L/5T/Q6bBZzPQqtfWLwwwDQYJKoZI
# hvcNAQEBBQAEggIANdhFTjsCnd7MJSOgQvByl0BJ6rqHZkRc0s4Uc1xsMuL9gRMn
# D1O0Rqg9UxPRirGHtgYszVBc66JoSJIQ/CfTVooMciRBacasGyk1Og8Pfwj5MnSU
# CWCBBOrlmyEBx5hw0XuG4ITPYSCeFNhtNN3/YdwTjkmDvnST1kOb8Tu8M5JGkDnt
# O0Sw09Qkl+G+TzNvO/EI0s+znxq6yv673N2aJXZb6KzOdDUx5ArL7M6E+/oBx7zc
# yQaU/vrjh2For5V1MfUu85FJrL53xUlsmVqL6WBrXwvm+Xbgc1Cjg1TpgHaSaQjP
# A7+4ZW0E/umraA08xsaAS+7GHYoSajJQ27AWII8910JYBMZv87d+xo5QRbotHaKY
# Z8lk95FuRHk+Ij4zzLgmblkzMXH+x03wQeTOuKILH/QmPJyLTiLMIlockK8QxT9R
# Q8DF+4qQ882rbi7UNsf5Uu8oGJwOOLUW5QEBE/MvrsWKwtXj8c/H+V0kZLqh56SA
# HEJ2SIFJ76/xd9dXMp/HYlAqMtIJ6AcQlZ7n7NbxJhOpgegneeoUx3fTxL4r6Y19
# Sq7BthyUK93d5EOgh32zZmnsLRlCmp5vl+WYq4Se5qaA8gukS+0mem49Tuing/Tp
# qI1jannVtH9jibRf2WRPgH7tf8J78eDSWOWtzekTcYNTol3rzQfl/8WaTzo=
# SIG # End signature block
