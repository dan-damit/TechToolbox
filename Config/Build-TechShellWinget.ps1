[CmdletBinding()]
param(
    [Parameter(Mandatory)]
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
    [switch]$EnforcePublicTrustPreflight,
    [switch]$SkipManifestWrite,
    [switch]$SkipManifestValidation
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

function Invoke-MsixSigning {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string]$Thumb,
        [Parameter(Mandatory)] [string]$Timestamp
    )

    $signtool = Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if (-not $signtool) {
        throw 'signtool.exe was not found in PATH. Install the Windows SDK signing tools or configure PATH.'
    }

    $certificate = Get-CodeSigningCert -Thumb $Thumb
    if (-not $certificate) {
        throw "The configured signing certificate was not found in CurrentUser\My or LocalMachine\My for thumbprint $Thumb."
    }

    & $signtool.Source sign /fd SHA256 /td SHA256 /tr $Timestamp /sha1 $Thumb /v $FilePath
    if ($LASTEXITCODE -ne 0) {
        throw "Signing failed for $FilePath using thumbprint $Thumb."
    }
}

if ([string]::IsNullOrWhiteSpace($ReleaseTag)) {
    $ReleaseTag = "v$PackageVersion"
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
    if ($EnforcePublicTrustPreflight) {
        throw "$preflightMessage Use a publicly trusted code-signing certificate or rerun without -EnforcePublicTrustPreflight for local-only testing."
    }

    Write-Warning "$preflightMessage Continuing because -EnforcePublicTrustPreflight was not specified."
}
else {
    Write-Host "Code-signing trust preflight passed for thumbprint $Thumbprint." -ForegroundColor Green
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
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDKPNRetx7a6G2K
# yVrzNkqiEa9GWIFEIpHOIfhqpxQcH6CCFmgwggMqMIICEqADAgECAhAUclYcLlB0
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
# CQQxIgQga2yD3JJOyalM8uXy1ytoFslCJrUyjawhD0U3ocImt54wDQYJKoZIhvcN
# AQEBBQAEggEAe37u1ghWE8iBkmbrVOp0DK7aoRtYABoNQgQV/dOaTvhjspEJACL2
# 2Go9ga0jYkVPyHwSzNt+sGwNufho+EUcHOfX+qvySmwZVxHGi/evkRzPSWSxa+uI
# iXklgYQzESMcG5E6DVHIQb+WsoPqyJygf0uh+iVryJ/ORDozoUjyClAFtyRtNQqQ
# /iYND0B2cLB9x2gY9L/ieKuX0twGqaqeGGLvlsKR7Xv1cymL53VG4jrFxkute1rk
# F+PaHOF4eCpRXUkCmOfJirX0hD5mn49ezRqjXqkbSfF0SyLf+XwMxnwCb3JwsHi6
# cOwhnCAyqPiEcVc52+fVY+noNIO08MKCe6GCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDMyMDE3MjRaMC8GCSqGSIb3DQEJBDEiBCCLZ/tJSXMHnymiZSLU9kWp
# ULHZMCKATvIHRPKn3F9E2TANBgkqhkiG9w0BAQEFAASCAgAcK71mW7cR057yjqgt
# m5WaKCVxB2235aWr3Hcv3ZlzdkbWiO/vpX6ehZm03kC3SKlqTpEqk4oB3LdN3auX
# Ph6zPiTKfOILmD9j3NBa37V+yCa40t6bsyZ37bDW8fiwGyLSPEzygYEN52iaKCUV
# DMu4v/ZkR5Gm8MuZgoXisVtFllEUzwYw3udHCjfjSX2ZXMuPEvHo37/A0kjfePAG
# GhgdiyQp+5lqR96zFZZqdaV1s0m1tYXdSwrzytuHoYxDEFSRUylEfkxdlPu5CXCP
# +tC4VOQdmsMFDiRISX+UE52Jve4p/j3Z9H0wXBXugfC5Jd3rA4NCTnmFBn0xTDQ7
# T51Uskc5fNJsktTlahqX3gZeRMpRlGGn/dCBL6xcchNGMGsiBQO0hOyVLbe6Jmp7
# 3rN41SNT9cSgmO9JBF7U2k/1TBlIsRb8L1YRyrRpkem1ApUBDCxAmP61g6i00NZk
# eJUctXBBv0ducxw+6cx7fumQo5Cp0h7NzSBpFEOtADjuBtyyRPz8l7e/bVUlASsC
# bcZ7yT/9ctKYerWNAJH9O0FR2rK7GxYU20AhCBkq/9CUx/o5kPoaK6q0NUdURywO
# kn53FmnZvB824pPT1ooSK8ZLa+GzakwjZaCQiyrwctxED+o/rvytJ9d6PUcKU3iR
# 9CRlJolr3HoenA3Y5RIEPLOxVA==
# SIG # End signature block
