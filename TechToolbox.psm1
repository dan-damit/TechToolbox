Set-StrictMode -Version Latest
$InformationPreference = 'Continue'

function Test-TTInteractive {
    try {
        return (
            $Host -and $Host.UI -and $Host.UI.RawUI -and
            -not [Console]::IsOutputRedirected
        )
    }
    catch { return $false }
}

function Show-TTBannerOncePerSession {
    [CmdletBinding()]
    param([switch]$Force)

    if (-not $Force -and -not (Test-TTInteractive)) { return }
    if (-not $Force -and $env:TT_BANNER_SHOWN -eq '1') { return }

    $m = Get-Module -Name TechToolbox -ErrorAction SilentlyContinue
    $version = if ($m -and $m.Version) { $m.Version.ToString() } else {
        try {
            $psd1 = Join-Path $ExecutionContext.SessionState.Module.ModuleBase 'TechToolbox.psd1'
            if (Test-Path $psd1) { (Import-PowerShellDataFile $psd1).ModuleVersion.ToString() } else { '?' }
        }
        catch { '?' }
    }

    $ts = (Get-Date).ToString('HH:mm:ss')
    Write-Host ""
    Write-Host ("[{0}] TechToolbox v{1} loaded" -f $ts, $version) -ForegroundColor Green
    Write-Host "Quick start: Get-Command -Module TechToolbox" -ForegroundColor DarkGray
    Write-Host "Help: Get-Help <CommandName> -Online" -ForegroundColor DarkGray

    $env:TT_BANNER_SHOWN = '1'
}

function Write-TTLoadedLine {
    [CmdletBinding()]
    param(
        [ValidateSet('Loaded', 'AlreadyLoaded', 'Reloaded')]
        [string]$Status = 'Loaded',
        [switch]$Quiet,
        [switch]$Force
    )

    if (-not $Force -and -not (Test-TTInteractive)) { return }
    if ($Quiet) { return }

    # IMPORTANT: during import, Get-Module may or may not resolve yet depending on timing.
    # So we fall back to module context if needed.
    $m = Get-Module -Name TechToolbox -ErrorAction SilentlyContinue
    $name = if ($m) { $m.Name } else { 'TechToolbox' }
    $version = if ($m -and $m.Version) { $m.Version.ToString() } else {
        # Try manifest as fallback
        try {
            $psd1 = Join-Path $ExecutionContext.SessionState.Module.ModuleBase 'TechToolbox.psd1'
            if (Test-Path $psd1) { (Import-PowerShellDataFile $psd1).ModuleVersion.ToString() } else { '?' }
        }
        catch { '?' }
    }

    # Author from manifest (best effort)
    $author = $null
    try {
        $psd1 = Join-Path $ExecutionContext.SessionState.Module.ModuleBase 'TechToolbox.psd1'
        if (Test-Path $psd1) {
            $manifest = Import-PowerShellDataFile -Path $psd1
            $author = $manifest.Author
        }
    }
    catch {}

    $ts = (Get-Date).ToString('HH:mm:ss')
    $psv = $PSVersionTable.PSVersion.ToString()
    $ed = $PSVersionTable.PSEdition
    $who = if ($author) { "by $author" } else { "" }

    Write-Host ("[{0}] {1} v{2} {3} ({4})  PS {5} {6}" -f $ts, $name, $version, $who, $Status, $psv, $ed) -ForegroundColor DarkGray
    Write-Host "Quick start: Get-Command -Module TechToolbox" -ForegroundColor DarkGray
    Write-Host "Help: Get-Help <CommandName> -Online" -ForegroundColor DarkGray
}

# --------------------------------------------
# TechToolbox Loader v2 (fast import)
# --------------------------------------------

# Important: avoid any code outside of functions that relies on module state or config
$script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase

# Predefine script-scoped vars before any reads
if (-not (Test-Path -Path 'variable:script:TT_Initialized')) { $script:TT_Initialized = $false }
if (-not (Test-Path -Path 'variable:script:TT_RuntimeReady')) { $script:TT_RuntimeReady = $false }
if (-not (Test-Path -Path 'variable:script:ConfigPath')) { $script:ConfigPath = $null }
if (-not (Test-Path -Path 'variable:script:SecretsPath')) { $script:SecretsPath = $null }
if (-not (Test-Path -Path 'variable:script:domainAdminCred')) { $script:domainAdminCred = $null }
if (-not (Test-Path -Path 'variable:script:TT_Secrets')) { $script:TT_Secrets = $null }
if (-not (Test-Path -Path 'variable:script:log')) { $script:log = $null }
if (-not (Test-Path -Path 'variable:script:ModuleDependencies')) { $script:ModuleDependencies = $null }
if (-not (Test-Path -Path 'variable:script:PrivateLoaded')) { $script:PrivateLoaded = $false }
if (-not (Test-Path -Path 'variable:script:cfg')) { $script:cfg = $null }
if (-not (Test-Path -Path 'variable:script:__cfgCache')) { $script:__cfgCache = $null }

# --- Standard runtime container (used by workers/helpers locally + remotely) ---
if (-not (Test-Path -Path 'variable:script:TT')) {
    $script:TT = [ordered]@{
        RuntimeId   = [guid]::NewGuid().ToString()
        IsRemote    = $false
        SessionType = $null        # 'WSMan' / 'SSH' / 'PS7' etc (optional)

        ModuleRoot  = $script:ModuleRoot

        # (ephemeral) staging roots:
        WorkRoot    = $null        # e.g. $env:TEMP\TT_Worker_{guid}
        WorkersRoot = $null        # e.g. $env:TEMP\TT_Worker_{guid}\workers
        HelpersRoot = $null        # e.g. $env:TEMP\TT_Worker_{guid}\helpers

        WorkerPath  = $null        # main worker .ps1 path staged on remote (or local if used)

        LogRoot     = (Join-Path $env:TEMP 'TechToolbox')
    }
}

# --- Config/data paths bootstrap (final binding happens after home resolution) ---
$script:TT['Home'] = $script:ModuleRoot
$script:TT['AgentHistoryFile'] = Join-Path $script:TT.Home 'AgentHistory.jsonl'

if (-not (Test-Path $script:TT.Home)) { New-Item -ItemType Directory -Path $script:TT.Home | Out-Null }

# Guard re-import (but still print status line)
if ($script:TT_Initialized) {
    # Don't show banner again; just show status
    Write-TTLoadedLine -Status AlreadyLoaded
    return
}

# Optional timing (enable with $env:TT_TraceImport=1)
$__trace = [bool]($env:TT_TraceImport -eq '1')
$__sw = [System.Diagnostics.Stopwatch]::StartNew()
function __tt_trace([string]$msg) { if ($__trace) { Write-Verbose ("[TT Import] {0} @ {1}" -f $msg, $__sw.Elapsed) } }

# --- Load the self-install helper ---
$initHelper = Join-Path $script:ModuleRoot 'Private\Loader\Initialize-TechToolboxHome.ps1'
if (Test-Path $initHelper) { . $initHelper; __tt_trace "Sourced Initialize-TechToolboxHome.ps1" }
else { Write-Verbose "Initialize-TechToolboxHome.ps1 not found; skipping." }

# --- Resolve runtime/data roots (module-root by default) ---
try {
    if ($env:TT_SkipHomeInit -ne '1') {

        # -------------------------------------------------------
        # Determine TechToolbox home (config/data root)
        # Priority: $env:TT_Home > ModuleRoot
        # -------------------------------------------------------
        if ($env:TT_Home) {
            try {
                $TT_Home = [System.IO.Path]::GetFullPath($env:TT_Home)
            }
            catch {
                $TT_Home = $env:TT_Home
            }
        }
        else {
            $TT_Home = $script:ModuleRoot
        }

        # --- TechToolbox module root is always the actual import location ---
        # Decoupled from config/home path. This keeps the module's code
        # location independent of where logs/configs are stored.
        $TT_ModuleRoot = $script:ModuleRoot

        # --- Export for child sessions ---
        $env:TT_Home = $TT_Home
        $env:TT_ModuleRoot = $TT_ModuleRoot

        # Agent filesystem and path authorization defaults are environment-driven so
        # gallery installs and local dev both work without hardcoded repo paths.
        if ([string]::IsNullOrWhiteSpace($env:TT_AGENT_FILESYSTEM_ROOT)) {
            $env:TT_AGENT_FILESYSTEM_ROOT = $TT_ModuleRoot
        }

        if ([string]::IsNullOrWhiteSpace($env:TT_AGENT_ALLOWED_PATH_ROOTS)) {
            $defaultAllowedRoots = @(
                $TT_ModuleRoot,
                $TT_Home
            ) |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { [System.IO.Path]::GetFullPath($_) } |
                Select-Object -Unique

            $defaultAllowedRoots = @($defaultAllowedRoots)
            if ($defaultAllowedRoots.Count -gt 0) {
                $env:TT_AGENT_ALLOWED_PATH_ROOTS = [string]::Join([System.IO.Path]::PathSeparator, $defaultAllowedRoots)
            }
        }

        if ([string]::IsNullOrWhiteSpace($env:TT_AGENT_LOCAL_MCP_ADAPTER_PATH)) {
            $localMcpAdapterCandidates = @(
                (Join-Path $TT_ModuleRoot 'AgentRuntime\TechToolbox.LocalMcpAdapter\TechToolbox.LocalMcpAdapter.dll'),
                (Join-Path $TT_ModuleRoot 'src\TechToolbox.Agent\TechToolbox.LocalMcpAdapter\bin\Release\net8.0\publish\TechToolbox.LocalMcpAdapter.dll'),
                (Join-Path $TT_ModuleRoot 'src\TechToolbox.Agent\TechToolbox.LocalMcpAdapter\bin\Release\net8.0\TechToolbox.LocalMcpAdapter.dll'),
                (Join-Path $TT_ModuleRoot 'src\TechToolbox.Agent\TechToolbox.LocalMcpAdapter\bin\Debug\net8.0\TechToolbox.LocalMcpAdapter.dll')
            )

            $resolvedLocalMcpAdapterPath = $localMcpAdapterCandidates |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                Select-Object -First 1

            if ([string]::IsNullOrWhiteSpace($resolvedLocalMcpAdapterPath)) {
                $resolvedLocalMcpAdapterPath = $localMcpAdapterCandidates[0]
            }

            $env:TT_AGENT_LOCAL_MCP_ADAPTER_PATH = $resolvedLocalMcpAdapterPath
        }

        # Rebind runtime container paths to the effective home.
        $script:TT['Home'] = $TT_Home
        $script:TT['AgentHistoryFile'] = Join-Path $script:TT.Home 'AgentHistory.jsonl'

        # --- Centralized path roots (OneDrive-aware) ---
        $TT_LogsAndExportsRoot = Join-Path $TT_Home 'LogsAndExports'
        $env:TT_LogsAndExportsRoot = $TT_LogsAndExportsRoot
        $env:TT_LogsRoot = Join-Path $TT_LogsAndExportsRoot 'Logs'
        $env:TT_ExportsRoot = Join-Path $TT_LogsAndExportsRoot 'Exports'

        # Ensure runtime folders exist. No self-copy or self-heal staging is performed.
        foreach ($path in @($TT_LogsAndExportsRoot, $env:TT_LogsRoot, $env:TT_ExportsRoot)) {
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }

        __tt_trace "Runtime folders ensured (no home copy)."
    }
    else {
        __tt_trace "Home init skipped via TT_SkipHomeInit=1"
    }
}
catch {
    Write-Warning "Initialize-TechToolboxHome failed: $($_.Exception.Message)"
}

# --- Load Private functions ---
$privateRoot = Join-Path $script:ModuleRoot 'Private'
Get-ChildItem -Path $privateRoot -Recurse -Filter *.ps1 |
ForEach-Object { . $_.FullName }

# --- Load canonical Export-ToolboxFunctions helper ---
$exportHelper = Join-Path $script:ModuleRoot 'Public\Export-ToolboxFunctions.ps1'
if (Test-Path -Path $exportHelper) {
    . $exportHelper
}
else {
    throw "Required helper not found: $exportHelper"
}

# --- Lazy runtime initialization (config/logging/etc.) ---
function Initialize-TechToolboxRuntime {
    if ($script:TT_RuntimeReady) { return }

    try {
        Initialize-ModulePath
        Initialize-Config
        Initialize-Logging
        Initialize-Interop
        Initialize-Environment

        $script:TT_RuntimeReady = $true
    }
    catch {
        Write-Error "Runtime initialization failed: $_"
        throw
    }
}

# --- Load Public scripts in module scope before export discovery ---
$publicRoot = Join-Path $script:ModuleRoot 'Public'
if (Test-Path -Path $publicRoot) {
    Get-ChildItem -Path $publicRoot -Recurse -Filter *.ps1 -File |
    Where-Object { $_.Name -ne 'Export-ToolboxFunctions.ps1' } |
    ForEach-Object {
        __tt_trace "Sourcing public: $($_.Name)"
        . $_.FullName
    }
}

# --- Load **Public** functions using the robust exporter ---
$publicFunctionNames = Export-ToolboxFunctions
if ($publicFunctionNames.Count -gt 0) {
    __tt_trace ("Exporting {0} public functions: {1}" -f $publicFunctionNames.Count, ($publicFunctionNames -join ', '))
}

if ($env:TT_ExportLocalHelper -eq '1') {
    Export-ModuleMember -Function 'Start-PDQDiagLocalSystem'
}
Export-ModuleMember -Function $publicFunctionNames

$script:TT_Initialized = $true
__tt_trace "Import complete"

# --- Call on import ---
Show-TTBannerOncePerSession
# SIG # Begin signature block
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCRd6VRsdyxqGzY
# XcRR3qc+F6K9fjMKbWYeD3TlN9DSE6CCFmgwggMqMIICEqADAgECAhAUclYcLlB0
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
# CQQxIgQgg2P/Da24OmayAUQAcah2/YLE8BVYCLLl2KkLAteq6rAwDQYJKoZIhvcN
# AQEBBQAEggEAfyqY/gtORpTYrhU0tGoVebi+hqNumszUO+4QXHGZ0sODWuHf0ZJ7
# gf4QiGx637hwITvJANXMh8TqFu48ROYEng1SQgcejoe0OwU+c8XJsCQAayd24mcD
# suG5mBM6jktan3Uls4NjzOCvtZ3tjsrfCopx1+swirkxiI6SzVUbZGTTsYUiJL3W
# diV5LTehu4+T02qzekg/VCn1gmRVGMr3TXCTN1kPsJsrtpMBm1bnz0iGHjDGeQRi
# opNGA3ej5oZZHxBMIDJj/BiUQAU9jnrOkSs9gczU3mBGSFF5zS5qor54X8c/dtEO
# lOoocUjnmZSxR8oUg0EsR4NLvCf4+XXqpaGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDUwMjQ3MTNaMC8GCSqGSIb3DQEJBDEiBCCEt8pPeJzECztGwNkTmUoP
# ZvoYk5BU5nvWxJL4wpoHQzANBgkqhkiG9w0BAQEFAASCAgCBcLdIB55pkXJrmFyE
# FcHdxJodZoEla4lnIoxNcl6sBVQo0ElJ6ZnTFH04MTbMuICp3YNufpxglbEbG+yK
# 7AYoYN2+EXx/7qO3rHnsLJUADYX8xCS3jq3BKux96LT/KGl3ymX0dsXs0rNDakc2
# y2kmeUvEg/lhUrU5DkxFCPpZ+IKMbOnLXyKsshHNAji/nw+uby4haogDFGndQqrz
# YOvZzeUUbAgoI8GIVzWS32B5fOuUPDxXRLOZSBQtTwuZpWuwq9MZ7K9tvFsT6J0W
# P23SepTt76rNA0WYrm8g/WWehAkdX27VGYXGGaKUUqkw9tH7++h9EwRA+sPbK3m9
# LKg7PXCz0/yGhZS9K0uxRBGsJLhfgLsa17XkphGOTB58b8ybrnIst6P+htYoV6zL
# ROOqg/W9LzoXgmVo7pzITV0Npud7fZkbonjZ/tqCrpDWjO5SPl8+y01ItA0jDwRm
# jLWEkI0gEAgZcMuKLJrx7LAf5WQ9/5COul5jOFO4BozFazbAU7X/+o6UGXPLug7V
# EnrIB+BeyPBJHaS6cy4H8v+8TkAEjEX32gp9UGkx5vYKSIB3FkjlhV26cn2Iunvu
# +sK9+ujsvTDeGVmwKVdkim7CP6r9kIwbMn7KC5iYnCrjWZiZJLzpGPfytyHJ0KyU
# CynO2+PxXaffDwGnfcq0iOfjAw==
# SIG # End signature block
