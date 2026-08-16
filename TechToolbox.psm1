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

    Write-Host @"

╔══════════════════════════════════════╗
║        T E C H T O O L B O X         ║
║   Technician-Grade PowerShell Tools  ║
╚══════════════════════════════════════╝
"@ -ForegroundColor Green

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

    Write-Host ("`n[{0}] {1} v{2} {3} ({4})  PS {5} {6}" -f $ts, $name, $version, $who, $Status, $psv, $ed) `
        -ForegroundColor DarkGray
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
Write-TTLoadedLine -Status Loaded
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAS4MmneL7kNTmA
# w51q5j+zR5eoiVzbhaZ9gFtGj6AppaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAIRSM6KA/W
# Ct2/6QfiPN+LE6jBWAK12r7rvH4m60qXADANBgkqhkiG9w0BAQEFAASCAgAwoVoL
# WHnFW+lnESNDJ5/WSjGYeHKjIc6MRqMvGLkYvkuKPEUXIqm4gv3W+VH0HV1hzbS6
# xCDfvDVJgVy8v0q5O8+RsZiC/vsgCohzL5AJhpspbfEmdbyxC0MLAdgs/2gS/R1s
# igkVsTMTfAecm1mj2d3fLttGzicegwYqOviapFyT+v3GzPEUdo5bo1FfUuAkZ/pA
# JmQYfQqEN0Hc7BUOb4Oi75yqYq1JJUO/MRIw9v/Oo7eGm8QgxPEiKLA6BSB3dCYh
# oZfxBSG9qX9o/iNtRkm4JK2Q0imdJ7dixeXAUDUyezMgyfFjwEVcHkzyaZPTqFEa
# NutkZDdkvXw5gOhFRs2ubJKcrRJ6qbd30pb5W952SN83/jRl1GMN49DYHpVYow1Z
# fVQgdlMBdLj7ZiXGRT0knkFAze7pv7/OCq/opbywBnKI7BPRBc8epAzNy2Pu9w+i
# EHtBZow+b9VXWlEFFV6rNpFbEhDCAdSohkWMzPVy35Twt+YdutUbQsr/hXQZfYpS
# xUNIZYZApVdl96HOyLpiXLJqMy3/MLsdQXmE+/e0OCTuhZr5XJmKkhwGFtdnercu
# L8rZluMkEVl4guT107vLwMmt7O0tAZUv8oCEtE+9vlKRmvV96WHy5s/YQ8GtBvkX
# kCjm1ZREbBcGjI1AOdy9UuB4qVmFuHiM8ZGb6KGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA4MTYyMjMyMzJaMC8GCSqGSIb3DQEJBDEiBCDJYXZ4VmwG7ALeOyOT
# 1omFppdXFBovXVudPm9JvRiAajANBgkqhkiG9w0BAQEFAASCAgC3v8eaH6GMCP1O
# aDXtZd0ot9/2doODG+fcLgTm8jAb+YoJBRyOpFZ8PU/8xLSX9tEDyNtE8zFcc2qo
# hYJfGD92IjtW23Dg/IlLBbsPXuhu+jNXA4VoUAFcXBOYqAMrFMHyh06YBmZrRzqw
# 1Sm4qLTndn2gzkQI3va1JcffHrZc0Ivq4VRGT7hTupcqrvTdN5/R8Chu3rKgknVB
# 2kYLZzknKhoSnCKYBFvIXc0uOOQ4g4mZVHAEc1XZ6ub2FTUKdUvzqps1dpLMpNiy
# BiS41ANcbHTEseA6sk9vSzJuQ8NKjP25Ca6gyDOixRjPToukWAXrq67O5mAgrY6j
# O7Va5MNja8dOTPOJR7Gwk1655a+FdbL2a9a5UW0Ml/Ijr2pCWZ+qgbj5u1OEjKlF
# WTLNxO7yeWw0vJ6fGAMBDeEsgJxfIEW4c14w/jdnGB9BdnP8kFVaccmUhl88cyL5
# CVRkLSQ35pIKeQ5kINydbkUT0p5EjPa+SSsqx4umfS9TJevHM67iGcvTzG/cwy6Y
# INpmOJajaeM3Xnp0Q3kbxzKczcvlYn9TobF0n+vdCGhphQPRbqaXT2D1QkKMn0N8
# MWICDduT5TirkFXsaowbZh01Gh37U9z7POgfDDVkMzko38btA/Pckoj+967BXMr/
# lPEVco6I2G/OMlQJBcNmDWmWfwgPBQ==
# SIG # End signature block
