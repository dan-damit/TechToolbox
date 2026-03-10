
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

---------------------------------
╺┳╸┏━╸┏━╸╻ ╻╺┳╸┏━┓┏━┓╻  ┏┓ ┏━┓╻ ╻
 ┃ ┣╸ ┃  ┣━┫ ┃ ┃ ┃┃ ┃┃  ┣┻┓┃ ┃┏╋┛
 ╹ ┗━╸┗━╸╹ ╹ ╹ ┗━┛┗━┛┗━╸┗━┛┗━┛╹ ╹
---------------------------------
A PowerShell Module for daily ops
---------------------------------
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

# Predefine script-scoped vars before any reads
if (-not (Get-Variable -Name ModuleRoot        -Scope Script -ErrorAction SilentlyContinue)) { $script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase }
if (-not (Get-Variable -Name TT_Initialized    -Scope Script -ErrorAction SilentlyContinue)) { $script:TT_Initialized = $false }
if (-not (Get-Variable -Name TT_RuntimeReady   -Scope Script -ErrorAction SilentlyContinue)) { $script:TT_RuntimeReady = $false }
if (-not (Get-Variable -Name ConfigPath        -Scope Script -ErrorAction SilentlyContinue)) { $script:ConfigPath = $null }
if (-not (Get-Variable -Name log               -Scope Script -ErrorAction SilentlyContinue)) { $script:log = $null }
if (-not (Get-Variable -Name ModuleDependencies -Scope Script -ErrorAction SilentlyContinue)) { $script:ModuleDependencies = $null }
if (-not (Get-Variable -Name PrivateLoaded -Scope Script -ErrorAction SilentlyContinue)) { $script:PrivateLoaded = $false }
if (-not (Get-Variable -Name cfg -Scope Script -ErrorAction SilentlyContinue)) { $script:cfg = $null }

# --- Standard runtime container (used by workers/helpers locally + remotely) ---
if (-not (Get-Variable -Name TT -Scope Script -ErrorAction SilentlyContinue)) {
    $script:TT = [ordered]@{
        RuntimeId   = [guid]::NewGuid().ToString()
        IsRemote    = $false
        SessionType = $null        # 'WSMan' / 'SSH' / 'PS7' etc (optional)

        ModuleRoot  = $script:ModuleRoot

        # Option B (ephemeral) staging roots:
        WorkRoot    = $null        # e.g. $env:TEMP\TT_Worker_{guid}
        WorkersRoot = $null        # e.g. $env:TEMP\TT_Worker_{guid}\workers
        HelpersRoot = $null        # e.g. $env:TEMP\TT_Worker_{guid}\helpers

        WorkerPath  = $null        # main worker .ps1 path staged on remote (or local if used)

        LogRoot     = (Join-Path $env:TEMP 'TechToolbox')
    }
}

# Guard re-import (but still print status line)
if ($script:TT_Initialized) {
    # Don’t show banner again; just show status
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

# --- Gate self-install / self-heal (skip or once) ---
try {
    if ($env:TT_SkipHomeInit -ne '1') {
        # Simple sentinel: run only if the destination doesn't exist (or add your own version/sentinel check)
        if (-not (Test-Path 'C:\TechToolbox\.ready')) {
            Initialize-TechToolboxHome -HomePath 'C:\TechToolbox'
            # Optional sentinel drop
            try { New-Item -ItemType File -Path 'C:\TechToolbox\.ready' -Force | Out-Null } catch {}
            __tt_trace "Initialize-TechToolboxHome executed"
        }
        else {
            __tt_trace "Home already initialized; skipping"
        }
    }
    else {
        __tt_trace "Home init skipped via TT_SkipHomeInit=1"
    }
}
catch {
    Write-Warning "Initialize-TechToolboxHome failed: $($_.Exception.Message)"
    # Continue; tool can still run from the current location this session.
}

# --- Load Private functions ---
$privateRoot = Join-Path $script:ModuleRoot 'Private'
Get-ChildItem -Path $privateRoot -Recurse -Filter *.ps1 |
ForEach-Object { . $_.FullName }

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

# --- Load **Public** functions only (1 function per file convention) ---
$publicRoot = Join-Path $script:ModuleRoot 'Public'
$publicFiles = Get-ChildItem -Path $publicRoot -Recurse -Filter *.ps1 -File
foreach ($file in $publicFiles) {
    # Trust convention: the file defines a function named as the basename
    # This avoids Select-String scans and is how most PS modules are structured.
    . $file.FullName
}
$publicFunctionNames = $publicFiles.BaseName
__tt_trace ("Loaded Public functions: {0}" -f ($publicFunctionNames -join ', '))

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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCYhWtX+HLREba1
# Cl3uwRDM30ptTLUvDjh4w9vRpBSPyKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC4m6Vwdoz5
# ydXMiqyoxPibXmb4jM9yQPWbOzh9gqq78DANBgkqhkiG9w0BAQEFAASCAgA8brTY
# AcV//4uB387ZCzr/dXlQkrWFpvQt9Q2ux5kZPl3lzHJfZmPKYmLlRcBJZQGNpvXm
# UwWuBQ508PJfQryzZuNptQ3tLAe2MnK9QVYlXB6MB9LHNteVVUu4Fw5B+eVQihC0
# rtnZJobCAgL5WTlR0cQ7duCZ2uwHnrovMzZI++1FvY9eZLuyUEnb2yhkWBRygIBx
# OJDdgBNBGlwdWGFc+VsiAY0uUHtp+wMnaeHgTv0VKLJktiUvINMukacevde0OP8X
# 31t4l1mM3DZEBJxJmjAOu22DGqz7x24suLQ0z9s+9lTfMOfdahxzUC9F3WeHj9Zu
# BnsHaPGkA1EGbPqSZKqV0fdww5xuCHIc8hoG7A7XZq1gwcQ+uQz6GLK6IuNPAqt2
# z5P+F4fYxMUPbqr1WvtmBb1KC2b31TdIF4w9OIOajpw+flKGcBSlR1nQGGmo9Lzk
# lKOoZzoTpwgw6SBhkir5fQvMPKH+dHMZXYLyVRwP7dvZUFdVKB8jX+izsvmQo/aI
# SDX4yc1emli2oxKu01VLsucxjdaxqn1/lP2jh+mpF0N0l3RaKU+Dmzw87+IgptSo
# CU5Yvw9wHGAqMwg77uZr3rVaMWSnJbc1iA/BX3haDd8g+frU87BQSrOMG15UPdxS
# gZAn9r+hffDyL3KbvosiEeHp3CDiskEXn3hUTaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMTAyMTM1MjdaMC8GCSqGSIb3DQEJBDEiBCDi6Ci2CoA4e1dgyQ2P
# M5Qw96PKk/vtHCC5XXN0GoNXnDANBgkqhkiG9w0BAQEFAASCAgBEgcl/hBeIKilw
# qBYXkV80+PiEvQsk2gCyy/wHpWaJvhBec30sPUi7+iuuS04Jjxotky4DtCgJzdsW
# Uz7IS1wFkDfg+8+7J2i+fc7b3O9hWnZlMxs79tc3XO+M1l+2ITHli2OrgUPp1FGy
# ptxoSPN8Muk+DYaAJfyA186R8XDOAdYPz662AG11KCfZjgBm/GF4xI2LIBTPmRz+
# vTn6vGDmH17FOFfCN6D2ORhDPeC3f+dDM771BdN9KHlumzJk9iaXbL17yG8bdFxx
# XFaX/nQKnwCofiXyK5VUNpZLeSpt7kH+J537FlmChSWQ6eflrAiViZOLhZmYX1kE
# oai5SyT7crL103RBAf35l/pQQKgfRSohWQmLn0vyBx9No7oWllAc+TEdp+HyIRl0
# AcaMcolU6OQfKs5R1ocN+Da4+Mo5BYOKaL1UG/RNcLqHiU2LesR9f/mLy1Z7Ubgx
# wZkicN2fU9Evj8fOzRjNWJG2R2pYujbz/IQw1zW9CtknaXmTHxXzIxxPW7XBgx3J
# /+r4g3NzlknH3/3Z3/ObKwvalaIDNe2FckGzZVT1wfxV3NwAbAakwmhN7z51hyzZ
# raXHw6p1jv2NPAU2yfzBGYaXb/NJrKOlZ8bDRWfpcWp7uFWBhcwCYcJ1YR9EuRTV
# oaIv7Lt/+XSEkWUWiKIyYb9mPv3LMw==
# SIG # End signature block
