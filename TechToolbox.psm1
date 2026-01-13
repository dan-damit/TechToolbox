# TechToolbox.psm1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Show logo on module import
$logo = @"
 _____         _       _____           _ _               
|_   _|__  ___| |__   |_   _|__   ___ | | |__   _____  __
  | |/ _ \/ __| '_ \    | |/ _ \ / _ \| | '_ \ / _ \ \/ /
  | |  __/ (__| | | |   | | (_) | (_) | | |_) | (_) >  < 
  |_|\___|\___|_| |_|   |_|\___/ \___/|_|_.__/ \___/_/\_\

                 Technician-Grade Toolkit
"@

Write-Host $logo -ForegroundColor Cyan


# 1) Module root & config path (use ModuleBase for reliability)
$script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase
$script:ConfigPath = Join-Path $script:ModuleRoot 'Config\config.json'

try {
    if (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf) {
        $cfg = Get-TechToolboxConfig -Path $script:ConfigPath
        if ($cfg) {
            $script:TechToolboxConfig = $cfg
            Write-Verbose "TechToolbox: config preloaded from $script:ConfigPath"
        }
        else {
            Write-Verbose "TechToolbox: config returned null from $script:ConfigPath"
            $script:TechToolboxConfig = $null
        }
    }
    else {
        Write-Verbose "TechToolbox: config path not found: $script:ConfigPath"
        $script:TechToolboxConfig = $null
    }
}
catch {
    Write-Verbose ("TechToolbox: config preload failed: {0}" -f $_.Exception.Message)
    $script:TechToolboxConfig = $null
}

# 2) Load Private first
$privateRoot = Join-Path $script:ModuleRoot 'Private'
$privateFiles = Get-ChildItem -Path $privateRoot -Recurse -Filter *.ps1 -File -ErrorAction SilentlyContinue
foreach ($file in $privateFiles) {
    . $file.FullName
}

# ----- Initialization helpers (folded in) -----

# Module-level init state
$script:ToolboxInitialized = $false
$script:ToolboxInitTimestamp = $null

function Write-Diag {
    param([string]$Message)
    # Use -Verbose on Import-Module or Initialize-Toolbox to surface details
    Write-Verbose $Message
}

function Get-ModulesFromConfig {
    # Reads Modules from the already-preloaded config if present; otherwise attempts to parse.
    # Returns $null if no valid section found.
    if ($script:TechToolboxConfig -and $script:TechToolboxConfig.Modules) {
        return $script:TechToolboxConfig.Modules
    }
    if (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf) {
        try {
            $cfg = Get-TechToolboxConfig -Path $script:ConfigPath
            if ($cfg -and $cfg.Modules) { return $cfg.Modules }
        }
        catch {
            Write-Warning "Failed to parse '$script:ConfigPath' for Modules: $($_.Exception.Message)"
        }
    }
    return $null
}

function Initialize-TechToolboxModules {
    <#
    .SYNOPSIS
    Prepares PSModulePath, resolves bundled modules, optionally defers import.

    .DESCRIPTION
    - Prepends .\Modules to PSModulePath
    - Reads Modules list from config.json (if present) or falls back to EXO 3.9.0 (bundled)
    - If a module entry sets 'Defer'=$true, it won't import until Ensure-* is called.
    #>
    [CmdletBinding()]
    param(
        [switch]$ForceReload
    )

    $modulesPath = Join-Path $script:ModuleRoot 'Modules'
    if (Test-Path $modulesPath) {
        $paths = $env:PSModulePath -split ';' | ForEach-Object { $_.Trim() }
        if (-not ($paths -contains $modulesPath)) {
            $env:PSModulePath = "$modulesPath;$env:PSModulePath"
            Write-Diag "Prepended bundled Modules path: $modulesPath"
        }
        else {
            Write-Diag "Bundled Modules path already present: $modulesPath"
        }
    }
    else {
        Write-Verbose "Bundled Modules path not found: $modulesPath"
    }

    $ModuleList = Get-ModulesFromConfig
    if (-not $ModuleList) {
        # Hardcoded fallback — Option A
        $ModuleList = @(
            @{
                Name     = 'ExchangeOnlineManagement'
                Version  = '3.9.0'
                Bundled  = $true
                Required = $true
                Defer    = $true
            }
        )
    }

    foreach ($m in $ModuleList) {
        $name = $m.Name
        $version = [version]$m.Version
        $bundled = [bool]$m.Bundled
        $required = [bool]$m.Required
        $defer = [bool]$m.Defer

        if ($defer -and -not $ForceReload) {
            Write-Diag "Deferred import for $name $version."
            continue
        }

        $available = Get-Module -ListAvailable $name | Where-Object { $_.Version -eq $version }
        if (-not $available -and $bundled) {
            $bundledPath = Join-Path $modulesPath (Join-Path $name $m.Version)
            if (Test-Path $bundledPath) {
                Write-Diag "Found bundled path for $name $version $bundledPath"
            }
            else {
                Write-Warning "Bundled path missing for $name $version at '$bundledPath'."
            }
        }

        try {
            Import-Module $name -RequiredVersion $version -Force -ErrorAction Stop
            Write-Diag "Imported $name $version."
        }
        catch {
            Write-Warning "Failed to import $name $version $($_.Exception.Message)"
            if ($required) { throw "Required module missing: $name $($version.ToString())" }
        }
    }
}

function Ensure-ExchangeOnlineModule {
    <#
    .SYNOPSIS
    Imports ExchangeOnlineManagement (Option A) just-in-time from bundled path.

    .PARAMETER RequiredVersion
    Defaults to 3.9.0.
    #>
    [CmdletBinding()]
    param(
        [string]$RequiredVersion = '3.9.0'
    )

    $name = 'ExchangeOnlineManagement'
    $version = [version]$RequiredVersion

    $alreadyLoaded = Get-Module -Name $name | Where-Object { $_.Version -eq $version }
    if ($alreadyLoaded) {
        Write-Diag "EXO $version already loaded."
        return
    }

    $available = Get-Module -ListAvailable $name | Where-Object { $_.Version -eq $version }
    if (-not $available) {
        Initialize-TechToolboxModules -ForceReload
        $available = Get-Module -ListAvailable $name | Where-Object { $_.Version -eq $version }
        if (-not $available) {
            throw "ExchangeOnlineManagement $($version.ToString()) not available in PSModulePath. Check bundled Modules."
        }
    }

    Import-Module $name -RequiredVersion $version -Force
    Write-Diag "Loaded ExchangeOnlineManagement $version."
}

function _InvokeModuleImport {
    <#
    .SYNOPSIS
    Idempotent one-time initialization (called on import and by Initialize-Toolbox).
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [string]$ConfigPath = $script:ConfigPath
    )

    if ($script:ToolboxInitialized -and -not $Force) { return }

    # Light-touch env prep; respects 'Defer'
    Initialize-TechToolboxModules

    $script:ToolboxInitialized = $true
    $script:ToolboxInitTimestamp = Get-Date
    Write-Verbose "TechToolbox initialized at $script:ToolboxInitTimestamp"
}

function Initialize-Toolbox {
    <#
    .SYNOPSIS
    Public entry point to initialize TechToolbox (paths, config, deferred modules).

    .PARAMETER Force
    Re-runs initialization even if already initialized.

    .PARAMETER ConfigPath
    Optional path to config.json.
    #>
    [CmdletBinding()]
    param(
        [switch]$Force,
        [string]$ConfigPath = $script:ConfigPath
    )

    _InvokeModuleImport -Force:$Force -ConfigPath $ConfigPath
}

# ----- End initialization helpers -----

# Define aliases from JSON
$aliasesConfigPath = Join-Path $script:ModuleRoot 'Config\AliasesToExport.json'
$aliasItems = @()

if (Test-Path $aliasesConfigPath) {
    try {
        $aliasJson = Get-Content -Raw -Path $aliasesConfigPath | ConvertFrom-Json
        $aliasItems = @($aliasJson.aliases)

        foreach ($a in $aliasItems) {
            if (-not $a.name -or -not $a.target) { continue }

            # Check target exists (should, since Private already loaded)
            if (-not (Get-Command -Name $a.target -ErrorAction SilentlyContinue)) {
                Write-Verbose "Alias '$($a.name)' target '$($a.target)' not found; skipping."
                continue
            }

            # Create alias in module scope (default); manifest will export it
            Set-Alias -Name $a.name -Value $a.target
        }
    }
    catch {
        Write-Warning "Failed to load aliases from '$aliasesConfigPath': $($_.Exception.Message)"
    }
}

# Collect aliases that should be exported
$exportableAliases = $aliasItems |
Where-Object { $_.export -and $_.name } |
Select-Object -ExpandProperty name

# 3) Load Public, collect names, and export only those
$publicRoot = Join-Path $script:ModuleRoot 'Public'
$publicFiles = Get-ChildItem -Path $publicRoot -Recurse -Filter *.ps1 -File -ErrorAction SilentlyContinue

$publicFunctionNames = @()
foreach ($file in $publicFiles) {
    . $file.FullName
    # Assumes file BaseName == function name (recommended convention)
    $publicFunctionNames += $file.BaseName
}

if ($publicFunctionNames.Count -gt 0 -or $exportableAliases.Count -gt 0) {
    Export-ModuleMember -Function $publicFunctionNames -Alias $exportableAliases
}
else {
    Write-Verbose "TechToolbox: no public functions or aliases found to export."
}

# 4) Load all C# interop classes recursively
$interopRoot = Join-Path $privateRoot 'Interop'
if (Test-Path $interopRoot) {
    $csFiles = Get-ChildItem -Path $interopRoot -Filter '*.cs' -Recurse -File -ErrorAction SilentlyContinue
    foreach ($cs in $csFiles) {
        try {
            Add-Type -Path $cs.FullName -ErrorAction Stop
        }
        catch {
            # Common duplicate type exception during reloads; adjust handling if needed
            Write-Verbose "Interop type load skipped for '$($cs.Name)': $($_.Exception.Message)"
        }
    }
}

# 5) Attempt to preload and cache the config for interactive convenience
try {
    $script:TechToolboxConfig = Get-TechToolboxConfig -Path $script:ConfigPath
}
catch {
    Write-Host "TechToolbox: config preload failed: $($_.Exception.Message)"
    $script:TechToolboxConfig = $null  # Allow callers to detect missing config
}

# 6) Export public Initialize-Toolbox entry point (in addition to Public\*)
Export-ModuleMember -Function Initialize-Toolbox

# 7) Auto-init on module import (toggle ON/OFF as you prefer)
_InvokeModuleImport

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBJYTTgcnVPrlte
# GBXeNXTdYvsQXb+wkAjpvCGS8y0/XKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA74Camhv0j
# tVp1WdR2m/EYRQyVAEZ8tX+C81/jLn86QzANBgkqhkiG9w0BAQEFAASCAgC3109S
# gLeJYrpdOQ42Nphhqf3nIgdOwz6gBV+9uM8XNnQlOWcQ41eJYEJKukfLdr1NTgCU
# caDK9RFD4IjuOi7f3Sapgfw/D6Nb/E0HhiCzW2MSl89Cz/BNnqmcV6T7Xt5UCTvB
# 2w6kEKVAjY8lYPMYFsXxUdgxN6n/63o3rbdQIvbuAe8eW1fez3Lr3lpInOsz1szn
# 616iy19wQ8oCCeVmZ3dMzMHf1ToFcdU4+gY/+vyHGvtZJQ7+paBHP9NyacLUuixY
# JplOebJuO/+uCSpUyjCj/OdhkNoWn+TXyWs9UnFQfwHNtvSm73BKxN6LnzLrk7qO
# 1vQQmOmpq6lZ92qcO8V5BSzuX9JNg6tR5EsIF+MmJLJlKCu7cd7M4Ytuq+AR8jhU
# onqbdZPRGxmqfLEHjh+JJyKJ42EG3gsTAP8SVGACsZGsWaNctwLvCi5agAj3itrn
# yNHda9X3sHEAsrynG5P7y4Fg1+BUMQzoVRpU02dgDtq5q1DzqprlY+66L/560i/W
# uCo/GJMm1gP/ejJyHVzXSAuxpwreeJKDR193Vf7ylDHtshJHih7L8ZNCf1HgqfmX
# z3jagyoETxfweI8EqsqExYHQqWMYlQpFMKkvl9hTKnpsrzOaheywGB/dnRyV8VdX
# inyJtNRppofCvm8DUKYOeY/474xRaeqpdWPfzKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTMxNDUzNTRaMC8GCSqGSIb3DQEJBDEiBCCpl+LYE0EgkWmFRaYr
# LVq8WmdrgpjemlO8sthIgXM9BjANBgkqhkiG9w0BAQEFAASCAgAAAh9DxX+m+vf0
# cGVjXBFQcfW+booacwNkZ9ZC+AOKVHUvjznzzwgVoJrdDf6tOcztxjVDb4ecRO54
# AapKKxl5pntvMGMVS0AlHXH2tcvNwxrUlr1/vR2A0Boquv/89pleAMheWeK0El5E
# gCq7LExdCTx0dfagKC7T2/Unrz7dVxsLCpflP59uGzFU2yeQbx6+KNfF7djFZ5VA
# cs7h8BC/Ij+gMAoAXPl38/r91OeBPs01DVrbXdXlXpYKKX3shsLWiQs/eYTJIumU
# cn/agA2AQ8JNVlSGY2aSmICdaFmf1fIjv3JXEsINlD1YptXEnG3RP5T+KAUVReyJ
# iYrbw5VK211YKcAFgM4v/r+5ujsHTf9D43Jht5OydkCEbF4Ax+UYYdQ57HrJMCwg
# /e56f1XwfS8q/tTOPLZBZQMRj5Jh4tF7d6V1Mw5L9KK6T/hG/g4wwBuhZ8htJlI5
# N//R/jA/z3ki8FhEy7nihnnSEfmBcAJ8sq8gm6/lC5kYDYZs2zOFVdEV2zpMrygM
# K4Z4VzK+IjfH4GJAibQBn3dic9zszacJAsaSolMaE760JpEBIqrtL2Pe9o/09Fqu
# SRHYzhTlzH2G/FqtroSoTv105EYuY2YsQujGRXJdLqD+Bgv1AIRCzgNZNi/NcHq6
# LpN4VmZuBvOD/85DeFd1goTONCKEIg==
# SIG # End signature block
