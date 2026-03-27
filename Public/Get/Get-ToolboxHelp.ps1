function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    .DESCRIPTION
        Displays overview, lists commands (grouped by verb + synopsis), shows
        full help (or examples) for a given command, or prints the effective
        configuration (optionally as JSON).

    .PARAMETER Name
        A specific command name (or partial name) to show help for. Supports
        fuzzy matching and suggestions if not found.

    .PARAMETER List
        Lists available TechToolbox commands (PUBLIC/EXPORTED ONLY). By default
        groups by verb and shows synopsis when available.

    .PARAMETER ShowEffectiveConfig
        Prints the effective configuration currently loaded (or attempts to load
        config.json directly if runtime init didn’t load it).

    .PARAMETER AsJson
        Outputs list/config as JSON.

    .PARAMETER Examples
        When used with -Name, displays Examples-only help for that command.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$Name,

        [switch]$List,
        [switch]$ShowEffectiveConfig,
        [switch]$AsJson,
        [switch]$Examples
    )

    # ---------------------------
    # Runtime initialization (best effort)
    # ---------------------------
    try {
        Initialize-TechToolboxRuntime
    }
    catch {
        Write-Verbose ("Get-ToolboxHelp: runtime init failed: {0}" -f $_.Exception.Message)
    }

    # ---------------------------
    # Determine module name (resilient)
    # ---------------------------
    $modName = $PSCmdlet.MyInvocation.MyCommand.ModuleName
    if (-not $modName) { $modName = $ExecutionContext.SessionState.Module.Name }
    if (-not $modName) { $modName = 'TechToolbox' }

    # Grab module object (for ExportedFunctions)
    $mod = Get-Module -Name $modName -ErrorAction SilentlyContinue
    if (-not $mod) {
        # In-module execution fallback
        $mod = $ExecutionContext.SessionState.Module
    }

    # ---------------------------
    # Interactive / non-interactive output behavior
    # ---------------------------
    $IsServerHost = $Host.Name -like '*ServerHost*'
    $SupportsHostUI = $null -ne $Host.UI -and $null -ne $Host.UI.RawUI
    $IsInteractive = (-not $IsServerHost) -and $SupportsHostUI

    function Write-TTText {
        param(
            [Parameter(Mandatory)]
            [string]$Text,

            [ConsoleColor]$Color = [ConsoleColor]::Gray,

            [switch]$NoNewLine
        )

        if ($IsInteractive) {
            if ($NoNewLine) {
                Write-Host $Text -ForegroundColor $Color -NoNewline
            }
            else {
                Write-Host $Text -ForegroundColor $Color
            }
        }
        else {
            Write-Information $Text
        }
    }

    # ---------------------------
    # Resolve effective config safely
    # ---------------------------
    $configLoaded = $false
    $Config = $null

    if (Get-Variable -Name cfg -Scope Script -ErrorAction SilentlyContinue) {
        $Config = $script:cfg
        $configLoaded = [bool]$Config
    }

    if ($ShowEffectiveConfig -and -not $configLoaded) {
        try {
            if (-not $script:ModuleRoot) { $script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase }
            $configDir = Join-Path $script:ModuleRoot 'Config'
            $cfgPath = Join-Path $configDir 'config.json'
            if (Test-Path -LiteralPath $cfgPath) {
                $Config = Get-TechToolboxConfig -Path $cfgPath
                $configLoaded = [bool]$Config
            }
        }
        catch {
            Write-Verbose ("Get-ToolboxHelp: direct config load failed: {0}" -f $_.Exception.Message)
        }
    }

    # ---------------------------
    # Title varies by mode
    # ---------------------------
    $title =
    if ($ShowEffectiveConfig) { 'TechToolbox Configuration' }
    elseif ($List) { 'TechToolbox Command Catalog' }
    elseif ($Name) { "TechToolbox Help: $Name" }
    else { 'TechToolbox Help Center' }

    # ---------------------------
    # Header / Overview (shown only when interactive)
    # ---------------------------
    if ($IsInteractive) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor DarkCyan
        Write-Host ("        {0,-28}" -f $title) -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor DarkCyan
        Write-Host ""
    }

    if (-not $ShowEffectiveConfig -and -not $List -and -not $Name) {
        Write-TTText "A technician-grade PowerShell toolkit for:" Gray
        Write-TTText "  • Diagnostics" Gray
        Write-TTText "  • Automation" Gray
        Write-TTText "  • Environment-agnostic workflows" Gray
        Write-TTText "" Gray

        Write-TTText "----------------------------------------" DarkGray
        Write-TTText " Common Commands:" White
        Write-TTText "----------------------------------------" DarkGray
        Write-TTText "" Gray

        Write-TTText "  Get-ToolboxHelp -List" Yellow
        Write-TTText "    Displays available PUBLIC commands (grouped + synopsis)." Gray
        Write-TTText "" Gray

        Write-TTText "  Get-ToolboxHelp Invoke-SubnetScan" Yellow
        Write-TTText "    Shows detailed help for Invoke-SubnetScan." Gray
        Write-TTText "" Gray

        Write-TTText "  Get-ToolboxHelp subnet" Yellow
        Write-TTText "    Suggests matching PUBLIC commands if exact name isn't found." Gray
        Write-TTText "" Gray

        Write-TTText "  Invoke-PurviewPurge -CaseName 'XYZ123'" Yellow
        Write-TTText "    Creates a Case search and purges the search results." Gray
        Write-TTText "" Gray

        Write-TTText "----------------------------------------" DarkGray
        Write-TTText " For full help on any command:" White
        Write-TTText "----------------------------------------" DarkGray
        Write-TTText "" Gray
        Write-TTText "  Get-ToolboxHelp <CommandName>" Yellow
        Write-TTText "" Gray
        Write-TTText "========================================" DarkCyan
        return
    }

    # ---------------------------
    # Effective configuration mode
    # ---------------------------
    if ($ShowEffectiveConfig) {
        Write-TTText "" Gray
        Write-TTText "Effective Configuration" Cyan
        Write-TTText "----------------------------------------" DarkGray

        if (-not $configLoaded) {
            Write-TTText "(configuration not loaded)" Yellow
            return
        }

        if ($AsJson) {
            $Config | ConvertTo-Json -Depth 10
        }
        else {
            $Config | Format-List
        }

        Write-TTText "" Gray
        return
    }

    # ---------------------------
    # List commands mode (PUBLIC ONLY)
    # ---------------------------
    if ($List) {
        # Public commands only = exported functions
        $cmds = @()
        if ($mod -and $mod.ExportedFunctions.Count -gt 0) {
            $cmds = $mod.ExportedFunctions.Values | Sort-Object Name
        }
        else {
            # Safety fallback (rare)
            $cmds = Get-Command -Module $modName -CommandType Function -ErrorAction SilentlyContinue |
            Sort-Object Name
        }

        if ($AsJson) {
            $out = foreach ($c in $cmds) {
                $h = $null
                try { $h = Get-Help $c.Name -ErrorAction SilentlyContinue } catch {}
                [pscustomobject]@{
                    Name     = $c.Name
                    Verb     = $c.Verb
                    Noun     = $c.Noun
                    Synopsis = if ($h) { $h.Synopsis } else { $null }
                }
            }
            $out | ConvertTo-Json -Depth 4
            return
        }

        Write-TTText "" Gray
        Write-TTText "Commands (PUBLIC / Exported) — grouped by verb" Cyan
        Write-TTText "----------------------------------------" DarkGray
        Write-TTText "" Gray

        $helpCache = @{}

        $cmds |
        Group-Object Verb |
        Sort-Object Name |
        ForEach-Object {
            $verb = $_.Name
            Write-TTText "[$verb]" Cyan

            $_.Group |
            Sort-Object Name |
            ForEach-Object {
                $cmdName = $_.Name
                if (-not $helpCache.ContainsKey($cmdName)) {
                    try { $helpCache[$cmdName] = Get-Help $cmdName -ErrorAction SilentlyContinue }
                    catch { $helpCache[$cmdName] = $null }
                }

                $syn = $null
                if ($helpCache[$cmdName]) { $syn = $helpCache[$cmdName].Synopsis }

                if ([string]::IsNullOrWhiteSpace($syn)) {
                    Write-TTText ("  {0}" -f $cmdName) Yellow
                }
                else {
                    $left = ("  {0,-34}" -f $cmdName)
                    Write-TTText ($left + $syn) Gray
                }
            }

            Write-TTText "" Gray
        }

        return
    }

    # ---------------------------
    # Specific command help mode (PUBLIC fuzzy matching)
    # ---------------------------
    if ($Name) {
        # Exact resolution first
        $exact = Get-Command -Name $Name -ErrorAction SilentlyContinue

        if (-not $exact) {
            # Only suggest exported/public functions
            $candidates = @()
            if ($mod -and $mod.ExportedFunctions.Count -gt 0) {
                $candidates = $mod.ExportedFunctions.Values
            }
            else {
                $candidates = Get-Command -Module $modName -CommandType Function -ErrorAction SilentlyContinue
            }

            $matches = $candidates |
            Where-Object { $_.Name -like "*$Name*" } |
            Select-Object -ExpandProperty Name -Unique |
            Sort-Object

            if ($matches.Count -eq 1) {
                $resolved = $matches[0]
                Write-TTText "" Gray
                Write-TTText ("Resolved '{0}' → '{1}'" -f $Name, $resolved) Yellow
                $Name = $resolved
            }
            elseif ($matches.Count -gt 1) {
                Write-TTText "" Gray
                Write-TTText ("No exact command found for '{0}'." -f $Name) Yellow
                Write-TTText "Did you mean:" Yellow
                $matches | ForEach-Object { Write-TTText ("  {0}" -f $_) Gray }
                Write-TTText "" Gray
                return
            }
            else {
                Write-TTText "" Gray
                Write-TTText ("No command found matching '{0}'." -f $Name) Yellow
                Write-TTText "Tip: try Get-ToolboxHelp -List" Gray
                Write-TTText "" Gray
                return
            }
        }

        try {
            Write-TTText "" Gray
            Write-TTText ("Help for: {0}" -f $Name) Cyan
            Write-TTText "----------------------------------------" DarkGray

            if ($Examples) {
                Get-Help -Name $Name -Examples
            }
            else {
                Get-Help -Name $Name -Full
            }

            Write-TTText "" Gray
        }
        catch {
            Write-TTText ("No help found for '{0}'." -f $Name) Yellow
        }

        return
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9rcIf95ry39NT
# ejg42jCo/BYG3A/cBa1mw6PCTyOFBqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA1uYj7+Zc4
# LsdhbtrJSuF+qOaK2VoHAjIk4IgtNjycHzANBgkqhkiG9w0BAQEFAASCAgCJ8hHh
# 3jhuPPaOOLO8dREkRsszR5fDBdsTfeBFIMlyPAwxn8qzkabPxJQaxlwLnKUqnKWv
# LrXfMKXldGLEq/oc9xq8Be9jldkF3/T0eEfXDXHVt8eBYjgDUnI71wCF+yaxu7e9
# VJv+BOPuTAq7O5p9LMFvoJYAIn2sDSoFIDdOtjEiPMlyAlhgBCHwPhYd4154bMYX
# gwtID2ebK4vuGobHrlnlbsP2aNw0zsvIuc48dBYRUPOypvs3XMypwBC1sqCUyys7
# GwmqSL1QjNWnuAjJqBQwOY9br4lAGWcx0qaHsZ1EdYoQfd+kGcppRjows7prQaNN
# jXv03ObSPr9J/CaQBCy/TR09ZEKehWxISg4hh9wLfTAPwuA630ia13VzCFI8hEq1
# LOUxPPidkl+g+dtAZSa0GUa60i/SWWXerT2IB+QMFYHebTdtKrdyJshhYoqPRSNH
# ri0HRz9GFdv3zY7o9EKBTfaVD/HDR9QgbSnE2kr/PVLg1OveTtQjANLfbUo3V+Zq
# wgy5B/tmJgkcvdCHN6yHZ1e3gOEkgBTtM2f/XYGxVda+wAB1I3IAB7/y09pO0ouY
# d/JCnJIdDjSu4LYtmWriSG1G9krgAjKjygKw5xVGTaaWPVQnoO05a1B90lnaKTh2
# 0nkvpXFmPNxtg7iy6Jkzt/q9MsEq8/MNkVx4Z6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMjcxODAwNDFaMC8GCSqGSIb3DQEJBDEiBCAy8hccQqdhscfS3cDd
# tWmsuEGL4P/oSZDGz4lNFo/fjzANBgkqhkiG9w0BAQEFAASCAgA8IeBANhoWD0U5
# RC7PSLjaTS7TuvMyRSSRmGqqSsmJayZoVlLnXZBe7JjIUvVACDBGerB18OmD4Bzk
# jdZ42pygqlgwcxpeqVrL6plV136b793rrIDxR1ygT+KT5rUq+2w+Iw2QdyDdH5lZ
# ynr432anxJv6YrrvQgWJkHqi4DEBcsZ8zEMnAYikaqta3Zdh5rCWo2rQtiBgVQE7
# SXuwPpUM63I1A7Vzklv53tl210SPlPtn5IQRXueiHCBLbOIXbfL36PB3LktzyVlz
# kvmX9KdZ/a9CnsDLHT111sZmjl+4VrztjHFPCK+W+lZdrDbYZWR588Wrd370VkZP
# zpHv525FzRL8xkOb4H08ON6+50iKeY3o8fi/0SjX8+u6c2BfFZJ1XKSfezQ1k5bY
# 2swVDNT47MVpYBzvXtYDChd8v7nugIhoSt2Yc9Yl7jXcH79LxRM8+hyjhqI7Kuq5
# vKz19lJ6FP1PpzhHp/RzicOkCdk2HJy5xvGvISQ9UqfrbOQQnC+sfgYosXXWyX2Z
# eeoaUfCuN29975sY8n8jpKouMFoDTVSzVfIEcxVYYu9KVa8SkKQixQqB9cv6ewRE
# xy+BK72ru/Szgwua69v0or9kV14542vNrwTRCLNMexBxwpHnU6oOXE3S7ib3JIjm
# Si4wGjPQrG2bVJqPBvnv8jW87JCBag==
# SIG # End signature block
