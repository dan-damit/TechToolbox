function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    .DESCRIPTION
        Displays overview, lists commands, shows full help for a given command,
        or prints the effective configuration.
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$List,
        [switch]$ShowEffectiveConfig,
        [switch]$AsJson
    )

    # Ensure runtime (config/logging/etc.) is initialized
    try {
        Initialize-TechToolboxRuntime
    }
    catch {
        # If runtime can't init (e.g., config missing), we still want the help text to show.
        Write-Verbose ("Get-ToolboxHelp: runtime init failed: {0}" -f $_.Exception.Message)
    }

    # Safe access to config (strict-mode friendly)
    $configLoaded = $false
    $Config = $null
    if (Get-Variable -Name cfg -Scope Script -ErrorAction SilentlyContinue) {
        $Config = $script:cfg
        $configLoaded = [bool]$Config
    }

    # If user explicitly asked for effective config but it's not loaded, try to load it directly
    if ($ShowEffectiveConfig -and -not $configLoaded) {
        try {
            # Resolve default config path the same way Initialize-Config does
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

    # ---------- Presentation ----------
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "        TechToolbox Help Center         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "A technician-grade PowerShell toolkit for:" -ForegroundColor Gray
    Write-Host "  • Diagnostics" -ForegroundColor Gray
    Write-Host "  • Automation" -ForegroundColor Gray
    Write-Host "  • Environment-agnostic workflows" -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " Common Commands:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp -List" -ForegroundColor Yellow
    Write-Host "    Displays all available commands." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp Invoke-SubnetScan" -ForegroundColor Yellow
    Write-Host "    Shows detailed help for Invoke-SubnetScan." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Invoke-PurviewPurge -CaseName 'XYZ123'" -ForegroundColor Yellow
    Write-Host "    Creates a Case search and purges the search results." -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " For full help on any command:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp <CommandName>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan

    # ----- Effective configuration requested -----
    if ($ShowEffectiveConfig) {
        Write-Host ""
        Write-Host "TechToolbox Effective Configuration" -ForegroundColor Cyan
        Write-Host "----------------------------------------"

        if (-not $configLoaded) {
            Write-Host "(configuration not loaded)" -ForegroundColor Yellow
            return
        }

        if ($AsJson) {
            $Config | ConvertTo-Json -Depth 10
        }
        else {
            $Config | Format-List
        }

        Write-Host ""
        return
    }

    # ----- List commands -----
    if ($List) {
        Write-Host ""
        Write-Host "TechToolbox Commands" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        # Use the current module name to be resilient if someone renames it
        $modName = $PSCmdlet.MyInvocation.MyCommand.ModuleName
        if (-not $modName) { $modName = 'TechToolbox' }

        Get-Command -Module $modName -CommandType Function |
        Select-Object -ExpandProperty Name |
        Sort-Object |
        ForEach-Object { Write-Host "  $_" }
        Write-Host ""
        return
    }

    # ----- Specific command help -----
    if ($Name) {
        try {
            Write-Host ""
            Write-Host "Help for: $Name" -ForegroundColor Cyan
            Write-Host "----------------------------------------"
            # -Full can be noisy; keep it if that’s your preference
            Get-Help -Name $Name -Full
            Write-Host ""
        }
        catch {
            Write-Host "No help found for '$Name'." -ForegroundColor Yellow
        }
        return
    }

    # Clear-BrowserProfileData
    if ($Name -eq 'Clear-BrowserProfileData') {
        Write-Host ""
        Write-Host "Clear-BrowserProfileData" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SubnetScan
    if ($Name -eq 'Invoke-SubnetScan') {
        Write-Host ""
        Write-Host "Invoke-SubnetScan" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-RemoteInstalledSoftware
    if ($Name -eq 'Get-RemoteInstalledSoftware') {
        Write-Host ""
        Write-Host "Get-RemoteInstalledSoftware" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-BatteryHealth
    if ($Name -eq 'Get-BatteryHealth') {
        Write-Host ""
        Write-Host "Get-BatteryHealth" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-MessageTrace
    if ($Name -eq 'Get-MessageTrace') {
        Write-Host ""
        Write-Host "Get-MessageTrace" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-TechToolboxConfig
    if ($Name -eq 'Get-TechToolboxConfig') {
        Write-Host ""
        Write-Host "Get-TechToolboxConfig" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-ToolboxHelp
    if ($Name -eq 'Get-ToolboxHelp') {
        Write-Host ""
        Write-Host "Get-ToolboxHelp" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-WindowsProductKey
    if ($Name -eq 'Get-WindowsProductKey') {
        Write-Host ""
        Write-Host "Get-WindowsProductKey" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-AADSyncRemote
    if ($Name -eq 'Invoke-AADSyncRemote') {
        Write-Host ""
        Write-Host "Invoke-AADSyncRemote" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-DownloadsCleanup
    if ($Name -eq 'Invoke-DownloadsCleanup') {
        Write-Host ""
        Write-Host "Invoke-DownloadsCleanup" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-PurviewPurge
    if ($Name -eq 'Invoke-PurviewPurge') {
        Write-Host ""
        Write-Host "Invoke-PurviewPurge" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SystemRepair
    if ($Name -eq 'Invoke-SystemRepair') {
        Write-Host ""
        Write-Host "Invoke-SystemRepair" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-PageFileSize
    if ($Name -eq 'Set-PageFileSize') {
        Write-Host ""
        Write-Host "Set-PageFileSize" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-ProxyAddress
    if ($Name -eq 'Set-ProxyAddress') {
        Write-Host ""
        Write-Host "Set-ProxyAddress" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-DnsQueryLogger
    if ($Name -eq 'Start-DnsQueryLogger') {
        Write-Host ""
        Write-Host "Start-DnsQueryLogger" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Copy-Directory
    if ($Name -eq 'Copy-Directory') {
        Write-Host ""
        Write-Host "Copy-Directory" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Reset-WindowsUpdateComponents
    if ($Name -eq 'Reset-WindowsUpdateComponents') {
        Write-Host ""
        Write-Host "Reset-WindowsUpdateComponents" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Test-PathAs
    if ($Name -eq 'Test-PathAs') {
        Write-Host ""
        Write-Host "Test-PathAs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemSnapshot
    if ($Name -eq 'Get-SystemSnapshot') {
        Write-Host ""
        Write-Host "Get-SystemSnapshot" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Search-User
    if ($Name -eq 'Search-User') {
        Write-Host ""
        Write-Host "Search-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Disable-User
    if ($Name -eq 'Disable-User') {
        Write-Host ""
        Write-Host "Disable-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    #Remove-Printers
    if ($Name -eq 'Remove-Printers') {
        Write-Host ""
        Write-Host "Remove-Printers" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-DomainAdminCred
    if ($Name -eq 'Initialize-DomainAdminCred') {
        Write-Host ""
        Write-Host "Initialize-DomainAdminCred" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-DomainAdminCredential
    if ($Name -eq 'Get-DomainAdminCredential') {
        Write-Host ""
        Write-Host "Get-DomainAdminCredential" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Enable-NetFx3
    if ($Name -eq 'Enable-NetFx3') {
        Write-Host ""
        Write-Host "Enable-NetFx3" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-TTWordList
    if ($Name -eq 'Initialize-TTWordList') {
        Write-Host ""
        Write-Host "Initialize-TTWordList" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemUptime
    if ($Name -eq 'Get-SystemUptime') {
        Write-Host ""
        Write-Host "Get-SystemUptime" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-AutodiscoverXmlInteractive
    if ($Name -eq 'Get-AutodiscoverXmlInteractive') {
        Write-Host ""
        Write-Host "Get-AutodiscoverXmlInteractive" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-PDQDiagLocalElevated
    if ($Name -eq 'Start-PDQDiagLocalElevated') {
        Write-Host ""
        Write-Host "Start-PDQDiagLocalElevated" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-PDQDiagLogs
    if ($Name -eq 'Get-PDQDiagLogs') {
        Write-Host ""
        Write-Host "Get-PDQDiagLogs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-LocalLLM
    if ($Name -eq 'Invoke-LocalLLM') {
        Write-Host ""
        Write-Host "Invoke-LocalLLM" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }
    
    # Invoke-CodeAssistant
    if ($Name -eq 'Invoke-CodeAssistant') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistant" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-CodeAssistantWrapper
    if ($Name -eq 'Invoke-CodeAssistantWrapper') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistantWrapper" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-CodeAssistantFolder
    if ($Name -eq 'Invoke-CodeAssistantFolder') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistantFolder" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Watch-ISPConnection
    if ($Name -eq 'Watch-ISPConnection') {
        Write-Host ""
        Write-Host "Watch-ISPConnection" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBSuk0R89W7pbSu
# dnAjIIUwvUq/uL21g+J6uoTR8uxEtKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDcR47k5/ke
# G0CFCaV1iXil7uf85CyZS+dy5YU2k/nxATANBgkqhkiG9w0BAQEFAASCAgA7erhL
# AdxnYMXwf7YZVx3xvBlcuKC1KDv6RzrZPqJ0DzXKGJrIGfoaceokxUPqMWPOitEu
# q+U/zgcj+50N01Cws5PiV1tW06caDMy45RcElYgq5aTxFyM7xuNp9sD+rGgebAcF
# 93S4lZKXA6V+QNIpUaTewAR2gy40oSsl6lnzv/u1OU/kuUYUKGjdwuBkaaU+ONI/
# zMJvwWwQxIl6wqriYYQ0h9H8gBtZEfATSLFhYSWutRXSSvU8zIgJRR7+ypaqnGI/
# TFS0jqCbZoSjA8EDL/TM2nGjPfyCV9A90IIWgVBpcvkRk8SnJ7SOPZU39VIYb+9y
# NU2MyAEAYrxJC324qFtHssYXWm3qvnm9XhyibZnxqBZksNC64V2RyAFyQOWd86Lk
# 6ZyotCzOJV0AiSfjkPxc7N+jDZhcoiExLZ514knjfdb11Yjia0hS5J/5pTWXGgMA
# RToP/nwuKZqzMCX1FhkPlrnKVvQtjiqC06vaBRFzyTs9Ko0J7gaEf2oTL8zDRdDW
# rrlC91wCHfo30qA4KQjC4M8rYJYGcKXUxrsdQv2UsNRk7Oo36lQUvbViJhJwA3BJ
# L+8e9z1w2qSIpqLWjKcBs+jeuxiNye594sfoZ2OM8sLI0wFkJrd0Id8Sdwy3yR8F
# 3JCYhK3aPww29qaPqfwUwxXNJsLwBUcc6uv4caGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTAyMDIxMzRaMC8GCSqGSIb3DQEJBDEiBCBYxHJ7jRhQks1Rm1ED
# tB435pEezQnNonTrR0phI62WmTANBgkqhkiG9w0BAQEFAASCAgBREdNItRujg5XF
# 7+bQT4vZGUiCVuKl8TmfPA9n3odr8Ve71yMSz1Bp8K04N3JI+PVVUtkmCKUomTWm
# o7alFCNc5klYrxcil2KLXAD7mW86DAF1SQI9adhzJBbZ1QUjSTxYW7N23k9PCtMs
# qODjzfL4tpuwk2A5EngWvZwOeSCcbNO1py4hwzfhhHPbXUt7qpvOS3kJ2v19+H0K
# qrlcSBqnp87zVaVbNPpQDoQZJOc0QQatyKozhnac9iEwTcwSZdUcrbZ1Ui7BsrG+
# Wi1VOGliKprZ0tlty6HF1dM6VK4GTewvraVyDY++uMTRkL7KSpcryPBoPOPsa3Bh
# dbxxKZB7auOXp10GTLv0Xz13Y4E3BO5OD9xHzO1A+ESpIITZxfqj+FVsxjUp0q2v
# ZB0oMEqt8JVfGJszSzUPw+8UnuOzRmOwX34c9maG7NSkth+NkMJXNiAmff/AI1mL
# 74ZiwTQ4H3DxhjzPYkX3YAB1aS0GZTqGQY/lNTWWJ3YthCnd3yBxQ6vMxAm3WWY6
# eKPzwBpurleKgEEbvr+NV2pCyMlm4mrfFLrAvpsulNuVwNG6r4zekquFipFBu5Nn
# v7kfiZHZkLtq9mTwYO3MBdG3M0dt7G3b3Q9XEKjP+tb8hmvnxgQT+8GMgmIQe0j9
# hZamB0U9kTmV6nmzlWpwWGMOJDJzVw==
# SIG # End signature block
