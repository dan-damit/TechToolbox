function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    .DESCRIPTION
        The Get-ToolboxHelp cmdlet displays help information for TechToolbox
        public commands. It can show an overview of the module, list all
        available commands, or provide detailed help for a specific command.
        Additionally, it can display the effective configuration settings used
        by TechToolbox.
    .PARAMETER Name
        The name of the TechToolbox command to get help for.
    .PARAMETER List
        Switch to list all available TechToolbox commands.
    .PARAMETER ShowEffectiveConfig
        Switch to display the effective configuration settings used by
        TechToolbox.
    .PARAMETER AsJson
        When used with -ShowEffectiveConfig, outputs the configuration in JSON
        format.
    .INPUTS
        None. You cannot pipe objects to Get-ToolboxHelp.
    .OUTPUTS
        None. Output is written to the host.
    .EXAMPLE
        Get-ToolboxHelp -List
        # Lists all available TechToolbox commands.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$List,
        [switch]$ShowEffectiveConfig,
        [switch]$AsJson
    )

    # Load merged runtime config
    $Config = Get-TechToolboxConfig
    
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

    # Show effective configuration
    if ($ShowEffectiveConfig) {
        Write-Host ""
        Write-Host "TechToolbox Effective Configuration" -ForegroundColor Cyan
        Write-Host "----------------------------------------"

        if ($AsJson) {
            $Config | ConvertTo-Json -Depth 10
        }
        else {
            $Config | Format-List
        }

        Write-Host ""
        return
    }

    # List all public functions
    if ($List) {
        Write-Host ""
        Write-Host "TechToolbox Commands" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        Get-Command -Module TechToolbox |
        Where-Object { $_.CommandType -eq 'Function' } |
        Select-Object -ExpandProperty Name |
        Sort-Object |
        ForEach-Object { Write-Host "  $_" }
        Write-Host ""
        return
    }

    # If a specific function was requested
    if ($Name) {
        try {
            Write-Host ""
            Write-Host "Help for: $Name" -ForegroundColor Cyan
            Write-Host "----------------------------------------"
            Get-Help $Name -Full
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
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBo/SGn9zybySD
# bJb4ocGr3ci/VW0j1umCZWmhi75Ur6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBMnUhII/U0
# dYO2EuLNnG1F1uglULwrs+kQI5tdNtJDGDANBgkqhkiG9w0BAQEFAASCAgA2HIT/
# do7oMicqOCpUf8Jiz2Z8YgR+PKXzaT7cdadHehGTKacFp15bDymRBK7DDkrxv8rO
# 1+fGiLH4j4Wl8xEnIoVdjwZK7irzNVkbG7CztpSOUswLkj74tRBiwhMXwXfqdAjW
# v+rP0E0e5jGZbavxFWpg2uYWgZEeNBRdVBhEeY8IjTZen6id5AcPr6JsXycVdFnD
# HEnnVT04uGGjk/+QVLp11gTs5QpImTWJqV7Z5xSSKKx/PYb63FtAf6rF4tJ1T+zJ
# GnBmZcg3xbfdhZlUGr9/2szJgab0pyABFVzI0Lt7SaA+aDW7qP+fny53lpJSwN2Z
# 60wuPnhu33dOEjVmOFTkVOQUPM+bpdCf1pteJHh1tG2hq7INnDj8/JesjkxWY/Qw
# 7OVsnbbcibf+kCzuPhmSmZSNfbhbhE3ddCck9i2raJ5SJ4pMVP3NUJBhImkwWtNO
# 3brrM9Iskj1g/+hUxqPK63h2p7Av2Hv62/17WU6cOZf3Tyt/OroNVT8QaDjpd1K/
# Jxhwnor6zGJCcozNdQ7HzlH/CRPGc5MSuzN9cm1XWvjege/3cwkGWUwYEd9Dnxf0
# D24LAwv94mHTBUJjsiVYKztlofLK3+VkSn0s4X/k4pObNFVv760KQ1jhlIuJDEoF
# MRPeXlgQRPT6QUig4RPpClVsMpe//YyRsCnyUKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTUwNDM0MzFaMC8GCSqGSIb3DQEJBDEiBCA2qmXWtkRnsvpmcrsi
# oiHJk5ziOA5rsVT3x/LXdM8jITANBgkqhkiG9w0BAQEFAASCAgAHah5IIuB7xY7j
# VUyfDq6gcazeHMOdYuECqHhfPlrtcK9kIlGULBmiuD/8hVW79M2GE/WCAi7+89ky
# OOykKAzZSe2KKlHAcakCxzr0RURXeagiTzVMgbj9MbxF21tA0gs0LlVMNVJj2bam
# 4FA35a0ltcvM2nxoXZau4mWvG/xqZkyebur8tLkccnDfqh7IBcn3bJp+Ww4kNpwW
# YlYRfqmHQXay4UK24GGrzb24LlC9XZTXcbJ+ECNhRYXNVnvKYk0Jfi011qpJiNKQ
# JClfoByj6kRQYw6UzL2R4D7261eWsQTSrG7PqJ7t9qWa6qqQCbHOMceJzDz8XoPi
# nJd7nthIJqdFT272xF3Xj7qB9lDmNb9bqJNlyOar/zEqKOTztnf6beOPKl2W9b4f
# gTWhSAcfuxuBI+sUxbqeXgsjq4QIW6IIl4ZqZnutmBmhYk4q8o2LyVrnLs7FV5PU
# eg3a0i82sPB2Z+7u35GvXNJ1sBAI3B2Thd1x7vlkncUIXfoYc+19d2aokkuo5Mpd
# QFBLcS+goCIIRL/3wihFVjvwwGW6Gc0VaMcbfM0wAv7tArqroMpSsmBm861RBFXN
# scBI2G6UxU85T/zzDTcKaTPDysJg4Fn+e40iaDb1d6pL+gzeiS24ZcsrNCdO3ERA
# T9mekn/A5NYNAnYEKDiZUkTKK8rpZA==
# SIG # End signature block
