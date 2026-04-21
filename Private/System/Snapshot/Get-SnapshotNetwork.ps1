function Get-SnapshotNetwork {
    [CmdletBinding()]
    param(
        [switch]$IncludeVirtual,   # include vEthernet, VPN, Docker, etc.
        [switch]$IncludeDown       # include disconnected/administratively down adapters
    )

    <#
.SYNOPSIS
    Collect network adapter and IP configuration (worker-friendly).
.DESCRIPTION
    Uses modern NetAdapter/NetTCPIP cmdlets for reliable data. Returns a list of
    PSCustomObjects, one per relevant adapter, with IPv4/IPv6, DNS, gateway, and
    basics.
#>

    Write-Verbose "Collecting network information..."

    function Get-LinkSpeedMbps {
        param($BitsPerSecond)

        if ($null -eq $BitsPerSecond) { return $null }

        if ($BitsPerSecond -is [ValueType]) {
            # Numeric link speeds are typically reported in bits per second.
            return [math]::Round(([double]$BitsPerSecond / 1mb), 0)
        }

        $text = [string]$BitsPerSecond
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }

        $m = [regex]::Match($text.Trim(), '^(?<value>[0-9]+(?:\.[0-9]+)?)\s*(?<unit>[KMGTP]?)(?:bps)?$', 'IgnoreCase')
        if (-not $m.Success) { return $null }

        $value = [double]$m.Groups['value'].Value
        $scale = switch ($m.Groups['unit'].Value.ToUpperInvariant()) {
            'K' { 1kb }
            'M' { 1mb }
            'G' { 1gb }
            'T' { 1tb }
            'P' { 1pb }
            default { 1 }
        }

        return [math]::Round((($value * $scale) / 1mb), 0)
    }

    function Get-OptionalPropertyValue {
        param(
            [Parameter(Mandatory)]$InputObject,
            [Parameter(Mandatory)][string]$PropertyName
        )

        if ($null -eq $InputObject) { return $null }
        $prop = $InputObject.PSObject.Properties[$PropertyName]
        if ($prop) { return $prop.Value }
        return $null
    }

    try {
        # Base adapter set
        $adapters = Get-NetAdapter -ErrorAction Stop

        # Filter by state unless IncludeDown
        if (-not $IncludeDown) {
            $adapters = $adapters | Where-Object { $_.Status -eq 'Up' }
        }

        # Filter out common virtuals unless IncludeVirtual
        if (-not $IncludeVirtual) {
            $adapters = $adapters | Where-Object {
                $n = $_.Name
                $d = $_.InterfaceDescription
                ($n -notmatch 'vEthernet|Hyper-V|Loopback|isatap|Teredo|Docker|VirtualBox|VMware|Bluetooth|Npcap') -and
                ($d -notmatch 'vEthernet|Hyper-V|Loopback|isatap|Teredo|Docker|VirtualBox|VMware|Bluetooth|Npcap')
            }
        }

        # Gather richer IP config objects in one shot
        $ipConfigs = Get-NetIPConfiguration -All -ErrorAction SilentlyContinue

        # If filtering removed everything, relax constraints so we still emit usable data.
        if (-not $adapters -or @($adapters).Count -eq 0) {
            Write-Verbose "No adapters left after filters; retrying with less restrictive selection."

            if ($ipConfigs) {
                $ifIndexes = @(
                    $ipConfigs |
                    Where-Object { $_.InterfaceIndex -ne $null } |
                    Select-Object -ExpandProperty InterfaceIndex -Unique
                )

                if ($ifIndexes.Count -gt 0) {
                    $adapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
                    Where-Object { $ifIndexes -contains $_.ifIndex }
                }
            }

            if (-not $adapters -or @($adapters).Count -eq 0) {
                $adapters = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue
            }
        }

        $results = New-Object System.Collections.Generic.List[psobject]

        foreach ($nic in $adapters) {
            $cfg = $ipConfigs | Where-Object { $_.InterfaceIndex -eq $nic.ifIndex } | Select-Object -First 1
            $nicName = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'Name'
            $nicDescription = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'InterfaceDescription'
            $nicIfIndex = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'ifIndex'
            $nicMacAddress = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'MacAddress'
            $nicStatus = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'Status'
            $nicLinkSpeed = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'LinkSpeed'
            $nicMtu = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'Mtu'
            $nicVlanId = Get-OptionalPropertyValue -InputObject $nic -PropertyName 'VlanID'
            $cfgIPv4Address = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'IPv4Address'
            $cfgIPv6Address = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'IPv6Address'
            $cfgIPv4Gateway = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'IPv4DefaultGateway'
            $cfgIPv6Gateway = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'IPv6DefaultGateway'
            $cfgDnsServer = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'DnsServer'
            $cfgDnsSuffix = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'DnsSuffix'
            $cfgDhcpEnabled = Get-OptionalPropertyValue -InputObject $cfg -PropertyName 'DhcpEnabled'

            # IPv4 / IPv6 addresses with prefix lengths
            $ipv4 = @()
            $ipv6 = @()
            if ($cfgIPv4Address) {
                $ipv4 = $cfgIPv4Address | ForEach-Object {
                    [pscustomobject]@{
                        Address      = $_.IPAddress
                        PrefixLength = $_.PrefixLength
                    }
                }
            }
            if ($cfgIPv6Address) {
                $ipv6 = $cfgIPv6Address | ForEach-Object {
                    [pscustomobject]@{
                        Address      = $_.IPAddress
                        PrefixLength = $_.PrefixLength
                    }
                }
            }

            # Gateways (IPv4/IPv6)
            $gateways = @()
            if ($cfgIPv4Gateway) {
                $gateways += [pscustomobject]@{ Address = $cfgIPv4Gateway.NextHop; AddressFamily = 'IPv4' }
            }
            if ($cfgIPv6Gateway) {
                $gateways += [pscustomobject]@{ Address = $cfgIPv6Gateway.NextHop; AddressFamily = 'IPv6' }
            }

            # DNS servers and suffix
            $dnsServers = @()
            if ($cfgDnsServer) {
                $dnsServers = $cfgDnsServer.ServerAddresses
            }
            $dnsSuffix = $cfgDnsSuffix

            # Profile (Domain/Private/Public) if available
            $netProfile = $null
            try {
                $profile = Get-NetConnectionProfile -InterfaceIndex $nicIfIndex -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($profile) { $netProfile = $profile.NetworkCategory }
            }
            catch { }

            # Compose object
            $results.Add([pscustomobject]@{
                    InterfaceAlias       = $nicName
                    InterfaceDescription = $nicDescription
                    InterfaceIndex       = $nicIfIndex
                    MACAddress           = $nicMacAddress
                    Status               = $nicStatus                 # Up/Down/Disabled
                    LinkSpeedMbps        = Get-LinkSpeedMbps $nicLinkSpeed
                    MTU                  = $nicMtu
                    VlanID               = $nicVlanId
                    DHCPEnabled          = if ($null -ne $cfgDhcpEnabled) { [bool]$cfgDhcpEnabled } else { $null }
                    DNSSuffix            = $dnsSuffix
                    DNSServers           = $dnsServers                 # array
                    IPv4Addresses        = $ipv4                       # array of {Address, PrefixLength}
                    IPv6Addresses        = $ipv6                       # array of {Address, PrefixLength}
                    Gateways             = $gateways                   # array of {Address, AddressFamily}
                    NetworkProfile       = $netProfile                 # Domain/Private/Public
                })
        }

        # Fallback for hosts where NetAdapter/NetTCPIP data is unavailable or filtered out.
        if ($results.Count -eq 0) {
            Write-Verbose "NetAdapter pipeline returned no network rows; falling back to CIM IPEnabled adapters."
            $cimNics = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPEnabled -and $_.IPAddress }

            foreach ($c in $cimNics) {
                $ipv4 = @()
                $ipv6 = @()
                foreach ($ip in @($c.IPAddress)) {
                    if ($ip -match ':') {
                        $ipv6 += [pscustomobject]@{ Address = $ip; PrefixLength = $null }
                    }
                    else {
                        $ipv4 += [pscustomobject]@{ Address = $ip; PrefixLength = $null }
                    }
                }

                $gateways = @()
                foreach ($gw in @($c.DefaultIPGateway)) {
                    if ([string]::IsNullOrWhiteSpace([string]$gw)) { continue }
                    $gateways += [pscustomobject]@{
                        Address = $gw
                        AddressFamily = if ($gw -match ':') { 'IPv6' } else { 'IPv4' }
                    }
                }

                $results.Add([pscustomobject]@{
                        InterfaceAlias       = $c.Description
                        InterfaceDescription = $c.Description
                        InterfaceIndex       = $c.InterfaceIndex
                        MACAddress           = $c.MACAddress
                        Status               = $null
                        LinkSpeedMbps        = $null
                        MTU                  = $null
                        VlanID               = $null
                        DHCPEnabled          = $c.DHCPEnabled
                        DNSSuffix            = $c.DNSDomain
                        DNSServers           = @($c.DNSServerSearchOrder)
                        IPv4Addresses        = $ipv4
                        IPv6Addresses        = $ipv6
                        Gateways             = $gateways
                        NetworkProfile       = $null
                    })
            }
        }

        Write-Verbose ("Network information collected for {0} adapter(s)." -f $results.Count)
        return $results
    }
    catch {
        Write-Verbose ("Get-SnapshotNetwork: {0}" -f $_.Exception.Message)
        return @()
    }
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBlB18DYMnwX6LO
# 32rhwvUQtmEZSk918lz9s3c9+fKLEKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDBnp71Loo8
# JqyA3W4qslmw0yA0wCFUzA/gJ523Sj970TANBgkqhkiG9w0BAQEFAASCAgDLNEJy
# Tj4QbevkphsPWpOveEaprCIodGotckcuLwXxKYXSkXkUWqMN1/+5qv/nSDUF0vMm
# 8srL3zmQ74RZ5uvB5hCQWp9Ftqe5VCfR43KkiRl6KjFOSHyaiKqsNKEzUmSCISbK
# 6/JvzIYEiwv311CDUYLoiEfi4EJX4Ps7+riq7ksG4aADukdWJZxsTZGqCRlVXPKu
# sZwe49JauRlZO9y2c1+MBnuse6YmCbt7nspY3HgCEq3O6dvbwK/ZbRFSM6DSlKrB
# rsC2cG2f3eiFQLy3/fBM7Z2KcdohctH4rkdL4qeCI3WX9lPW5l8JheEm3Tt3pfqP
# 0axsSBPO6EbyDnfdZgCXnjw3JFXjL4WhllvZZWdiiVSuUdh4tSPPc5kvsgBT/Poy
# MIQQCIedQEZ8rfKs6e06RCQ5TO+NxOX560Msfkw574G5h7N+WSTinHdrmzoP4e4W
# g7/GJm1m1zh3PV+0uD50fVxYxt8vQzhup2md75M1sUGK/zeb2PBKJ9u3gllFLtgm
# SSv0vV/euqQLMJl48SdQvKb17VEd++a8B+IPg3ePmUddo+efrvzD2xax5/FLApO3
# p4WcaedM9X5fywyiS1FugmKec5N34gVIa7Gij19M5VJ+JcCv4EPFz3KmKWhz1ADG
# 44aXEtpShYs2uHRNmf5WteoydjZei2L0TKeNjaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MjExNjIzNDVaMC8GCSqGSIb3DQEJBDEiBCCMkkqP5idNtTGW/nK8
# j1kF1mSLebL0TTyr0vi0A8v8OzANBgkqhkiG9w0BAQEFAASCAgA1C1ht4mEIT58H
# FEmhhLrI6UFSnUaZBmEEFHOVhtqS3YQt6O4VaEsH8kwJokw8M9S8Q5RZqEvXST66
# HevPMHh6RpmoC6bkYPZoovlq5S5n6jKoXmK+c5W+oztCG/MrR+RpUPCIeP3mY4Pz
# +nvcwCPhZV8FUcBJcYaDV4avbYtL/DXUrkw64sYsvq9fDYWaTNJUPyKlUBJl7Y1b
# psu6FzTy4SeXiSb+4j1ZVxpIojrEbIkppHhIqgPOtp3IGLcJZHZ3tWeSpFqVjIP+
# BfoVxCo9WP69n26j9Pij0isPqxV8tGntMaYpJgnxIRF2SmxEK21+A8UFE0YaOO6Z
# lPHY9CaVVCCgDQi5sIUaSHBaPO0U4wn2eP69mLnh5gfX+xzB4TQ/KUT8pXWLSSvI
# 793UljoTA8cT/BlWJ8R/LoBu4717YpYIkpL8zre3DiV2HhEiM+ak1bDZ4kTOe7vS
# Z6TWBdYWsqUyhWIgU0UsYKKHZ621tW4gvv/a0B5e5yoqHcm6exxy+DTO8IciQVEN
# i/BavbOmYShdfgalNKWnx07A84MBRfGI6EDgP3k56jNsN4wvFcy7p+t4i0IZyWWK
# 3NSi6HfOYFkwDeuaDbTeFZS0re6zXLeDV7Sx+bCvI4qkl1RgLDDNPc2fHYgkOouK
# G+V87j0qrBEk5CAIPUpNaCge3Zz5Iw==
# SIG # End signature block
