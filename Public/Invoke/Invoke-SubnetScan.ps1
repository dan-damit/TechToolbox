function Invoke-SubnetScan {
    <#
    .SYNOPSIS
        Scans a subnet for active hosts and returns details to CSV.
    .DESCRIPTION
        This function orchestrates a subnet scan, either locally or on a
        remote computer, based on the provided parameters. It supports options
        for port scanning, DNS name resolution, HTTP banner grabbing, and CSV
        export of results. The actual scanning logic is handled by the
        Invoke-SubnetScanLocal function.
    .PARAMETER CIDR
        The subnet to scan in CIDR notation (e.g.,
    .PARAMETER ComputerName
        The name of the remote computer to run the scan on. If not provided,
        the scan runs locally.
    .PARAMETER Port
        The port to check for HTTP banners. Default is defined in config.
    .PARAMETER ResolveNames
        Switch to enable DNS name resolution for active hosts. Default is
        defined in config.
    .PARAMETER HttpBanner
        Switch to enable HTTP banner grabbing. Default is defined in config.
    .PARAMETER ExportCsv
        Switch to enable exporting results to a CSV file. Default is defined
        in config.
    .PARAMETER LocalOnly
        Switch to force local execution of the scan, even if ComputerName is
        provided. Default is false.
    .INPUTS
        None. You cannot pipe objects to Invoke-SubnetScan.
    .OUTPUTS
        [pscustomobject] entries summarizing scan results per host.
    .EXAMPLE
        Invoke-SubnetScan -CIDR "192.168.1.0/24"
    .EXAMPLE
        Invoke-SubnetScan -CIDR "10.0.0.0/16" -ComputerName "RemoteHost"
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        [string]$ComputerName,

        [int]$Port,

        [switch]$ResolveNames,
        [switch]$HttpBanner,
        [switch]$ExportCsv,
        [switch]$LocalOnly
    )

    # Load config
    $scanCfg = $cfg["settings"]["subnetScan"]

    # Apply defaults
    if (-not $Port) { $Port = $scanCfg.defaultPort }
    if (-not $ResolveNames) { $ResolveNames = $scanCfg.resolveNames }
    if (-not $HttpBanner) { $HttpBanner = $scanCfg.httpBanner }
    if (-not $ExportCsv) { $ExportCsv = $scanCfg.exportCsv }

    Write-Log -Level Info -Message "Starting subnet scan for $CIDR"

    # Determine execution mode
    $runLocal = $LocalOnly -or (-not $ComputerName)

    if ($runLocal) {
        Write-Log -Level Info -Message "Executing subnet scan locally."
        return Invoke-SubnetScanLocal -CIDR $CIDR -Port $Port -ResolveNames:$ResolveNames -HttpBanner:$HttpBanner -ExportCsv:$ExportCsv
    }

    # Remote execution
    Write-Log -Level Info -Message "Executing subnet scan on remote host: $ComputerName"

    $creds = $null
    if ($cfg.settings.defaults.promptForCredentials) {
        $creds = Get-Credential -Message "Enter credentials for $ComputerName"
    }

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $creds
        Write-Log -Level Ok -Message "Connected to $ComputerName."
    }
    catch {
        Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
        return
    }

    try {
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($CIDR, $Port, $ResolveNames, $HttpBanner, $scanCfg)

            # -------------------------------
            # INLINE LOCAL SCAN ENGINE BELOW
            # -------------------------------

            function Get-IPsFromCIDR {
                param([string]$CIDR)
                $parts = $CIDR -split '/'
                $baseIP = $parts[0]
                $prefix = [int]$parts[1]

                $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
                [Array]::Reverse($ipBytes)
                $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

                $hostBits = 32 - $prefix
                $numHosts = [math]::Pow(2, $hostBits) - 2
                if ($numHosts -lt 1) { return @() }

                $startIP = $ipInt + 1

                $list = for ($i = 0; $i -lt $numHosts; $i++) {
                    $cur = $startIP + $i
                    $b = [BitConverter]::GetBytes($cur)
                    [Array]::Reverse($b)
                    [System.Net.IPAddress]::Parse(($b -join '.')).ToString()
                }

                return , $list
            }

            function Test-TcpPort {
                param([string]$ip, [int]$port, [int]$timeoutMs)
                try {
                    $client = New-Object System.Net.Sockets.TcpClient
                    $ar = $client.BeginConnect($ip, $port, $null, $null)
                    if (-not $ar.AsyncWaitHandle.WaitOne($timeoutMs)) { $client.Close(); return $false }
                    $client.EndConnect($ar)
                    $client.Close()
                    return $true
                }
                catch { return $false }
            }

            function Get-MacAddress {
                param([string]$ip)
                try {
                    $arp = arp -a | Where-Object { $_ -match $ip }
                    if ($arp -match '([0-9a-f]{2}[-:]){5}[0-9a-f]{2}') {
                        return $matches[0].ToUpper()
                    }
                    return $null
                }
                catch { return $null }
            }

            function Get-ReverseDns {
                param([string]$ip)
                try { (Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop).NameHost } catch { $null }
            }

            function Get-NetbiosName {
                param([string]$ip)
                try {
                    $output = & nbtstat -A $ip 2>$null
                    if ($output) {
                        $line = $output | Select-String "<00>" -First 1
                        if ($line) { return ($line -split '\s+')[0] }
                    }
                    return $null
                }
                catch { return $null }
            }

            function Get-MdnsName {
                param([string]$ip)
                try {
                    $arpEntry = arp -a | Where-Object { $_ -match $ip }
                    if ($arpEntry -and $arpEntry -match '([a-zA-Z0-9\-]+\.local)') {
                        return $matches[1]
                    }

                    $mdnsName = Resolve-DnsName -Name "$ip.in-addr.arpa" -Type PTR -ErrorAction Stop |
                    Where-Object { $_.NameHost -like '*.local' } |
                    Select-Object -ExpandProperty NameHost -First 1

                    return $mdnsName
                }
                catch { return $null }
            }

            function Get-HttpInfo {
                param([string]$ip, [int]$port, [int]$timeoutMs)
                try {
                    $req = [System.Net.WebRequest]::Create("http://$ip`:$port/")
                    $req.Timeout = $timeoutMs
                    $req.Method = "HEAD"
                    $resp = $req.GetResponse()
                    $headers = @{}
                    $resp.Headers | ForEach-Object { $headers[$_.Key] = $_.Value }
                    $resp.Close()
                    return $headers
                }
                catch { return $null }
            }

            # Begin scan
            $ips = Get-IPsFromCIDR $CIDR
            $results = [System.Collections.Generic.List[PSObject]]::new()

            $ping = New-Object System.Net.NetworkInformation.Ping

            $avgHostMs = 0.0
            $current = 0
            $total = $ips.Count
            $online = 0

            foreach ($ip in $ips) {

                $hostSw = [System.Diagnostics.Stopwatch]::StartNew()

                $result = [PSCustomObject]@{
                    IP         = $ip
                    Responded  = $false
                    RTTms      = $null
                    MacAddress = $null
                    PTR        = $null
                    NetBIOS    = $null
                    Mdns       = $null
                    PortOpen   = $false
                    ServerHdr  = $null
                    Timestamp  = (Get-Date)
                }

                try {
                    $reply = $ping.Send($ip, $scanCfg.pingTimeoutMs)

                    if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {

                        $result.Responded = $true
                        $result.RTTms = $reply.RoundtripTime
                        $online++

                        try { $result.MacAddress = Get-MacAddress $ip } catch {}

                        if ($ResolveNames) {
                            try { $result.PTR = Get-ReverseDns $ip } catch {}
                            if (-not $result.PTR) { try { $result.NetBIOS = Get-NetbiosName $ip } catch {} }
                            if (-not $result.PTR -and -not $result.NetBIOS) { try { $result.Mdns = Get-MdnsName $ip } catch {} }
                        }

                        try { $result.PortOpen = Test-TcpPort $ip $Port $scanCfg.tcpTimeoutMs } catch {}

                        if ($HttpBanner -and $result.PortOpen) {
                            try {
                                $hdrs = Get-HttpInfo $ip $Port $scanCfg.httpTimeoutMs
                                if ($hdrs -and $hdrs['Server']) { $result.ServerHdr = $hdrs['Server'] }
                            }
                            catch {}
                        }
                    }
                }
                catch {}

                $hostSw.Stop()
                $results.Add($result)
            }

            $ping.Dispose()
            return $results

        } -ArgumentList $CIDR, $Port, $ResolveNames, $HttpBanner, $scanCfg
    }
    catch {
        Write-Log -Level Error -Message "Remote scan failed: $($_.Exception.Message)"
        return
    }
    finally {
        Remove-PSSession $session
    }

    Write-Log -Level Ok -Message "Remote subnet scan complete."
    return $result
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCArmWU8sSyFEK/4
# F75ClpH89SkZ2/174pxjavle5TGNiaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAGAYqg6IWT
# 7+Y2PmS2Cs4x/TrgHmkkOyj2lrTIAbai7DANBgkqhkiG9w0BAQEFAASCAgDbYfW5
# uZ+Wk9u2xXTcDctvvIbZFD36KXL3uuOG84zOxhVl1dDQ9wlNqR46abyow02z1PHe
# yXPgMUJ3rD1cTNy0bVgYG7ZjGwEXnfQ8U69K3nwAEVg+RNnFcew372vt0tYIyJlW
# 1ssNw0LFLgUJkkH5FTXgrxU24o+k41GHcSmaNiJ69P5JS6efqT5jiQ3Ue/QJAtPE
# OSH+01GlRK547dmR1gzPASpE9ORxOQHre3Yu4vWiYgPy8Uc600coJCoMQ+3r+9Up
# Id8IWTiSLss8Gqr2xjsmSuzxI2kFZ5yQ/l5VBgQ9sMMO60hnSujUf9QeFK1+5uOS
# VJwuTBot/wn1zkON16YrkdsYPG851gIecuQ8dQAocu5kH1+9OjijS4DE0vpcyPbL
# 4Yvw1/ZfT67Qjiilm9gDiYFU/nSzFizwx2mblnG6Q5xnDOyMwwnMkf79juXbz2zh
# mrasQwtYF1wP9ByM1kn/+KSRl4ZGFbf5EnVD766yZZg+nivuHir1TgFESuSxNwK3
# w4y/BgAOpzTXd5zxWiAaEXqvJ/Ojy4m7JEPBkczZImKcStWqPglqFkv9AE0EEqdn
# r+ThKZJt5z0MKnxxNQDdUVA6BAKVGyyy4UM7sjxG2Cl7J1BSZu6MTzpcIy1CRFZy
# OiiSMaBYylmYnYDijcZ5Elefd1N+bgCD/Hw3RqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTIyMjE4MjBaMC8GCSqGSIb3DQEJBDEiBCDCnH5kr9vuqSnvdQvt
# p5QUOhx1sUAMHxlaJUcFQDQl+DANBgkqhkiG9w0BAQEFAASCAgBQVFNtz5IlUQol
# XI1lnJvkJ/zVBW34s08xaw2qN603YJE8WqaF/lhg/GDyFE24OPyUAifortVnzyIy
# 3Vf1Tfcl6qv3dZM19EjoA/2DjTmQPIcv2r/T380FBxynXyrFN8h2j6RMdOLDWPce
# t5sKBEsC+ATVF1FNpTroNfslInYY/AqZinAJWi3s6crhsDrwqHHoWEoBASOqlFsc
# 8X0M/dPwduFVRtbLUAcTabBQpghq5Z6Acp0GzSanlOdSiDvtL4yaF2fNgb66ehwe
# 4oJeMPmj/m8J+rmJ44z1uuReX+0Epvw/UJyxnt/T2Ji5ZrrEgacQ+6nj53QCH899
# ZUi5Lv9IZDxXabZ8+jDycPCRQPhRIT2LUbcGbwj/2HwJlUtQOkt57gRILTzdt9m/
# PJ2S7fUTsJHR+MJANL5vGxITtMixmLTlnSGYXaHcR+7nYD0BXwoKhE8/LI9kjd7c
# jk7uA9Wtbih5gMQZYTVHlAqMMJID++i1104eZejSd8KTLHYw04Qurmi1HceHRYX4
# enPGJc1bRJnNnCC0kMPqL14Q4GGG0p8o//dOZEOOmUDpsY9hnebixlMgG5fwpTb+
# PMz/8QldcFRGomdQYAtKkGzzWtkQszv5QAwN+DPUhHYbaIL3lqpEcNelSVpfEn3T
# EDBmZXGPJsQuPk9AgGf9oIAuBmBNHQ==
# SIG # End signature block
