<# PSScriptInfo

Author: Dan.Damit (annotated) (https://github.com/dan-damit)
Synchronous CIDR scanner with ETA and smoothed progress banner
Adding reversedns queries for hostname and http header detection

Created: 2025.06.04
Last Modified: 2025.11.10
#>

# Func to build array of IPs
function Get-IPsFromCIDR {
    param([string]$cidr)
    # Split into IPs and prefix
    $parts = $cidr -split '/'
    $baseIP = $parts[0]; $prefix = [int]$parts[1]
    $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
    [Array]::Reverse($ipBytes); $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $hostBits = 32 - $prefix; $numHosts = [math]::Pow(2, $hostBits) - 2
    if ($numHosts -lt 1) { return @() }
    $startIP = $ipInt + 1
    $list = for ($i = 0; $i -lt $numHosts; $i++) {
        $cur = $startIP + $i; $b = [BitConverter]::GetBytes($cur); [Array]::Reverse($b)
        [System.Net.IPAddress]::Parse(($b -join '.')).ToString()
    }
    return , $list
}

# Func to show progress banner with new ETA calculation
function Show-ProgressBanner {
    param(
        [int]$current,
        [int]$total,
        [double]$displayPct,
        [TimeSpan]$eta
    )
    $width = 48
    $percent = [math]::Round($displayPct)
    $filled = [math]::Floor(($percent / 100) * $width)
    $bar = ('#' * $filled).PadRight($width)
    $etaText = if ($eta.TotalSeconds -le 0) { '00:00:00' } else { $eta.ToString("hh\:mm\:ss") }
    Write-Host -NoNewline "`rProgress: [$bar] $percent% ($current/$total) ETA: $etaText" -ForegroundColor Yellow
}

# Func to grab hostname from reverse dns zone
function Get-ReverseDns {
    param([string]$ip)
    try { (Resolve-DnsName -Name $ip -ErrorAction Stop -Type PTR).NameHost } catch { $null }
}

# Func to query NetBIOS name via nbtstat (Windows-only, local subnet)
function Get-NetbiosName {
    param([string]$ip)
    try {
        $output = & nbtstat -A $ip 2>$null
        if ($output) {
            $line = $output | Select-String "<00>" -First 1
            if ($line) {
                # Extract name from line like: "DESKTOP-ABC123 <00> UNIQUE Registered"
                return ($line -split '\s+')[0]
            }
        }
        return $null
    }
    catch {
        return $null
    }
}

# Func to attempt mDNS resolution (e.g., for .local hostnames)
function Get-MdnsName {
    param([string]$ip)
    try {
        # Use ping to get the .local name from ARP cache (if available)
        $arpEntry = arp -a | Where-Object { $_ -match $ip }
        if ($arpEntry -and $arpEntry -match '([a-zA-Z0-9\-]+\.local)') {
            return $matches[1]
        }

        # Fallback: try resolving via mDNS (requires mDNS responder on network)
        $mdnsName = Resolve-DnsName -Name "$ip.in-addr.arpa" -Type PTR -ErrorAction Stop |
        Where-Object { $_.NameHost -like '*.local' } |
        Select-Object -ExpandProperty NameHost -First 1
        return $mdnsName
    }
    catch {
        return $null
    }
}

# Func to get MAC address from ARP cache
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

# Func to see if host has http banner
function Get-HttpInfo {
    param([string]$ip, [int]$port = 80, [int]$timeoutMs = 1000)
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

# Func to test if port 80 is open on the host
function Test-TcpPort {
    param([string]$ip, [int]$port, [int]$timeoutMs = 500)
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

# --------- main flow (with ETA + smoothing) ----------
Write-Host "`nSubnet Scanner 2025 https://github.com/dan-damit/Scripts-and-Snippets/blob/main/PowerShell/PowerShell.IP.Scan.ps1`n" -ForegroundColor Yellow
$cidr = Read-Host "`nEnter CIDR block (e.g., 192.168.1.0/24)"
$ips = Get-IPsFromCIDR $cidr
if ($ips.Count -eq 0) { Write-Host "No hosts to scan for $cidr"; return }

# Tunables
$pingTimeoutMs = 250        # per-host ping timeout
$ewmaAlpha = 0.15       # EWMA alpha for average per-host duration (0..1). Higher = more reactive.
$displayAlpha = 0.10        # smoothing alpha for displayed percent (0..1). Lower = smoother.

$total = $ips.Count
Write-Host "Starting scan of $total IPs..." -ForegroundColor Green

$ping = New-Object System.Net.NetworkInformation.Ping

# state
$current = 0
$online = 0
$avgHostMs = 0.0        # EWMA of host duration in ms (starts at 0)
$displayPct = 0.0       # smoothed displayed percent

# ensure an efficient appendable list exists
if (-not $hostResults) {
    $hostResults = [System.Collections.Generic.List[PSObject]]::new()
}

# Loop through each IP getting the additional info along with IP addr
foreach ($ip in $ips) {
    $hostSw = [System.Diagnostics.Stopwatch]::StartNew()

    # Prepare a minimal result object with defaults
    $result = [PSCustomObject]@{
        IP           = $ip
        Responded    = $false
        RTTms        = $null
        MacAddress   = $null
        PTR          = $null
        NetBIOS      = $null
        Mdns         = $null
        Port80Open   = $false
        ServerHdr    = $null
        Timestamp    = (Get-Date)
    }

    try {
        $reply = $ping.Send($ip, $pingTimeoutMs)
        if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            # mark basic reachability and RTT
            $result.Responded = $true
            $result.RTTms = $reply.RoundtripTime

            # safe, per-probe isolation (errors won't abort the scan)
            try {
                $result.MacAddress = Get-MacAddress $ip
            }
            catch {
                $result.MacAddress = $null
            }
            try { $result.PTR = Get-ReverseDns $ip } catch { $result.PTR = $null }
            try {
                if (-not $result.PTR) {
                    $result.NetBIOS = Get-NetbiosName $ip
                }
            }
            catch {
                $result.NetBIOS = $null
            }
            try {
                if (-not $result.PTR -and -not $result.NetBIOS) {
                    $result.Mdns = Get-MdnsName $ip
                }
            }
            catch {
                $result.Mdns = $null
            }
            try { $result.Port80Open = Test-TcpPort $ip 80 300 } catch { $result.Port80Open = $false }
            if ($result.Port80Open) {
                try {
                    $hdrs = Get-HttpInfo $ip 80 600
                    if ($hdrs -and $hdrs['Server']) { $result.ServerHdr = $hdrs['Server'] }
                }
                catch { $result.ServerHdr = $null }
            }

            $online++    # maintain online counter
        }
    }
    catch {
        # treat as no response; keep moving
    }
    finally {
        $hostSw.Stop()
        $durMs = $hostSw.Elapsed.TotalMilliseconds

        # update EWMA for per-host duration
        if ($avgHostMs -le 0) { $avgHostMs = $durMs } else { $avgHostMs = ($ewmaAlpha * $durMs) + ((1 - $ewmaAlpha) * $avgHostMs) }

        $current++

        # actual percent
        $actualPct = if ($total -gt 0) { ($current / $total) * 100 } else { 100 }

        # smooth the displayed percent toward actual percent
        $displayPct = ($displayAlpha * $actualPct) + ((1 - $displayAlpha) * $displayPct)

        # estimate remaining time using EWMA per-host duration
        $remaining = $total - $current
        $etaMs = [math]::Max(0, $avgHostMs * $remaining)
        $eta = [TimeSpan]::FromMilliseconds($etaMs)

        # update ONLY the banner line
        Show-ProgressBanner $current $total $displayPct $eta -ForegroundColor Yellow

        # store the result object (no console noise)
        $hostResults.Add($result)
    }
}

# ---- finalization: show 100% banner and then output results ----
$displayPct = 100
Show-ProgressBanner $total $total $displayPct ([TimeSpan]::Zero)
$ping.Dispose()
Write-Host "`n`nScan complete!" -ForegroundColor Green
Write-Host "$online hosts responded." -ForegroundColor Yellow

# Print collected results: compact table first
Write-Host "Discovered hosts:" -ForegroundColor DarkYellow
$tableText = $hostResults |
Where-Object { $_.Responded } |
Select-Object IP, RTTms, MacAddress, NetBIOS, PTR, Mdns, Name, Port80Open, ServerHdr |
Format-Table -AutoSize | Out-String

Write-Host $tableText -ForegroundColor Blue

# Export CSV for later analysis
$csvPath = "$env:TEMP\cidr-scan-$($cidr.Replace('/','-'))-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
$hostResults | ForEach-Object {
    $name = if ($_.PTR) { $_.PTR }
    elseif ($_.NetBIOS) { $_.NetBIOS }
    elseif ($_.Mdns) { $_.Mdns }
    else { $null }
    $_ | Add-Member -NotePropertyName Name -NotePropertyValue $name -Force
}
Write-Host "Saved CSV: $csvPath" -ForegroundColor Yellow
Pause
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1u9zMxXLrC0iI
# ib2Q6ox1rdoMC+kOPmsxm3wVd8l/P6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCxMTP9VtJE
# Uf+Ud+5wr3B5/FsE505BWjYU7WeaQkElkzANBgkqhkiG9w0BAQEFAASCAgDczKcf
# fk33y8SkKJR6uPbtNAHiwUeToNmLrBi8jZvYy2YssfPBIrX4gVYWRJxkfSBjg2H3
# gg9OgfvOLDiCvntltmDeosdMP9onAyLBE6TgxVbgsO81AVXFz1hOcOxR0QWbvQD6
# wj4GdXtKLWXLQcEfefIiVbzE4CPIpkba1iX+NrUU8cTHV618RtaghqGlreSVfGiv
# GZYLtvb62he8KbbxhgUKJTCabrefxCPJKiH3fq1PSd/PevbyCKzvONrrp0zhVaBG
# hsYa3Or/eYT5Y94FD0ts/yg4fd9/jYhwrtcjZbLlpAL3BuZzLwtP/Xis3AYXstPy
# t51rM2Jr3fHFF/oCkaZkfxZobIml4E2gXTUp+b7eXwCe5gu+beqFY0TLgjrkACYS
# Rv/QmWogVbgG3RYJ+2lGODVMnbOPd261AJ2gdfS7ceK0g41CH65fusSXcvnJewAp
# md8zPU8DOZdeqDnNwknGc2VzLND/K5vcVsluO2jLByd/w+XhvGkG0sDehmLm7i+y
# HfVX3HwKAuBgipB/PFHprd6mK6slR7un/Do8ThOunluS0xkwJdL7u6dTjpecihJ1
# Xt4fEB3vylsAQEt1xWBHIRIGNeyJO3aGoI1l++kc8l5Vki0X6BaZSzIQ1GGxeV+u
# c2orhvvlNMnjqCQAdhLVClkvru90L83MXVK1kqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNTEyMjYxODU0NThaMC8GCSqGSIb3DQEJBDEiBCB93oZ0Fm+zXHpDbJck
# i0BmvHMgCVKIzOiAiLBqNwV0eTANBgkqhkiG9w0BAQEFAASCAgAWPnaTXu09BxEH
# dsmDYPSJf5ffm5zfGENMJp1RY4NbQXXKOW3g6wny6OJ/KxmR1PVTcGsuJ7L3xKbQ
# lwk+RvSVIPwli9cVv5th1ZBIAjaYHQ7uVXoBlSw4R3sfNFLNskgL0JFgNYpAnbOE
# 2idXGhEKEMO40L2846ReDhkKuRsu60ATL88GhcX3FYjlJtHue/feJhZx3NXpnRjB
# Kl2Q6hnAerC79T7a6cvhZqVao8Qhx/or4Fhd+zY3QO9bJG291umtbhQ1wQwXfPcK
# P0nZk7CU6wkjf/k3cpI2rIF/PB71PsU7000izunokL9rpvqPFzD83qT30ilsgfi6
# Zku+u4zEdpGX3io/cCti1m1qlSdpymhawhrJoUUdu39RL4PkJnWLQFc1xYPu1/AJ
# om2nBdd60babYFCwaA8EgVR1NlCKRlXbUUJaKOsoTslSIAqqSCTzJPzSXgxevbEh
# rJM0I7GTuBGm6AfXuuURiZkuRk6JaGiRrjosXWa5Dr3FvZI9k/9HBfKfEBxtsNRf
# qEtPiQfSF5SEGOJlVtPPJUbWovX+qRuKGpkTP9FbUEXXMigZor69FQvw1kQb5jc0
# uxw+hxS9xckJpkFUS4OHdkjEAfVVyJnWJ5TI6b6vBDG9BwRjEb6g64FpS5JHjLwa
# InzHXI7DTVmg78duBp9FH24IPvQKlQ==
# SIG # End signature block
