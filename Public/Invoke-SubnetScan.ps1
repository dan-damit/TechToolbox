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
    .EXAMPLE
        Invoke-SubnetScan -CIDR "192.168.1.0/24"
    .EXAMPLE
        Invoke-SubnetScan -CIDR "10.0.0.0/16" -ComputerName "RemoteHost"
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
    $cfg = Get-TechToolboxConfig
    $scanCfg = $cfg.settings.subnetScan

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