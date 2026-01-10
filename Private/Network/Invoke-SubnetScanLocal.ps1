
function Invoke-SubnetScanLocal {
    <#
    .SYNOPSIS
        This is the scanning engine for consumption by Invoke-SubnetScan.ps1.
    .DESCRIPTION
        This function performs a subnet scan on the local machine, given a CIDR
        notation. It pings each host in the subnet, optionally resolves hostnames,
        checks for HTTP banners, and can export results to a CSV file.
    .NOTES
        This function is intended to be called internally by Invoke-SubnetScan.ps1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        [int]$Port,

        [switch]$ResolveNames,
        [switch]$HttpBanner,
        [switch]$ExportCsv
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $scanCfg = $cfg.settings.subnetScan

    # Apply defaults
    if (-not $Port) { $Port = $scanCfg.defaultPort }
    if (-not $ResolveNames) { $ResolveNames = $scanCfg.resolveNames }
    if (-not $HttpBanner) { $HttpBanner = $scanCfg.httpBanner }
    if (-not $ExportCsv) { $ExportCsv = $scanCfg.exportCsv }

    Write-Log -Level Info -Message "Local subnet scan starting for $CIDR"

    # Expand CIDR into IP list
    $ips = Get-IPsFromCIDR -CIDR $CIDR
    if (-not $ips -or $ips.Count -eq 0) {
        Write-Log -Level Warn -Message "No hosts found for CIDR $CIDR"
        return @()
    }

    Write-Log -Level Info -Message "Scanning $($ips.Count) hosts..."

    # Prepare results list
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Initialize timing + smoothing state
    $pingTimeoutMs = $scanCfg.pingTimeoutMs
    $ewmaAlpha = $scanCfg.ewmaAlpha
    $displayAlpha = $scanCfg.displayAlpha

    $avgHostMs = 0.0
    $displayPct = 0.0
    $current = 0
    $total = $ips.Count
    $online = 0

    # Create ping object
    $ping = New-Object System.Net.NetworkInformation.Ping

    # --- MAIN SCAN LOOP ---
    foreach ($ip in $ips) {

        $hostSw = [System.Diagnostics.Stopwatch]::StartNew()

        # Prepare result object
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
            # Ping host
            $reply = $ping.Send($ip, $pingTimeoutMs)

            if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {

                $result.Responded = $true
                $result.RTTms = $reply.RoundtripTime
                $online++

                # MAC lookup (local only)
                try { $result.MacAddress = Get-MacAddress -ip $ip } catch {}

                # Name resolution (PTR → NetBIOS → mDNS)
                if ($ResolveNames) {
                    try { $result.PTR = Get-ReverseDns -ip $ip } catch {}

                    if (-not $result.PTR) {
                        try { $result.NetBIOS = Get-NetbiosName -ip $ip } catch {}
                    }

                    if (-not $result.PTR -and -not $result.NetBIOS) {
                        try { $result.Mdns = Get-MdnsName -ip $ip } catch {}
                    }
                }

                # TCP port test
                try { $result.PortOpen = Test-TcpPort -ip $ip -port $Port -timeoutMs $scanCfg.tcpTimeoutMs } catch {}

                # HTTP banner detection
                if ($HttpBanner -and $result.PortOpen) {
                    try {
                        $hdrs = Get-HttpInfo -ip $ip -port $Port -timeoutMs $scanCfg.httpTimeoutMs
                        if ($hdrs -and $hdrs['Server']) {
                            $result.ServerHdr = $hdrs['Server']
                        }
                    }
                    catch {}
                }
            }
        }
        catch {
            # treat as no response
        }
        finally {
            $hostSw.Stop()
            $durMs = $hostSw.Elapsed.TotalMilliseconds

            # EWMA smoothing for per-host duration
            if ($avgHostMs -le 0) {
                $avgHostMs = $durMs
            }
            else {
                $avgHostMs = ($ewmaAlpha * $durMs) + ((1 - $ewmaAlpha) * $avgHostMs)
            }

            $current++

            # Actual percent
            $actualPct = ($current / $total) * 100

            # Smooth displayed percent
            $displayPct = ($displayAlpha * $actualPct) + ((1 - $displayAlpha) * $displayPct)

            # ETA calculation
            $remaining = $total - $current
            $etaMs = [math]::Max(0, $avgHostMs * $remaining)
            $eta = [TimeSpan]::FromMilliseconds($etaMs)

            # Update progress bar
            Show-ProgressBanner -current $current -total $total -displayPct $displayPct -eta $eta

            # Store result
            $results.Add($result)
        }
    }

    # Dispose ping object
    $ping.Dispose()

    Write-Log -Level Ok -Message "Local subnet scan complete. $online hosts responded."

    # Export CSV if requested
    if ($ExportCsv) {
        try {
            $exportDir = $cfg.settings.paths.ExportDirectory
            if (-not (Test-Path $exportDir)) {
                New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
            }

            $csvPath = Join-Path $exportDir ("subnet-scan-$($CIDR.Replace('/','-'))-{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

            $results | Export-Csv -Path $csvPath -NoTypeInformation -Force

            Write-Log -Level Ok -Message "Results exported to $csvPath"
        }
        catch {
            Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
        }
    }

    return $results
}