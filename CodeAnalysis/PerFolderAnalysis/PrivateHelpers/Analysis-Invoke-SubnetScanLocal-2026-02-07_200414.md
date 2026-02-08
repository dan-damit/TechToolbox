# Code Analysis Report
Generated: 2/7/2026 8:04:14 PM

## Summary
 The provided PowerShell script, `Invoke-SubnetScanLocal.ps1`, is a function for scanning a given CIDR range to identify responding hosts. Here are some observations and suggestions for improvement:

1. **Commenting**: Add more comments throughout the code to explain what each section does, making it easier for others to understand your code. The existing comments provide a good starting point but could be expanded upon.

2. **Parameter validation**: Consider adding validation checks for parameters to ensure that they meet certain requirements (e.g., valid IP address range, valid port number). This can help prevent unexpected behavior due to invalid input.

3. **Error handling**: The script catches exceptions but doesn't always provide meaningful error messages. Consider refactoring the code to make it more resilient and provide better error messages when things go wrong.

4. **Code Organization**: Break down the function into smaller, more manageable functions for readability. For example, separate the configuration loading, CIDR expansion, and host scanning logic into individual functions.

5. **Performance optimization**: To improve performance, consider implementing parallel processing to scan multiple hosts simultaneously instead of sequentially. You could use PowerShell's `workflow` feature for this. Additionally, you might want to look into caching the results of certain operations (e.g., MAC address lookup) to reduce redundant network requests.

6. **Logging and reporting**: Provide more detailed progress reports and logging information, including the elapsed time, total hosts scanned, and average response time. This can help users understand the status of the scan and troubleshoot any issues that might arise.

7. **Output formatting**: Format the output as a table or custom object to make it easier to read and analyze. Consider using PowerShell's built-in formatting capabilities (e.g., `Format-Table`, `Format-List`) or creating your own custom formatters for more control over the output appearance.

8. **Modularity**: Split the script into multiple files (e.g., separate modules) to improve maintainability and reusability of the code. This can also help organize related functionality and make it easier for other users to find what they need.

9. **Documentation**: Write detailed documentation explaining how to use your script, including examples, usage scenarios, and configuration options. This will help others understand how to leverage your tool effectively.

10. **Code formatting**: Follow PowerShell coding standards and conventions for better readability, maintainability, and consistency with other PowerShell codebases. Consider using a tool like PSScriptAnalyzer (https://github.com/PowerShell/PSScriptAnalyzer) to automatically check your code against these guidelines.

By addressing these suggestions, you can make the script more functional, readable, and performant for users.

## Source Code
```powershell

function Invoke-SubnetScanLocal {
    <#
.SYNOPSIS
    Scanning engine used by Invoke-SubnetScan.ps1.
.DESCRIPTION
    Pings each host in a CIDR, (optionally) resolves names, tests port,
    grabs HTTP banner; returns *only responding hosts*. Export is off by default
    so orchestrator can export consistently to settings.subnetScan.exportDir.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$CIDR,
        [int]$Port,
        [switch]$ResolveNames,
        [switch]$HttpBanner,
        [switch]$ExportCsv
    )

    Set-StrictMode -Version Latest
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'

    try {
        # --- CONFIG ---
        $cfg = Get-TechToolboxConfig -Verbose
        if (-not $cfg) { throw "TechToolbox config is null/empty. Ensure Config\config.json exists and is valid JSON." }
        $scanCfg = $cfg['settings']?['subnetScan']
        if (-not $scanCfg) { throw "Config missing 'settings.subnetScan'." }

        # Defaults (only if not passed)
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $scanCfg['defaultPort'] ?? 80 }
        if (-not $PSBoundParameters.ContainsKey('ResolveNames')) { $ResolveNames = [bool]($scanCfg['resolveNames'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('HttpBanner')) { $HttpBanner = [bool]($scanCfg['httpBanner'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('ExportCsv')) { $ExportCsv = [bool]($scanCfg['exportCsv'] ?? $false) }

        # Timeouts / smoothing
        $pingTimeoutMs = $scanCfg['pingTimeoutMs'] ?? 1000
        $tcpTimeoutMs = $scanCfg['tcpTimeoutMs'] ?? 1000
        $httpTimeoutMs = $scanCfg['httpTimeoutMs'] ?? 1500
        $ewmaAlpha = $scanCfg['ewmaAlpha'] ?? 0.30
        $displayAlpha = $scanCfg['displayAlpha'] ?? 0.50

        # Expand CIDR → IP list
        $ips = Get-IPsFromCIDR -CIDR $CIDR
        if (-not $ips -or $ips.Count -eq 0) {
            Write-Log -Level Warn -Message "No hosts found for CIDR $CIDR"
            return @()
        }

        Write-Log -Level Info -Message "Scanning $($ips.Count) hosts..."

        $results = [System.Collections.Generic.List[psobject]]::new()

        # Progress telemetry
        $avgHostMs = 0.0
        $displayPct = 0.0
        $current = 0
        $total = $ips.Count
        $online = 0

        $ping = [System.Net.NetworkInformation.Ping]::new()

        foreach ($ip in $ips) {
            $hostSw = [System.Diagnostics.Stopwatch]::StartNew()

            $result = [pscustomobject]@{
                IP         = $ip
                Responded  = $false
                RTTms      = $null
                MacAddress = $null
                PTR        = $null
                NetBIOS    = $null
                Mdns       = $null
                PortOpen   = $false
                ServerHdr  = $null
                Timestamp  = Get-Date
            }

            try {
                $reply = $ping.Send($ip, $pingTimeoutMs)

                if ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                    $result.Responded = $true
                    $result.RTTms = $reply.RoundtripTime
                    $online++

                    try { $result.MacAddress = Get-MacAddress -ip $ip } catch {}

                    if ($ResolveNames) {
                        try { $result.PTR = Get-ReverseDns -ip $ip } catch {}
                        if (-not $result.PTR) { try { $result.NetBIOS = Get-NetbiosName -ip $ip } catch {} }
                        if (-not $result.PTR -and -not $result.NetBIOS) { try { $result.Mdns = Get-MdnsName -ip $ip } catch {} }
                    }

                    try { $result.PortOpen = Test-TcpPort -ip $ip -port $Port -timeoutMs $tcpTimeoutMs } catch {}

                    if ($HttpBanner -and $result.PortOpen) {
                        try {
                            $hdrs = Get-HttpInfo -ip $ip -port $Port -timeoutMs $httpTimeoutMs
                            if ($hdrs -and $hdrs['Server']) { $result.ServerHdr = $hdrs['Server'] }
                        }
                        catch {}
                    }

                    # Add only responding hosts
                    $results.Add($result)
                }
            }
            catch {
                # ignore host-level exceptions; treat as no response
            }
            finally {
                $hostSw.Stop()
                $durMs = $hostSw.Elapsed.TotalMilliseconds

                if ($avgHostMs -le 0) { $avgHostMs = $durMs }
                else { $avgHostMs = ($ewmaAlpha * $durMs) + ((1 - $ewmaAlpha) * $avgHostMs) }

                $current++
                $actualPct = ($current / $total) * 100
                $displayPct = ($displayAlpha * $actualPct) + ((1 - $displayAlpha) * $displayPct)

                $remaining = $total - $current
                $etaMs = [math]::Max(0, $avgHostMs * $remaining)
                $eta = [TimeSpan]::FromMilliseconds($etaMs)

                Show-ProgressBanner -current $current -total $total -displayPct $displayPct -eta $eta
            }
        }

        $ping.Dispose()
        Write-Log -Level Ok -Message "Local subnet scan complete. $online hosts responded."

        # Remote-side export when explicitly requested (used by ExportTarget=Remote)
        if ($ExportCsv -and $results.Count -gt 0) {
            try {
                $exportDir = $scanCfg['exportDir']
                if (-not $exportDir) { throw "Config 'settings.subnetScan.exportDir' is missing." }
                if (-not (Test-Path -LiteralPath $exportDir)) {
                    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                }
                $cidrSafe = $CIDR -replace '[^\w\-\.]', '_'
                $csvPath = Join-Path $exportDir ("subnet-scan-{0}-{1}.csv" -f $cidrSafe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log -Level Ok -Message "Results exported to $csvPath"
            }
            catch {
                Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
            }
        }
        elseif ($ExportCsv) {
            Write-Log -Level Warn -Message "Export skipped: no responding hosts."
        }

        return $results
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}
[SIGNATURE BLOCK REMOVED]

```
