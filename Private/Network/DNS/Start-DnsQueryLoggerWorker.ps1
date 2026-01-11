
function Start-DnsQueryLoggerWorker {
    <#
    .SYNOPSIS
        Worker function to start real-time DNS query logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    # Load config
    $cfg = $script:TechToolboxConfig
    $dnsCfg = $cfg["settings"]["dnsLogging"]
    if ($dnsCfg["autoEnableDiagnostics"]) {
        Set-DnsServerDiagnostics -QueryLogging $true
    }

    # Ensure DNS logging is enabled
    try {
        Set-DnsServerDiagnostics -QueryLogging $true -ErrorAction Stop
        Write-Log -Level Ok -Message "DNS query logging enabled."
    }
    catch {
        Write-Log -Level Error -Message "Failed to enable DNS query logging: $($_.Exception.Message)"
        return
    }

    # Get DNS debug log path
    $diag = Get-DnsServerDiagnostics
    $dnsDebugPath = $diag.LogFilePath

    if (-not (Test-Path $dnsDebugPath)) {
        Write-Log -Level Error -Message "DNS debug log not found at $dnsDebugPath"
        return
    }

    Write-Log -Level Info -Message "Watching DNS debug log: $dnsDebugPath"

    # Tail the log in real time
    Get-Content -Path $dnsDebugPath -Wait -Tail 0 |
    ForEach-Object {
        $line = $_

        # Skip empty lines
        if ([string]::IsNullOrWhiteSpace($line)) { return }

        # Parse DNS query lines (simple example)
        if ($line -match 'Query for (.+?) from (\d+\.\d+\.\d+\.\d+)') {
            $record = @{
                Timestamp = (Get-Date)
                Query     = $matches[1]
                Client    = $matches[2]
            }

            # Write to output file
            $json = $record | ConvertTo-Json -Compress
            Add-Content -Path $OutputPath -Value $json

            # Console/log output
            Write-Log -Level Info -Message "DNS Query: $($record.Query) from $($record.Client)"
        }
    }
}