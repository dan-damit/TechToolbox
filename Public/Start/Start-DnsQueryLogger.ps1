
function Start-DnsQueryLogger {
    <#
    .SYNOPSIS
        Starts real-time DNS query logging using the Windows DNS debug log.
    #>
    [CmdletBinding()]
    param()

    # Load config
    $cfg = $script:TechToolboxConfig
    $dnsCfg = $cfg["settings"]["dnsLogging"]

    if (-not $dnsCfg["enabled"]) {
        Write-Log -Level Warn -Message "DNS logging disabled in config.json"
        return
    }

    $logDir = $dnsCfg["logPath"]
    $parseMode = $dnsCfg["parseMode"]

    # Ensure directory exists
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    Write-Log -Level Info -Message "Starting DNS query logger. Output: $dnsLog"

    # Call private worker
    Start-TTDnsQueryLogger -OutputPath $dnsLog
}