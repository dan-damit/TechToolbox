function Initialize-Logging {
    if (-not $script:log) {
        $script:log = @{
            enableConsole = $true
            logFile       = $null
        }
    }

    $cfg = $script:TechToolboxConfig
    if (-not $cfg) { return }

    $logDir = $cfg["paths"]["logs"]
    $logFile = $cfg["settings"]["logging"]["logFile"]

    if (-not $logFile -and $logDir) {
        $logFile = Join-Path $logDir ("TechToolbox_{0:yyyyMMdd}.log" -f (Get-Date))
    }

    $script:log['enableConsole'] = $cfg["settings"]["logging"]["enableConsole"]
    $script:log['logFile'] = $logFile
}