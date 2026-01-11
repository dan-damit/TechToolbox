
function Write-Log {
    <#
    .SYNOPSIS
        Centralized logging for TechToolbox (Info/Ok/Warn/Error).
    .DESCRIPTION
        Uses module config (paths, settings.logging) and writes to PowerShell
        streams and (optionally) to a daily log file.
    .PARAMETER Level
        One of: Info, Ok, Warn, Error.
    .PARAMETER Message
        Text to log.
    .EXAMPLE
        Write-Log -Level Info -Message "Starting task."
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Ok', 'Warn', 'Error')]
        [string] $Level,

        [Parameter(Mandatory)]
        [string] $Message
    )

    # --- Load normalized config ---
    $cfg = Get-TechToolboxConfig
    $log = $cfg["settings"]["logging"]
    $paths = $cfg["paths"]

    # --- Level filtering (MinimumLevel from config) ---
    $severityMap = @{
        'Info'  = 1
        'Ok'    = 2
        'Warn'  = 3
        'Error' = 4
    }

    # Default to Info if config is missing/invalid
    $minLevel = $log["minimumLevel"]
    if (-not $severityMap.ContainsKey($minLevel)) { $minLevel = 'Info' }
    if ($severityMap[$Level] -lt $severityMap[$minLevel]) { return }

    # --- Build entry (timestamps optional for file) ---
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = if ($log["includeTimestamps"]) {
        "[{0}] [{1}] {2}" -f $timestamp, $Level.ToUpper(), $Message
    }
    else {
        "[{0}] {1}" -f $Level.ToUpper(), $Message
    }

    # --- Console/Streams ---
    if ($log["enableConsole"]) {
        switch ($Level) {
            'Info' { Write-Information -MessageData $Message -Tags 'TechToolbox', 'Info' }
            'Ok' { Write-Information -MessageData $Message -Tags 'TechToolbox', 'Ok' }
            'Warn' { Write-Warning     -Message $Message }
            'Error' { Write-Error       -Message $Message }
        }
    }

    # --- File logging ---
    if ($log["enableFileLogging"] -and $paths["logs"]) {
        try {
            if (-not (Test-Path -LiteralPath $paths["logs"])) {
                New-Item -ItemType Directory -Path $paths["logs"] -Force | Out-Null
            }

            $fileName = $log["logFileNameFormat"]
            if ([string]::IsNullOrWhiteSpace($fileName)) {
                $fileName = 'TechToolbox_{yyyyMMdd}.log'
            }

            # Honor pattern "TechToolbox_{yyyyMMdd}.log"
            $fileName = $log["logFileNameFormat"] ?? 'TechToolbox_{yyyyMMdd}.log'
            $logFile = Join-Path -Path $paths["logs"] -ChildPath $fileName

            # Reliable append with StreamWriter
            $sw = [System.IO.StreamWriter]::new($logFile, $true)
            try {
                $sw.WriteLine($entry)
            }
            finally {
                $sw.Flush()
                $sw.Dispose()
            }
        }
        catch {
            # Fall back to warning stream if file write fails
            Write-Warning ("Write-Log failed to write to file: {0}" -f $_.Exception.Message)
        }
    }
}
