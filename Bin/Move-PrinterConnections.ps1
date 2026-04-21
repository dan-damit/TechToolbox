[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$OldServer = 'E10-REPORT-1',
    [string]$NewServer = 'PRINTSRV-1'
)

# Per-user log location (best for PDQ "Run as Logged On User")
$LogRoot = Join-Path $env:LOCALAPPDATA 'PrinterMigration'
$LogFile = Join-Path $LogRoot "PrinterMigration-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message)
    if (-not (Test-Path $LogRoot)) { New-Item -Path $LogRoot -ItemType Directory -Force | Out-Null }
    $line = "[{0}] {1}" -f (Get-Date -Format 's'), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Verbose $Message
}

# Guard rail: printer connections are per-user, so SYSTEM won't see them
if ($env:USERNAME -eq 'SYSTEM') {
    Write-Log "Detected SYSTEM context. Network printer connections are per-user. Exiting without changes."
    return
}

Write-Log "Starting printer migration"
Write-Log "User: $env:USERDOMAIN\$env:USERNAME"
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "Old: \\$OldServer\  New: \\$NewServer\"

$oldPrefix = "\\$OldServer\"

# Capture current default printer connection (only used if it's from the old server)
$defaultConn = $null
try {
    $defaultWmi = Get-CimInstance -ClassName Win32_Printer -Filter "Default = TRUE" -ErrorAction Stop
    if ($defaultWmi -and $defaultWmi.Name) {
        $dp = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $defaultWmi.Name }
        $defaultConn = $dp.ConnectionName
        Write-Log "Current default printer: $($defaultWmi.Name) ($defaultConn)"
    }
    else {
        Write-Log "No default printer detected."
    }
}
catch {
    Write-Log "WARNING: Could not read default printer: $($_.Exception.Message)"
}

# ONLY printers connected from \\OldServer\
$oldPrinters = Get-Printer -ErrorAction SilentlyContinue |
Where-Object { $_.ConnectionName -like "$oldPrefix*" }

if (-not $oldPrinters) {
    Write-Log "No printers found from $OldServer. Nothing to do."
    Write-Log "Log file: $LogFile"
    return
}

Write-Log "Found $($oldPrinters.Count) printer(s) connected from $OldServer."

# Decide if we need to restore default printer after migration (only if default was from old server)
$setDefaultTo = $null
if ($defaultConn -like "$oldPrefix*") {
    $defaultShare = $defaultConn -replace "^\\\\$OldServer\\", ""
    $setDefaultTo = "\\$NewServer\$defaultShare"
    Write-Log "Default printer is on old server; will set default to: $setDefaultTo"
}

foreach ($p in $oldPrinters) {
    $oldConn = $p.ConnectionName

    # Extract share name from \\OldServer\Share
    $share = $oldConn -replace "^\\\\$OldServer\\", ""
    $newConn = "\\$NewServer\$share"

    Write-Log "Migrating: $oldConn -> $newConn"

    # Remove ONLY the old connection
    if ($PSCmdlet.ShouldProcess($oldConn, "Remove printer connection")) {
        try {
            Remove-Printer -Name $p.Name -ErrorAction Stop
            Write-Log "Removed: $oldConn"
        }
        catch {
            Write-Log "WARNING: Failed to remove '$oldConn' (Printer Name: '$($p.Name)'): $($_.Exception.Message)"
        }
    }

    # Add the new connection
    if ($PSCmdlet.ShouldProcess($newConn, "Add printer connection")) {
        try {
            Add-Printer -ConnectionName $newConn -ErrorAction Stop
            Write-Log "Added: $newConn"
        }
        catch {
            Write-Log "ERROR: Failed to add '$newConn': $($_.Exception.Message)"
        }
    }
}

# Restore default printer if it was migrated
if ($setDefaultTo) {
    if ($PSCmdlet.ShouldProcess($setDefaultTo, "Set default printer")) {
        try {
            $newPrinter = Get-Printer -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionName -eq $setDefaultTo }
            if ($newPrinter) {
                Set-Printer -Name $newPrinter.Name -IsDefault $true -ErrorAction Stop
                Write-Log "Default printer set: $($newPrinter.Name)"
            }
            else {
                # Fallback
                rundll32 printui.dll, PrintUIEntry /y /n "$setDefaultTo" | Out-Null
                Write-Log "Default printer set via PrintUIEntry: $setDefaultTo"
            }
        }
        catch {
            Write-Log "WARNING: Failed to set default printer to '$setDefaultTo': $($_.Exception.Message)"
        }
    }
}

Write-Log "Completed printer migration."
Write-Log "Log file: $LogFile"
