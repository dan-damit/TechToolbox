# Code Analysis Report
Generated: 2/7/2026 8:28:20 PM

## Summary
 This PowerShell script is designed to remove all printers, ports, drivers, and per-user mappings from a Windows system. Here are some suggestions for enhancements and improvements:

1. Modularize the code by creating separate functions for each task (e.g., stopSpooler, clearSpoolFolder, removePrinters, removePorts, removeDrivers, removeUserMaps). This would make the script more maintainable and easier to test.

2. Use try-catch blocks consistently throughout the script to handle errors and improve readability. Currently, some parts of the script use try-catch while others do not, which can be confusing.

3. Add comments explaining the purpose and behavior of each variable and parameter. This would make the code more accessible to other users or maintainers.

4. Use PowerShell Core instead of the older PowerShell v2 syntax (e.g., `$cfg = Get-TechToolboxConfig` should be replaced with `Get-ConfigurationData -Path TechToolboxConfig`). This would make the script compatible with more platforms and easier to maintain.

5. Use PowerShell's built-in logging functionality for better error reporting and debugging. For example, you can use `Write-Verbose`, `Write-Debug`, `Write-Warning`, and `Write-Error` instead of writing to a log file directly.

6. Consider adding optional parameters for specifying the spooler service name or the printer, port, driver, and user mapping paths to improve flexibility and avoid hardcoding paths.

7. Use PowerShell's built-in help system (`Get-Help`) to provide better documentation for the script and its parameters.

8. Consider using a parameter set to handle multiple combinations of switches more elegantly.

9. Add tests for the various functions to ensure they work as expected. This would catch any issues before they affect users.

10. Consider using PowerShell's built-in remoting capabilities (`Invoke-Command`, `Register-PsSessionConfiguration`, etc.) to allow running the script remotely on multiple computers at once.

Overall, the script is well-written and functional, but some of these suggestions could help improve its readability, maintainability, and flexibility.

## Source Code
```powershell

function Remove-Printers {
    <#
    .SYNOPSIS
        Removes all printers from the system, with optional removal of ports,
        drivers, and per-user mappings.
    .DESCRIPTION
        Uses Win32_Printer (CIM) to remove queues after resetting the spooler
        and clearing the spool folder. Optionally removes TCP/IP ports and
        printer drivers. Adds fallbacks for provider hiccups and frees common
        process locks (splwow64/PrintIsolationHost). Can also remove per-user
        connections across all profiles.
    .PARAMETER IncludePorts
        Also remove TCP/IP printer ports (non-standard).
    .PARAMETER IncludeDrivers
        Also remove printer drivers (after queues are gone).
    .PARAMETER Force
        Best-effort forced cleanup of driver packages via pnputil if standard
        removal fails.
    .PARAMETER AllUsers
        Attempt to remove per-user network printer connections for all user
        profiles.
    .PARAMETER PassThru
        Output a summary object with counts and failures.
    .EXAMPLE
        Remove-Printers -IncludePorts -IncludeDrivers -Force -AllUsers -PassThru
    .EXAMPLE
        Remove-Printers -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch] $IncludePorts,
        [switch] $IncludeDrivers,
        [switch] $Force,
        [switch] $AllUsers,
        [switch] $PassThru
    )

    $cfg = Get-TechToolboxConfig
    $defs = $cfg.defaults
    $log = $cfg.logging
    $paths = $cfg.paths

    # Counters
    $removedPrinters = 0; $failedPrinters = @()
    $removedPorts = 0; $failedPorts = @()
    $removedDrivers = 0; $failedDrivers = @()
    $removedUserMaps = 0; $failedUserMaps = @()

    Begin {
        Write-Log -Level Info -Message "=== Remove-Printers started ==="
    }

    Process {
        # Track original spooler state
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $spoolerWasRunning = $false
        if ($spooler) { $spoolerWasRunning = $spooler.Status -eq 'Running' }

        # 1) Stop spooler and clear jobs
        if ($PSCmdlet.ShouldProcess("Spooler", "Stop and clear PRINTERS folder")) {
            Write-Log -Level Info -Message "Stopping Print Spooler..."
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

            $spoolPath = Join-Path $env:WINDIR 'System32\spool\PRINTERS'
            if (Test-Path $spoolPath) {
                Write-Log -Level Info -Message "Clearing spool folder: $spoolPath"
                Get-ChildItem -Path $spoolPath -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            }

            Write-Log -Level Info -Message "Starting Print Spooler..."
            Start-Service -Name Spooler -ErrorAction SilentlyContinue
        }

        # (Optional) Remove per-user connections for all profiles
        if ($AllUsers) {
            Write-Log -Level Info -Message "Removing per-user network printer connections for all profiles..."
            # Enumerate mounted + offline hives under HKEY_USERS
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' } |
            ForEach-Object { $_.PSChildName }

            foreach ($sid in $userSids) {
                $connKey = "Registry::HKEY_USERS\$sid\Printers\Connections"
                if (Test-Path $connKey) {
                    Get-ChildItem $connKey -ErrorAction SilentlyContinue | ForEach-Object {
                        # Value names typically look like ,Server,Queue (commas)
                        $raw = $_.PSChildName.Trim()
                        # Normalize to \\server\queue if possible
                        $serverQueue = $raw -replace '^,', '' -replace ',', '\'
                        if ($serverQueue -notmatch '^\\\\') { $serverQueue = "\\$serverQueue" }
                        if ($PSCmdlet.ShouldProcess("User:${sid} Mapping '$serverQueue'", "Disconnect")) {
                            try {
                                # Current process context removes only for current user,
                                # so we invoke PrintUIEntry targeting the path (best-effort).
                                rundll32 printui.dll, PrintUIEntry /dn /q /n "$serverQueue"
                                $removedUserMaps++
                                Write-Log -Level Info -Message "  - Disconnected $serverQueue for ${sid}"
                            }
                            catch {
                                $failedUserMaps += $serverQueue
                                Write-Log -Level Warn -Message "    Failed to disconnect $serverQueue for ${sid}: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping per-user mapping removal (use -AllUsers to enable)."
        }

        # 2) Remove printers via Win32_Printer (bypasses MSFT_Printer provider issues)
        Write-Log -Level Info -Message "Removing all printers via Win32_Printer..."
        Get-CimInstance Win32_Printer | ForEach-Object {
            $name = $_.Name
            if ($PSCmdlet.ShouldProcess("Printer '$name'", "Remove")) {
                try {
                    $_ | Remove-CimInstance -ErrorAction Stop
                    $removedPrinters++
                    Write-Log -Level Info -Message "  - Removed $name"
                }
                catch {
                    $failedPrinters += $name
                    Write-Log -Level Warn -Message "    Failed to remove '$name': $($_.Exception.Message)"
                }
            }
        }

        # 3) Optional: remove ports (with WMI fallback)
        if ($IncludePorts) {
            Write-Log -Level Info -Message "Removing TCP/IP printer ports..."
            $standardPrefixes = @('FILE:', 'LPT', 'COM', 'WSD', 'XPS', 'SHRFAX:', 'PORTPROMPT:', 'NULL:')
            $ports = @()

            try {
                $ports = Get-PrinterPort -ErrorAction Stop
            }
            catch {
                Write-Log -Level Warn -Message "Get-PrinterPort failed, falling back to Win32_TCPIPPrinterPort..."
                $ports = Get-WmiObject -Class Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue |
                ForEach-Object { New-Object psobject -Property @{ Name = $_.Name } }
            }

            $ports = $ports | Where-Object {
                $n = $_.Name
                -not ($standardPrefixes | ForEach-Object { $n.StartsWith($_, 'CurrentCultureIgnoreCase') }) `
                    -and ($n -notmatch '^(nul:|PDF:)')
            }

            foreach ($p in $ports) {
                if ($PSCmdlet.ShouldProcess("Port '$($p.Name)'", "Remove")) {
                    try {
                        Remove-PrinterPort -Name $p.Name -ErrorAction Stop
                        $removedPorts++
                        Write-Log -Level Info -Message "  - Removed port $($p.Name)"
                    }
                    catch {
                        $failedPorts += $p.Name
                        Write-Log -Level Warn -Message "    Failed to remove port '$($p.Name)': $($_.Exception.Message)"
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping port removal (use -IncludePorts to enable)."
        }

        # 4) Optional: remove drivers (free common locks first)
        if ($IncludeDrivers) {
            # Make sure spooler is running
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service Spooler -ErrorAction SilentlyContinue
            }

            # Free common locks
            Get-Process splwow64, PrintIsolationHost -ErrorAction SilentlyContinue | ForEach-Object {
                try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {}
            }

            Write-Log -Level Info -Message "Removing printer drivers..."
            $drivers = Get-PrinterDriver -ErrorAction SilentlyContinue
            foreach ($d in $drivers) {
                if ($PSCmdlet.ShouldProcess("Driver '$($d.Name)'", "Remove")) {
                    try {
                        Remove-PrinterDriver -Name $d.Name -ErrorAction Stop
                        $removedDrivers++
                        Write-Log -Level Info -Message "  - Removed driver '$($d.Name)'"
                    }
                    catch {
                        $failedDrivers += $d.Name
                        Write-Log -Level Warn -Message "    Failed to remove driver '$($d.Name)': $($_.Exception.Message)"

                        if ($Force) {
                            # Attempt package removal by published name (oemXX.inf)
                            Write-Log -Level Info -Message "    Enumerating driver packages via pnputil..."
                            $enum = & pnputil /enum-drivers 2>$null
                            if ($enum) {
                                # crude but effective matching
                                $blocks = ($enum -join "`n") -split "(?ms)^Published Name : "
                                $targets = $blocks | Where-Object { $_ -match [regex]::Escape($d.Name) -and $_ -match "Class\s*:\s*Printer" }
                                foreach ($blk in $targets) {
                                    if ($blk -match '^(oem\d+\.inf)') {
                                        $oem = $matches[1]
                                        try {
                                            Write-Log -Level Info -Message "    Forcing removal of ${oem} via pnputil..."
                                            & pnputil /delete-driver $oem /uninstall /force | Out-Null
                                        }
                                        catch {
                                            Write-Log -Level Warn -Message "    pnputil failed for ${oem}: $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping driver removal (use -IncludeDrivers to enable)."
        }

        # Restore spooler to original state
        if ($spoolerWasRunning) {
            # ensure it's up
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service -Name Spooler -ErrorAction SilentlyContinue
            }
        }
        else {
            # it was stopped before we began; stop it again
            if ($PSCmdlet.ShouldProcess("Spooler", "Restore to Stopped state")) {
                Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            }
        }
    }

    End {
        Write-Log -Level Info -Message "=== Remove-Printers completed ==="
        if ($PassThru) {
            [pscustomobject]@{
                PrintersRemoved = $removedPrinters
                PrintersFailed  = $failedPrinters
                PortsRemoved    = $removedPorts
                PortsFailed     = $failedPorts
                DriversRemoved  = $removedDrivers
                DriversFailed   = $failedDrivers
                UserMapsRemoved = $removedUserMaps
                UserMapsFailed  = $failedUserMaps
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

```
