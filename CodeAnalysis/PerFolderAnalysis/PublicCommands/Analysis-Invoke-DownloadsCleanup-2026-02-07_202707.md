# Code Analysis Report
Generated: 2/7/2026 8:27:07 PM

## Summary
 The PowerShell script provided is a function `Invoke-DownloadsCleanup` that cleans up old files from the Downloads folders of local or remote machines. Here's a breakdown and suggestions for improvements:

1. Variable Naming:
   - Use more descriptive variable names, especially for objects like `$cfg`, `$dlCfg`, `$users`, `$oldFiles`, `$result`, etc. This will make the code easier to read and understand.

2. Code Organization:
   - Split the function into smaller functions or classes to improve modularity and maintainability. For instance, create a separate function for handling local cleanup and another for remote cleanup. This would make the main function cleaner and easier to navigate.

3. Error Handling:
   - Improve error handling by using custom error records instead of just `$_.Exception.Message`. This will provide more context about what went wrong, making it easier to diagnose issues.

4. Documentation:
   - Add more detailed comments explaining the purpose and logic behind each part of the code, not just at the beginning. This would help others understand your thought process and make further modifications if necessary.

5. Performance Optimization:
   - Use parallel processing to clean up multiple folders simultaneously, which could significantly reduce the time taken for the cleanup process. However, be careful when implementing this to avoid potential issues with concurrent file deletions.

6. Input/Output:
   - Consider adding input validation to ensure that only valid parameters are passed to the function. Also, handle cases where the user does not have sufficient permissions to delete files on the target machine(s). For output, provide a way for users to specify an output file or store the results in a database for later analysis.

7. Code Formatting:
   - Follow PowerShell formatting guidelines, such as using consistent indentation and line wrapping where necessary. This will make the code easier on the eyes and more readable.

8. Logging:
   - Implement proper logging to keep track of what's happening during execution. This could include information about which files are being deleted, any errors encountered, and the overall progress of the cleanup process.

9. Configuration File:
   - Instead of hardcoding configuration settings in the script, consider using a separate configuration file (JSON or XML) for storing parameters like cutoff year, prompting for credentials, etc. This makes it easier to change settings without modifying the main script and also allows for centralized management of configurations.

10. Code Testing:
    - Implement unit tests for individual functions to ensure they work as expected under various conditions. This will help catch any bugs or issues early on in the development process.

## Source Code
```powershell

function Invoke-DownloadsCleanup {
    <#
    .SYNOPSIS
        Cleans up old files from Downloads folders on local or remote machines.
    .DESCRIPTION
        This cmdlet connects to a specified remote computer (or the local machine
        if -Local is used) and scans all user Downloads folders for files last
        modified on or before a specified cutoff year. Those files are deleted to
        help free up disk space and reduce clutter.
    .PARAMETER ComputerName
        The name of the remote computer to clean up. If omitted, -Local must be
        used.
    .PARAMETER CutoffYear
        The year threshold; files last modified on or before this year will be
        deleted. Defaults to config value.
    .PARAMETER Local
        If specified, runs the cleanup on the local machine instead of a remote
        computer.
    .INPUTS
        None. You cannot pipe objects to Invoke-DownloadsCleanup.
    .OUTPUTS
        [pscustomobject] entries summarizing cleanup results per user.
    .EXAMPLE
        Invoke-DownloadsCleanup -ComputerName "Workstation01"
    .EXAMPLE
        Invoke-DownloadsCleanup -Local -CutoffYear 2020
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()][string]$ComputerName,
        [Parameter()][int]$CutoffYear,
        [switch]$Local
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $dlCfg = $cfg["settings"]["downloadsCleanup"]

    # Defaults
    if (-not $CutoffYear) { $CutoffYear = $dlCfg["cutoffYear"] }
    $dryRun = $dlCfg["dryRun"]

    # If -Local is used, ignore ComputerName entirely
    if ($Local) {
        Write-Log -Level Info -Message "Running Downloads cleanup locally."

        $result = & {
            param($CutoffYear, $DryRun)

            $basePath = "C:\Users"
            $users = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue

            $report = @()

            foreach ($user in $users) {
                $downloadsPath = Join-Path $user.FullName "Downloads"

                if (-not (Test-Path $downloadsPath)) {
                    $report += [pscustomobject]@{
                        User    = $user.Name
                        Path    = $downloadsPath
                        Status  = "No Downloads folder"
                        Deleted = 0
                    }
                    continue
                }

                $oldFiles = Get-ChildItem -Path $downloadsPath -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime.Year -le $CutoffYear }

                $deletedCount = 0

                foreach ($file in $oldFiles) {
                    if ($DryRun) {
                        $deletedCount++
                        continue
                    }

                    try {
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        $deletedCount++
                    }
                    catch {
                        $report += [pscustomobject]@{
                            User    = $user.Name
                            Path    = $file.FullName
                            Status  = "Failed: $($_.Exception.Message)"
                            Deleted = 0
                        }
                    }
                }

                $report += [pscustomobject]@{
                    User    = $user.Name
                    Path    = $downloadsPath
                    Status  = "OK"
                    Deleted = $deletedCount
                }
            }

            return $report

        } -ArgumentList $CutoffYear, $dryRun

        foreach ($entry in $result) {
            if ($entry.Status -eq "OK") {
                Write-Log -Level Ok -Message "[$($entry.User)] Deleted $($entry.Deleted) old files."
            }
            elseif ($entry.Status -like "Failed*") {
                Write-Log -Level Warn -Message "[$($entry.User)] Failed to delete: $($entry.Path) — $($entry.Status)"
            }
            else {
                Write-Log -Level Info -Message "[$($entry.User)] $($entry.Status)"
            }
        }

        Write-Log -Level Ok -Message "Local Downloads cleanup completed."
        return
    }

    # ────────────────────────────────────────────────────────────────
    # REMOTE EXECUTION (default)
    # ────────────────────────────────────────────────────────────────

    if (-not $ComputerName) {
        Write-Log -Level Error -Message "You must specify -ComputerName or use -Local."
        return
    }

    # Prompt for credentials if config says so
    $creds = $null
    if ($cfg["settings"]["defaults"]["promptForCredentials"]) {
        $creds = Get-Credential -Message "Enter credentials for $ComputerName"
    }

    Write-Log -Level Info -Message "Connecting to $ComputerName..."

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $creds
        Write-Log -Level Ok -Message "Connected to $ComputerName."
    }
    catch {
        Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
        return
    }

    Write-Log -Level Info -Message "Scanning Downloads folders on $ComputerName..."

    $result = Invoke-Command -Session $session -ScriptBlock {
        param($CutoffYear, $DryRun)

        $basePath = "C:\Users"
        $users = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue

        $report = @()

        foreach ($user in $users) {
            $downloadsPath = Join-Path $user.FullName "Downloads"

            if (-not (Test-Path $downloadsPath)) {
                $report += [pscustomobject]@{
                    User    = $user.Name
                    Path    = $downloadsPath
                    Status  = "No Downloads folder"
                    Deleted = 0
                }
                continue
            }

            $oldFiles = Get-ChildItem -Path $downloadsPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime.Year -le $CutoffYear }

            $deletedCount = 0

            foreach ($file in $oldFiles) {
                if ($DryRun) {
                    $deletedCount++
                    continue
                }

                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $deletedCount++
                }
                catch {
                    $report += [pscustomobject]@{
                        User    = $user.Name
                        Path    = $file.FullName
                        Status  = "Failed: $($_.Exception.Message)"
                        Deleted = 0
                    }
                }
            }

            $report += [pscustomobject]@{
                User    = $user.Name
                Path    = $downloadsPath
                Status  = "OK"
                Deleted = $deletedCount
            }
        }

        return $report

    } -ArgumentList $CutoffYear, $dryRun

    Remove-PSSession $session

    foreach ($entry in $result) {
        if ($entry.Status -eq "OK") {
            Write-Log -Level Ok -Message "[$($entry.User)] Deleted $($entry.Deleted) old files."
        }
        elseif ($entry.Status -like "Failed*") {
            Write-Log -Level Warn -Message "[$($entry.User)] Failed to delete: $($entry.Path) — $($entry.Status)"
        }
        else {
            Write-Log -Level Info -Message "[$($entry.User)] $($entry.Status)"
        }
    }

    Write-Log -Level Ok -Message "Downloads cleanup completed on $ComputerName."
}
[SIGNATURE BLOCK REMOVED]

```
