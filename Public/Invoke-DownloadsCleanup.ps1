
function Invoke-TTDownloadsCleanup {
    <#
    .SYNOPSIS
        Cleans up old files from Downloads folders on local or remote machines.
    .PARAMETER ComputerName
        The name of the remote computer to clean up. If omitted, -Local must be
        used.
    .PARAMETER CutoffYear
        The year threshold; files last modified on or before this year will be
        deleted. Defaults to config value.
    .PARAMETER Local
        If specified, runs the cleanup on the local machine instead of a remote
        computer.
    .EXAMPLE
        Invoke-DownloadsCleanup -ComputerName "Workstation01"
    .EXAMPLE
        Invoke-DownloadsCleanup -Local -CutoffYear 2020
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()][string]$ComputerName,
        [Parameter()][int]$CutoffYear,
        [switch]$Local
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $dlCfg = $cfg.settings.downloadsCleanup

    # Defaults
    if (-not $CutoffYear) { $CutoffYear = $dlCfg.cutoffYear }
    $dryRun = $dlCfg.dryRun

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
    if ($cfg.settings.defaults.promptForCredentials) {
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