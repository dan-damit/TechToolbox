# Code Analysis Report
Generated: 2/7/2026 8:27:57 PM

## Summary
 Here are some suggestions to enhance the code's functionality, readability, and performance:

1. Use PowerShell core to make the script compatible with cross-platform environments.

2. Add validation for input parameters. For example, ensure that the source directory exists, the destination root is a valid directory, and the source and destination paths are not the same.

3. Consider using the `Test-Path` cmdlet in combination with the `throw` statement to throw an error when the source or destination does not exist.

4. Add validation for the Robocopy command arguments, such as ensuring that the provided copyFlags are valid options for the Robocopy command and providing helpful error messages if they're not.

5. To improve readability, consider using constants for configurable settings (e.g., `$LOG_DIR`, `$DEFAULT_COMPUTER_NAME`, etc.).

6. Consider separating the configuration into a separate file to make it easier to manage and modify.

7. Add support for logging errors and other informational messages during the Robocopy execution, rather than only at the start and end of the script. This will provide more detailed information about what happened during the copy process.

8. To improve performance, you could consider using asynchronous methods to execute the Robocopy command, which would allow other tasks to be processed concurrently. However, keep in mind that this might introduce additional complexity and error handling.

9. Finally, consider adding a progress bar or status updates while copying files to give users more feedback on the script's progress. This can help prevent users from thinking the script is stuck or unresponsive.

## Source Code
```powershell
function Copy-Directory {
    <#
    .SYNOPSIS
        Copies a directory to another directory using Robocopy.
    .DESCRIPTION
        Supports local or remote execution via PowerShell Remoting. Uses
        config-driven defaults for logging, flags, retries, and mirror behavior.
    .PARAMETER Source
        The source directory to copy.
    .PARAMETER DestinationRoot
        The root destination directory where the source folder will be copied.
        The final destination will be DestinationRoot\SourceFolderName.
    .PARAMETER ComputerName
        The name of the remote computer to perform the copy on. If omitted, the
        copy is performed locally unless -Local is specified.
    .PARAMETER Local
        Switch to force local execution of the copy.
    .PARAMETER Mirror
        Switch to enable mirror mode (/MIR) for the copy, which deletes files in
        the destination that no longer exist in the source.
    .PARAMETER Credential
        Optional PSCredential to use for remote connections.
    .INPUTS
        None. You cannot pipe objects to Copy-Directory.
    .OUTPUTS
        The final destination path where the directory was copied.
    .EXAMPLE
        Copy-Directory -Source "C:\Data\FolderA" -DestinationRoot "D:\Backup"
        Copies FolderA to D:\Backup\FolderA locally.
    .EXAMPLE
        Copy-Directory -Source "C:\Data\FolderA" -DestinationRoot "D:\Backup" -ComputerName "Server01"
        Copies FolderA to D:\Backup\FolderA on the remote computer Server01.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [string]$DestinationRoot,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Local,

        [Parameter()]
        [switch]$Mirror,

        [Parameter()]
        [pscredential]$Credential
    )

    # --- Config ---
    $cfg = Get-TechToolboxConfig
    $settings = $cfg["settings"]
    $copy = $settings["copyDirectory"]

    $runRemote = $copy["runRemote"] ?? $true
    $defaultComp = $copy["defaultComputerName"]
    $logDir = $copy["logDir"] ?? "C:\LogsAndExports\TechToolbox\Logs\Robocopy"
    $retryCount = $copy["retryCount"] ?? 2
    $waitSeconds = $copy["waitSeconds"] ?? 5
    $copyFlags = $copy["copyFlags"] ?? @("/E", "/COPYALL")
    $mirrorCfg = $copy["mirror"] ?? $false

    # Effective mirror mode (param overrides config)
    $mirrorEffective = if ($Mirror.IsPresent) { $true } else { [bool]$mirrorCfg }

    if ($mirrorEffective) {
        # /MIR implies /E + purge; ignore configured copyFlags when mirroring
        $copyFlags = @("/MIR", "/COPYALL")
    }

    # Ensure log directory exists (local)
    if (-not (Test-Path -Path $logDir -PathType Container)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    # Derive folder name & destination
    $folderName = Split-Path -Path $Source -Leaf
    $destination = Join-Path -Path $DestinationRoot -AdditionalChildPath $folderName

    # Log file (local path; may be on remote share if desired)
    $logFile = Join-Path -Path $logDir -AdditionalChildPath ("{0}-robocopy.log" -f $folderName)

    Write-Log -Level Info -Message "Preparing to copy directory..."
    Write-Log -Level Info -Message (" Source: {0}" -f $Source)
    Write-Log -Level Info -Message (" Destination root: {0}" -f $DestinationRoot)
    Write-Log -Level Info -Message (" Effective destination: {0}" -f $destination)
    Write-Log -Level Info -Message (" Log file: {0}" -f $logFile)

    if ($mirrorEffective) {
        Write-Log -Level Warn -Message "MIRROR MODE ENABLED: destination deletions will occur to match source (/MIR)."
    }

    # Decide local vs remote
    $targetComputer = $ComputerName
    if (-not $Local) {
        if (-not $targetComputer -and $defaultComp) {
            $targetComputer = $defaultComp
        }
    }

    $runRemoteEffective =
    -not $Local -and
    -not [string]::IsNullOrWhiteSpace($targetComputer) -and
    $runRemote

    $targetDescription = if ($runRemoteEffective) {
        "{0} (remote on {1})" -f $destination, $targetComputer
    }
    else {
        "{0} (local)" -f $destination
    }

    if ($mirrorEffective) {
        $targetDescription = "$targetDescription [MIRROR: deletions may occur]"
    }

    if ($PSCmdlet.ShouldProcess($targetDescription, "Copy directory via Robocopy")) {

        if ($runRemoteEffective) {
            Write-Log -Level Info -Message (" Executing Robocopy remotely on [{0}]." -f $targetComputer)

            Start-RobocopyRemote `
                -Source $Source `
                -Destination $destination `
                -LogFile $logFile `
                -RetryCount $retryCount `
                -WaitSeconds $waitSeconds `
                -CopyFlags $copyFlags `
                -ComputerName $targetComputer `
                -Credential $Credential
        }
        else {
            Write-Log -Level Info -Message " Executing Robocopy locally."

            Start-RobocopyLocal `
                -Source $Source `
                -Destination $destination `
                -LogFile $logFile `
                -RetryCount $retryCount `
                -WaitSeconds $waitSeconds `
                -CopyFlags $copyFlags `
                -Credential $Credential
        }

        Write-Log -Level Ok -Message ("Copy completed for folder '{0}'." -f $folderName)
    }

    return $destination
}
[SIGNATURE BLOCK REMOVED]

```
