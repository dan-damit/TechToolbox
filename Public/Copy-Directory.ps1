
function Copy-Directory {
    <#
    .SYNOPSIS
        Copies a directory to a destination using Robocopy, with logging.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$DestinationRoot
    )

    # --- Config ---
    $cfg = Get-TechToolboxConfig
    $copy = $cfg["settings"]["copyDirectory"]

    # Config-driven log directory with fallback
    $logDir = $copy["logDir"] ?? "C:\LogsAndExports\TechToolbox\Logs\Robocopy"

    if (-not (Test-Path -Path $logDir -PathType Container)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    $folderName = Split-Path -Path $Source -Leaf
    $destination = Join-Path -Path $DestinationRoot -AdditionalChildPath $folderName
    $logFile = Join-Path -Path $logDir -AdditionalChildPath "$folderName-robocopy.log"

    Write-Log -Level Info -Message "Preparing to copy '$folderName'..."
    Write-Log -Level Info -Message " Source: $Source"
    Write-Log -Level Info -Message " Destination: $destination"
    Write-Log -Level Info -Message " Log: $logFile"

    if ($PSCmdlet.ShouldProcess($destination, "Copy directory via Robocopy")) {
        Start-RobocopyWorker -Source $Source -Destination $destination -LogFile $logFile
        Write-Log -Level Ok -Message "Copy complete for '$folderName'."
    }

    return $destination
}