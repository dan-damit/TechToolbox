
function Start-RobocopyWorker {
    <#
    .SYNOPSIS
        Internal worker function to perform Robocopy operation with logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile
    )

    if (-not (Test-Path -Path $Destination -PathType Container)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $arguments = @(
        "`"$Source`"",
        "`"$Destination`"",
        "/E",
        "/COPYALL",
        "/R:2",
        "/W:5",
        "/LOG:$LogFile"
    )

    Write-Log -Level Info -Message "Running Robocopy..."
    Write-Log -Level Info -Message " Command: robocopy $($arguments -join ' ')"

    Start-Process -FilePath "robocopy.exe" -ArgumentList $arguments -NoNewWindow -Wait
}