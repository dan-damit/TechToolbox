function Start-RobocopyLocal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][int]$RetryCount,
        [Parameter(Mandatory)][int]$WaitSeconds,
        [Parameter(Mandatory)][string[]]$CopyFlags,
        [Parameter()][pscredential]$Credential
    )

    # Optional: credential-aware UNC access (basic pattern)
    # For now, we log that credentials were supplied and rely on existing access.
    if ($Credential) {
        Write-Log -Level Info -Message " Credential supplied for local execution (ensure access to UNC paths is configured)."
    }

    if (-not (Test-Path -Path $Destination -PathType Container)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }

    $arguments = @(
        "`"$Source`"",
        "`"$Destination`""
    ) + $CopyFlags + @(
        "/R:{0}" -f $RetryCount,
        "/W:{0}" -f $WaitSeconds,
        "/LOG:$LogFile"
    )

    Write-Log -Level Info -Message " Running Robocopy locally..."
    Write-Log -Level Info -Message (" Command: robocopy {0}" -f ($arguments -join ' '))

    $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru
    $exitCode = $proc.ExitCode

    Write-Log -Level Info -Message (" Robocopy exit code: {0}" -f $exitCode)

    # Robocopy exit codes 0–7 are typically non-fatal; >7 indicates serious issues.
    if ($exitCode -gt 7) {
        Write-Log -Level Warn -Message (" Robocopy reported a severe error (exit code {0})." -f $exitCode)
    }
}