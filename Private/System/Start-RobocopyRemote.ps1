function Start-RobocopyRemote {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [Parameter(Mandatory)][string]$LogFile,
        [Parameter(Mandatory)][int]$RetryCount,
        [Parameter(Mandatory)][int]$WaitSeconds,
        [Parameter(Mandatory)][string[]]$CopyFlags,
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][pscredential]$Credential
    )

    Write-Log -Level Info -Message (" Opening remote session to {0}..." -f $ComputerName)

    if ($Credential) {
        $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
    }
    else {
        $session = New-PSSession -ComputerName $ComputerName
    }

    try {
        $exitCode = Invoke-Command -Session $session -ScriptBlock {
            param(
                $Source,
                $Destination,
                $LogFile,
                $RetryCount,
                $WaitSeconds,
                $CopyFlags
            )

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

            Write-Host "Running Robocopy on remote host..."
            Write-Host ("Command: robocopy {0}" -f ($arguments -join ' '))

            $proc = Start-Process -FilePath "robocopy.exe" -ArgumentList $arguments -NoNewWindow -Wait -PassThru
            $proc.ExitCode
        } -ArgumentList $Source, $Destination, $LogFile, $RetryCount, $WaitSeconds, $CopyFlags

        Write-Log -Level Info -Message (" Remote Robocopy exit code: {0}" -f $exitCode)

        if ($exitCode -gt 7) {
            Write-Log -Level Warn -Message (" Remote Robocopy reported a severe error (exit code {0})." -f $exitCode)
        }
    }
    finally {
        if ($session) {
            Write-Log -Level Info -Message (" Closing remote session to {0}." -f $ComputerName)
            Remove-PSSession -Session $session
        }
    }
}