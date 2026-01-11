function Copy-Directory {
    <#
    .SYNOPSIS
        Copies a directory to another directory using Robocopy.
    .DESCRIPTION
        Supports local or remote execution via PowerShell Remoting.
        Uses config-driven defaults for logging, flags, retries, and mirror behavior.
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