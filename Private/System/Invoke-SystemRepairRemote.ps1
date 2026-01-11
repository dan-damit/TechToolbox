
function Invoke-SystemRepairRemote {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations on a remote computer via
        PSRemoting.
    .DESCRIPTION
        Wraps common repair operations (DISM RestoreHealth,
        StartComponentCleanup, ResetBase, SFC, and Windows Update component
        reset) in a TechToolbox-style function with remote execution
        and credential support.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][switch]$RestoreHealth,
        [Parameter()][switch]$StartComponentCleanup,
        [Parameter()][switch]$ResetBase,
        [Parameter()][switch]$SfcScannow,
        [Parameter()][switch]$ResetUpdateComponents,
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
        Invoke-Command -Session $session -ScriptBlock {
            param(
                $RestoreHealth,
                $StartComponentCleanup,
                $ResetBase,
                $SfcScannow,
                $ResetUpdateComponents
            )

            if ($RestoreHealth) {
                Write-Host "Running DISM /RestoreHealth remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/RestoreHealth" -NoNewWindow -Wait
            }

            if ($StartComponentCleanup) {
                Write-Host "Running DISM /StartComponentCleanup remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup" -NoNewWindow -Wait
            }

            if ($ResetBase) {
                Write-Host "Running DISM /StartComponentCleanup /ResetBase remotely..."
                Start-Process dism.exe -ArgumentList "/Online","/Cleanup-Image","/StartComponentCleanup","/ResetBase" -NoNewWindow -Wait
            }

            if ($SfcScannow) {
                Write-Host "Running SFC /scannow remotely..."
                Start-Process sfc.exe -ArgumentList "/scannow" -NoNewWindow -Wait
            }

            if ($ResetUpdateComponents) {
                Write-Host "Resetting Windows Update components remotely..."

                Stop-Service -Name wuauserv, cryptsvc, bits, msiserver -Force

                Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

                Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
                Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force

                Start-Service -Name wuauserv, cryptsvc, bits, msiserver

                Write-Host "Windows Update components reset remotely."
            }
        } -ArgumentList $RestoreHealth, $StartComponentCleanup, $ResetBase, $SfcScannow, $ResetUpdateComponents
    }
    finally {
        if ($session) {
            Write-Log -Level Info -Message (" Closing remote session to {0}." -f $ComputerName)
            Remove-PSSession -Session $session
        }
    }
}