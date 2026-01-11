
function Invoke-SystemRepairLocal {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations locally.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][switch]$RestoreHealth,
        [Parameter()][switch]$StartComponentCleanup,
        [Parameter()][switch]$ResetBase,
        [Parameter()][switch]$SfcScannow,
        [Parameter()][switch]$ResetUpdateComponents
    )

    if ($RestoreHealth) {
        Write-Log -Level Info -Message " Running DISM /RestoreHealth locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -NoNewWindow -Wait
    }

    if ($StartComponentCleanup) {
        Write-Log -Level Info -Message " Running DISM /StartComponentCleanup locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup" -NoNewWindow -Wait
    }

    if ($ResetBase) {
        Write-Log -Level Info -Message " Running DISM /StartComponentCleanup /ResetBase locally..."
        Start-Process dism.exe -ArgumentList "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase" -NoNewWindow -Wait
    }

    if ($SfcScannow) {
        Write-Log -Level Info -Message " Running SFC /scannow locally..."
        Start-Process sfc.exe -ArgumentList "/scannow" -NoNewWindow -Wait
    }

    if ($ResetUpdateComponents) {
        Write-Log -Level Info -Message " Resetting Windows Update components locally..."

        Stop-Service -Name wuauserv, cryptsvc, bits, msiserver -Force

        Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction SilentlyContinue

        Rename-Item -Path "$env:SystemRoot\SoftwareDistribution" -NewName "SoftwareDistribution.old" -Force
        Rename-Item -Path "$env:SystemRoot\System32\catroot2" -NewName "catroot2.old" -Force

        Start-Service -Name wuauserv, cryptsvc, bits, msiserver

        Write-Log -Level Info -Message " Windows Update components reset locally."
    }
}