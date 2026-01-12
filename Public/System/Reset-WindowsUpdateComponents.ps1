function Reset-WindowsUpdateComponents {
    <#
    .SYNOPSIS
    Resets Windows Update components locally or on a remote machine.
    .DESCRIPTION
    This function stops Windows Update-related services, renames key folders,
    and restarts the services to reset Windows Update components. It can operate
    on the local or a remote computer using PowerShell remoting. A log file is
    generated summarizing the actions taken.
    .PARAMETER ComputerName
    The name of the computer to reset Windows Update components on. Defaults to
    the local computer.
    .PARAMETER Credential
    Optional PSCredential for remote connections.
    .EXAMPLE
    Reset-WindowsUpdateComponents -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
    Reset-WindowsUpdateComponents
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Load config
    $logDir = $script:TechToolboxConfig["settings"]["windowsUpdate"]["logDir"]
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    # Helper for remote execution
    function Invoke-Remote {
        param(
            [string]$ComputerName,
            [scriptblock]$ScriptBlock,
            [System.Management.Automation.PSCredential]$Credential
        )

        if ($ComputerName -eq $env:COMPUTERNAME) {
            return & $ScriptBlock
        }

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $ScriptBlock
            ErrorAction  = 'Stop'
        }

        if ($Credential) { $params.Credential = $Credential }

        return Invoke-Command @params
    }

    # Scriptblock that runs on local or remote machine
    $resetScript = {
        $result = [ordered]@{
            StoppedServices = @()
            RenamedFolders  = @()
            Errors          = @()
        }

        $services = 'wuauserv', 'cryptsvc', 'bits', 'msiserver'

        foreach ($svc in $services) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                $result.StoppedServices += $svc
            }
            catch {
                $result.Errors += "Failed to stop $svc $($_.Exception.Message)"
            }
        }

        # Delete qmgr files
        try {
            Remove-Item -Path "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -Force -ErrorAction Stop
        }
        catch {
            $result.Errors += "Failed to delete qmgr files: $($_.Exception.Message)"
        }

        # Rename SoftwareDistribution
        try {
            $sd = Join-Path $env:SystemRoot "SoftwareDistribution"
            if (Test-Path $sd) {
                Rename-Item -Path $sd -NewName "SoftwareDistribution.old" -Force
                $result.RenamedFolders += "SoftwareDistribution → SoftwareDistribution.old"
            }
        }
        catch {
            $result.Errors += "Failed to rename SoftwareDistribution: $($_.Exception.Message)"
        }

        # Rename catroot2
        try {
            $cr = Join-Path $env:SystemRoot "System32\catroot2"
            if (Test-Path $cr) {
                Rename-Item -Path $cr -NewName "catroot2.old" -Force
                $result.RenamedFolders += "catroot2 → catroot2.old"
            }
        }
        catch {
            $result.Errors += "Failed to rename catroot2: $($_.Exception.Message)"
        }

        # Restart services
        foreach ($svc in $services) {
            try {
                Start-Service -Name $svc -ErrorAction Stop
            }
            catch {
                $result.Errors += "Failed to start $svc $($_.Exception.Message)"
            }
        }

        return [pscustomobject]$result
    }

    # Execute
    $resetResult = Invoke-Remote -ComputerName $ComputerName -ScriptBlock $resetScript -Credential $Credential

    # Export log
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $exportPath = Join-Path $logDir ("WUReset_{0}_{1}.txt" -f $ComputerName, $timestamp)

    $log = @()
    $log += "Windows Update Reset Report"
    $log += "Computer: $ComputerName"
    $log += "Timestamp: $timestamp"
    $log += ""
    $log += "Stopped Services:"
    $log += $resetResult.StoppedServices
    $log += ""
    $log += "Renamed Folders:"
    $log += $resetResult.RenamedFolders
    $log += ""
    $log += "Errors:"
    $log += $resetResult.Errors

    $log | Out-File -FilePath $exportPath -Encoding UTF8

    Write-Host "Windows Update components reset. Log saved to: $exportPath" -ForegroundColor Green

    return $resetResult
}