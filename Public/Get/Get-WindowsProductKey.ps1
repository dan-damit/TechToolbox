function Get-WindowsActivationInfo {
    <#
    .SYNOPSIS
    Retrieves Windows activation information, including OEM product key, partial
    product keys, and activation report.
    .DESCRIPTION
    This function gathers Windows activation details from the local or a remote
    computer using CIM and WMI. It retrieves the OEM product key, partial product
    keys, and the output of the SLMGR /DLV command. The results are exported to a
    timestamped log file in a configured directory.
    .PARAMETER ComputerName
    The name of the computer to query. Defaults to the local computer.
    .PARAMETER Credential
    Optional PSCredential for remote connections.
    .EXAMPLE
    Get-WindowsActivationInfo -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
    Get-WindowsActivationInfo
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Determine export root from config
    $exportRoot = $script:TechToolboxConfig["settings"]["licensing"]["logDir"]
    if (-not (Test-Path -LiteralPath $exportRoot)) {
        New-Item -Path $exportRoot -ItemType Directory -Force | Out-Null
    }

    # Helper for remote execution
    function Invoke-Remote {
        param(
            [string]$ComputerName,
            [string]$Command,
            [System.Management.Automation.PSCredential]$Credential
        )

        if ($ComputerName -eq $env:COMPUTERNAME) {
            return Invoke-Expression $Command
        }

        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = { param($cmd) Invoke-Expression $cmd }
            ArgumentList = $Command
            ErrorAction  = 'Stop'
        }

        if ($Credential) { $params.Credential = $Credential }

        return Invoke-Command @params
    }

    # OEM Product Key
    try {
        $oemParams = @{
            ClassName    = 'SoftwareLicensingService'
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $oemParams.Credential = $Credential }

        $oemKey = (Get-CimInstance @oemParams).OA3xOriginalProductKey
    }
    catch {
        $oemKey = $null
    }

    # Partial Keys
    try {
        $prodParams = @{
            ClassName    = 'SoftwareLicensingProduct'
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $prodParams.Credential = $Credential }

        $partialKeys = Get-CimInstance @prodParams |
        Where-Object { $_.PartialProductKey } |
        Select-Object Name, Description, LicenseStatus, PartialProductKey
    }
    catch {
        $partialKeys = $null
    }

    # Activation Report
    try {
        $slmgrOutput = Invoke-Remote -ComputerName $ComputerName `
            -Command 'cscript.exe //Nologo C:\Windows\System32\slmgr.vbs /dlv' `
            -Credential $Credential

        $slmgrOutput = $slmgrOutput -join "`n"
    }
    catch {
        $slmgrOutput = "Failed to retrieve slmgr report: $_"
    }

    # Build final object
    $result = [pscustomobject]@{
        ComputerName     = $ComputerName
        OemProductKey    = $oemKey
        PartialKeys      = $partialKeys
        ActivationReport = $slmgrOutput
    }

    # Build timestamped filename
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $exportPath = Join-Path $exportRoot ("ActivationInfo_{0}_{1}.txt" -f $ComputerName, $timestamp)

    # Build export content
    $logContent = @()
    $logContent += "Computer Name: $ComputerName"
    $logContent += "OEM Product Key: $oemKey"
    $logContent += ""
    $logContent += "=== Partial Keys ==="

    if ($partialKeys) {
        foreach ($item in $partialKeys) {
            $logContent += "Name: $($item.Name)"
            $logContent += "Description: $($item.Description)"
            $logContent += "LicenseStatus: $($item.LicenseStatus)"
            $logContent += "PartialProductKey: $($item.PartialProductKey)"
            $logContent += ""
        }
    }
    else {
        $logContent += "None found."
    }

    $logContent += ""
    $logContent += "=== SLMGR /DLV Output ==="
    $logContent += $slmgrOutput

    # Write to disk
    $logContent | Out-File -FilePath $exportPath -Encoding UTF8
    Write-Host "Windows activation info exported to: $exportPath"

    # Return object last for pipeline safety
    return $result
}