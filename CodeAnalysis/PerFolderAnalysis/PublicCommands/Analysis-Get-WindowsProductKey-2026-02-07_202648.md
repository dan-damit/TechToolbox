# Code Analysis Report
Generated: 2/7/2026 8:26:48 PM

## Summary
 Here are some suggestions for enhancing the code's functionality, readability, and performance:

1. Use PowerShell Core instead of Windows PowerShell: The code you provided uses Windows PowerShell-specific features like `Get-CimInstance` that are not available in PowerShell Core. Using PowerShell Core will make your script cross-platform compatible, as it runs on Linux, macOS, and Windows.

2. Use functions for readability: Split long functions into smaller ones to improve the readability of the code. For example, the `Get-WindowsProductKey` function can be broken down further into separate functions for retrieving each piece of data (OEM Product Key, Partial Keys, and Activation Report).

3. Use parameter validation: Validate parameters to ensure user input is valid before proceeding with the script execution. This will prevent errors from occurring due to invalid input.

4. Improve error handling: The current error handling in the code catches only specific exceptions. To make the script more robust, consider catching all possible exceptions and providing informative error messages for users.

5. Use constants for configuration values: Instead of hardcoding configurable values like the log directory or file name format, use constants defined at the beginning of your script. This will make it easier to modify the configuration without having to search through the entire script.

6. Add comments to explain complex sections of the code: Some parts of the script are quite complex and could benefit from additional explanatory comments. This will help others understand your code more easily.

7. Use PowerShell's built-in logging functionality: Instead of writing logs manually, consider using PowerShell's built-in logging features like `Add-Content` to write logs in a more structured way. This will make it easier to parse the logs later on if needed.

8. Add unit tests: To ensure the script works as expected, add unit tests for each function to test its functionality under various conditions. This will help catch bugs and regressions before they reach users.

9. Use PowerShell's advanced formatting capabilities: Consider using PowerShell's advanced formatting capabilities like `Format-Table` or `Format-Wide` to make the output more readable.

10. Use modules instead of embedding scripts: Embedding scripts in the script makes it harder to manage dependencies and update them separately. Consider using PowerShell modules instead, which allow you to separate code into multiple files that can be easily managed and updated independently.

## Source Code
```powershell
function Get-WindowsProductKey {
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
    .INPUTS
        None. You cannot pipe objects to Get-WindowsActivationInfo.
    .OUTPUTS
        [pscustomobject] with properties:
        - ComputerName
        - OemProductKey
        - PartialKeys
        - ActivationReport
    .EXAMPLE
    Get-WindowsActivationInfo -ComputerName "RemotePC" -Credential (Get-Credential)
    .EXAMPLE
    Get-WindowsActivationInfo
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    # Determine export root from config
    $exportRoot = $script:TechToolboxConfig["settings"]["windowsActivation"]["logDir"]
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
    $fileName = $script:TechToolboxConfig["settings"]["windowsActivation"]["fileNameFormat"]
    $fileName = $fileName -replace '{computer}', $ComputerName
    $fileName = $fileName -replace '{yyyyMMdd-HHmmss}', $timestamp
    $exportPath = Join-Path $exportRoot $fileName

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
[SIGNATURE BLOCK REMOVED]

```
