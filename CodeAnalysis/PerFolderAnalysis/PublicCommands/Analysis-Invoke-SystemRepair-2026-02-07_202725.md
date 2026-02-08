# Code Analysis Report
Generated: 2/7/2026 8:27:25 PM

## Summary
 The provided PowerShell script is a function named `Invoke-SystemRepair` which allows for the execution of various system repair operations such as DISM RestoreHealth, SFC scannow, and Windows Update component reset, both locally and remotely.

Here are some suggestions to enhance its functionality, readability, and performance:

1. **Modularization**: The script could be further modularized by separating the local and remote execution logic into separate functions. This would make the code more maintainable and easier to test.

2. **Error Handling**: Adding error handling (try-catch blocks) can help ensure that the script behaves gracefully in case of unexpected errors during the repair operations.

3. **Documentation**: Although the script is well-documented, adding comments explaining the purpose and logic of each section could make it easier for others to understand and maintain.

4. **Input/Output validation**: The script currently doesn't validate its inputs or outputs. Adding input validation can help prevent errors caused by incorrect parameter values. Similarly, validating the output can help ensure that the script behaves as expected.

5. **Logging improvements**: Although logging is already implemented, it could be improved by including more detailed information in the log messages. This could help with debugging and understanding the behavior of the script.

6. **Parameter validation**: Adding parameter validation can help ensure that the script behaves as expected when users provide unexpected values for parameters such as `ComputerName` or `Credential`.

7. **Performance optimization**: To improve performance, you could consider optimizing the script by reducing redundancy in the code and minimizing network calls when running operations locally if possible.

8. **Usage examples**: Adding more usage examples that cover edge cases and various combinations of parameters can help users understand how to effectively use the script.

9. **Code formatting**: Following PowerShell's recommended coding style and conventions can make the code easier to read and maintain.

10. **PowerShell Core compatibility**: Ensure that the script is compatible with both PowerShell 5 and PowerShell Core, as this allows it to run on a wider range of systems. This may involve using features available only in one version or the other and providing workarounds for those cases.

## Source Code
```powershell
function Invoke-SystemRepair {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations locally or via PSRemoting.
    .DESCRIPTION
        Wraps common repair operations (DISM RestoreHealth,
        StartComponentCleanup, ResetBase, SFC, and Windows Update component
        reset) in a TechToolbox-style function with optional remote execution
        and credential support.
    .PARAMETER RestoreHealth
        Runs DISM /RestoreHealth.
    .PARAMETER StartComponentCleanup
        Runs DISM /StartComponentCleanup.
    .PARAMETER ResetBase
        Runs DISM /StartComponentCleanup /ResetBase.
    .PARAMETER SfcScannow
        Runs SFC /scannow.
    .PARAMETER ResetUpdateComponents
        Resets Windows Update components.
    .PARAMETER ComputerName
        Specifies the remote computer name to run the operations on. If not
        specified, and -Local is not set, the function will check the config for
        a default computer name.
    .PARAMETER Local
        If set, forces local execution regardless of ComputerName or config
        settings.
    .PARAMETER Credential
        Specifies the credentials to use for remote execution. Ignored if -Local
        is set.
    .INPUTS
        None. You cannot pipe objects to Invoke-SystemRepair.
    .OUTPUTS
        None. Output is written to the Information stream.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -SfcScannow
        Runs DISM RestoreHealth and SFC /scannow locally.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -ComputerName "Client01" -Credential (Get-Credential)
        Runs DISM RestoreHealth on the remote computer "Client01" using the
        specified credentials.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [switch]$RestoreHealth,

        [Parameter()]
        [switch]$StartComponentCleanup,

        [Parameter()]
        [switch]$ResetBase,

        [Parameter()]
        [switch]$SfcScannow,

        [Parameter()]
        [switch]$ResetUpdateComponents,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Local,

        [Parameter()]
        [pscredential]$Credential
    )

    # Short-circuit: nothing selected
    if (-not ($RestoreHealth -or $StartComponentCleanup -or $ResetBase -or $SfcScannow -or $ResetUpdateComponents)) {
        Write-Log -Level Warn -Message "No operations specified. Choose at least one operation to run."
        return
    }

    # --- Config hook (future-friendly) ---
    $cfg = Get-TechToolboxConfig
    $settings = $cfg["settings"]
    $repair = $settings["systemRepair"] 

    $runRemoteDefault = $repair["runRemote"] ?? $true

    # Decide local vs remote
    $targetComputer = $ComputerName
    if (-not $Local) {
        if (-not $targetComputer -and $repair.ContainsKey("defaultComputerName")) {
            $targetComputer = $repair["defaultComputerName"]
        }
    }

    $runRemoteEffective =
    -not $Local -and
    -not [string]::IsNullOrWhiteSpace($targetComputer) -and
    $runRemoteDefault

    $targetLabel = if ($runRemoteEffective) {
        "remote host $targetComputer"
    }
    else {
        "local machine"
    }

    Write-Log -Level Info -Message ("Preparing system repair operations on {0}." -f $targetLabel)

    # Build a friendly description for ShouldProcess
    $ops = @()
    if ($RestoreHealth) { $ops += "DISM RestoreHealth" }
    if ($StartComponentCleanup) { $ops += "DISM StartComponentCleanup" }
    if ($ResetBase) { $ops += "DISM ResetBase" }
    if ($SfcScannow) { $ops += "SFC /scannow" }
    if ($ResetUpdateComponents) { $ops += "Reset Windows Update Components" }

    $operationDesc = $ops -join ", "

    if ($PSCmdlet.ShouldProcess($targetLabel, "Run: $operationDesc")) {

        if ($runRemoteEffective) {
            Write-Log -Level Info -Message ("Executing repair operations remotely on [{0}]." -f $targetComputer)

            Invoke-SystemRepairRemote `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents `
                -ComputerName $targetComputer `
                -Credential $Credential
        }
        else {
            Write-Log -Level Info -Message "Executing repair operations locally."

            Invoke-SystemRepairLocal `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents
        }

        Write-Log -Level Ok -Message ("System repair operations completed on {0}." -f $targetLabel)
    }
}
[SIGNATURE BLOCK REMOVED]

```
