# Code Analysis Report
Generated: 2/7/2026 8:08:06 PM

## Summary
 The provided PowerShell script, `Invoke-RemoteSystemCollection`, is a function that runs PDQ diagnostics on a remote system via a one-shot Scheduled Task. Here's an analysis of the code and suggestions for potential improvements:

1. **Code Organization**: The script could be organized better by using functions to separate different tasks such as preparing the payload, creating the scheduled task, and cleaning up after the task completes. This would make the script more readable and easier to maintain.

2. **Error Handling**: Error handling could be improved throughout the script. Currently, errors are handled in specific places, but a consistent error-handling strategy should be applied across the entire script to provide better feedback to users when issues occur.

3. **Comments**: Some parts of the code lack sufficient comments explaining what they do or why they are necessary. Adding more detailed and descriptive comments would make the script easier for other developers to understand and maintain.

4. **Variables Naming**: Variable names could be improved to better reflect their purpose. For example, `res` is unclear, while `remoteExecutionResult` or `executionResults` might provide more context.

5. **Parameters Validation**: It would be beneficial to validate the input parameters to ensure they meet certain criteria (e.g., check if the provided session object is valid). This can help prevent errors and improve the user experience.

6. **Function Parameters Organization**: The function definition could be reorganized to group related parameters together, making it easier to understand what each parameter does at a glance.

7. **Error Messages**: Error messages should be more descriptive and informative. For example, instead of throwing an error saying that "Get-SystemWorkerScriptContent is not available," the function could check if the required private function is loaded in the module before running, and provide a more detailed error message explaining why the script failed.

8. **Code Formatting**: The code formatting could be improved to better align with PowerShell style guide recommendations. For example, indenting code blocks consistently, adding blank lines between sections, and using consistent naming conventions for variables and functions.

9. **Input Validation**: Add validation checks for the input parameters like `Session`, `Timestamp`, `ExtraPaths` and `ConnectDataPath`. Ensure that they are of expected data types and meet certain criteria (e.g., valid computer name or timestamp format).

10. **Logging**: Implementing logging would provide better insight into the script's execution, making it easier to diagnose issues if they occur. This could include logging the creation and deletion of scheduled tasks, as well as any errors that may arise during the process.

## Source Code
```powershell
function Invoke-RemoteSystemCollection {
    <#
    .SYNOPSIS
      Run the PDQ diagnostics on a remote host under SYSTEM via a one-shot Scheduled
      Task.
    
    .DESCRIPTION
      - Sends a small JSON args file and the SYSTEM worker script to the remote host
        (in C:\Windows\Temp).
      - Registers a one-time scheduled task to run the worker as SYSTEM.
      - Waits (up to 180s) for a done flag, then returns the remote staging and zip
        paths.
      - Leaves the ZIP in C:\Windows\Temp on the remote for the caller to retrieve.
      - Cleans up the scheduled task registration and temp files best-effort.
    
    .PARAMETER Session
      A live PSSession to the remote computer.
    
    .PARAMETER Timestamp
      Timestamp string (yyyyMMdd-HHmmss) used in names. Typically generated once by
      the caller and passed in.
    
    .PARAMETER ExtraPaths
      Additional file/folder paths on the remote target to include in the
      collection.
    
    .PARAMETER ConnectDataPath
      PDQ Connect agent data root on the remote target. Default (if not provided
      remotely) is $env:ProgramData\PDQ\PDQConnectAgent Note: Value is passed to the
      worker; if $null or empty, worker uses its own default.
    
    .OUTPUTS
      PSCustomObject with:
        - Staging : remote staging folder
          (C:\Windows\Temp\PDQDiag_<Computer>_<Timestamp>)
        - ZipPath : remote zip path
          (C:\Windows\Temp\PDQDiag_<Computer>_<Timestamp>.zip)
        - Script  : remote worker script path
        - Args    : remote args JSON path
    
    .NOTES
      Requires Private:Get-SystemWorkerScriptContent to be available in the local
      module so we can pass its content to the remote.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Mandatory)]
        [string]$Timestamp,

        [string[]]$ExtraPaths,

        [string]$ConnectDataPath
    )

    if (-not (Get-Command -Name Get-SystemWorkerScriptContent -ErrorAction SilentlyContinue)) {
        throw "Get-SystemWorkerScriptContent is not available. Ensure the private function is loaded in the module."
    }

    # Pull the worker content locally (here-string) and send it over in one go
    $workerContent = Get-SystemWorkerScriptContent

    # Execute the SYSTEM workflow remotely
    $res = Invoke-Command -Session $Session -ScriptBlock {
        param(
            [string]$ts,
            [string[]]$extras,
            [string]$connectPath,
            [string]$workerText
        )

        $ErrorActionPreference = 'Stop'

        # Always use C:\Windows\Temp so SYSTEM can read/write
        $tempRoot = Join-Path $env:windir 'Temp'
        $argsPath = Join-Path $tempRoot ("PDQDiag_args_{0}.json" -f $ts)
        $scrPath = Join-Path $tempRoot ("PDQDiag_worker_{0}.ps1" -f $ts)
        $stagPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME, $ts)
        $doneFlag = Join-Path $stagPath 'system_done.flag'
        $zipPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $ts)

        # Prepare arguments payload for the worker
        $payload = [pscustomobject]@{
            Timestamp       = $ts
            ConnectDataPath = $connectPath
            ExtraPaths      = @($extras)
        } | ConvertTo-Json -Depth 5

        # Write worker + args to remote temp
        $payload     | Set-Content -Path $argsPath -Encoding UTF8
        $workerText  | Set-Content -Path $scrPath  -Encoding UTF8

        # Create and start SYSTEM scheduled task
        $taskName = "PDQDiag-Collect-$ts"
        $actionArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scrPath`" -ArgsPath `"$argsPath`""
        $usedSchtasks = $false

        try {
            $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArgs
            $task = Register-ScheduledTask -TaskName $taskName -Action $act -RunLevel Highest -User 'SYSTEM' -Force
            Start-ScheduledTask -TaskName $taskName
        }
        catch {
            # Fallback to schtasks in case scheduled tasks cmdlets are restricted
            $usedSchtasks = $true
            & schtasks.exe /Create /TN $taskName /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR ("powershell.exe {0}" -f $actionArgs) /F | Out-Null
            & schtasks.exe /Run /TN $taskName | Out-Null
        }

        # Wait up to 180 seconds for the worker to finish
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $doneFlag -ErrorAction SilentlyContinue)) {
            Start-Sleep -Seconds 2
        }

        # Cleanup registration (leave the zip + staging for caller to retrieve/verify)
        try {
            if ($usedSchtasks) {
                & schtasks.exe /Delete /TN $taskName /F | Out-Null
            }
            else {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
        }
        catch {}

        # Return the paths for the caller to retrieve/clean
        [pscustomobject]@{
            Staging = $stagPath
            ZipPath = $zipPath
            Script  = $scrPath
            Args    = $argsPath
        }
    } -ArgumentList $Timestamp, $ExtraPaths, $ConnectDataPath, $workerContent

    return $res
}

[SIGNATURE BLOCK REMOVED]

```
