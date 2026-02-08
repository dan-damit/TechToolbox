# Code Analysis Report
Generated: 2/7/2026 8:08:32 PM

## Summary
 Here's a breakdown of the given PowerShell script, along with some suggestions for improvement:

1. **Modularization**: The code includes an external script `Get-SystemWorkerScriptContent.ps1` which is not included in this example. It would be beneficial to ensure that all required scripts are available before running the function, and potentially modularize the code further into separate functions or classes if the script grows in complexity.

2. **Parameter validation**: While the script does include some parameter validation (e.g., checking if `Get-SystemWorkerScriptContent` is available), it could be improved by adding additional checks to ensure that all required parameters are provided and valid. For example, you can add validation for existing paths before creating new directories, or checking if the specified timestamp format is correct.

3. **Code organization**: The script could benefit from better organization and formatting. For instance, you can use functions to separate the different tasks (e.g., scheduling the task, waiting for completion, cleaning up) to make the code more readable and easier to maintain.

4. **Error handling**: Error handling in the script is limited. You can add more detailed error messages and handle potential errors that might occur during the execution of the script, such as when creating temporary files or scheduling tasks.

5. **Comments and documentation**: While the script includes some comments and documentation, it could be improved by adding more detailed comments explaining the purpose of each section of code, as well as any assumptions made while writing the script. This will make it easier for others to understand and maintain the script in the future.

6. **Performance**: To improve performance, you can consider optimizing the script's execution time by minimizing the use of external scripts (e.g., using inline functions instead), reducing unnecessary calls to external programs (such as `schtasks.exe`), and carefully managing the temporary files created during the execution.

Overall, the code seems well-written, but with some improvements in organization, error handling, and documentation, it could be made more maintainable and efficient.

## Source Code
```powershell
function Start-PDQDiagLocalSystem {
    <#
.SYNOPSIS
  Collect PDQ diagnostics on THIS machine under SYSTEM and drop the ZIP to LocalDropPath.

.DESCRIPTION
  - Creates a one-shot scheduled task as SYSTEM that runs the PDQ worker.
  - Worker writes to C:\Windows\Temp\PDQDiag_<Host>_<Timestamp>.zip
  - This function then copies that ZIP to -LocalDropPath.

.PARAMETER LocalDropPath
  Destination folder for the final ZIP. Default: C:\PDQDiagLogs

.PARAMETER ExtraPaths
  Additional files/folders to include.

.PARAMETER ConnectDataPath
  Root for PDQ Connect agent data. Default: "$env:ProgramData\PDQ\PDQConnectAgent"

.PARAMETER Timestamp
  Optional fixed timestamp (yyyyMMdd-HHmmss). If not provided, generated automatically.

.OUTPUTS
  [pscustomobject] with ComputerName, Status, ZipPath, Notes
#>
    [CmdletBinding()]
    param(
        [string]  $LocalDropPath = 'C:\PDQDiagLogs',
        [string[]]$ExtraPaths,
        [string]  $ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),
        [string]  $Timestamp
    )

    if (-not (Get-Command -Name Get-SystemWorkerScriptContent -ErrorAction SilentlyContinue)) {
        throw "Get-SystemWorkerScriptContent is not available. Make sure it's dot-sourced in the module (Private\Get-SystemWorkerScriptContent.ps1)."
    }

    if (-not $Timestamp) { $Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss' }
    if (-not (Test-Path -LiteralPath $LocalDropPath)) {
        New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
    }

    $tempRoot = Join-Path $env:windir 'Temp'
    $argsPath = Join-Path $tempRoot ("PDQDiag_args_{0}.json" -f $Timestamp)
    $scrPath = Join-Path $tempRoot ("PDQDiag_worker_{0}.ps1" -f $Timestamp)
    $staging = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME, $Timestamp)
    $doneFlag = Join-Path $staging  'system_done.flag'
    $zipPath = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $Timestamp)
    $finalZip = Join-Path $LocalDropPath ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $Timestamp)

    # Write worker + args for SYSTEM
    [pscustomobject]@{
        Timestamp       = $Timestamp
        ConnectDataPath = $ConnectDataPath
        ExtraPaths      = @($ExtraPaths)
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $argsPath -Encoding UTF8

    (Get-SystemWorkerScriptContent) | Set-Content -Path $scrPath -Encoding UTF8

    Write-Host ("[{0}] Scheduling SYSTEM worker..." -f $env:COMPUTERNAME) -ForegroundColor Cyan
    $taskName = "PDQDiag-Local-$Timestamp"
    $actionArg = "-NoProfile -ExecutionPolicy Bypass -File `"$scrPath`" -ArgsPath `"$argsPath`""

    $usedSchtasks = $false
    try {
        $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $actionArg
        $task = Register-ScheduledTask -TaskName $taskName -Action $act -RunLevel Highest -User 'SYSTEM' -Force
        Start-ScheduledTask -TaskName $taskName
    }
    catch {
        $usedSchtasks = $true
        & schtasks.exe /Create /TN $taskName /SC ONCE /ST 00:00 /RL HIGHEST /RU SYSTEM /TR ("powershell.exe {0}" -f $actionArg) /F | Out-Null
        & schtasks.exe /Run /TN $taskName | Out-Null
    }

    # Wait up to 3 minutes for done flag
    Write-Host ("[{0}] Waiting for completion..." -f $env:COMPUTERNAME) -ForegroundColor DarkCyan
    $deadline = (Get-Date).AddSeconds(180)
    while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $doneFlag -ErrorAction SilentlyContinue)) {
        Start-Sleep -Seconds 2
    }

    # Cleanup task registration
    try {
        if ($usedSchtasks) { & schtasks.exe /Delete /TN $taskName /F | Out-Null }
        else { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    }
    catch {}

    if (-not (Test-Path -LiteralPath $zipPath -ErrorAction SilentlyContinue)) {
        throw "SYSTEM worker did not produce ZIP at $zipPath"
    }

    Copy-Item -LiteralPath $zipPath -Destination $finalZip -Force
    Write-Host ("[{0}] ZIP ready: {1}" -f $env:COMPUTERNAME, $finalZip) -ForegroundColor Green

    # Best-effort cleanup of temp artifacts
    try {
        if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $scrPath) { Remove-Item -LiteralPath $scrPath -Force -ErrorAction SilentlyContinue }
        if (Test-Path $argsPath) { Remove-Item -LiteralPath $argsPath -Force -ErrorAction SilentlyContinue }
    }
    catch {}

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'Success'
        ZipPath      = $finalZip
        Notes        = 'Local SYSTEM collection (scheduled task)'
    }
}

[SIGNATURE BLOCK REMOVED]

```
