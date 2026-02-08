# Code Analysis Report
Generated: 2/7/2026 8:27:47 PM

## Summary
 The code provided is a PowerShell script named `Start-PDQDiagLocalElevated`. It's designed to run a local diagnostic tool (PDQ diag) under the SYSTEM context, capture its output in a log file, and optionally keep the elevated console open.

Here are some suggestions for improving the code:

1. **Modularize functions**: Break down large functions into smaller ones. For example, the runner script could be a separate function that returns the generated script content as a string, allowing for easier reuse and less clutter in the main function.

2. **Input validation**: Add input validation to check if parameters are null or empty before using them in the script. This will help prevent errors caused by invalid inputs.

3. **Error handling**: Improve error handling throughout the script. For example, instead of throwing an exception when a module is not found, you could provide a more helpful error message and suggest potential solutions.

4. **Code formatting**: Adhere to PowerShell coding standards for better readability. This includes indenting code blocks correctly, adding comments to explain complex sections, and using consistent naming conventions.

5. **Variable naming**: Use meaningful variable names that clearly indicate their purpose. For example, `$runnerLines` could be named something like `$scriptContent`.

6. **Logging**: Instead of writing detailed logs only on error, consider logging important events and actions throughout the script's execution. This will help with debugging and understanding what happened if something goes wrong.

7. **Command line arguments**: The script currently accepts parameters in a PowerShell-specific way (e.g., `-ExtraPaths`). To make it more versatile, you could also accept command-line arguments (e.g., `Start-PDQDiagLocalElevated --extra-paths C:\Temp\PDQ D:\Logs\PDQ`) which would be useful if the script is run from a non-PowerShell environment.

8. **Documentation**: Add more detailed documentation to explain what each part of the script does, as well as any assumptions or limitations. This will help others understand and maintain your code more easily.

9. **Command output**: Instead of capturing the entire output (using `Format-List *`) in the runner script, consider only capturing error information for easier debugging. For other output, you can use `Write-Output` or custom objects to display the results in the elevated console without needing to capture them in a log file.

10. **Environment variables**: Instead of hardcoding paths like `C:\PDQDiagLogs`, consider using environment variables (e.g., setting an environment variable named `$env:PDQ_LOGS` and then using that variable in your script). This will make it easier to change the log path if needed without modifying the script itself.

## Source Code
```powershell
function Start-PDQDiagLocalElevated {
    <#
    .SYNOPSIS
      Open a new elevated PowerShell console (UAC), then run the local PDQ diag
      under SYSTEM.
    
    .DESCRIPTION
      - Spawns a new console with RunAs (UAC prompt).
      - In that console: Import-Module TechToolbox, call private
        Start-PDQDiagLocalSystem.
      - Captures full transcript to C:\PDQDiagLogs\LocalRun_<timestamp>.log.
      - On error, writes detailed info and optionally pauses so you can read it.
    
    .PARAMETER LocalDropPath
      Destination folder for the final ZIP. Default: C:\PDQDiagLogs
    
    .PARAMETER ExtraPaths
      Additional files/folders to include.
    
    .PARAMETER ConnectDataPath
      Root for PDQ Connect agent data. Default:
      "$env:ProgramData\PDQ\PDQConnectAgent"
    
    .PARAMETER StayOpen
      Keep the elevated console open after it finishes (adds -NoExit and a prompt).
    
    .PARAMETER ForcePwsh
      Prefer pwsh.exe explicitly; otherwise auto-detect pwsh then powershell.
    
    .EXAMPLE
      Start-PDQDiagLocalElevated -StayOpen
    
    .EXAMPLE
      Start-PDQDiagLocalElevated -ExtraPaths 'C:\Temp\PDQ','D:\Logs\PDQ'
    #>
    [CmdletBinding()]
    param(
        [string]  $LocalDropPath = 'C:\PDQDiagLogs',
        [string[]]$ExtraPaths,
        [string]  $ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),
        [switch]  $StayOpen,
        [switch]  $ForcePwsh
    )

    # Resolve the module path (ensure the elevated console imports the same module)
    $module = Get-Module -Name TechToolbox -ListAvailable | Select-Object -First 1
    if (-not $module) { throw "TechToolbox module not found in PSModulePath." }
    $modulePath = $module.Path

    # Ensure local drop path exists (used for transcript and final ZIP)
    if (-not (Test-Path -LiteralPath $LocalDropPath)) {
        New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
    }

    # Pre-compute timestamp so both runner + private use the same naming (optional/consistent)
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $finalZip = Join-Path $LocalDropPath ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME, $timestamp)
    $logPath = Join-Path $LocalDropPath ("LocalRun_{0}.log" -f $timestamp)

    # Safely render ExtraPaths as a PowerShell literal
    $extraLiteral = if ($ExtraPaths) {
        $escaped = $ExtraPaths | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }
        "@(" + ($escaped -join ',') + ")"
    }
    else { '@()' }

    # Build the runner script content that will execute in the elevated console
    $runnerLines = @()
    $runnerLines += '$ErrorActionPreference = "Continue"'
    $runnerLines += '$VerbosePreference = "Continue"'
    $runnerLines += "if (-not (Test-Path -LiteralPath `"$LocalDropPath`")) { New-Item -ItemType Directory -Path `"$LocalDropPath`" -Force | Out-Null }"
    $runnerLines += "Start-Transcript -Path `"$logPath`" -IncludeInvocationHeader -Force | Out-Null"
    $runnerLines += "`$modulePath = `"$modulePath`""
    $runnerLines += 'Import-Module $modulePath -Force'
    $runnerLines += ""
    $runnerLines += "Write-Host ('[LOCAL] Running Start-PDQDiagLocalSystem (SYSTEM)...') -ForegroundColor Cyan"
    $runnerLines += "try {"
    $runnerLines += "    Start-PDQDiagLocalSystem -LocalDropPath `"$LocalDropPath`" -ConnectDataPath `"$ConnectDataPath`" -ExtraPaths $extraLiteral -Timestamp `"$timestamp`" | Format-List *"
    $runnerLines += "    Write-Host ('[LOCAL] Expected ZIP: $finalZip') -ForegroundColor Green"
    $runnerLines += "} catch {"
    $runnerLines += "    Write-Host ('[ERROR] ' + `$_.Exception.Message) -ForegroundColor Red"
    $runnerLines += "    if (`$Error.Count -gt 0) {"
    $runnerLines += "        Write-Host '--- $Error[0] (detailed) ---' -ForegroundColor Yellow"
    $runnerLines += "        `$Error[0] | Format-List * -Force"
    $runnerLines += "    }"
    $runnerLines += "    throw"
    $runnerLines += "} finally {"
    $runnerLines += "    Stop-Transcript | Out-Null"
    $runnerLines += "}"
    if ($StayOpen) {
        # Keep the elevated console open so you can review logs/output
        $runnerLines += "Write-Host 'Transcript saved to: $logPath' -ForegroundColor Yellow"
        $runnerLines += "Read-Host 'Press Enter to close this elevated window'"
    }

    $runnerScript = Join-Path $env:TEMP ("PDQDiag_LocalElevated_{0}.ps1" -f $timestamp)
    Set-Content -Path $runnerScript -Value ($runnerLines -join [Environment]::NewLine) -Encoding UTF8

    # Pick host exe (pwsh preferred if available or forced; else Windows PowerShell)
    $hostExe = $null
    if ($ForcePwsh) {
        $hostExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue)?.Source
        if (-not $hostExe) { throw "ForcePwsh requested, but pwsh.exe not found." }
    }
    else {
        $hostExe = (Get-Command pwsh.exe -ErrorAction SilentlyContinue)?.Source
        if (-not $hostExe) { $hostExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue)?.Source }
    }
    if (-not $hostExe) { throw "Neither pwsh.exe nor powershell.exe found on PATH." }

    $prelude = '$env:TT_ExportLocalHelper="1";'
    $args = @()
    if ($StayOpen) { $args += '-NoExit' }
    $args = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $prelude + " & `"$runnerScript`"")

    # Launch elevated; parent console stays open
    Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $args -WindowStyle Normal | Out-Null

    # Emit a quick hint in the parent console
    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'Launched'
        ZipExpected  = $finalZip
        Transcript   = $logPath
        Notes        = "Elevated console opened. Output + errors captured to transcript. Use -StayOpen to keep the window open."
    }
}

[SIGNATURE BLOCK REMOVED]

```
