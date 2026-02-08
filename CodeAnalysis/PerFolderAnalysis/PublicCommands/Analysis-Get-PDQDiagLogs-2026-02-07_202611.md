# Code Analysis Report
Generated: 2/7/2026 8:26:11 PM

## Summary
 The provided PowerShell script is well-written and follows good practices, but there are a few suggestions for improvement:

1. Function documentation: The script already has good function documentation, but it could be improved by adding more details about the parameters, such as their required input types and acceptable values. This would make it easier for users to understand how to use the function correctly.
2. Error handling: While the script does handle errors during remote collection and retrieval, it could benefit from better error reporting. For example, when a computer name is not provided or an invalid computer name is given, the script should output an error message instead of simply continuing without collecting data for that computer.
3. Modularization: The script could be modularized by separating the remote collection and retrieval logic into separate functions. This would make it easier to maintain and test the different parts of the script independently.
4. Performance optimization: To optimize performance, consider using parallel processing to collect data from multiple computers simultaneously instead of sequentially. You can use the `Parallel.ForEach` method for this purpose.
5. Logging: The script uses a custom logging function, which is good practice. However, it could be improved by adding more details about the collection process for each computer, such as the start and end times, any errors that occurred, etc. This would make it easier to diagnose issues if they arise.
6. Readability: The script is generally well-written and easy to read, but consider using consistent indentation throughout the script to improve its readability. Additionally, you could use comments to explain more complex sections of the code.
7. Error handling in remote collection: During remote collection, the script uses a try/catch block to handle errors that may occur when starting the remote session or collecting data. However, it only handles exceptions thrown by the `Start-NewPSRemoteSession` and `Invoke-RemoteSystemCollection` commands. To improve error handling, consider adding more specific error checking for these commands, such as checking if they return non-zero exit codes or checking for errors in their output streams.
8. Performance optimization (continued): To further optimize performance, consider using a queue to store the computers to be collected and collecting data from multiple computers in parallel instead of sequentially. This would reduce the amount of time spent waiting for remote sessions to complete.
9. Use PowerShell Core: The script uses several PowerShell 7-specific features, such as `$Global:TTDomainCred` and `Start-NewPSRemoteSession`. While these are not available in PowerShell v5, the script could be made more versatile by using cross-platform PowerShell commands where possible.
10. Use param blocks for each function: The script defines several parameters at the top level of the script instead of within separate param blocks for each function. Consider defining parameters within a param block for each function to make it easier to manage and understand which parameters are specific to that function.

Overall, the provided PowerShell script is well-written and follows good practices. However, there are several areas where improvements could be made to enhance functionality, readability, and performance.

## Source Code
```powershell

function Get-PDQDiagLogs {
    <#
    .SYNOPSIS
      Collect PDQ diagnostics under SYSTEM context (local and remote), zip on
      target, and copy back to C:\PDQDiagLogs on the machine running this script.
    
    .DESCRIPTION
      - Local & remote: run a one-time Scheduled Task as SYSTEM that performs
        collection.
      - PS7-first remoting via New-PSRemoteSession helper if present (fallback
        included).
      - Resilient copy (Copy-Item then robocopy /B), plus Event Log export via
        wevtutil.
      - ZIP pulled back to the collector and named
        PDQDiag_<Computer>_<timestamp>.zip.
    
    .PARAMETER ComputerName
      Target computer(s). Defaults to local machine.
    
    .PARAMETER Credential
      Optional credential for remote connections. If omitted and
      $Global:TTDomainCred exists, New-PSRemoteSession helper may use it.
    
    .PARAMETER LocalDropPath
      Path on the collector to store retrieved ZIP(s). Default: C:\PDQDiagLogs.
    
    .PARAMETER TransferMode
      Retrieval method for remote ZIPs: FromSession (default), Bytes, or SMB.
    
    .PARAMETER ExtraPaths
      Extra file/folder paths on the target(s) to include.
    
    .PARAMETER ConnectDataPath
      PDQ Connect data root. Default: "$env:ProgramData\PDQ\PDQConnectAgent"
    
    .PARAMETER UseSsh, SshPort, Ps7ConfigName, WinPsConfigName
      Passed through to session creation if helper supports them.
    
    .EXAMPLE
      Get-PDQDiagLogs
    .EXAMPLE
      Get-PDQDiagLogs -ComputerName EDI-2.vadtek.com -Credential (Get-Credential)
    .EXAMPLE
      Get-PDQDiagLogs. -ComputerName PC01,PC02 -ExtraPaths 'C:\Temp\PDQ','D:\Logs\PDQ'
    #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [pscredential]$Credential,

        [string]$LocalDropPath = 'C:\PDQDiagLogs',

        [ValidateSet('FromSession', 'Bytes', 'SMB')]
        [string]$TransferMode = 'FromSession',

        [string[]]$ExtraPaths,

        [string]$ConnectDataPath = (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent'),

        [switch]$UseSsh,
        [int]$SshPort = 22,

        [string]$Ps7ConfigName = 'PowerShell.7',
        [string]$WinPsConfigName = 'Microsoft.PowerShell'
    )

    begin {
        $UseUserHelper = $false
        if (Get-Command -Name Start-NewPSRemoteSession -ErrorAction SilentlyContinue) {
            $UseUserHelper = $true
        }

        # Ensure local drop path exists on the collector
        if (-not (Test-Path -LiteralPath $LocalDropPath)) {
            New-Item -ItemType Directory -Path $LocalDropPath -Force | Out-Null
        }

        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $results = New-Object System.Collections.Generic.List[object]
    }

    process {
        foreach ($comp in $ComputerName) {
            if ([string]::IsNullOrWhiteSpace($comp)) { continue }
            $display = $comp
            $fileName = "PDQDiag_{0}_{1}.zip" -f ($display -replace '[^\w\.-]', '_'), $timestamp
            $collectorZipPath = Join-Path $LocalDropPath $fileName

            Write-Log -Level Info -Message ("[{0}] Starting collection (SYSTEM)..." -f $display)

            # Remote
            $session = $null
            try {
                $params = @{
                    ComputerName    = $comp
                    Credential      = $Credential
                    UseSsh          = $UseSsh
                    Port            = $SshPort
                    Ps7ConfigName   = $Ps7ConfigName
                    WinPsConfigName = $WinPsConfigName
                }
                $session = Start-NewPSRemoteSession @params

                $remote = Invoke-RemoteSystemCollection -Session $session -Timestamp $timestamp -ExtraPaths $ExtraPaths -ConnectDataPath $ConnectDataPath

                # Retrieve ZIP to collector
                Receive-RemoteFile -Session $session -RemotePath $remote.ZipPath -LocalPath $collectorZipPath -Mode $TransferMode
                Write-Log -Level Info -Message ("[{0}] ZIP retrieved: {1}" -f $comp, $collectorZipPath)

                # Remote cleanup
                try {
                    Invoke-Command -Session $session -ScriptBlock {
                        param($stag, $zip, $scr, $arg)
                        foreach ($p in @($stag, $zip, $scr, $arg)) {
                            if ($p -and (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue)) {
                                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                            }
                        }
                    } -ArgumentList $remote.Staging, $remote.ZipPath, $remote.Script, $remote.Args -ErrorAction SilentlyContinue | Out-Null
                }
                catch {}

                $results.Add([pscustomobject]@{
                        ComputerName = $comp
                        Status       = 'Success'
                        ZipPath      = $collectorZipPath
                        Notes        = 'Remote SYSTEM collection'
                    }) | Out-Null
            }
            catch {
                Write-Log -Level Error -Message ("[{0}] FAILED: {1}" -f $comp, $_.Exception.Message)
                $results.Add([pscustomobject]@{
                        ComputerName = $comp
                        Status       = 'Failed'
                        ZipPath      = $null
                        Notes        = $_.Exception.Message
                    }) | Out-Null
            }
            finally {
                if ($session) { Remove-PSSession $session }
            }
        }
    }

    end {
        # Emit objects (choose formatting at call site)
        return $results
    }
}

[SIGNATURE BLOCK REMOVED]

```
