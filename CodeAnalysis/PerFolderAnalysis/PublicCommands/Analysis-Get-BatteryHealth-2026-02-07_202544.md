# Code Analysis Report
Generated: 2/7/2026 8:25:44 PM

## Summary
 This PowerShell script, named `Get-BatteryHealth`, generates a Windows battery report, parses its HTML into structured JSON with health metrics, and optionally exports the JSON file. Here's an analysis of the code:

1. The function begins with a detailed help section that explains its purpose, syntax, examples, links to documentation, and other useful information. This is excellent for onboarding new developers or users who want to understand the script's functionality.

2. The function uses CmdletBinding, which allows it to work with PowerShell's cmdlet infrastructure. It also specifies its output type as an array of objects, ensuring that it produces consistent results.

3. The function takes three parameters: `ReportPath`, `OutputJson`, and `DebugInfo`. These parameters can be overridden by passing values when invoking the function or using defaults from a TechToolbox configuration file. This makes the script more flexible and user-friendly.

4. The script resolves its defaults from a normalized config when parameters are not supplied. This ensures that the script works as expected even if users don't provide all necessary parameters.

5. The script writes logs with different levels (Info, Ok, Warning, Error) to aid debugging and monitoring during execution. This is great for maintaining a clear overview of what's happening within the script.

6. To generate the battery report, the script invokes another function `Invoke-BatteryReport`. It checks if the report is generated successfully and if it contains battery data before proceeding with further processing.

7. The script reads and parses the HTML using the `Get-Content` cmdlet and a custom helper function `Get-BatteryReportHtml`. If no batteries are found, it logs an error and provides helpful information on why no batteries were detected.

8. Once battery data is parsed, the script checks whether to export the JSON file. If so, it first ensures the output directory exists and then writes the JSON content to a file.

9. The function returns an array of battery objects with capacity and health metrics as its output.

To enhance the code's functionality or readability:
- Consider using functions for tasks such as checking if a directory exists, ensuring it doesn't repeat the same logic throughout the script.
- Add comments to the helper functions (`Get-BatteryReportHtml`) to explain their purpose and how they work.
- Use constant variables to store paths or other values that don't change frequently to improve readability and maintainability.
- Consider adding error handling for exceptional cases, such as when the TechToolbox config file is not found or cannot be parsed.

## Source Code
```powershell

function Get-BatteryHealth {
    <#
    .SYNOPSIS
        Generates a Windows battery report and parses its HTML into structured
        JSON with health metrics.
    .DESCRIPTION
        Runs 'powercfg /batteryreport' to produce the HTML report, parses the
        "Installed batteries" table, computes health (FullCharge/Design ratios),
        logs progress, and exports a JSON file. Paths can be provided by
        parameters or taken from TechToolbox config (BatteryReport section).
    .PARAMETER ReportPath
        Output path for the HTML report (e.g., C:\Temp\battery-report.html). If
        omitted, uses config.
    .PARAMETER OutputJson
        Path to write parsed JSON (e.g., C:\Temp\installed-batteries.json). If
        omitted, uses config.
    .PARAMETER DebugInfo
        Optional path to write parser debug info (e.g., detected headings) when
        table detection fails. If omitted, uses config.
    .INPUTS
        None. You cannot pipe objects to Get-BatteryHealth.
    .OUTPUTS
        [pscustomobject[]] Battery objects with capacity and health metrics.
    .EXAMPLE
        Get-BatteryHealth
    .EXAMPLE
        Get-BatteryHealth -ReportPath 'C:\Temp\battery-report.html' -OutputJson 'C:\Temp\batteries.json' -WhatIf
        # Preview file creation/JSON export without writing.
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([object[]])]
    param(
        [Parameter()][string]$ReportPath,
        [Parameter()][string]$OutputJson,
        [Parameter()][string]$DebugInfo
    )

    # --- Resolve defaults from normalized config when parameters not supplied ---
    $cfg = Get-TechToolboxConfig
    $br = $cfg["settings"]["batteryReport"]

    # ReportPath
    if (-not $PSBoundParameters.ContainsKey('ReportPath') -or [string]::IsNullOrWhiteSpace($ReportPath)) {
        if ($null -ne $br["reportPath"] -and -not [string]::IsNullOrWhiteSpace($br["reportPath"])) {
            $ReportPath = [string]$br["reportPath"]
        }
    }
    # OutputJson
    if (-not $PSBoundParameters.ContainsKey('OutputJson') -or [string]::IsNullOrWhiteSpace($OutputJson)) {
        if ($null -ne $br["outputJson"] -and -not [string]::IsNullOrWhiteSpace($br["outputJson"])) {
            $OutputJson = [string]$br["outputJson"]
        }
    }
    # DebugInfo
    if (-not $PSBoundParameters.ContainsKey('DebugInfo') -or [string]::IsNullOrWhiteSpace($DebugInfo)) {
        if ($null -ne $br["debugInfo"] -and -not [string]::IsNullOrWhiteSpace($br["debugInfo"])) {
            $DebugInfo = [string]$br["debugInfo"]
        }
    }

    Write-Log -Level Info -Message "Generating battery report..."
    $reportReady = Invoke-BatteryReport -ReportPath $ReportPath -WhatIf:$WhatIfPreference -Confirm:$false
    if (-not $reportReady) {
        Write-Log -Level Error -Message ("Battery report was not generated or is empty at: {0}" -f $ReportPath)
        return
    }
    Write-Log -Level Ok -Message "Battery report generated."

    # Read and parse HTML with check for no batteries
    $html = Get-Content -LiteralPath $ReportPath -Raw
    if ($html -notmatch 'Installed batteries') {
        Write-Log -Level Warning -Message "No battery detected on this system."
        return [pscustomobject]@{
            hasBattery = $false
            reason     = "System does not contain a battery subsystem."
            timestamp  = (Get-Date)
        }
    }
    $batteries, $debug = Get-BatteryReportHtml -Html $html

    if (-not $batteries -or $batteries.Count -eq 0) {
        Write-Log -Level Error -Message "No battery data parsed."
        if ($DebugInfo -and $debug) {
            Write-Log -Level Warn -Message ("Writing parser debug info to: {0}" -f $DebugInfo)
            if ($PSCmdlet.ShouldProcess($DebugInfo, 'Write debug info')) {
                Set-Content -LiteralPath $DebugInfo -Value $debug -Encoding UTF8
            }
        }
        return
    }

    Write-Log -Level Ok -Message ("Parsed {0} battery object(s)." -f $batteries.Count)

    # Export JSON
    if ($OutputJson) {
        $dir = Split-Path -Parent $OutputJson
        if ($dir -and $PSCmdlet.ShouldProcess($dir, 'Ensure output directory')) {
            if (-not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
        }

        $json = $batteries | ConvertTo-Json -Depth 6
        if ($PSCmdlet.ShouldProcess($OutputJson, 'Write JSON')) {
            Set-Content -LiteralPath $OutputJson -Value $json -Encoding UTF8
        }
        Write-Log -Level Ok -Message ("Exported JSON with health metrics to {0}" -f $OutputJson)
    }

    return $batteries
}

[SIGNATURE BLOCK REMOVED]

```
