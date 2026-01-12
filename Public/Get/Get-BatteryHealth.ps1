
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
    .OUTPUTS
        [pscustomobject[]] Battery objects with capacity and health metrics.
    .EXAMPLE
        Get-BatteryHealth
    .EXAMPLE
        Get-BatteryHealth -ReportPath 'C:\Temp\battery-report.html' -OutputJson 'C:\Temp\batteries.json' -WhatIf
        # Preview file creation/JSON export without writing.
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
        if ($null -ne $br.reportPath -and -not [string]::IsNullOrWhiteSpace($br.reportPath)) {
            $ReportPath = [string]$br.reportPath
        }
    }
    # OutputJson
    if (-not $PSBoundParameters.ContainsKey('OutputJson') -or [string]::IsNullOrWhiteSpace($OutputJson)) {
        if ($null -ne $br.outputJson -and -not [string]::IsNullOrWhiteSpace($br.outputJson)) {
            $OutputJson = [string]$br.outputJson
        }
    }
    # DebugInfo
    if (-not $PSBoundParameters.ContainsKey('DebugInfo') -or [string]::IsNullOrWhiteSpace($DebugInfo)) {
        if ($null -ne $br.debugInfo -and -not [string]::IsNullOrWhiteSpace($br.debugInfo)) {
            $DebugInfo = [string]$br.debugInfo
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
