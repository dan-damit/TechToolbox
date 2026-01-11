
function Export-MessageTraceResults {
    <#
    .SYNOPSIS
        Exports message trace summary and details to CSV.
    .DESCRIPTION
        Creates the export folder if needed and writes Summary/Details CSVs.
        Honours -WhatIf/-Confirm via SupportsShouldProcess.
    .PARAMETER Summary
        Summary objects (Received, SenderAddress, RecipientAddress, Subject,
        Status, MessageTraceId).
    .PARAMETER Details
        Detail objects (Recipient, MessageTraceId, Date, Event, Detail).
    .PARAMETER ExportFolder
        Target folder for CSVs.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)][object[]]$Summary,
        [Parameter()][object[]]$Details,
        [Parameter(Mandatory)][string]$ExportFolder
    )

    try {
        if ($PSCmdlet.ShouldProcess($ExportFolder, 'Ensure export folder')) {
            if (-not (Test-Path -LiteralPath $ExportFolder)) {
                New-Item -Path $ExportFolder -ItemType Directory -Force | Out-Null
            }
        }

        $ts = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $sumPath = Join-Path -Path $ExportFolder -AdditionalChildPath ("MessageTraceSummary_{0}.csv" -f $ts)
        $detPath = Join-Path -Path $ExportFolder -AdditionalChildPath ("MessageTraceDetails_{0}.csv" -f $ts)

        if ($PSCmdlet.ShouldProcess($sumPath, 'Export summary CSV')) {
            $Summary | Export-Csv -Path $sumPath -NoTypeInformation -Encoding UTF8 -UseQuotes AsNeeded
        }

        if (($Details ?? @()).Count -gt 0) {
            if ($PSCmdlet.ShouldProcess($detPath, 'Export details CSV')) {
                $Details | Export-Csv -Path $detPath -NoTypeInformation -Encoding UTF8 -UseQuotes AsNeeded
            }
        }

        Write-Log -Level Ok  -Message "Export complete."
        Write-Log -Level Info -Message (" Summary: {0}" -f $sumPath)

        if (Test-Path -LiteralPath $detPath) {
            Write-Log -Level Info -Message (" Details: {0}" -f $detPath)
        }
    }
    catch {
        Write-Log -Level Error -Message ("Export failed: {0}" -f $_.Exception.Message)
        throw
    }
}
