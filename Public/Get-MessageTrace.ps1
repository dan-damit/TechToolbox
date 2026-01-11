
function Get-MessageTrace {
    <#
    .SYNOPSIS
        Queries Exchange Online message trace (V2) by RFC822 Message-ID, shows
        summary & per-recipient details, and optionally exports CSVs.
    .DESCRIPTION
        Connects to Exchange Online if not already connected, resolves a time
        window (explicit or config-based lookback), runs Get-MessageTraceV2 and
        Get-MessageTraceDetailV2, writes tables to Information stream, and
        exports CSVs when enabled.
    .PARAMETER MessageId
        RFC822 Message-ID value from message headers (e.g., <GUID@domain.com>).
    .PARAMETER StartDate
        UTC start datetime for the trace window.
    .PARAMETER EndDate
        UTC end datetime for the trace window.
    .PARAMETER ExportFolder
        Destination folder for CSV exports. If omitted, config defaults apply
        when AutoExport is enabled.
    .EXAMPLE
        Get-MessageTrace -MessageId '<abc123@company.com>' -StartDate (Get-Date).AddHours(-24) -EndDate (Get-Date)
    .EXAMPLE
        Get-MessageTrace -MessageId '<abc123@company.com>' -WhatIf
        # Preview directory creation/CSV export without writing files.
    .NOTES
        Uses Get-MessageTraceV2 / Get-MessageTraceDetailV2; retention and
        latency apply per EXO limits.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter()][string]  $MessageId,
        [Parameter()][datetime]$StartDate,
        [Parameter()][datetime]$EndDate,
        [Parameter()][string]  $ExportFolder
    )

    # --- Config & defaults (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $exo = $cfg["settings"]["exchangeOnline"]
    $mt = $cfg["settings"]["messageTrace"]

    # Prompting and defaults (parameter-aware)
    if (-not $PSBoundParameters.ContainsKey('MessageId')) {
        # Use config-driven prompting; default to $true if unset
        $promptInputs = $mt.promptForMissingInputs
        if ($null -eq $promptInputs) { $promptInputs = $true }
    }
    else {
        # If MessageId is supplied, no need to prompt
        $promptInputs = $false
    }

    # Lookback hours (safe default)
    $lookbackHours = [int]$mt.defaultLookbackHours
    if ($lookbackHours -le 0) { $lookbackHours = 48 }

    # Auto export flag from config
    $autoExport = [bool]$mt.autoExport

    # Resolve export folder default (falls back to paths.exportDirectory)
    $defaultExport = $mt.defaultExportFolder
    if ([string]::IsNullOrWhiteSpace($defaultExport)) {
        $defaultExport = $cfg["paths"]["exportDirectory"]
    }

    # --- Connect to EXO if needed ---
    Connect-ExchangeOnlineIfNeeded -ShowProgress:([bool]$exo.showProgress)

    # --- Gather inputs (prompting only if allowed by config) ---
    if ([string]::IsNullOrWhiteSpace($MessageId) -and $promptInputs) {
        $MessageId = Read-Host "Enter RFC822 Message-ID (from message header)"
    }
    if ([string]::IsNullOrWhiteSpace($MessageId)) {
        Write-Log -Level Error -Message "MessageId is required."
        throw "MessageId is required."
    }

    # Resolve time window (StartDate/EndDate can be provided or inferred via lookback)
    $window = Resolve-MessageTraceWindow -StartDate $StartDate -EndDate $EndDate -LookbackHours $lookbackHours
    $StartDate = $window.StartDate
    $EndDate = $window.EndDate

    Write-Log -Level Info -Message ("Searching for Message-ID: {0}" -f $MessageId)
    Write-Log -Level Info -Message ("Time window (UTC): {0} to {1}" -f $StartDate.ToString('u'), $EndDate.ToString('u'))

    # --- Main trace logic (summary + details) ---
    try {
        Write-Log -Level Info -Message "Running Get-MessageTraceV2..."
        $summary = Get-MessageTraceV2 -MessageId $MessageId -StartDate $StartDate -EndDate $EndDate -ErrorAction Stop
    }
    catch {
        Write-Log -Level Error -Message ("Get-MessageTraceV2 failed: {0}" -f $_.Exception.Message)
        throw
    }

    if (-not $summary -or $summary.Count -eq 0) {
        Write-Log -Level Warn -Message "No results found. Check the date window (V2 traces have retention limits)."
        return
    }

    # Summary table (to Information stream)
    $summaryView = $summary | Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageTraceId
    Write-Log -Level Ok -Message "Summary results:"
    $summaryStr = $summaryView | Format-Table -AutoSize | Out-String
    Write-Information $summaryStr

    # Details per recipient
    Write-Log -Level Info -Message "Enumerating per-recipient details..."
    $detailsAll = @()
    foreach ($row in $summary) {
        $mtid = $row.MessageTraceId
        $rcpt = $row.RecipientAddress
        if (-not $mtid -or -not $rcpt) { continue }
        try {
            $details = Get-MessageTraceDetailV2 -MessageTraceId $mtid -RecipientAddress $rcpt -ErrorAction Stop
            $detailsView = $details | Select-Object @{n = 'Recipient'; e = { $rcpt } }, @{n = 'MessageTraceId'; e = { $mtid } }, Date, Event, Detail
            $detailsAll += $detailsView
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to get details for {0} / MTID {1}: {2}" -f $rcpt, $mtid, $_.Exception.Message)
        }
    }

    if ($detailsAll.Count -gt 0) {
        Write-Log -Level Ok -Message "Details:"
        $detailsStr = $detailsAll | Format-Table -AutoSize | Out-String
        Write-Information $detailsStr
    }
    else {
        Write-Log -Level Warn -Message "No detail records returned."
    }

    # --- Export (config-driven) ---
    $shouldExport = $autoExport -or (-not [string]::IsNullOrWhiteSpace($ExportFolder))
    if ($shouldExport) {
        if ([string]::IsNullOrWhiteSpace($ExportFolder)) { $ExportFolder = $defaultExport }
        Export-MessageTraceResults -Summary $summaryView -Details $detailsAll -ExportFolder $ExportFolder -WhatIf:$WhatIfPreference -Confirm:$false
    }

    # --- Optional disconnect prompt (config-driven) ---
    $promptDisconnect = $exo.autoDisconnectPrompt
    if ($null -eq $promptDisconnect) { $promptDisconnect = $true }
    if ($promptDisconnect) {
        $resp = Read-Host "Disconnect from Exchange Online? (Y/N)"
        if ($resp -match '^(?i)(Y|YES)$') {
            try {
                Disconnect-ExchangeOnline -Confirm:$false
                Write-Log -Level Info -Message "Disconnected from Exchange Online."
            }
            catch {
                Write-Log -Level Warn -Message ("Failed to disconnect cleanly: {0}" -f $_.Exception.Message)
            }
        }
    }
}
