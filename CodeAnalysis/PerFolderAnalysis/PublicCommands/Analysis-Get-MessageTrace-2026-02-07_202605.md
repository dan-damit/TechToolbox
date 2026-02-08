# Code Analysis Report
Generated: 2/7/2026 8:26:05 PM

## Summary
 This PowerShell script is a function named `Get-MessageTrace` that retrieves message trace data from Exchange Online using the V2 cmdlets. Here are some suggestions for enhancing its functionality, readability, and performance:

1. Organize the code into functions or classes to make it more modular and easier to maintain. For example, you could create separate functions for connecting to Exchange Online, retrieving summary data, retrieving detailed data, exporting results, etc.
2. Use PowerShell Core instead of the classic console host for cross-platform compatibility and improved performance.
3. Implement a logging mechanism using built-in PowerShell cmdlets like `Write-Verbose`, `Write-Debug`, `Write-Warning`, `Write-Error`, and `Write-Information` to provide better insight into what's happening during the execution of the script.
4. Use parameter validation attributes to ensure that input parameters meet certain criteria, such as requiring non-empty values for search filters or validating dates within a specific range.
5. Consider using PowerShell remoting (WinRM) or PSSession to reduce the impact on the Exchange Online server when running large queries, as well as improve performance by executing the script remotely.
6. Implement input and output parameter sets for different scenarios, such as exporting results only or filtering by various criteria like sender, recipient, subject, etc.
7. Utilize PowerShell jobs to run multiple tasks concurrently and manage resource usage more efficiently.
8. Leverage PowerShell modules like `PSSession` and `PowerCLI` to simplify interactions with Exchange Online and other systems.
9. Consider adding error handling and recovery mechanisms to handle unexpected errors or network issues that may arise during the execution of the script.
10. Use descriptive variable names and comments throughout the code to make it more readable and easier for others to understand.
11. Finally, implement a help system using PowerShell's built-in help features to provide documentation on how to use the function and its parameters. This will make it easier for users to learn and utilize the script effectively.

## Source Code
```powershell
function Get-MessageTrace { 
    <#
    .SYNOPSIS
    Retrieve Exchange Online message trace summary and details using V2 cmdlets
    with chunking and throttling handling.
    .DESCRIPTION
    This cmdlet retrieves message trace summary and details from Exchange Online
    using the V2 cmdlets (Get-MessageTraceV2 and Get-MessageTraceDetailV2). It
    handles chunking for date ranges over 10 days and manages throttling with
    exponential backoff retries. The cmdlet supports filtering by MessageId,
    Sender, Recipient, and Subject, and can automatically export results to CSV.
    .PARAMETER MessageId
    Filter by specific Message ID.
    .PARAMETER Sender
    Filter by sender email address.
    .PARAMETER Recipient
    Filter by recipient email address.
    .PARAMETER Subject
    Filter by email subject.
    .PARAMETER StartDate
    Start of the date range for the message trace (default: now - configured
    lookback).
    .PARAMETER EndDate
    End of the date range for the message trace (default: now).
    .PARAMETER ExportFolder
    Folder path to export results. If not specified, uses default from config.
    .EXAMPLE
    Get-MessageTrace -Sender "user@example.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)
    Retrieves message traces for the specified sender over the last 7 days.
    .NOTES
    Requires Exchange Online V2 cmdlets (3.7.0+). Ensure you are connected to
    Exchange Online before running this cmdlet.
    .INPUTS
    None.
    .OUTPUTS
    None. Outputs are logged to the console and optionally exported to CSV.
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter()][string]  $MessageId,
        [Parameter()][string]  $Sender,
        [Parameter()][string]  $Recipient,
        [Parameter()][string]  $Subject,
        [Parameter()][datetime]$StartDate,
        [Parameter()][datetime]$EndDate,
        [Parameter()][string]  $ExportFolder
    )

    # --- Config & defaults ---
    $cfg = Get-TechToolboxConfig
    $exo = $cfg["settings"]["exchangeOnline"]
    $mt = $cfg["settings"]["messageTrace"]

    # Make sure our in-house EXO module is imported
    Import-ExchangeOnlineModule  # v3.7.0+ exposes V2 cmdlets after connect

    # Lookback hours (safe default)
    $lookbackHours = [int]$mt["defaultLookbackHours"]
    if ($lookbackHours -le 0) { $lookbackHours = 48 }

    # Auto export flag
    $autoExport = [bool]$mt["autoExport"]

    # Resolve export folder default
    $defaultExport = $mt["defaultExportFolder"]
    if ([string]::IsNullOrWhiteSpace($defaultExport)) {
        $defaultExport = $cfg["paths"]["exportDirectory"]
    }

    # Resolve StartDate/EndDate defaults
    if (-not $StartDate) { $StartDate = (Get-Date).AddHours(-$lookbackHours) }
    if (-not $EndDate) { $EndDate = (Get-Date) }

    if ($StartDate -ge $EndDate) {
        Write-Log -Level Error -Message "StartDate must be earlier than EndDate."
        throw "Invalid date window."
    }

    # --- Validate search criteria ---
    if (-not $MessageId -and -not $Sender -and -not $Recipient -and -not $Subject) {
        Write-Log -Level Error -Message "You must specify at least one of: MessageId, Sender, Recipient, Subject."
        throw "At least one search filter is required."
    }

    # --- Ensure EXO connection and V2 availability ---
    # V2 cmdlets are only available after Connect-ExchangeOnline (they load into tmpEXO_*).
    # We'll auto-connect (quietly) if V2 isn't visible, then re-check.  (Docs: GA + V2 usage)  [TechCommunity + Learn]
    function Confirm-EXOConnected {
        if (-not (Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
            if (Get-Command -Name Connect-ExchangeOnline -ErrorAction SilentlyContinue) {
                try {
                    # Prefer your wrapper if present
                    if (Get-Command -Name Connect-ExchangeOnlineIfNeeded -ErrorAction SilentlyContinue) {
                        Connect-ExchangeOnlineIfNeeded -ShowProgress:([bool]$exo.showProgress)
                    }
                    else {
                        Connect-ExchangeOnline -ShowBanner:$false | Out-Null
                    }
                }
                catch {
                    Write-Log -Level Error -Message ("Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
                    throw
                }
            }
        }
    }
    Confirm-EXOConnected

    # Resolve cmdlets (they are Functions exported from tmpEXO_* after connect)
    try {
        $getTraceCmd = Get-Command -Name Get-MessageTraceV2       -ErrorAction Stop
        $getDetailCmd = Get-Command -Name Get-MessageTraceDetailV2 -ErrorAction Stop
    }
    catch {
        Write-Log -Level Error -Message ("Message Trace V2 cmdlets not available. Are you connected to EXO? {0}" -f $_.Exception.Message)
        throw
    }

    # --- Helper: throttle-aware invoker with retries for transient 429/5xx ---
    function Invoke-WithBackoff {
        param([scriptblock]$Block)
        $delay = 1
        for ($i = 1; $i -le 5; $i++) {
            try { return & $Block }
            catch {
                $msg = $_.Exception.Message
                if ($msg -match 'Too many requests|429|throttle|temporarily unavailable|5\d{2}') {
                    Write-Log -Level Warn -Message ("Transient/throttle error (attempt {0}/5): {1} — sleeping {2}s" -f $i, $msg, $delay)
                    Start-Sleep -Seconds $delay
                    $delay = [Math]::Min($delay * 2, 30)
                    continue
                }
                throw
            }
        }
        throw "Exceeded retry attempts."
    }

    # --- Chunked V2 invoker (≤10-day slices + continuation when >5k rows) ---
    function Invoke-MessageTraceV2Chunked {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][datetime]$StartDate,
            [Parameter(Mandatory)][datetime]$EndDate,
            [Parameter()][string] $MessageId,
            [Parameter()][string] $SenderAddress,
            [Parameter()][string] $RecipientAddress,
            [Parameter()][string] $Subject,
            [Parameter()][int]    $ResultSize = 5000
        )
        # Docs: V2 supports 90 days history but only 10 days per request; up to 5000 rows; times are returned as UTC.  [Learn]
        # When result size is exceeded, query subsequent data by using StartingRecipientAddress and EndDate with
        # the values from the previous result's Recipient address and Received time.  [Learn]
        $sliceStart = $StartDate
        $endLimit = $EndDate
        $maxSpan = [TimeSpan]::FromDays(10)
        $results = New-Object System.Collections.Generic.List[object]

        while ($sliceStart -lt $endLimit) {
            $sliceEnd = $sliceStart.Add($maxSpan)
            if ($sliceEnd -gt $endLimit) { $sliceEnd = $endLimit }

            Write-Information ("[Trace] Querying slice {0:u} → {1:u}" -f $sliceStart.ToUniversalTime(), $sliceEnd.ToUniversalTime()) -InformationAction Continue

            $continuationRecipient = $null
            $continuationEndUtc = $sliceEnd

            do {
                $params = @{
                    StartDate   = $sliceStart
                    EndDate     = $continuationEndUtc
                    ResultSize  = $ResultSize
                    ErrorAction = 'Stop'
                }
                if ($MessageId) { $params.MessageId = $MessageId }
                if ($SenderAddress) { $params.SenderAddress = $SenderAddress }
                if ($RecipientAddress) { $params.RecipientAddress = $RecipientAddress }
                if ($Subject) { $params.Subject = $Subject }

                if ($continuationRecipient) {
                    $params.StartingRecipientAddress = $continuationRecipient
                }

                $batch = Invoke-WithBackoff { & $getTraceCmd @params }

                if ($batch -and $batch.Count -gt 0) {
                    $results.AddRange($batch)

                    # Continuation: use the oldest row's RecipientAddress and Received (UTC)
                    $last = $batch | Sort-Object Received -Descending | Select-Object -Last 1
                    $continuationRecipient = $last.RecipientAddress
                    $continuationEndUtc = $last.Received

                    # Pace to respect tenant throttling (100 req / 5 min)
                    Start-Sleep -Milliseconds 200
                }
                else {
                    $continuationRecipient = $null
                }

            } while ($batch.Count -ge $ResultSize)

            $sliceStart = $sliceEnd
        }

        return $results
    }

    # --- Log filters (friendly) ---
    Write-Log -Level Info -Message "Message trace filters:"
    Write-Log -Level Info -Message ("  MessageId : {0}" -f ($MessageId ?? '<none>'))
    Write-Log -Level Info -Message ("  Sender    : {0}" -f ($Sender ?? '<none>'))
    Write-Log -Level Info -Message ("  Recipient : {0}" -f ($Recipient ?? '<none>'))
    Write-Log -Level Info -Message ("  Subject   : {0}" -f ($Subject ?? '<none>'))
    Write-Log -Level Info -Message ("  Window    : {0} → {1} (UTC shown by EXO)" -f $StartDate.ToString('u'), $EndDate.ToString('u'))

    # --- Execute (chunked) ---
    $summary = Invoke-MessageTraceV2Chunked `
        -StartDate        $StartDate `
        -EndDate          $EndDate `
        -MessageId        $MessageId `
        -SenderAddress    $Sender `
        -RecipientAddress $Recipient `
        -Subject          $Subject `
        -ResultSize       5000

    if (-not $summary -or $summary.Count -eq 0) {
        Write-Log -Level Warn -Message "No results found. Check filters, UTC vs. local time, and the 10-day-per-call limit."
        return
    }

    # Summary view (EXO returns UTC timestamps)
    $summaryView = $summary |
    Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, MessageTraceId

    Write-Log -Level Ok   -Message ("Summary results ({0}):" -f $summaryView.Count)
    Write-Log -Level Info -Message ($summaryView | Sort-Object Received | Format-Table -AutoSize | Out-String)

    # --- Details ---
    Write-Log -Level Info -Message "Enumerating per-recipient details..."
    $detailsAll = New-Object System.Collections.Generic.List[object]

    foreach ($row in $summary) {
        $mtid = $row.MessageTraceId
        $rcpt = $row.RecipientAddress
        if (-not $mtid -or -not $rcpt) { continue }

        try {
            $details = Invoke-WithBackoff { & $getDetailCmd -MessageTraceId $mtid -RecipientAddress $rcpt -ErrorAction Stop }
            if ($details) {
                $detailsView = $details | Select-Object `
                @{n = 'Recipient'; e = { $rcpt } },
                @{n = 'MessageTraceId'; e = { $mtid } },
                Date, Event, Detail
                $detailsAll.AddRange($detailsView)
            }
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to get details for {0} / MTID {1}: {2}" -f $rcpt, $mtid, $_.Exception.Message)
        }
    }

    if ($detailsAll.Count -gt 0) {
        Write-Log -Level Ok   -Message ("Details ({0} rows):" -f $detailsAll.Count)
        Write-Log -Level Info -Message ($detailsAll | Format-Table -AutoSize | Out-String)
    }
    else {
        Write-Log -Level Warn -Message "No detail records returned."
    }

    # --- Export ---
    $shouldExport = $autoExport -or (-not [string]::IsNullOrWhiteSpace($ExportFolder))
    if ($shouldExport) {
        if ([string]::IsNullOrWhiteSpace($ExportFolder)) {
            $ExportFolder = $defaultExport
        }

        if ($PSCmdlet.ShouldProcess($ExportFolder, "Export message trace results")) {
            Export-MessageTraceResults `
                -Summary $summaryView `
                -Details $detailsAll `
                -ExportFolder $ExportFolder `
                -WhatIf:$WhatIfPreference `
                -Confirm:$false
        }
    }
    [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo)
}
[SIGNATURE BLOCK REMOVED]

```
