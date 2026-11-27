function Get-MessageTrace {
    <#
    .SYNOPSIS
    Retrieves Exchange Online message trace summaries and per-recipient details
    using the V2 cmdlets, with automatic date-range chunking and throttle-aware
    retries.

    .DESCRIPTION
    Executes a full message trace workflow against Exchange Online:

      1. VALIDATION Confirms that at least one filter (MessageId, Sender,
           Recipient, or Subject) is supplied and that StartDate < EndDate.

      2. CONNECTION Auto-connects to Exchange Online if the V2 cmdlets are not
           already visible in the session. Uses Connect-ExchangeOnlineAlways
           (internal wrapper) when available, otherwise falls back to the native
           Connect-ExchangeOnline.

      3. CHUNKED SUMMARY QUERY (Get-MessageTraceV2) EXO limits each
           Get-MessageTraceV2 request to a 10-day window and returns at most
           5,000 rows per call. This function automatically splits the requested
           date range into ≤10-day slices and uses the continuation-token
           pattern (StartingRecipientAddress + adjusted EndDate) to page through
           result sets larger than 5,000 rows.

      4. THROTTLE HANDLING All EXO calls are wrapped in an exponential-backoff
           retry loop (up to 5 attempts, doubling from 1 s to a 30 s cap) that
           retries on HTTP 429 / 503 / "Too many requests" / "temporarily
           unavailable" errors. A 200 ms inter-request pause is applied between
           continuation pages to stay within the tenant rate limit (~100
           requests / 5 min).

      5. DETAIL QUERY (Get-MessageTraceDetailV2) For every row in the summary,
           individual delivery-event details are fetched by MessageTraceId +
           RecipientAddress. Non-fatal per-recipient failures are logged as
           warnings and do not abort the run.

      6. EXPORT (optional) When settings.messageTrace.autoExport is true, or
           when -ExportFolder is supplied, both the summary view and the detail
           rows are passed to Export-MessageTraceResults. The -WhatIf flag is
           honoured; no files are written during a preview run.

      7. DISCONNECT Calls Invoke-DisconnectExchangeOnline at the end of every
           run.

    DATE HANDLING All timestamps returned by EXO are UTC. The local datetime
    values you pass to -StartDate / -EndDate are forwarded as-is; be mindful of
    timezone offset when specifying narrow windows.

    SUBJECT FILTER TYPE The SubjectFilterType parameter is auto-resolved at
    runtime against the actual enum exposed by the installed EXO module version.
    The resolution order is: caller-supplied value → config default → "Contains"
    → first available enum value. An invalid caller-supplied value falls back
    with a warning rather than a hard error.

    .PARAMETER MessageId
    Internet Message-ID of the email to trace (e.g.
    "<abc123@mail.contoso.com>"). Passed directly to Get-MessageTraceV2 as the
    MessageId filter. Can be combined with Sender/Recipient.

    .PARAMETER Sender
    SMTP address of the sending mailbox to filter on (e.g. "alice@contoso.com").
    Passed to Get-MessageTraceV2 as SenderAddress. Supports partial values only
    insofar as EXO's own filter supports them.

    .PARAMETER Recipient
    SMTP address of the recipient to filter on (e.g. "bob@contoso.com"). Passed
    to Get-MessageTraceV2 as RecipientAddress.

    .PARAMETER Subject
    Subject text to filter on. The matching mode is controlled by
    -SubjectFilterType (default: Contains). Wildcards are not supported; the
    value is passed verbatim to the EXO cmdlet.

    .PARAMETER SubjectFilterType
    Controls how the -Subject value is matched. Accepted values depend on the
    installed EXO module version (typically: Contains, StartsWith, Equals /
    Exact). When omitted, "Contains" is used if supported by the module,
    otherwise the first available enum value is selected automatically. Ignored
    when -Subject is not specified.

    .PARAMETER StartDate
    The inclusive start of the trace window. Accepts any [datetime] value.
    Defaults to now minus settings.messageTrace.defaultLookbackHours (config),
    falling back to 48 hours when the config value is absent or zero. EXO
    supports a maximum history of 90 days from today.

    .PARAMETER EndDate
    The inclusive end of the trace window. Defaults to the current date/time
    when omitted. Must be later than -StartDate.

    .PARAMETER ExportFolder
    Filesystem path to write CSV export files into. Overrides
    settings.messageTrace.defaultExportFolder (and the global
    paths.exportDirectory fallback) for this invocation. When omitted and
    settings.messageTrace.autoExport is false, no files are written.

    .INPUTS
    None. This function does not accept pipeline input.

    .OUTPUTS
    None. Results are written to the console via Write-Log, and optionally
    exported to CSV by Export-MessageTraceResults. No objects are returned to
    the pipeline.

    .EXAMPLE
    Get-MessageTrace -Sender "alice@contoso.com"

    Traces all mail from alice@contoso.com over the configured default lookback
    window (e.g. last 48 hours). Results are displayed in the console.

    .EXAMPLE
    Get-MessageTrace -Sender "alice@contoso.com" -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date)

    Traces mail from alice over the last 7 days. The date range is automatically
    split into ≤10-day chunks (only one chunk needed here).

    .EXAMPLE
    Get-MessageTrace -Recipient "bob@contoso.com" -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)

    30-day recipient trace. Three ≤10-day slices are issued automatically.

    .EXAMPLE
    Get-MessageTrace -Subject "Invoice" -SubjectFilterType StartsWith -StartDate (Get-Date).AddDays(-3)

    Traces messages whose subject starts with "Invoice" over the last 3 days.

    .EXAMPLE
    Get-MessageTrace -MessageId "<abc123@mail.contoso.com>" -Sender "alice@contoso.com"

    Combines MessageId and Sender filters to narrow results to a specific
    message from a known sender.

    .EXAMPLE
    Get-MessageTrace -Sender "alice@contoso.com" -ExportFolder "C:\Exports\Traces"

    Runs the trace and writes summary + detail CSV files to the specified
    folder, overriding the default export path from config.

    .EXAMPLE
    Get-MessageTrace -Sender "alice@contoso.com" -WhatIf

    Previews the trace run — EXO queries are still executed, but no CSV files
    are written and no disconnect is performed.

    .NOTES
    - Requires ExchangeOnlineManagement module v3.7.0 or later, which exposes
      Get-MessageTraceV2 and Get-MessageTraceDetailV2 after connecting.
    - EXO message trace history is limited to 90 days from today.
    - Each Get-MessageTraceV2 call covers at most 10 days and returns up to
      5,000 rows; both limits are handled automatically by this function.
    - All EXO timestamps are returned in UTC regardless of local timezone.
    - The 200 ms inter-page sleep and 5-attempt backoff are tuned for the
      default tenant throttle limit (~100 EXO requests per 5 minutes).

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-MessageTrace

    .LINK
    Export-MessageTraceResults

    .LINK
    Connect-ExchangeOnlineAlways

    .LINK
    Invoke-DisconnectExchangeOnline
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter()][string]  $MessageId,
        [Parameter()][string]  $Sender,
        [Parameter()][string]  $Recipient,
        [Parameter()][string]  $Subject,
        [Parameter()][string]  $SubjectFilterType,
        [Parameter()][datetime]$StartDate,
        [Parameter()][datetime]$EndDate,
        [Parameter()][string]  $ExportFolder
    )

    if (-not $PSBoundParameters.ContainsKey('StartDate') -or $null -eq $StartDate) {
        Write-Log -Level Error -Message 'StartDate is required.'
        throw 'StartDate is required.'
    }

    # --- Config & defaults ---
    Initialize-TechToolboxRuntime

    $exo = $script:cfg.settings.exchangeOnline
    $mt = $script:cfg.settings.messageTrace

    # Make sure our in-house EXO module is imported
    Import-ExchangeOnlineModule  # v3.7.0+ exposes V2 cmdlets after connect

    # Lookback hours (safe default)
    $lookbackHours = [int]$mt.defaultLookbackHours
    if ($lookbackHours -le 0) { $lookbackHours = 48 }

    # Auto export flag
    $autoExport = [bool]$mt.autoExport

    # Resolve export folder default
    $defaultExport = $mt.defaultExportFolder
    if ([string]::IsNullOrWhiteSpace($defaultExport)) {
        $defaultExport = $script:cfg.paths.exportDirectory
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
    # Import only the commands this wrapper needs so EXO's deprecated Get-MessageTrace
    # does not shadow the TechToolbox function after the first run.
    function Confirm-EXOConnected {
        if (-not (Get-Command -Name Get-MessageTraceV2 -ErrorAction SilentlyContinue)) {
            $requiredExoCommands = @(
                'Get-MessageTraceV2',
                'Get-MessageTraceDetailV2',
                'Disconnect-ExchangeOnline'
            )

            $connectCmd = Get-Command -Name Connect-ExchangeOnlineAlways -ErrorAction SilentlyContinue
            if ($connectCmd) {
                try {
                    $connectParams = @{}

                    if ($connectCmd.Parameters.ContainsKey('ShowBanner')) {
                        $connectParams.ShowBanner = $false
                    }

                    if ($connectCmd.Parameters.ContainsKey('ShowProgress')) {
                        $connectParams.ShowProgress = [bool]$exo.showProgress
                    }

                    if ($connectCmd.Parameters.ContainsKey('CommandName')) {
                        $connectParams.CommandName = $requiredExoCommands
                    }

                    & $connectCmd @connectParams | Out-Null
                }
                catch {
                    Write-Log -Level Error -Message ("Failed to connect to Exchange Online: {0}" -f $_.Exception.Message)
                    throw
                }
            }
            else {
                try {
                    $nativeConnectCmd = Get-Command -Name Connect-ExchangeOnline -ErrorAction Stop
                    $connectParams = @{}

                    if ($nativeConnectCmd.Parameters.ContainsKey('ShowBanner')) {
                        $connectParams.ShowBanner = $false
                    }

                    if ($nativeConnectCmd.Parameters.ContainsKey('ShowProgress')) {
                        $connectParams.ShowProgress = [bool]$exo.showProgress
                    }

                    if ($nativeConnectCmd.Parameters.ContainsKey('CommandName')) {
                        $connectParams.CommandName = $requiredExoCommands
                    }

                    & $nativeConnectCmd @connectParams | Out-Null
                }
                catch {
                    Write-Log -Level Error -Message ("Failed to connect to Exchange Online via native Connect-ExchangeOnline: {0}" -f $_.Exception.Message)
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

    # --- Resolve SubjectFilterType with preference for user request, then
    # config default, then sensible fallback ---
    function Resolve-SubjectFilterType {
        param(
            [Parameter()][string]$Requested,
            [Parameter(Mandatory)][object]$TraceCommand,
            [Parameter()][string]$Default = 'Contains'
        )

        # If cmdlet doesn't expose SubjectFilterType, return $null (older module behavior)
        if (-not $TraceCommand.Parameters.ContainsKey('SubjectFilterType')) { return $null }

        $p = $TraceCommand.Parameters['SubjectFilterType']
        $allowed = @()

        # If it's an enum, capture allowed values
        try {
            if ($p.ParameterType -and $p.ParameterType.IsEnum) {
                $allowed = $p.ParameterType::GetEnumNames()
            }
        }
        catch { }

        # If user requested one, accept it if valid (case-insensitive)
        if ($Requested) {
            if (-not $allowed -or ($allowed -contains $Requested)) { return $Requested }

            $match = $allowed | Where-Object { $_.ToLower() -eq $Requested.ToLower() } | Select-Object -First 1
            if ($match) { return $match }

            Write-Log -Level Warn -Message ("Requested SubjectFilterType '{0}' not valid. Allowed: {1}. Falling back to '{2}'." -f $Requested, ($allowed -join ', '), $Default)
        }

        # Default preference (you said Contains is best)
        foreach ($candidate in @($Default, 'StartsWith', 'Equals', 'Exact')) {
            if (-not $allowed -or ($allowed -contains $candidate)) { return $candidate }
        }

        # If enum exists but none matched, pick first as last resort
        if ($allowed.Count -gt 0) { return $allowed[0] }

        return $null
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

    # --- Helper: safely read a field from varied EXO object shapes ---
    function Get-TraceFieldValue {
        param(
            [Parameter()][object]$InputObject,
            [Parameter(Mandatory)][string]$Name
        )

        if ($null -eq $InputObject) { return $null }

        if ($InputObject -is [System.Collections.IDictionary]) {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }
            return $null
        }

        try {
            $value = $InputObject.$Name
            if ($null -ne $value) {
                return $value
            }
        }
        catch { }

        try {
            if ($InputObject.PSObject -and $InputObject.PSObject.Properties) {
                $prop = $InputObject.PSObject.Properties[$Name]
                if ($prop) {
                    return $prop.Value
                }
            }
        }
        catch { }

        return $null
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
            [Parameter()][string] $SubjectFilterType,
            [Parameter()][int]    $ResultSize = 5000
        )

        # Docs: V2 supports 90 days history but only 10 days per request; up to
        # 5000 rows; times are returned as UTC. When result size is exceeded,
        # query subsequent data by using StartingRecipientAddress and EndDate
        # with the values from the previous result's Recipient address and
        # Received time.
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
            $canContinue = $true

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
                if ($Subject) {
                    $params.Subject = $Subject

                    # Newer EXO requires SubjectFilterType whenever Subject is specified
                    $resolvedSft = Resolve-SubjectFilterType -Requested $SubjectFilterType -TraceCommand $getTraceCmd -Default 'Contains'
                    if ($resolvedSft) {
                        $params.SubjectFilterType = $resolvedSft
                    }
                }

                if ($continuationRecipient) {
                    $params.StartingRecipientAddress = $continuationRecipient
                }

                $batch = Invoke-WithBackoff { & $getTraceCmd @params }
                $batchItems = @($batch)
                $batchCount = $batchItems.Count

                if ($batchCount -gt 0) {
                    $results.AddRange($batchItems)

                    # Continuation: use the oldest row that has both RecipientAddress and Received.
                    $last = $batchItems |
                    Where-Object {
                        $recipientValue = Get-TraceFieldValue -InputObject $_ -Name 'RecipientAddress'
                        $receivedValue = Get-TraceFieldValue -InputObject $_ -Name 'Received'

                        -not [string]::IsNullOrWhiteSpace([string]$recipientValue) -and
                        $null -ne $receivedValue
                    } |
                    Sort-Object Received -Descending |
                    Select-Object -Last 1

                    if ($last) {
                        $continuationRecipient = [string](Get-TraceFieldValue -InputObject $last -Name 'RecipientAddress')
                        $continuationEndUtc = Get-TraceFieldValue -InputObject $last -Name 'Received'
                    }
                    else {
                        if ($batchCount -ge $ResultSize) {
                            Write-Log -Level Warn -Message "Continuation token could not be derived from this batch (missing RecipientAddress/Received). Stopping pagination for this slice to avoid duplicate-looping."
                        }
                        $canContinue = $false
                    }

                    # Pace to respect tenant throttling (100 req / 5 min)
                    Start-Sleep -Milliseconds 200
                }
                else {
                    $continuationRecipient = $null
                    $canContinue = $false
                }

            } while ($batchCount -ge $ResultSize -and $canContinue)

            $sliceStart = $sliceEnd
        }

        return $results
    }

    try {
        # --- Log filters (friendly) ---
        Write-Log -Level Info -Message "Message trace filters:"
        Write-Log -Level Info -Message ("  MessageId : {0}" -f ($MessageId ?? '<none>'))
        Write-Log -Level Info -Message ("  Sender    : {0}" -f ($Sender ?? '<none>'))
        Write-Log -Level Info -Message ("  Recipient : {0}" -f ($Recipient ?? '<none>'))
        Write-Log -Level Info -Message ("  Subject   : {0}" -f ($Subject ?? '<none>'))
        Write-Log -Level Info -Message ("  Window    : {0} → {1} (UTC shown by EXO)" -f $StartDate.ToString('u'), $EndDate.ToString('u'))

        # --- Execute (chunked) ---
        $summary = Invoke-MessageTraceV2Chunked `
            -StartDate         $StartDate `
            -EndDate           $EndDate `
            -MessageId         $MessageId `
            -SenderAddress     $Sender `
            -RecipientAddress  $Recipient `
            -Subject           $Subject `
            -SubjectFilterType $SubjectFilterType `
            -ResultSize        5000

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
            $mtid = $null
            $rcpt = $null

            $mtid = Get-TraceFieldValue -InputObject $row -Name 'MessageTraceId'
            $rcpt = Get-TraceFieldValue -InputObject $row -Name 'RecipientAddress'

            if (-not $mtid -or -not $rcpt) { continue }

            try {
                $details = Invoke-WithBackoff { & $getDetailCmd -MessageTraceId $mtid -RecipientAddress $rcpt -ErrorAction Stop }
                if ($details) {
                    $detailsView = @($details | Select-Object `
                        @{n = 'Recipient'; e = { $rcpt } },
                        @{n = 'MessageTraceId'; e = { $mtid } },
                        Date, Event, Detail)
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
    }
    finally {
        Write-Log -Level E-Info -Message "`nRemember to disconnect from Exchange Online..."
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAMZsifU7zwHxpr
# PZflaW0pTH9SiYrxgwvPs94KiAGaUaCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBJ
# /Stre6Ml22GqAdculm2f3R9ga90MuIFyTv7rOxG2ozANBgkqhkiG9w0BAQEFAASC
# AYB7A6HpBR79iJOj02X24wNyfPZtsUzdPiacgN439Pe2pYcCvM/BVAZjN7RKCREv
# gNlUqD8s/6OADJ6j1v8qCiiINtVZdQT058t00ymrgCOPeTM5FOigdvdMuQuqlNs4
# ASO+vNSsAotfPX7iAeT8/s3ORnhT36/+BlV+51b7JW4MInStd35eyGyhfrteRKpp
# lV71JpgAnCIR07RTbh6lBf6Fsb/wdi5zy1d+gRtPh14cDgUJ4ArBNukzTfu34pGo
# VG3Ef4R3bDFPiEtw8A1qfxZRnCCYAzo2wr2SCCGJ0/mr++c+JwEbBeODSX4TTau6
# bVVviDeKza6Y+qVNONSiO2v5jasIATDwPtP38kD4z7ZgXRKTP68pcDHyOJK01ZEF
# 7TPiMPO096AAlbV9qmlRwCkrZe/LXNiopgfVafN+gLsReIv9FZJr/bGPxm+fVuhC
# aIAqHqp4+lPh2TdOKeSqfYSzkzI71BuJI9edAtUqT/qa9PFwfsMTU2hxPKTHLBdM
# gMehggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDMyWjAvBgkqhkiG
# 9w0BCQQxIgQgU6+JxRY3WzR/0zN1QKoBC3NLglBXHSBtn4sLqkzJpVUwDQYJKoZI
# hvcNAQEBBQAEggIAFqud+up17hNRkJn2EVZdzmdz3HPuZhQ/vIxXglmnziEBEUsQ
# yxJodui2xRl4RWyLN5fvtVLXeucJwEdFQDS4is2gA28ffmaZv5ILWSwuHkqIAm+L
# 68oLpjYlbtsfBC2RH0D/X7tSpypX70iYu3QLvJ5c3PUXFruN6DM4Px9LRDSZ1yMy
# OGhTJBmGJcn2AuN3HSJck+DxHfFqTEeATtaUJGh/zHO2Ps7HZGhNS5ZXEJGpjnPH
# 9umZFtvgQt06DK/ZhyewyZi5k7CVbVJaFRf/2RG8/ZKRyBG/3VHolxPFW134Uhvc
# oeNZ+hUxe6GEulSWWbDuAn5fjKLkFeOilq8QN+N6Y4GuSaCYqfxJEFSdsGqHzdXH
# 4Lrbj0nxt0Vs4mu7p0oZ8D/FVzOwMAbKHxsZDYbnJLXhkdypZEEOqqQO06q9Ly07
# KDgIDaZ8vIuQQZSZ/DrGRwxZooKz/EC74jRv0O6/r8KkQ+Tj8Li1rxN9vuOaPOtn
# as04IxMHmtPeU3mPeqO1Q0RknuNwm2gtgXP6D8PXXpskAa6t/SMuJw1Nf3gCucvQ
# dlyl3+obYhxqlkiOjTAtNPoc2f3pPxfJgYgck635JawqWHkD3W5luNc7BHahLkSs
# dbx4yFPkzMXJuFwQJL4Fm6IvDrFz/uyy8wOUENHO7nph4TxTRzlwD6jMZTs=
# SIG # End signature block
