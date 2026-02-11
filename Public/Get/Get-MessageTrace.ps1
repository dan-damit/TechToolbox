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
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDSKQODZ1mkr10o
# cvS6gp/W265Kpeywn71dvmSmYz3Tn6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDqYWLSf0/m
# po/8b6sSuhV0IWamysjn52IA17vHxumAtDANBgkqhkiG9w0BAQEFAASCAgDCO46m
# Yv97vPB4pFvkolJaQ9Whvvoexr5kuRV2a8Rktm/j26/gAh6uwfyv5D8BbVxVT2ac
# RPCXu1qLCfUVgXcLBhrBx/pKObhUJmS6RYYl5rTFDKkAe16Qd84k73AQV2n6by7t
# 17ifWCWWjnMWIiECFp0pCSLk+kh3+PgSEodzBGdwUCrprKoevIeCEdHf76hVybC+
# JWT6QFwxXLRpv3nwyjfBxQRNsVUn6NFHYHOwFtzJKJIH1ybIM29JaO6Msa65mIjT
# ldh6v5cGS+efK5jEcdE4eOnUDp3NvXJt/UkotdDnyR4QmZ+yL61vMvJdCEo5Rfo9
# y3HyeBafsvKEaTtNigmB/CBRUvfJWOL71MtRXKD3iOBxjXV+NmPG6OFOykIYHVvM
# JHJJUW1qsjvBtOsMxG4OMFgJt4IgnadPcHKwlk09WZops6QBtXjCKroKpM6NB2br
# +/A6aR5lhzsulgxQRwBtVs7FL/1J+S96YawzCFCCRuVLtfAV/YENiu9+HBjRU3AO
# neFxPDfJaB9mnbAtknnyn0rbkBpWDm7dnzMiX/7vJ0RgmYG4hvWNQL+Zxd5RC0PJ
# nIzUEvjNcy6DGsFt/7+Dc2e+aSNkgUTPpvHCmDisB2geGmY/eIA9uTSDeB2Jydzr
# qiIcYP5uWhhpXN5rJGk8R7OlVT36cT6f0YASSKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTEwMzUxMTlaMC8GCSqGSIb3DQEJBDEiBCDdfDR/dzw1vKtdpkmG
# 4nVdbGKHvrqhKq6YBimWCCKmUjANBgkqhkiG9w0BAQEFAASCAgBWn6IrIfUbvSDr
# OakHEbGah6iSG5URkAuAEXwkNXXcVgC6G9j1v86CeMmv8oIOIfKAlHLsS1BZSSq1
# b9Fpke4VuYsKOkD8F3pqVVzLf1NtbXUQAFHCbrfnNu5gp6dESoBvdvcstivaelrR
# kPUGPkMDN28nBlOJDWqz08ewEJSO7siE8f6+Kk3j1cnKmEneuGTEcW9OZ14oL9fz
# 7Vn4RxOTZd8NwdzA0pUGpKHFwC37VIBYnkQYFR9P6duaFeQ3kno5dR/OtHKseW3d
# Vu2qt5wG7jQdvKN0sQi+soRsnJA9Hee8nB3G42YhRJuW36W8bi7oDPCi/2UtrRHa
# 16qsebJrQKyXs0yaip6vXvFTEI8m/Rr63epR3YGGI9lFmzqzyOT2RbwCFur7wxL4
# Ni9Gh20j4gmp9/mlW6L6dE4l5Ss1loydHbB2a36lvOcPMpkOSpAuuvp5lzwrcaYm
# xw06eel/NxSiC/xqb0TGyQ95eHDDZoRlbaSwxZ8TO7jyezz3e0ACC0KiD7JeJl10
# uCPOKdVy3N3qTjReoPRuyT45EwdE6a/bNgae7yRZC+LgBQ4l9TgN7dm8uVZxj0zR
# 3hRH48lmbrlonIFLwkNRRcqonHmSqiPyf1DiXjY5Mz/aFDmqDDFeQz4Qtf/tk3kS
# 8IGOe1WnN801YSnPDLr/93BvZrza/g==
# SIG # End signature block
