function Test-MailHeaderAuth {
    <#
    .SYNOPSIS
    Analyzes email headers to determine authentication status and phishing risk.

    .DESCRIPTION
    Tests mail headers for SPF, DKIM, DMARC, and ARC authentication results.
    Provides verdict on message legitimacy based on authentication alignment.

    .PARAMETER HeadersText
    Raw email headers as a string.

    .PARAMETER Path
    Path to a file containing email headers.

    .PARAMETER FromClipboard
    Read headers from clipboard (Windows only).

    .PARAMETER Format
    Output format: 'Summary' (default), 'Markdown', 'Object', or 'Json'.

    .PARAMETER AsObject
    Return PowerShell object instead of formatted output.

    .OUTPUTS
    PSCustomObject or formatted string depending on Format parameter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Text', Mandatory)][string]$HeadersText,
        [Parameter(ParameterSetName = 'File', Mandatory)][string]$Path,
        [Parameter(ParameterSetName = 'Clipboard')][switch]$FromClipboard,

        [ValidateSet('Summary', 'Markdown', 'Object', 'Json')]
        [string]$Format = 'Summary',

        [switch]$AsObject
    )

    $ErrorActionPreference = 'Stop'
    Initialize-TechToolboxRuntime
    Write-Log -Level Info -Message "Starting header analysis..."
    try {
        if ($PSCmdlet.ParameterSetName -eq 'File') {
            if (-not (Test-Path $Path)) { throw "File not found: $Path" }
            $HeadersText = Get-Content -LiteralPath $Path -Raw
            Write-Log -Level Warn -Message "Loaded headers from file: $Path"
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Clipboard') {
            if ($IsWindows) {
                $HeadersText = Get-Clipboard -Raw
                if (-not $HeadersText) { throw "Clipboard is empty." }
                Write-Log -Level Warn -Message "Loaded headers from clipboard."
            }
            else {
                throw "-FromClipboard is only supported on Windows."
            }
        }

        $block = Get-HeaderBlock -HeadersText $HeadersText
        $lines = $block.Lines

        # Extract key headers
        $kv = @{
            From       = ($lines | Where-Object { $_ -match '^(?i)From:' }        | Select-Object -First 1)
            Sender     = ($lines | Where-Object { $_ -match '^(?i)Sender:' }      | Select-Object -First 1)
            ReturnPath = ($lines | Where-Object { $_ -match '^(?i)Return-Path:' } | Select-Object -First 1)
            Subject    = ($lines | Where-Object { $_ -match '^(?i)Subject:' }     | Select-Object -First 1)
            MessageID  = ($lines | Where-Object { $_ -match '^(?i)Message-Id:' }  | Select-Object -First 1)
        }

        $fromAddr = $kv.From -replace '^(?i)From:\s*', ''
        $senderAddr = $kv.Sender -replace '^(?i)Sender:\s*', ''
        $returnPath = $kv.ReturnPath -replace '^(?i)Return-Path:\s*', ''

        $fromDomain = if ($fromAddr) { Get-Domain $fromAddr }
        $senderDomain = if ($senderAddr) { Get-Domain $senderAddr }
        $rpDomain = if ($returnPath) { Get-Domain $returnPath }

        # Collect Authentication-Results variants
        $ar_edge = $lines | Where-Object { $_ -match '^(?i)Authentication-Results:' }
        $ar_origin1 = $lines | Where-Object { $_ -match '^(?i)Authentication-Results-Original:' }
        $ar_origin2 = $lines | Where-Object { $_ -match '^(?i)X-Original-Authentication-Results:' }

        $edgeAuth = if ($ar_edge) { Format-AuthResults -Lines $ar_edge    -Label 'edge' }   else { $null }
        $originAuth = if ($ar_origin1 -or $ar_origin2) {
            Format-AuthResults -Lines ($ar_origin1 + $ar_origin2) -Label 'origin'
        }
        else { $null }

        # Received chain
        $receivedLines = $lines | Where-Object { $_ -match '^(?i)Received:' }
        $firstPublicIP = if ($receivedLines) { Get-FirstPublicIP -ReceivedLines $receivedLines } else { $null }

        # Also look for helper hints
        $xLastPublicIp = ($lines | Where-Object { $_ -match '^(?i)X-Fe-Last-Public-Client-Ip:' } | Select-Object -First 1) -replace '^(?i)X-Fe-Last-Public-Client-Ip:\s*', ''
        if (-not $firstPublicIP -and $xLastPublicIp) { $firstPublicIP = $xLastPublicIp }

        # Find envelope MailFrom (smtp.mailfrom)
        $mailFrom = $null
        if ($edgeAuth -and $edgeAuth.SPF_MailFrom) { $mailFrom = $edgeAuth.SPF_MailFrom }
        elseif ($originAuth -and $originAuth.SPF_MailFrom) { $mailFrom = $originAuth.SPF_MailFrom }
        elseif ($returnPath) { $mailFrom = $returnPath }

        $mailFromDomain = if ($mailFrom) { Get-Domain $mailFrom } else { $null }

        # Determine alignment & verdict
        $signals = [ordered]@{
            FromDomain        = $fromDomain
            MailFromDomain    = $mailFromDomain
            DKIM_Domains      = @()  # always an array
            SPF_Status_Edge   = $edgeAuth.SPF
            SPF_Status_Orig   = $originAuth.SPF
            DKIM_Status_Edge  = $edgeAuth.DKIM
            DKIM_Status_Orig  = $originAuth.DKIM
            DMARC_Status_Edge = $edgeAuth.DMARC
            DMARC_Status_Orig = $originAuth.DMARC
            ARC_Status_Edge   = $edgeAuth.ARC
            ARC_Status_Orig   = $originAuth.ARC
            CompAuth          = $edgeAuth.CompAuth
        }
    
        # Collect
        $dkimCollected = @()
        if ($edgeAuth -and ($edgeAuth.PSObject.Properties.Name -contains 'DKIM_Domains') -and $edgeAuth.DKIM_Domains) {
            $dkimCollected += @($edgeAuth.DKIM_Domains)
        }
        if ($originAuth -and ($originAuth.PSObject.Properties.Name -contains 'DKIM_Domains') -and $originAuth.DKIM_Domains) {
            $dkimCollected += @($originAuth.DKIM_Domains)
        }

        # De-dup & normalize
        $dkimDomains = @($dkimCollected | Where-Object { $_ } | Select-Object -Unique)
    
        # Prepare DKIM display vars from the finalized list (no $obj yet)
        $dkimList = @($dkimDomains)              # already unique & normalized
        $dkimCount = $dkimList.Count

        # (Optional) compute alignment now that we have final lists
        $dkimAligned = $false
        foreach ($d in $dkimDomains) {
            if ($fromDomain -and $d) {
                if ($d -eq $fromDomain -or $d -like "*.$fromDomain" -or $fromDomain -like "*.$d") {
                    $dkimAligned = $true; break
                }
            }
        }

        $spfAligned = $false
        if ($fromDomain -and $mailFromDomain) {
            if ($mailFromDomain -eq $fromDomain -or
                $mailFromDomain -like "*.$fromDomain" -or
                $fromDomain -like "*.$mailFromDomain") {
                $spfAligned = $true
            }
        }

        # Build reasons list (for human-readable explanations in summary/markdown, and also include in object for structured output)
        $reasons = New-Object System.Collections.Generic.List[string]
        # Determine best-available statuses (prefer edge if present; else origin)
        $spf = $signals.SPF_Status_Edge ?? $signals.SPF_Status_Orig
        $dkim = $signals.DKIM_Status_Edge ?? $signals.DKIM_Status_Orig
        $dmarc = $signals.DMARC_Status_Edge ?? $signals.DMARC_Status_Orig
        $arc = $signals.ARC_Status_Edge ?? $signals.ARC_Status_Orig

        if ($dmarc -eq 'pass') {
            $verdict = 'Low chance of phishing, etc. - Likely Legitimate'
            $reasons.Add('DMARC passed (aligned).')
        }
        elseif ($dkim -eq 'pass' -and $dkimAligned) {
            $verdict = 'Low chance of phishing, etc. - Likely Legitimate'
            $reasons.Add('DKIM passed and aligned with From domain.')
        }
        elseif ($spf -eq 'pass' -and $spfAligned) {
            $verdict = 'Low chance of phishing, etc. - Likely Legitimate'
            $reasons.Add('SPF passed and aligned with From domain.')
        }
        elseif ($dkim -eq 'pass' -and -not $dkimAligned) {
            $verdict = 'Medium - Possibly Legitimate - Check DKIM domains.'
            $reasons.Add('DKIM passed but appears misaligned with From domain (possible mailing list/forwarder).')
        }
        elseif ($arc -eq 'pass' -and $dmarc -ne 'pass') {
            $verdict = 'Medium - Possibly Legitimate - Check ARC/DMARC.'
            $reasons.Add('ARC passed but DMARC did not; forwarded/mediated message likely.')
        }
        else {
            # If we get here, likely spoof or badly configured sender
            $verdict = 'High - Likely Malicious - Failing DMARC/SPF/DKIM is a strong signal of spoofing/phishing.'
            if ($dmarc -eq 'fail') { $reasons.Add('DMARC failed.') }
            if ($dkim -in @('fail', 'none', $null)) { $reasons.Add('DKIM did not validate.') }
            if ($spf -in @('fail', 'softfail', 'none', $null)) { $reasons.Add('SPF did not validate.') }
            if (-not $fromDomain) { $reasons.Add('Unable to parse From domain.') }
        }

        # Build object
        $obj = [pscustomobject]@{
            Verdict     = $verdict
            Confidence  = if ($verdict -like 'Low*') { 'High' } elseif ($verdict -like 'Medium*') { 'Medium' } else { 'Variable' }
            Reasons     = $reasons              # always a list/array

            VisibleFrom = $fromAddr
            Sender      = $senderAddr
            ReturnPath  = $returnPath

            Domains     = [pscustomobject]@{
                From     = $fromDomain
                MailFrom = $mailFromDomain
                DKIM     = $dkimDomains         # normalized array
            }

            AuthSummary = [pscustomobject]@{
                Edge      = $edgeAuth
                Origin    = $originAuth
                Best      = [pscustomobject]@{
                    SPF   = ($signals.SPF_Status_Edge ?? $signals.SPF_Status_Orig)
                    DKIM  = ($signals.DKIM_Status_Edge ?? $signals.DKIM_Status_Orig)
                    DMARC = ($signals.DMARC_Status_Edge ?? $signals.DMARC_Status_Orig)
                    ARC   = ($signals.ARC_Status_Edge ?? $signals.ARC_Status_Orig)
                }
                Alignment = [pscustomobject]@{
                    DKIM_Aligned = $dkimAligned
                    SPF_Aligned  = $spfAligned
                }
                CompAuth  = $signals.CompAuth
            }

            Path        = [pscustomobject]@{
                FirstPublicIP = $firstPublicIP
                ReceivedHops  = $receivedLines
            }

            KeyHeaders  = [pscustomobject]@{
                Subject   = ($kv.Subject -replace '^(?i)Subject:\s*', '')
                MessageId = ($kv.MessageID -replace '^(?i)Message-Id:\s*', '')
            }
        }

        if ($Format -eq 'Object' -or $AsObject) {
            return $obj
        }
        elseif ($Format -eq 'Json') {
            return ($obj | ConvertTo-Json -Depth 6)
        }
        elseif ($Format -eq 'Markdown') {
            $md = @()
            $md += "# Mail Header Authentication Analysis"
            $md += ""
            $md += "**Verdict:** $($obj.Verdict)  "
            $md += "**Confidence:** $($obj.Confidence)"
            $md += ""

            if ($obj.Reasons -and $obj.Reasons.Count) {
                $md += "### Reasons"
                foreach ($r in $obj.Reasons) { $md += "- $r" }
                $md += ""
            }

            $md += "### Sender"
            $md += "- From: ``$($obj.VisibleFrom)``"
            if ($obj.Sender) {
                $md += "- Sender: ``$($obj.Sender)``"
            }
            if ($obj.ReturnPath) {
                $md += "- Return-Path: ``$($obj.ReturnPath)``"
            }

            $md += ""
            $md += "### Domains"
            $md += "- header.from: **$($obj.Domains.From)**"
            $md += "- smtp.mailfrom: **$($obj.Domains.MailFrom)**"
            $md += "- DKIM d=: **$([string]::Join(', ',$obj.Domains.DKIM))**"

            $md += ""
            $md += "### Authentication"
            $md += "- SPF: **$($obj.AuthSummary.Best.SPF)** (aligned: $($obj.AuthSummary.Alignment.SPF_Aligned))"
            $md += "- DKIM: **$($obj.AuthSummary.Best.DKIM)** (aligned: $($obj.AuthSummary.Alignment.DKIM_Aligned))"
            $md += "- DMARC: **$($obj.AuthSummary.Best.DMARC)**"
            if ($obj.AuthSummary.Best.ARC) { $md += "- ARC: **$($obj.AuthSummary.Best.ARC)**" }
            if ($obj.AuthSummary.CompAuth) { $md += "- CompAuth: **$($obj.AuthSummary.CompAuth)**" }

            $md += ""
            $md += "### Path"
            if ($obj.Path.FirstPublicIP) { $md += "- First public IP: **$($obj.Path.FirstPublicIP)**" }

            # Use a fenced code block for the Received chain
            # Created reusable helper for future use: Add-FencedBlock -Lines $obj.Path.ReceivedHops -Language 'txt'
            $md += "<details><summary>Received chain</summary>"
            $md += ""
            $md += Add-FencedBlock -Lines $obj.Path.ReceivedHops    # or -Language 'txt'
            $md += "</details>"

            $md += ""
            $md += "### Key Headers"
            if ($obj.KeyHeaders.Subject) { $md += "- Subject: $($obj.KeyHeaders.Subject)" }
            if ($obj.KeyHeaders.MessageId) { $md += "- Message-Id: $($obj.KeyHeaders.MessageId)" }
            $md += ""

            return ($md -join "`n")
        }
        else {
            # Summary (colorized handled inside Write-Log)
            Write-Log -level Info -Message ""
            Write-Log -level Info -Message ""
            Write-Log -Level OK -Message "Mail Header Authentication Analysis"
            Write-Log -Level OK -Message "-----------------------------------"
            Write-Log -level Info -Message ""
            Write-Log -Level Info -Message ("Verdict: {0}" -f $obj.Verdict)
            Write-Log -Level Info -Message ("Confidence: {0}" -f $obj.Confidence)

            if ($obj.Reasons.Count) {
                Write-Log -Level Info -Message "Reasons:"
                $obj.Reasons | ForEach-Object {
                    Write-Log -Level Info -Message (" - {0}" -f $_)
                }
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level Info -Message "Sender"

            Write-Log -Level Info -Message (" From: {0}" -f $obj.VisibleFrom)

            if ($obj.Sender) {
                Write-Log -Level Info -Message (" Sender: {0}" -f $obj.Sender)
            }
            if ($obj.ReturnPath) {
                Write-Log -Level Info -Message (" Return-Path: {0}" -f $obj.ReturnPath)
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level Info -Message "Domains"
            Write-Log -Level Info -Message (" header.from: {0}" -f $obj.Domains.From)
            Write-Log -Level Info -Message (" smtp.mailfrom: {0}" -f $obj.Domains.MailFrom)
        
            # DKIM domains line
            Write-Log -Level Info -Message (" DKIM domains count: {0}" -f $dkimCount)
            if ($dkimCount -gt 0) {
                Write-Log -Level Info -Message (" dkim d=: {0}" -f ($dkimList -join ', '))
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level Info -Message "Authentication"
            Write-Log -Level Info -Message (" SPF: {0} (aligned: {1})" -f $obj.AuthSummary.Best.SPF, $obj.AuthSummary.Alignment.SPF_Aligned)
            Write-Log -Level Info -Message (" DKIM: {0} (aligned: {1})" -f $obj.AuthSummary.Best.DKIM, $obj.AuthSummary.Alignment.DKIM_Aligned)
            Write-Log -Level Info -Message (" DMARC: {0}" -f $obj.AuthSummary.Best.DMARC)

            if ($obj.AuthSummary.Best.ARC) {
                Write-Log -Level Info -Message (" ARC: {0}" -f $obj.AuthSummary.Best.ARC)
            }
            if ($obj.AuthSummary.CompAuth) {
                Write-Log -Level Info -Message (" CompAuth: {0}" -f $obj.AuthSummary.CompAuth)
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level Info -Message "Path"

            if ($obj.Path.FirstPublicIP) {
                Write-Log -Level Info -Message (" First public IP: {0}" -f $obj.Path.FirstPublicIP)
            }

            Write-Log -Level Info -Message (" Received hops: {0}" -f $obj.Path.ReceivedHops.Count)

            return $obj
        }
    }
    catch {
        Write-Log -Level Error -Message ("Error analyzing mail headers: {0}" -f $_.Exception.Message)
        return $null
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAhwrlyHnl+RgPc
# G56ITRhoFresb7o2VIj0tLvYKgWzoqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCxfaDS48aP
# 80cFfXd/PNMzz5TBxEizfD3lFkRTI5mZAzANBgkqhkiG9w0BAQEFAASCAgAyfsfp
# ABW8s8UsGzVt7yICrcmeUi/u1RrPsjgZEq04TWo67WS0vI/8lgF+E5fAUgZrPe6A
# Y65+xKJSoiKmG5Dr69T7t4zuHGcmAlX3yIHUrUEHLlUFZbs51sIkMttepQg2HRZH
# 7RN9C6b1PByBv8NIPkxyY9KlOHWzkB712Bq0ZsJimtB0UzLkz5k6fjaElczGemQL
# XsPL6lhsnPrFmRZaxlC0i9r63aTmZWI76d4Ra5PK+gGzl7QkKT9n0n6z+dCl1i5c
# FlMeoW160+CQ9yjc3smRk7lNWSJYnrt8ZgMxvEkR4m8zI7aiWMHpIGqQUFPx9Gfk
# DlQo4a9+0N3VDuh5uAjhkD2oSyJxFfY/HApiOxTalG1CPVO3TyqSsQ51g8l2NtWw
# FS/s1XDCiLiBmoRUgxMBx828BAy0l07A1ltj2AF7NUcl9wfiF6/1IpmNwv7ONZTV
# YiGOGqJ+db361rRlDdnn3udS6xwrMwJuyw1F7jhQ38nkPLcbsf6aBbDlaqRDb6l4
# LGldUih/W0axmC/6+PKSLtCwb4knmIWHADFj0YA8OgDCPu9Q+VFuH3SsLazOdzS8
# FeBhzB6QS8F6yltshunDttWfTGDRIB4DC8YtWNBTewebflKqUzlco5yir+/yTnMQ
# fkD7n5TLV/57BN1akHGzKYpvD0dQOCh5f8TbTqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTIyMjAxMzFaMC8GCSqGSIb3DQEJBDEiBCC0B+rTf78r5xNwVerm
# VEtDsG2EKxOjvxBqlBingVFB4jANBgkqhkiG9w0BAQEFAASCAgA4Sj6R48XCVSav
# TY8HoNWhjqckouuhsgGmbCNkO0yLQve7u1Lz0GMjK1/0d/CA/b65rTQSLd/v8waN
# cqcVLAJ7zPxfT1M89McSpJXwSqzhjvr/QytrOZdRjoRPRqp/1yVrpZOno+HgyQps
# HPdngingXWDTyIZEOL0cTv0pKeEMNd/UO4F4GIAKRP1c1Z8kzZmmEtmtxLe8slwC
# aqkJ2aPH4sHS5lNXvXPI5FC71nue32YuIdJfKw/OJ7DH2N7MU0XAsVbw3++/csDm
# d7m4KqlxzqUXSw+wSLDim2b8Fwqom3VHHr1XON3xI0puv5C0wUQ3L/pGeOnYLU2s
# N1IqJF/E3unNQqu4hdxgLH0RHvSjHGrru5STrsXw9BplMO6R6VhB1+vQq/icyPxO
# EexInr2nodVuV2WQ9xEhTlUKuwcjN5JnbZER+Dx7dGHMo4KVoMj71hXElp61GRJl
# 5F9l/oYMqvaQYqsw+A/C1R44eupf+eywZ4OvVPA5rlt6lpl+3uWht8XFDjgq04LO
# +EwY94Q1eekiEhulk4ppwOBn+liuTG323gLViHt01QVC2iF4DYj7kc9+84pY1HRl
# Ja2nnelvpGSdb1vDd2ec9YVEEmq5f2WeaHKnizkU5oVzZYVjyXOwzDk/ZEzsXxZs
# +V6pPdZemnbBBlt03/7wZhIyL0KfzA==
# SIG # End signature block
