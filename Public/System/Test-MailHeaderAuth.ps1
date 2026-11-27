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

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Test-MailHeaderAuth
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
            Write-Log -Level Warn -Message ("Verdict: {0}" -f $obj.Verdict)
            Write-Log -Level Info -Message ("Confidence: {0}" -f $obj.Confidence)

            if ($obj.Reasons.Count) {
                Write-Log -Level OK -Message "Reasons:"
                $obj.Reasons | ForEach-Object {
                    Write-Log -Level Info -Message (" - {0}" -f $_)
                }
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level OK -Message "Sender"

            Write-Log -Level Info -Message (" From: {0}" -f $obj.VisibleFrom)

            if ($obj.Sender) {
                Write-Log -Level Info -Message (" Sender: {0}" -f $obj.Sender)
            }
            if ($obj.ReturnPath) {
                Write-Log -Level Info -Message (" Return-Path: {0}" -f $obj.ReturnPath)
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level OK -Message "Domains"
            Write-Log -Level Info -Message (" header.from: {0}" -f $obj.Domains.From)
            Write-Log -Level Info -Message (" smtp.mailfrom: {0}" -f $obj.Domains.MailFrom)
        
            # DKIM domains line
            Write-Log -Level Info -Message (" DKIM domains count: {0}" -f $dkimCount)
            if ($dkimCount -gt 0) {
                Write-Log -Level Info -Message (" dkim d=: {0}" -f ($dkimList -join ', '))
            }

            Write-Log -Level Info -Message ""
            Write-Log -Level OK -Message "Authentication"
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
            Write-Log -Level OK -Message "Path"

            if ($obj.Path.FirstPublicIP) {
                Write-Log -Level Info -Message (" First public IP: {0}" -f $obj.Path.FirstPublicIP)
            }

            Write-Log -Level Info -Message (" Received hops: {0}" -f $obj.Path.ReceivedHops.Count)

            return $obj | Out-Null
        }
    }
    catch {
        Write-Log -Level Error -Message ("Error analyzing mail headers: {0}" -f $_.Exception.Message)
        return $null
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAHFrJltCVKSCyb
# rYJ3drnWef/z373LYSQIEO3yQ77+nKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCN
# D+Iml4l9hzJlUoxZjkbzlWFjo9+v8X2QrhaYNRYNnzANBgkqhkiG9w0BAQEFAASC
# AYA7GA/ktEV0Cmemp0tGNbGad/nhqptaeKVl388M/079xDZWuh85LV/kcO1QnZCI
# HjuKqY92e5eOlHzFUWWjEmbihmQvQjC24UYWKqWEaY9zAb47UA5+O9aErwOsCShn
# ABsBX6XfU5iEpDLYBOg9lOwWXUeLiZOuTPvytGyWIibfzx/22yf4UZRG9UdaxHhS
# Hv1v1sHmNiaxJZF7+dz68SsgsCdmZM9PDPmyC0+Mbzn/jX1kHe0L6EZWu2EiDUYY
# ZqE7elYPz495THDvEqOrMB8/tQw9/XhJN7aLEQIlG6mG37obr5IpxlxZEJc2K2o+
# C63k/B9+ywteDayfmLcDuLjV08S2rXpgsVMWE+tXVbYKOXmP7ZeRIeuSs+K2pR2Q
# okf08eBAtcbxEXy7/rrZj8IC8PPynVIZeAQ3zrpt3MkvtTNO1sMpbkRDIizW/l25
# /FGcsmIxng2YGCKKzxfjYG+j4DKHb/ozQjfG2SK1dz22Rsz+xvPaCTzr/QnDVEAh
# fIShggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNTE2WjAvBgkqhkiG
# 9w0BCQQxIgQgGIJb/gPWBNyDFD7Upck8uniYydiPEf49z6C8cxp1bsQwDQYJKoZI
# hvcNAQEBBQAEggIAotm19qFgxusyMCtjJxeBHu4fnuge+t5adtdbC5GA2MwqNRTD
# 18WJSv0I2yu54elxR3oIvJmhIQ5RuApOjGfrlwkoSlQ83Zx4JRA6QCLl4ZEgKrKw
# 3PrBnq3EiPzBZfpmg/EC9CRl1XAcNtAwi5Pmbptr+aX3rMu/YinLNgzHN1HMRMyV
# mO/ah8Hadcgy+m74uEHK9uFMeZnLI+nJWEKC0+9iAzQHDL8ARaXErGRMDKNiqEZl
# 8oiCWeRLSFhPaoUArz2WcCiuUNrjYQH50O+xmwnxQfRjr2ABm/j8rDVwM2U/LrVq
# BekGwrtPkY/YuUWpuiqMtqaGTpabyUA70AzQA9+/+Ec31xigB8P3o6CATbMU+dVf
# I8un/iYUKAnilICIAAnGr7O0yE8h6S2BUP+xVNiVddazEWt41S5R4cMM0GjCbLHQ
# PENptFLT8lsBViSn2QKw/zpwZ7CdsDpWjbuxegasbOyFnU1GQwLDsfNJ2olSKxXi
# 7K7NKNaP8E57BQjRiKJZeCtaU8nZEDnAyt+4m3FOSn/dh9+AWVUX8PvNf0zpmBPb
# N8vfCchwtkZY814CHsvONppLai2aP2o/2LiR7sNHJ7YVwRCsnsSgkKC+xKlIz8rF
# wu5HzJtxDgWU9LDgB8mA45QaZpvGjGytf320n6LOApoBABEq3vShfz6pH3E=
# SIG # End signature block
