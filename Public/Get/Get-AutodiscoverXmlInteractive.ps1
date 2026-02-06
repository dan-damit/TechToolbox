function Get-AutodiscoverXmlInteractive {
    <#
    .SYNOPSIS
        Interactive (or parameterized) Autodiscover XML probe for
        Exchange/Hosted/M365.

    .DESCRIPTION
        Prompts (or accepts params) for Email, Schema, URI, and Credentials;
        POSTs the Outlook Autodiscover request; follows redirects; saves the
        XML; and summarizes common nodes. Hardened for DNS/connection errors and
        missing ResponseUri.

    .PARAMETER Email
        Mailbox UPN/email to test. If omitted, prompts.

    .PARAMETER Uri
        Full Autodiscover endpoint (e.g.,
        https://autodiscover.domain.com/autodiscover/autodiscover.xml). If
        omitted, will suggest
        https://autodiscover.<domain>/autodiscover/autodiscover.xml.

    .PARAMETER Schema
        AcceptableResponseSchema. Defaults to 2006a.

    .PARAMETER TryAllPaths
        If set, will attempt a sequence of common endpoints derived from the
        email's domain.

    .EXAMPLE
        Get-AutodiscoverXmlInteractive

    .EXAMPLE
        Get-AutodiscoverXmlInteractive -Email user@domain.com -Uri https://autodiscover.domain.com/autodiscover/autodiscover.xml

    .EXAMPLE
        Get-AutodiscoverXmlInteractive -Email user@domain.com -TryAllPaths
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string] $Email,
        [Parameter(Position = 1)]
        [string] $Uri,
        [ValidateSet('http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
            'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006')]
        [string] $Schema = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
        [switch] $TryAllPaths
    )

    Write-Log -Level Info -Message "=== Autodiscover XML Probe (Interactive/Param) ==="

    # 1) Email
    while ([string]::IsNullOrWhiteSpace($Email) -or $Email -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        if ($Email) { Write-Log -Level Warn -Message "That doesn't look like a valid email address." }
        $Email = Read-Host "Enter the mailbox Email Address (e.g., user@domain.com)"
    }
    $domain = $Email.Split('@')[-1]

    # 2) URI (build suggestion if not provided)
    $suggested = "https://autodiscover.$domain/autodiscover/autodiscover.xml"
    if ([string]::IsNullOrWhiteSpace($Uri)) {
        Write-Log -Level Info -Message "Detected domain: $domain"
        Write-Log -Level Info -Message "Suggested Autodiscover URI: $suggested"
        $Uri = Read-Host "Enter Autodiscover URI or press Enter to use the suggestion"
        if ([string]::IsNullOrWhiteSpace($Uri)) { $Uri = $suggested }
    }

    # Helper: normalize URI and ensure well-known path
    function Resolve-AutodiscoverUri {
        param([string]$InputUri)
        try {
            $u = [Uri]$InputUri
            if (-not $u.Scheme.StartsWith("http")) { throw "URI must start with http or https." }
            if ($u.Host -match '\.xml$') { throw "Hostname ends with .xml (`"$($u.Host)`"). Remove the .xml from the host." }

            $path = $u.AbsolutePath.TrimEnd('/')
            if ([string]::IsNullOrWhiteSpace($path) -or $path -eq "/") {
                # Bare host/root → append the well-known path
                $normalized = ($u.GetLeftPart([System.UriPartial]::Authority)).TrimEnd('/') + "/autodiscover/autodiscover.xml"
            }
            elseif ($path -match '/autodiscover/?$') {
                # '/autodiscover' → append final segment
                $normalized = ($u.GetLeftPart([System.UriPartial]::Authority)).TrimEnd('/') + "/autodiscover/autodiscover.xml"
            }
            else {
                # Leave as-is if user pointed directly at an XML endpoint
                $normalized = $u.AbsoluteUri
            }
            return $normalized
        }
        catch {
            throw "Invalid URI '$InputUri': $($_.Exception.Message)"
        }
    }

    $Uri = Resolve-AutodiscoverUri -InputUri $Uri

    # Candidate list if -TryAllPaths is set
    $candidates = @($Uri)
    if ($TryAllPaths) {
        $candidates = @(
            "https://autodiscover.$domain/autodiscover/autodiscover.xml",
            "https://$domain/autodiscover/autodiscover.xml",
            "https://mail.$domain/autodiscover/autodiscover.xml"
        ) | Select-Object -Unique
    }

    # 3) Credentials
    Write-Log -Level Info -Message ""
    $cred = Get-Credential -Message "Enter credentials for $Email (or the mailbox being tested)"

    # 4) Request body
    $body = @"
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>$Email</EMailAddress>
    <AcceptableResponseSchema>$Schema</AcceptableResponseSchema>
  </Request>
</Autodiscover>
"@

    $headers = @{
        "User-Agent" = "AutodiscoverProber/1.3"
        "Accept"     = "text/xml, application/xml"
    }

    # 5) Probe loop (single or multiple URIs)
    foreach ($candidate in $candidates) {
        # DNS pre-check
        try {
            Write-Log -Level Info -Message "`nChecking DNS for host: $(([Uri]$candidate).Host)"
            $null = Resolve-DnsName -Name ([Uri]$candidate).Host -ErrorAction Stop
            Write-Log -Level Info -Message "DNS OK."
        }
        catch {
            Write-Log -Level Warn -Message "DNS check failed: $($_.Exception.Message)"
            if (-not $TryAllPaths) { return }
            else { continue }
        }

        Write-Log -Level Info -Message "`nPosting to: $candidate"
        try {
            Write-Log -Level Info -Message "`nPosting to: $candidate"

            # IMPORTANT: Do NOT throw on HTTP errors; we want to inspect redirects/challenges.
            $resp = Invoke-WebRequest `
                -Uri $candidate `
                -Method POST `
                -Headers $headers `
                -ContentType "text/xml" `
                -Body $body `
                -Credential $cred `
                -MaximumRedirection 10 `
                -AllowUnencryptedAuthentication:$false `
                -SkipHttpErrorCheck `
                -ErrorAction Stop

            # Try to capture the final URI if available (it may not exist on some failures)
            $finalUri = $null
            if ($resp.BaseResponse -and $resp.BaseResponse.PSObject.Properties.Name -contains 'ResponseUri' -and $resp.BaseResponse.ResponseUri) {
                $finalUri = $resp.BaseResponse.ResponseUri.AbsoluteUri
            }

            # If you want to see what status we actually got:
            $code = $null
            $reason = $null
            if ($resp.PSObject.Properties.Name -contains 'StatusCode') { $code = [int]$resp.StatusCode }
            if ($resp.PSObject.Properties.Name -contains 'StatusDescription') { $reason = $resp.StatusDescription }

            Write-Log -Level Info -Message ("`nHTTP Status: " + ($(if ($code) { "$code " } else { "" }) + ($reason ?? "")))
            if ($finalUri) { Write-Log -Level Info -Message "Final Endpoint: $finalUri" }

            Write-Log -Level Info -Message "`nHTTP Status: $($resp.StatusCode) $($resp.StatusDescription)"
            if ($finalUri) { Write-Log -Level Info -Message "Final Endpoint: $finalUri" }

            if ($resp.Content) {
                try {
                    [xml]$xml = $resp.Content
                    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
                    $outFile = Join-Path $PWD "Autodiscover_$($domain)_$stamp.xml"
                    $xml.Save($outFile)
                    Write-Log -Level Info -Message "Saved XML to: $outFile"

                    # Summarize common nodes if present
                    Write-Log -Level Info -Message "`n--- Key Autodiscover Nodes (if available) ---"
                    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
                    $ns.AddNamespace("a", "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a")
                    $ns.AddNamespace("r", "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006")

                    $ewsExt = $xml.SelectNodes("//a:Protocol[a:Type='EXPR' or a:Type='EXCH']/a:ExternalEwsUrl", $ns)
                    $ewsInt = $xml.SelectNodes("//a:Protocol[a:Type='EXCH']/a:InternalEwsUrl", $ns)
                    $mapiSrv = $xml.SelectNodes("//a:Protocol[a:Type='EXCH']/a:Server", $ns)

                    if ($ewsExt) { $ewsExt | ForEach-Object { Write-Log -Level Info -Message ("EWS External URL: " + $_.'#text') } }
                    if ($ewsInt) { $ewsInt | ForEach-Object { Write-Log -Level Info -Message ("EWS Internal URL: " + $_.'#text') } }
                    if ($mapiSrv) { $mapiSrv | ForEach-Object { Write-Log -Level Info -Message ("MAPI/HTTP Server: " + $_.'#text') } }

                    Write-Log -Level Info -Message "------------------------------------------------"
                }
                catch {
                    Write-Log -Level Warn -Message "Response received but not valid XML. Raw content follows:"
                    Write-Log -Level Info -Message $resp.Content
                }
            }
            else {
                Write-Log -Level Warn -Message "No content returned."
            }

            # Success: stop probing
            return
        }
        catch {
            # Primary error message only (no secondary exceptions)
            Write-Log -Level Error -Message ("Request failed: " + $_.Exception.Message)

            # Try to surface a helpful endpoint without assuming properties exist
            $respObj = $null
            $hintUri = $null

            # Windows-style WebException
            if ($_.Exception.PSObject.Properties.Name -contains 'Response') {
                try { $respObj = $_.Exception.Response } catch {}
                if ($respObj -and $respObj.PSObject.Properties.Name -contains 'ResponseUri' -and $respObj.ResponseUri) {
                    $hintUri = $respObj.ResponseUri.AbsoluteUri
                }
            }

            # PS7 HttpRequestException.ResponseMessage
            if (-not $hintUri -and $_.Exception.PSObject.Properties.Name -contains 'ResponseMessage') {
                try {
                    $respMsg = $_.Exception.ResponseMessage
                    if ($respMsg -and $respMsg.PSObject.Properties.Name -contains 'RequestMessage' -and $respMsg.RequestMessage) {
                        $hintUri = $respMsg.RequestMessage.RequestUri.AbsoluteUri
                    }
                }
                catch {}
            }

            # Fall back to the candidate we attempted
            if (-not $hintUri) { $hintUri = $candidate }

            Write-Log -Level Info -Message ("Endpoint (on error): " + $hintUri)

            if (-not $TryAllPaths) { return }
            else {
                Write-Log -Level Warn -Message "Trying next candidate endpoint..."
                Start-Sleep -Milliseconds 200
            }
        }
    }

    # If we got here with TryAllPaths, everything failed
    if ($TryAllPaths) {
        Write-Log -Level Error -Message "All Autodiscover candidates failed for $Email"
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDUVhfaUVUEnk26
# v6nZKorRM63P9ybVp3lzUlNi8e0rGKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD3dRSuxxwq
# pJEV0NgCKvkKR9lPg9q4nIkBZP4iTxdHoDANBgkqhkiG9w0BAQEFAASCAgAg3BMq
# 0PWLRUAfADk612cPSOio2Ylh8zawuJpWV4Dl3sraOpYL1l581aLGpsHdMmg8uphh
# IuUCQcwROrVeleMw1xeZ/IcPWySToeU8h0XY5fVmX7r0rNcZ7Zvd2WnP6Ja3m1D8
# MWSvxg1fhqEv16eaFioARMMkybj52HFWU8KIwk82ejw6Wir1mvkF6+Y9tM0CCx2P
# FfPFarYV4dCaAC4TjWT1lhwaQlZaKyhUYo07jgJkPVP8U8GR/s0X0WfJnt4YFEFd
# V4lQYTb8LDRXFBArZgndZsvysYaUQnDj9DUyXuSqGJz6UFRZcbGUUkL3wqwDpNYk
# lkBmo0Ls57SoyPmQpf4nCPBZVXQ8Vj7jLTcT5ZygUFqp1ZDRAhn801c73UasAhIh
# 1o5+ft4dDEZqyyels1jCe6q+kiYkZ7hFuX2/AQyCd25exYqKS/B4NdLVMhccM5F+
# 4biI5IgERhOLxFc0UnWUgOgEQHM0JnAl0wsk0P68fTsY75M0xCDSOj740p/mT5BG
# BVFb+cLnalKGiKJ4bOyKqBK5ztL2aCZ52yPvSNfsfi3P1EjnJdhBY6apIAgPLX2v
# AMzrKPNoPdJQiighDWYHMeUeo7AMdoxs82K5uSAOF2c8LdWG1FAlXBM5EK6sjjNt
# hGJCMt00454siNhsTAbn0qNwFMlFTrTI4hgdh6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMDUyMDQ5MzdaMC8GCSqGSIb3DQEJBDEiBCAuWICz+C14asU0juCf
# 1nuzQU5Ij1OoVLOE80/gXvbicTANBgkqhkiG9w0BAQEFAASCAgCLpQ4r5FELW1x6
# YKwlqjJV1QDYgEQphYEFUW8sfdkX52eFGuVksmuv3RUbSHOec1g3HjUA7S52kpOw
# 5t1rJ0lkZSmUCufypC9Hc5s/Cw+Sh87MUqZI7P9816S9Qvu8AD9OTfWTEz+BSZA5
# 8sqed0WyKqWbutMBjWUj64bdtcNUHZZXES00wfoEX6iRBauqidDyWTIAmP0+Sdvn
# ptDi1Y1RTq/SWGEHD0pgo7JZxAY5ppkXRNEBS5OTQK+lXMD3RI46Q6UoyOxbz4te
# YHgwH2FxbIfllctBk0R7wFp6/PeJvrA/TxM5gv2lBtlQJjdmeHTz7bVncMxWCNvZ
# Wu1Tj3+MHPKZ6J2DlN10ffFzbZzyMx8nQzIqlSvviJ9+NR7ICaF9l//0cSOQhazF
# +nSQFBZNJJvOBmEYBul/zwOjDOAsHz4o/z9MsW+6AvRPO5eHLTPTIELVCYmEqI8F
# 7YX0TX91ZKybz5baDK3n23nryctdSPsTe530WtvWRxjd/t6Yn01jfGJHo0xclui9
# 2C6B3vK2x62VugLFzfjhOknYDjGAiIUlvgrjT3pcQ/4A8JlKFvtBP3a8qiSwt53A
# 3B1wNyrE1/9zNCyRdlGrnakiPXQjswE/0U6gqTlFkl3/nimKC/WKzsmd1z1sc+GF
# v/DiTYtzmXgHdbDZH10HrTWBkxuAkA==
# SIG # End signature block
