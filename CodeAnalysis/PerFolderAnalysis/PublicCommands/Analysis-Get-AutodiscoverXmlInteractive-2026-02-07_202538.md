# Code Analysis Report
Generated: 2/7/2026 8:25:38 PM

## Summary
 The code you've provided is a PowerShell function called `Get-AutodiscoverXmlInteractive`. This function helps to probe Exchange/Hosted/M365 Autodiscover XML for various purposes, such as testing or configuration. Here are some suggestions for improving the functionality, readability, and performance:

1. **Code Organization**: The code could be more organized by separating the function into smaller, more manageable parts with clearer variable names. This would make it easier to understand what each section of the script does.

2. **Error Handling**: Some error handling in the script is specific to certain exceptions, which may not cover all potential errors that might occur during execution. A more robust approach could be to catch all errors and handle them appropriately based on their type or severity.

3. **Comments and Documentation**: While there are already comments throughout the code, they could be more consistent and comprehensive. Adding parameter descriptions, explanations for important sections of code, and examples of how to use the function effectively would make it easier for others to understand and use your script.

4. **Performance Optimization**: The script makes several HTTP requests and waits between them (`Start-Sleep -Milliseconds 200`). Depending on the number of candidates being tested, this could potentially slow down the function. To improve performance, you might consider adjusting the delay or implementing parallel processing for multiple candidates.

5. **Modularity**: Breaking the script into smaller, more modular functions would make it easier to reuse parts of the code in other scripts and help reduce complexity. For example, creating separate functions for handling URI resolution, credential input, and request body creation could make the overall script more maintainable and flexible.

6. **Variable Scoping**: Some variables are defined within loops or try-catch blocks, which means they're only accessible inside those sections. To make the code easier to read and modify, consider using functions or moving variables outside of loops when possible.

## Source Code
```powershell
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

[SIGNATURE BLOCK REMOVED]

```
