
<#
O365_Sales_Report_Graph.ps1
Weekly send/receive report using EXO CBA + Microsoft Graph app-only (certificate)
Anchor group: sales@vadtek.com (synced DL)
Author: Dan Damit (https://github.com/dan-damit)

Prereqs:
- ExchangeOnlineManagement module
- Microsoft.Graph module
- App "VAC Unattended Scripts" with Graph Mail.Send (Application) + admin
    consent: Which looks to be good to go on UTILITY-1 as of 12/2025
- Certificate installed in LocalMachine Store to run as SYSTEM in PDQ
  (thumbprint below)

- Refactored a couple of things to be compatible with Windows PowerShell
  5.1 (PDQ Deploy default) vs PowerShell 7+.
#>

[CmdletBinding()]
param(
    # ======= Tenant/App/Cert =======
    [string]$TenantDomain = "vadtek.com",
    [string]$TenantId = "e1b83792-ab2b-418b-9481-fe12c76f201e",
    [string]$ClientId = "9c0e43db-f3fc-4bba-9530-10b5d063730b",
    [string]$CertThumb = "F226D64FF93DE27A1CFC9F9078829FBBD5B21770",

    # ======= Mail settings =======
    [string]$SenderUpn = "office365@vadtek.com",
    [string]$AnchorAddress = "sales@vadtek.com",
    [string]$To = "llambie@vadtek.com",   # change to desired recipient(s) after testing
    [string]$Bcc = "alerts@vadtek.com",   # change to desired recipient(s) after testing

    # ======= Working directory =======
    [string]$WorkingDir = "C:\Users\Public\Documents\Admin Arsenal\PDQ Deploy\Repository\VAC Scripts\Office365_Send_Recieve_Reports"
)

# ------------------------- SETUP -------------------------
New-Item -ItemType Directory -Path $WorkingDir -Force | Out-Null
Set-Location -Path $WorkingDir

# ======= Load exclusions from _SalesEmailReport_Exclusions.txt =======
# \\UTILITY-1.vadtek.com\C$\Users\Public\Documents\Admin Arsenal\PDQ Deploy\Repository\VAC Scripts\Office365_Send_Recieve_Reports\_SalesEmailReport_Exclusions.txt
$ExclusionFile = Join-Path $WorkingDir '_SalesEmailReport_Exclusions.txt'
$Exclusions = @()
if (Test-Path -LiteralPath $ExclusionFile) {
    $Exclusions = Get-Content -LiteralPath $ExclusionFile |
    Where-Object { $_ -and $_.Trim() -ne '' } |
    ForEach-Object { $_.Trim().ToLower() }
    Write-Host "Loaded $($Exclusions.Count) exclusions from $ExclusionFile"
}
else {
    Write-Host "No exclusions file found at $ExclusionFile"
}

# ======= Labels/filenames (Sales only) =======
$mailboxGrpName = "Sales"
$dateStamp = (Get-Date).ToString("MM-dd-yyyy")

# Transcript/log
$logFile = Join-Path $WorkingDir "O365_Sales_$((Get-Date).ToString('MM-dd-yyyy')).log"
Start-Transcript -Path $logFile

# ======= Connect to Exchange Online (CBA) =======
Import-Module ExchangeOnlineManagement -ErrorAction Stop
$exoParams = @{
    AppId                 = $ClientId
    Organization          = $TenantDomain        # must be tenant domain, not GUID
    CertificateThumbprint = $CertThumb
    ShowBanner            = $false
}
Connect-ExchangeOnline @exoParams  # (https://michev.info/blog/post/5704/reporting-on-microsoft-365-groups-links-2023-updated-version)


# ======= Date window (previous Mon–Sun) =======
$startDate = (Get-Date).AddDays(-7).Date
$endDate = (Get-Date).AddDays(-1).Date.AddHours(23).AddMinutes(59).AddSeconds(59)
$subject = "Weekly e-mail report (Sales) $($startDate.ToShortDateString()) - $($endDate.ToShortDateString())"

# ======= Resolve Sales DL members (recursive, returns Address+DisplayName) =======
# Recursive DL expansion function to loop through the anchor group and grab
# member data (email + display name), handling nested groups if present (futureproofing).
function Resolve-AddressesFromAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Anchor
    )

    $dg = Get-DistributionGroup -Identity $Anchor -ErrorAction SilentlyContinue
    if ($dg) {
        $visitedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        function Expand-Group {
            param([string]$GroupId)
            if (-not $visitedGroups.Add($GroupId)) { return @() }

            $members = Get-DistributionGroupMember -Identity $GroupId -ResultSize Unlimited -ErrorAction SilentlyContinue
            $memberInfo = @()

            foreach ($m in $members) {
                switch -Regex ($m.RecipientType) {
                    # Mailboxes and mail users
                    "UserMailbox|SharedMailbox|MailUser|TeamMailbox" {
                        if ($m.PrimarySmtpAddress) {
                            $memberInfo += [pscustomobject]@{
                                EmailAddress = $m.PrimarySmtpAddress
                                DisplayName  = $m.DisplayName
                            }
                        }
                    }

                    # Nested groups: recurse
                    "MailUniversalDistributionGroup|MailUniversalSecurityGroup|Group" {
                        $memberInfo += Expand-Group -GroupId $m.Identity
                    }

                    # Mail contacts (external)
                    "MailContact" {
                        if ($m.ExternalEmailAddress) {
                            # ExternalEmailAddress can be prefixed (e.g., SMTP:someone@ext.com), normalize to SMTP form
                            $addr = $m.ExternalEmailAddress.ToString()
                            if ($addr -match 'SMTP:(.+)') { $addr = $Matches[1] }
                            $memberInfo += [pscustomobject]@{
                                EmailAddress = $addr
                                DisplayName  = $m.DisplayName
                            }
                        }
                    }
                }
            }

            return $memberInfo
        }

        # Expand, then de-dupe by EmailAddress while keeping the first DisplayName encountered
        $expanded = Expand-Group -GroupId $dg.Identity
        $dedup = $expanded | Group-Object -Property EmailAddress |
        ForEach-Object {
            # Prefer a non-empty DisplayName if available
            $first = $_.Group | Where-Object { $_.DisplayName } | Select-Object -First 1
            if (-not $first) { $first = $_.Group[0] }
            [pscustomobject]@{
                EmailAddress = $first.EmailAddress
                DisplayName  = $first.DisplayName
            }
        }

        # Sort by EmailAddress for stability
        return ($dedup | Sort-Object EmailAddress)
    }

    # Fallback: if not a DL, accept a single recipient
    $rec = Get-Recipient -Identity $Anchor -ErrorAction SilentlyContinue
    if ($rec -and $rec.PrimarySmtpAddress) {
        return @([pscustomobject]@{
                EmailAddress = $rec.PrimarySmtpAddress
                DisplayName  = $rec.DisplayName
            })
    }

    throw "Unable to resolve members for $Anchor"
}

# Resolve once: produces objects with EmailAddress + DisplayName
$memberInfo = Resolve-AddressesFromAnchor -Anchor $AnchorAddress


# ======= Normalizer for edge cases (e.g., SMTP: prefix) =======
# Can update regex as needed for other edge cases when found
function Format-Emails {
    param([string]$Email)
    if ($Email -match '^SMTP:(.+)$') { $Email = $Matches[1] }
    return $Email.Trim().ToLower()
}

# ======= Build address list and display-name cache =======
$emailAddresses = $memberInfo.EmailAddress
$DisplayCache = @{}

foreach ($mi in $memberInfo) {
    if (-not $DisplayCache.ContainsKey($mi.EmailAddress)) {
        $DisplayCache[$mi.EmailAddress] = if ($mi.DisplayName -and $mi.DisplayName.Trim() -ne '') { $mi.DisplayName }
        else {
            "[Display name not found]"
        }
    }
}

# ======= Pre-filter addresses using exclusions (exact match, normalized) =======
$FilteredAddresses = $emailAddresses | Where-Object {
    $Exclusions -notcontains (Format-Emails $_)
}

# (Optional) Align display cache to filtered addresses
$FilteredDisplayCache = @{}
foreach ($addr in $FilteredAddresses) {
    $FilteredDisplayCache[$addr] = $DisplayCache[$addr]
}

# ======= Trace (V2) and build CSV =======
$outputFile = Join-Path $WorkingDir ($mailboxGrpName + "_" + $dateStamp + ".csv")
Remove-Item -Path $outputFile -Force -ErrorAction SilentlyContinue

$TotalSendCount = 0
$TotalReceiveCount = 0
$result = @()

foreach ($addr in $FilteredAddresses) {
    $send = Get-MessageTraceV2 -SenderAddress    $addr -StartDate $startDate -EndDate $endDate -ResultSize 5000 -ErrorAction SilentlyContinue
    $recv = Get-MessageTraceV2 -RecipientAddress $addr -StartDate $startDate -EndDate $endDate -ResultSize 5000 -ErrorAction SilentlyContinue

    $sendCount = ($send | Group-Object -Property MessageTraceId).Count
    $receiveCount = ($recv  | Group-Object -Property MessageTraceId).Count

    $TotalSendCount += $sendCount
    $TotalReceiveCount += $receiveCount

    $displayName = $FilteredDisplayCache[$addr]

    $result += [pscustomobject]@{
        'Display Name'  = $displayName
        'Email Address' = $addr
        'Send Count'    = $sendCount
        'Receive Count' = $receiveCount
    }
}

# Output CSV
$result | ConvertTo-Csv -NoTypeInformation | Out-File $outputFile -Encoding utf8
Write-Host "Sales report CSV written: $outputFile"

# ======= HTML body =======
$head = @"
<style>
 body { font-family: Calibri; font-size: 11pt; color: #000; }
 th, td { text-align:left; border:1px solid #000; border-collapse:collapse; padding:3px 10px 3px 3px; }
 th { font-size:12pt; background-color:#d4d7d9; color:#000; }
 td { color:#000; }
</style>
"@
$importHtml = Import-Csv -Path $outputFile | ConvertTo-Html -Head $head
$bodyHtml = @"
<p><b>Range:</b> $($startDate.ToShortDateString()) - $($endDate.ToShortDateString())</p>
<p><b>Total Sent:</b> $TotalSendCount<br/><b>Total Received:</b> $TotalReceiveCount</p>
$importHtml
"@

# ======= Send via Microsoft Graph (app-only cert) =======
# Built for PowerShell 7+; if running Windows PowerShell 5.1, avoid loading the
# full meta-module to reduce function/variable count issues. Ran into this for 
# initial testing using Windows PowerShell 5.1 on UTILITY-1.
$psIsWin = $PSVersionTable.PSEdition -eq 'Desktop'
if ($psIsWin) {
    $Script:MaximumFunctionCount = 18000
    $Script:MaximumVariableCount = 18000
}
# Only load the small submodule that contains Send-MgUserMail
Import-Module Microsoft.Graph.Users.Actions -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
try {
    Connect-MgGraph -TenantId $TenantDomain -ClientId $ClientId -CertificateThumbprint $CertThumb -NoWelcome
    $null = Get-MgOrganization -ErrorAction Stop   # sanity check
}
catch {
    throw "Connect-MgGraph failed: $($_.Exception.Message)"
}

# --- Preflight: ensure the attachment exists ---
if (-not (Test-Path -LiteralPath $outputFile)) {
    Write-Error "Attachment file not found: $outputFile. Aborting send."
    throw
}

# Attachment
$bytes = [System.IO.File]::ReadAllBytes($outputFile)
$base64 = [System.Convert]::ToBase64String($bytes)
$attachment = @{
    "@odata.type" = "#microsoft.graph.fileAttachment"
    Name          = [System.IO.Path]::GetFileName($outputFile)
    ContentType   = "text/csv"
    ContentBytes  = $base64
}

# Payload
$payload = @{
    Message         = @{
        Subject       = $subject
        Body          = @{ ContentType = "HTML"; Content = $bodyHtml }
        ToRecipients  = @(@{ EmailAddress = @{ Address = $To } })
        BccRecipients = @(@{ EmailAddress = @{ Address = $Bcc } })
        Attachments   = @($attachment)
        ReplyTo       = @(
            @{ EmailAddress = @{ Address = "office365@vadtek.com" } }
            # Can add more if needed
        )
    }
    SaveToSentItems = $true
}

# ======= Send and error handling tailored to PDQ Connect Automations =======
# Fail-fast on non-terminating errors from cmdlets
$ErrorActionPreference = 'Stop'

try {
    Send-MgUserMail -UserId $SenderUpn -BodyParameter $payload
    Write-Output ("SUCCESS: Sales report email sent as {0} at {1}." -f $SenderUpn, (Get-Date))
    # Optional: Be explicit for PDQ Connect (return code 0 = success)
    # Adjusted for PowerShell 5.1 compatibility
    $global:LASTEXITCODE = 0
    return
}
catch {
    Write-Error ("Graph send failed: {0}" -f $_.Exception.Message)
    if ($_.Exception.PSObject.Properties['Response']) {
        Write-Error ("Status: {0}" -f $_.Exception.Response.StatusCode)
        Write-Error ("Headers: {0}" -f ($_.Exception.Response.Headers | Out-String))
    }
    # Non-zero exit code so PDQ Connect marks this as an error and shows 'Errors'
    # Adjusted for PowerShell 5.1 compatibility
    $global:LASTEXITCODE = 1
    return
}
finally {
    # Cleanup always runs (even after 'exit' in try/catch in PowerShell 7+)
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
Stop-Transcript | Out-Null
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAFzydP68mY3cPf
# DR8sbyxVzCOeP9OKABTusGLqZQ4FQ6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDwRkR4Ytmp
# OZRDkcAQ2AzOg/3oo2DTIxB7WqXfYlPToTANBgkqhkiG9w0BAQEFAASCAgAGrw9q
# t4ZWYWmch3ZoR0cFb6leSCZv/bhqYqvkQIemH706yRu9taUf1xMNVCptMWCdlcu/
# MR/fete45bLdChhF5cA5EqnPjTpJmdLQHUsveR8GlZAJCyDZU24T60ckJBX/0CbH
# AJnscOgcuEEjXcNcTttllCQiHskdZVD6D2aaRHNweMXjTmgiUkyrCD6qUVFERUSP
# fGbUioUHwoW4hGII/6So22WN2Bf3j2RDWzftPgI41yE/uUBMbWbs2IjxgEh+9TZB
# 0xG2F0KZMR6IqPdOje0xzJ9hxYjZa76YrwKCd85x+DzbLwxhe1VYvJs8W6kDBcGR
# +i5fAEPZlCvsPyzMB0i5TGp5Xisk3KjaV6cYoh0gMPPcDgN+yiwy3Jp/iLw+X7Ry
# CS8MSTUqalrlqlWMn6ziEBN1kjgU2I3ClpHRGoVzy25XtabZrNXdN9XWoM0nuRf4
# fV8H9nIBuxBmnVNT9DTs/dl3PhWwBk1AGO60LY8kAkdIPeJ5v5sxcHwxlDuL3S9j
# Oka1Iy6XU7WMc4tIR5r42RFkutTokHRdIfpBSQj82QV/ONmGzkw5P4FN3cziGV72
# jryRWSD66WV8NM84eN2LHqgyJwE+8kPSMyJ6MRP8ptA7ZyZQ5dleUgjgTPKOyoPy
# wzsZhkf9EJnXCWh3jsc3t4Pa9w+70ZM6wxsy9aGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMDkyMDQyMTZaMC8GCSqGSIb3DQEJBDEiBCAo2VaItkqxUFeduo9T
# wU4ra1q28ZpLJpyVoBdNVFdNpjANBgkqhkiG9w0BAQEFAASCAgBF1JHdWvvzh3rR
# etyUwus4J1WPTu2hOrXoySIEGpkHX5T+YWnfnrqb0JrdBHJRCT62R0niiTHa1YOw
# hqDbU37vJXj8RLN65d1Q4Ae7cMI/p1ZeoV/e1s1rDUylrDP5/QxZTxC8ANyJNYl8
# vJ2BSK0wCUl91dRK8NroZeuwFoYehmpItX1TbQKBjqYPWuw+l59G5CJQBa5rELC6
# EGqWj8psAChs3A7RtueuEZXS6yv84PcA3/76AwWoPesRr+Bn0E2DLf13d7Lzw6sE
# Cm1N7mhbcV0QBeI4JEgu079hNLKjSA2wB5zzq3JdPjwsY1m/vdCZ6aQrFNGRSbpv
# +9uXYnk3NnVonsfPVXU7UwkNCOzMi7gBFdpy1NmLkc3ftnkIyqZPJOZl3Z8Bunv2
# KrIYHXXCfrDGe5wT2gIAYfjK6b2fbsDa0wWDPf9ikNGiUmBgV4hHzaT/QGrhVRit
# nf8cYJgxQvmeGPV4dSYHUM0vWqle9NheNpM+IRsyzh0nliHi+5hgRKIkhEfLVXoT
# 4hk4qmjyRdGcW4lgYEkuCLJGTT11JE0navROgB56Qop1+5wAxd/gkX8rwRjyNh8V
# QSh0v67M5qLpFKwAouijz2HmzZu3EHuamxlpmUNR1M4oD4/mkYn8JITEm1g74V9B
# 2LwvVSZpxqPpRLrKTaw+BjwDmfKrVQ==
# SIG # End signature block
