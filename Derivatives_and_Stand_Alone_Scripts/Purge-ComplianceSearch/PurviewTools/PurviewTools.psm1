
# =====================================================================
# PurviewTools Module
# Version: 1.1.2
# Date   : 2026-01-07
# Author : Dan Damit (https://github.com/dan-damit)
#
# Changes in 1.1.2:
# - Hardened parameter handling: all SearchName params accept [object]
#   and normalize via Resolve-SearchName (supports string/array/PSObject).
# - Case-scoped operations aligned: use -Case only with Get-* cmdlets;
#   removed -Case from New-ComplianceSearchAction.
# - Invoke-HardDelete: added regex confirmation (YES/Y), try/catch,
#   and identity-based monitoring when available.
# - Wait-ForPurgeCompletion: logs terminal states only, guards props,
#   appends (items: N) from Get-ComplianceSearch on success.
# - Removed redundant New-MailboxOnlySearch.
# - Minor UX/logging refinements for clean console + solid audit trail.
# =====================================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Log {
    param([Parameter(Mandatory = $true, Position = 0)][string]$Message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "[{0}] {1}" -f $timestamp, $Message
    Add-Content -Path $script:logFile -Value $entry
    Write-Host $Message
}

function Set-LogFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $script:logFile = $Path
}

function Import-ExchangeOnlineModule {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Yellow
        Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
}

function Connect-SearchSession {
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName)
    Write-Host "Connecting using Search-Only session..." -ForegroundColor Cyan
    Connect-IPPSSession -UserPrincipalName $UserPrincipalName -EnableSearchOnlySession -ErrorAction Stop
    Write-Host "Connected." -ForegroundColor Green
}

function Resolve-OrCreateSearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CaseName,
        [string]$OriginalSearchName
    )

    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'

    if ([string]::IsNullOrWhiteSpace($OriginalSearchName)) {
        Write-Log "[Info] No search name provided. Prompting for KQL query..."
        $customQuery = Read-Host "Enter KQL query"
        if ([string]::IsNullOrWhiteSpace($customQuery)) { throw "Custom query cannot be empty." }

        $newSearchName = "CMS-$timestamp"
        Write-Log "[Custom] Creating mailbox-only search '$newSearchName'..."
        New-ComplianceSearch -Name $newSearchName -Case $CaseName -ExchangeLocation All -ContentMatchQuery $customQuery -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop
        Start-ComplianceSearch -Identity $newSearchName
        return [string]$newSearchName
    }

    try {
        Get-ComplianceSearch -Identity $OriginalSearchName -Case $CaseName -ErrorAction Stop | Out-Null
        Write-Log "[Info] Found existing search '$OriginalSearchName'. Cloning mailbox-only version..."

        $orig = Get-ComplianceSearch -Identity $OriginalSearchName -Case $CaseName -ErrorAction Stop
        $query = $orig.ContentMatchQuery
        if ([string]::IsNullOrWhiteSpace($query)) { throw "Original search has no ContentMatchQuery." }

        $cloneName = "$OriginalSearchName-MO-$timestamp"
        New-ComplianceSearch -Name $cloneName -Case $CaseName -ExchangeLocation All -ContentMatchQuery $query -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop
        Start-ComplianceSearch -Identity $cloneName
        return [string]$cloneName
    }
    catch {
        Write-Log "[Warning] Search '$OriginalSearchName' not found. Prompting for KQL query..."
        $customQuery = Read-Host "Enter KQL query"
        if ([string]::IsNullOrWhiteSpace($customQuery)) { throw "Custom query cannot be empty." }

        $newSearchName = "CMS-$timestamp"
        New-ComplianceSearch -Name $newSearchName -Case $CaseName -ExchangeLocation All -ContentMatchQuery $customQuery -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop
        Start-ComplianceSearch -Identity $newSearchName
        return [string]$newSearchName
    }
}

function Get-SearchDetails {
    param([object]$SearchName, [string]$CaseName)
    Get-ComplianceSearch -Identity $SearchName -Case $CaseName -ErrorAction Stop
}

function Resolve-SearchName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$SearchName
    )

    if ($null -eq $SearchName) {
        throw "Resolve-SearchName: SearchName is null."
    }
    if ($SearchName -is [string]) {
        return $SearchName.Trim()
    }
    if ($SearchName -is [array]) {
        return (Resolve-SearchName -SearchName $SearchName[0])
    }
    if ($SearchName.PSObject -and $SearchName.PSObject.Properties['Name']) {
        $n = [string]$SearchName.Name
        if (-not [string]::IsNullOrWhiteSpace($n)) { return $n.Trim() }
    }
    $s = $SearchName.ToString()
    if ($s -match '^Microsoft\.Exchange\.Compliance.*ComplianceSearch\s(.+)$') {
        return $Matches[1].Trim()
    }

    throw "Resolve-SearchName: Unable to resolve a search name from input type '$($SearchName.GetType().FullName)'. Pass the search name string."
}

function Wait-ForSearchCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$SearchName,
        [string]$CaseName,
        [int]$MaxAttempts = 40,
        [int]$DelaySec = 10
    )

    $name = Resolve-SearchName -SearchName $SearchName
    Write-Log "[Wait] Waiting for search '$name' to reach Completed..."

    for ($i = 1; $i -le $MaxAttempts; $i++) {
        $s = Get-ComplianceSearch -Identity $name -Case $CaseName -ErrorAction Stop
        Write-Log ("Status: {0} (attempt {1}/{2})" -f $s.Status, $i, $MaxAttempts)
        if ($s.Status -eq 'Completed') {
            Write-Log "Search Completed."
            Write-Host "[Success] Search Completed." -ForegroundColor Green
            return $s
        }
        Start-Sleep -Seconds $DelaySec
    }

    throw "Search did not complete in time."
}

function Invoke-HardDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$SearchName,
        [Parameter(Mandatory = $true)][string]$CaseName
    )

    $SearchName = Resolve-SearchName -SearchName $SearchName
    Write-Host "[Purge] Preparing to submit HardDelete for search '$SearchName' in case '$CaseName'." -ForegroundColor Cyan
    Write-Host "This will permanently delete all items found by the search." -ForegroundColor Yellow
    $confirm = Read-Host "Type 'YES' to confirm HardDelete purge"
    if ($confirm -notmatch '^(?i)(YES|Y)$') { throw "Cancelled by user." }

    try {
        $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -ErrorAction Stop
        if ($action -and $action.Identity) {
            Write-Host "[Purge] Submitted: $($action.Identity)" -ForegroundColor Green
            Wait-ForPurgeCompletion -ActionIdentity $action.Identity -CaseName $CaseName
        }
        else {
            Write-Host "[Purge] Submitted (no Identity returned)" -ForegroundColor Green
            Wait-ForPurgeCompletion -SearchName $SearchName -CaseName $CaseName
        }
    }
    catch {
        throw "Failed to submit HardDelete purge for '$SearchName' in case '$CaseName'. Details: $($_.Exception.Message)"
    }
}


function Wait-ForPurgeCompletion {
    [CmdletBinding(DefaultParameterSetName = 'BySearch')]
    param(
        [Parameter(ParameterSetName = 'BySearch', Mandatory = $true)][object]$SearchName,
        [Parameter(ParameterSetName = 'ByAction', Mandatory = $true)][string]$ActionIdentity,
        [string]$CaseName,
        [int]$TimeoutSeconds = 1200,
        [int]$PollSeconds = 5
    )

    $name = $null
    if ($PSCmdlet.ParameterSetName -eq 'BySearch') {
        $name = Resolve-SearchName -SearchName $SearchName
    }

    $targetDesc = $PSCmdlet.ParameterSetName -eq 'ByAction' ? "action '$ActionIdentity'" : "search '$name'"
    Write-Host "[Watch] Monitoring purge $targetDesc..." -ForegroundColor Cyan
    Write-Log  "[Watch] Monitoring purge $targetDesc..."

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $action = $null

        if ($PSCmdlet.ParameterSetName -eq 'ByAction') {
            $params = @{ Identity = $ActionIdentity }
            if ($CaseName) { $params.Case = $CaseName }
            $action = Get-ComplianceSearchAction @params -ErrorAction SilentlyContinue
        }
        else {
            $params = @{}
            if ($CaseName) { $params.Case = $CaseName }
            $action = Get-ComplianceSearchAction -Purge @params -ErrorAction SilentlyContinue |
            Where-Object { $_.SearchName -eq $name } |
            Sort-Object CreatedTime -Descending |
            Select-Object -First 1
        }

        if ($action) {
            $status = $action.PSObject.Properties['Status'] ? $action.Status : 'Unknown'
            Write-Log ("Status={0}" -f $status)

            switch ($status) {
                'Completed' {
                    $items = $null
                    try {
                        $searchId = $name
                        if (-not $searchId) { $searchId = $action.PSObject.Properties['SearchName'] ? $action.SearchName : $null }
                        if ($searchId) {
                            $searchObj = Get-ComplianceSearch -Identity $searchId -Case $CaseName -ErrorAction Stop
                            $items = $searchObj.PSObject.Properties['Items'] ? $searchObj.Items : $null
                        }
                    }
                    catch { $items = $null }

                    $suffix = ($null -ne $items) ? " (items: $items)" : ""
                    Write-Log "[Purge] Completed successfully.$suffix"
                    Write-Host "[Purge] Completed successfully.$suffix" -ForegroundColor Green
                    return
                }
                'PartiallySucceeded' {
                    $errMsg = $action.PSObject.Properties['ErrorMessage'] ? $action.ErrorMessage : 'No error details'
                    Write-Log "[Purge] Partially succeeded: $errMsg"
                    Write-Host "[Purge] Partially succeeded: $errMsg" -ForegroundColor Yellow
                    return
                }
                'Failed' {
                    $errMsg = $action.PSObject.Properties['ErrorMessage'] ? $action.ErrorMessage : 'No error details'
                    Write-Log "[Purge] Failed: $errMsg"
                    Write-Host "[Purge] Failed: $errMsg" -ForegroundColor Red
                    return
                }
            }
        }
        else {
            Write-Host "[Watch] No purge action found yet..." -ForegroundColor DarkYellow
            Write-Log  "[Watch] No purge action found yet..."
        }
        Start-Sleep -Seconds $PollSeconds
    }
    Write-Log  "[Purge] Timed out waiting for completion."
    Write-Host "[Purge] Timed out waiting for completion." -ForegroundColor Red
}

Export-ModuleMember -Function `
    Import-ExchangeOnlineModule, `
    Connect-SearchSession, `
    Get-SearchDetails, `
    Wait-ForSearchCompletion, `
    Invoke-HardDelete, `
    Wait-ForPurgeCompletion, `
    Resolve-OrCreateSearch, `
    Resolve-SearchName
# End of PurviewTools.psm1
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKAttm9vRnvbL5
# Nqve9UC5dFFL/UW0Siy+sdY3mZKy9aCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC8ZuYfgBah
# CijxA0QeER+J+kCfu5tUYqth2JUbgrfgbDANBgkqhkiG9w0BAQEFAASCAgANTYOg
# FFQdwZsxszc78B0MRoxvOAHe9Q2//l1BFKNoLindEI0jZ866GTk/sIOH9zTHHH5K
# k9EkKgwKLjmVnMdtcq1EVDbrLqEGzmFv8ItkbtO+N75UFPFPhQQ0oK1JdyJaeHhY
# QZt7Y2vSt9Gsjuzmh3EDd4dbjrxBRm6dg+ru8fVg4g61wu3sTZCv5rISvO4NPzrr
# fd/tvrZnKlJvGnmtePVGiN6bd2J2i0N8ww6dQrWTdlqBsTxEeIOw/zPLx2NC+rl9
# kihEmFyucXMIuBSC6Fsoqr8o2FfTgiQn2A+jJy3nCvkBSkv4rkhF8vmoyZ7bdD/o
# aGufG0aMPwrVIxibyruGeA83MVNz6c9k+euG2366UIFtoZ7kiJabRUGh6UBsvYBo
# vGuLKuZmesx1ySsaIRj0+s/arAamE8bLT4O9tkL9S7LKm0E1Om5NRV0Lck8/6O6e
# sTGiy7qYhnbWi+eG+2XFbj26CJq+W0XQCLj+1cuShsv0IV5EzAvfa3ZkXGBACEPa
# bAmD+OrUO7cZj8IDCs15IOvZ7S5FFhjYW8a4Cz7ASQORmhLmTXLEggqF/x6Ogtqk
# WkRqTiCLLAqQy0r45X1/urBMKJ3BPkKsS51SS+jN03kzHvNwwaIl2w3XceN8T02I
# pjHhs4OfIef1iRGGZQhl0gxbHT8jLZJeYRPKgqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTIxNTU3NTlaMC8GCSqGSIb3DQEJBDEiBCB65BYlt9UQJ3rcso8y
# n1axVLxqqUFNI8zWAgpmyA+M/jANBgkqhkiG9w0BAQEFAASCAgB4lOrXCUs4P0vO
# OojutO57quipwVD/bE2rwcgU99YdaJVAx+koG4HbQAMQ7aU23Qmjdqim4YjECQvu
# MX/m+g1yrfegHY5z2ruoI2EKEppL7iPAb5Cv6EqWvwZo1bWp+mNfmoEV4q8Wwzrl
# XyAXahVjgZZ18CT/Pz1aaNgb6bpMiXykXkfkXxv18iW9ZVR6ydn60VB09FMmxZ45
# 9S8m4WO9aQYU98jbbKu1sNoR62F4CqVkqvhbf0SC99TfrHPlFI2YgpqfXRqhDeSU
# YomhqtlKHuPAFts7w/+UVpoQ7iF22q/WeL8j/wpzxlbHLt3nmtoj10XxDvaOKT73
# ro6lU0C78XdG4rmfc1py+arKURU4Dop+UG6grecB6ZxTSoCnGBANIQc5mV0PG0/u
# 1TM7x8ttnJjTuCaH1iZsjo+7znG9zYT1ON5hrPI5+DcCvyYCRKbVXhosLQAUmdt7
# ZU9+9GyvBkydMAoWkQRRndNnXN8tTQG7F+WR33mp/EvGXO+ByaDEys0ghTJfNNiT
# RHckYabIzjVf3K4T+lwjyY+KGvecj04sfDn5FaSllmfAjkb4Qnnfp5nxri5EUeyw
# 3t2rvskmpa8CYQ3RqnSnR+bN6hyq9gEAiW4KaB5I1xuy/lQNrgVVKWp6r3S+ZiuZ
# 2IAuXwQAQEnRvPWUkiDc+ZPyjlLcgQ==
# SIG # End signature block
