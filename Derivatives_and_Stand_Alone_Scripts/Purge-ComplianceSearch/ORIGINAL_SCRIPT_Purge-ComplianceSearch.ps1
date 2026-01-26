
# ============================================================
# Purview Compliance Search: Workload-aware Preview & Purge
# Author: Dan.Damit (https://github.com/dan-damit)
# Enhancements:
# - Scope selection: Tenant-wide vs Case-scoped
# - Workload check (Exchange vs SharePoint/OneDrive sources)
# - Auto-create mailbox-only clone from original query
# - Guided Preview -> SoftDelete -> HardDelete flow
# - Search-Only session by default; fallback to Full only if needed
# - REMOVED: ForceFullSession parameter
# ============================================================

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --------------------------
# Module bootstrap
# --------------------------
function Import-ExchangeOnlineModule {
    try {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-Host "ExchangeOnlineManagement module not found. Installing..." -ForegroundColor Yellow
            Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to install/import ExchangeOnlineManagement: $($_.Exception.Message)"
        throw
    }
}

# --------------------------
# Connect (Search-Only by default; fallback to Full)
# --------------------------
function Connect-SearchSession {
    param([Parameter(Mandatory = $true)][string]$UserPrincipalName)

    Write-Host "Connecting using Search-Only session..." -ForegroundColor Cyan
    try {
        # Required for purge actions in many tenants (EXO v3.9.0+)
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -EnableSearchOnlySession -ErrorAction Stop
        Write-Host "Connected using Search-Only session." -ForegroundColor Green
        return "SearchOnly"
    }
    catch {
        Write-Host "Search-Only session failed. Falling back to full session..." -ForegroundColor Yellow
        Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        Write-Host "Connected using full IPPSSession." -ForegroundColor Green
        return "Full"
    }
}

# --------------------------
# Listing helpers (tenant-wide & case)
# --------------------------
function Show-RecentComplianceSearches {
    param([int]$Top = 10)
    Write-Host "`nTop $Top most recent TENANT-WIDE compliance searches:" -ForegroundColor Cyan
    $searches = Get-ComplianceSearch |
    Sort-Object -Property CreatedTime -Descending |
    
    # Select ItemsFound if present; else fall back to Items
    Select-Object -First $Top `
        Name, Status,
    @{ N  = 'Items';
        E = { if ($_.PSObject.Properties['ItemsFound'] -and $null -ne $_.ItemsFound) { $_.ItemsFound }
            else {
                $_.Items
            }
        }
    },
    @{ N = 'Created_Local'; E = { $_.CreatedTime.ToLocalTime() } }
    if (-not $searches) { Write-Warning "No tenant-wide searches." } else { $searches | Format-Table -AutoSize }
}

function Get-ComplianceCaseByName {
    param([Parameter(Mandatory = $true)][string]$CaseName)
    $case = Get-ComplianceCase | Where-Object { $_.Name -eq $CaseName -or $_.Identity -eq $CaseName }
    if (-not $case) { throw "Compliance case '$CaseName' not found." }
    return $case
}

function Show-CaseComplianceSearches {
    param([Parameter(Mandatory = $true)][string]$CaseName, [int]$Top = 15)
    Write-Host "`nTop $Top searches in case '$CaseName':" -ForegroundColor Cyan
    $searches = Get-ComplianceSearch -Case $CaseName |
    Sort-Object -Property CreatedTime -Descending |

    # Select ItemsFound if present; else fall back to Items
    Select-Object -First $Top `
        Name, Status,
    @{ N  = 'Items';
        E = { if ($_.PSObject.Properties['ItemsFound'] -and $null -ne $_.ItemsFound) { $_.ItemsFound }
            else {
                $_.Items
            }
        }
    },
    @{ N = 'Created_Local'; E = { $_.CreatedTime.ToLocalTime() } }
    if (-not $searches) { Write-Warning "No searches in case '$CaseName'." } else { $searches | Format-Table -AutoSize }
}

# --------------------------
# Workload analysis
# --------------------------
function Get-SearchDetails {
    param([Parameter(Mandatory = $true)][string]$SearchName, [string]$CaseName)
    if ([string]::IsNullOrWhiteSpace($CaseName)) {
        return Get-ComplianceSearch -Identity $SearchName -ErrorAction Stop
    }
    else {
        return Get-ComplianceSearch -Identity $SearchName -Case $CaseName -ErrorAction Stop
    }
}

function Test-HasNonMailboxWorkloads {
    param([Parameter(Mandatory = $true)]$SearchObj)
    # Some tenants expose these properties; others may not. Treat non-empty as true.
    $hasSP = $false
    $hasOD = $false
    $spProps = @('SharePointLocation', 'SharePointLocationExclusion')
    $odProps = @('OneDriveLocation', 'OneDriveLocationExclusion')  # property names vary; check presence

    foreach ($p in $spProps) { if ($SearchObj.PSObject.Properties[$p] -and $SearchObj.$p) { $hasSP = $true } }
    foreach ($p in $odProps) { if ($SearchObj.PSObject.Properties[$p] -and $SearchObj.$p) { $hasOD = $true } }

    return ($hasSP -or $hasOD)
}

function Get-MailboxSourcesFromSearch {
    param([Parameter(Mandatory = $true)]$SearchObj)
    # If ExchangeLocation is present, return it; otherwise assume 'All'
    if ($SearchObj.PSObject.Properties['ExchangeLocation'] -and $SearchObj.ExchangeLocation) {
        return $SearchObj.ExchangeLocation
    }
    else {
        return @('All')
    }
}

# --------------------------
# Normalize search name input
# --------------------------
function Resolve-SearchName {
    param([Parameter(Mandatory=$true)]$SearchName)
    # If an object was passed, try to read .Name; otherwise use the string as-is
    if ($SearchName -is [string]) { return $SearchName }
    if ($SearchName.PSObject.Properties['Name']) { return $SearchName.Name }
    # Last resort: strip any type prefix if someone passed .ToString()
    if ($SearchName -is [object]) {
        $s = $SearchName.ToString()
        # Remove type name prefix like '...ComplianceSearch ' if present
        if ($s -match '\s#') { return ($s -replace '^.*ComplianceSearch\s','') }
        return $s
    }
}

# --------------------------
# Wait for search completion (case-aware)
# --------------------------
function Wait-ForSearchCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$SearchName,
        [string]$CaseName,
        [int]$MaxAttempts = 40,
        [int]$DelaySec = 5
    )
    $name = Resolve-SearchName $SearchName
    Write-Host "[Wait] Ensuring search '$name' reaches 'Completed'..." -ForegroundColor Cyan

    for ($i=1; $i -le $MaxAttempts; $i++) {
        $s = Get-ComplianceSearch -Identity $name -Case $CaseName -ErrorAction Stop
        Write-Host ("Status: {0} (attempt {1}/{2})" -f $s.Status, $i, $MaxAttempts) -ForegroundColor Yellow
        if ($s.Status -eq 'Completed') { Write-Host "Search is Completed." -ForegroundColor Green; return $true }
        Start-Sleep -Seconds $DelaySec
    }
    Write-Host "Search never reached Completed. Cannot continue." -ForegroundColor Red
    return $false
}

# --------------------------
# Create mailbox-only clone (tenant or case)
# --------------------------
function New-MailboxOnlyClone {
    param(
        [Parameter(Mandatory = $true)][string]$OriginalSearchName,
        [string]$CaseName,
        [Parameter(Mandatory = $true)][string]$NewSearchName
    )

    Write-Host ("[Clone] Creating mailbox-only search '{0}' from '{1}'..." -f $NewSearchName, $OriginalSearchName) -ForegroundColor Cyan
    $orig = Get-SearchDetails -SearchName $OriginalSearchName -CaseName $CaseName

    # Try to read the query and mailbox sources
    $query = $orig.PSObject.Properties['ContentMatchQuery'] ? $orig.ContentMatchQuery : $null
    $mailboxes = Get-MailboxSourcesFromSearch -SearchObj $orig

    if ([string]::IsNullOrWhiteSpace($query)) {
        Write-Warning "[Clone] Original search has no ContentMatchQuery; you'll be prompted to confirm."
        $query = Read-Host "Enter ContentMatchQuery (KQL)"
        if ([string]::IsNullOrWhiteSpace($query)) { throw "[Clone] ContentMatchQuery is required." }
    }

    if ([string]::IsNullOrWhiteSpace($CaseName)) {
        New-ComplianceSearch -Name $NewSearchName `
            -ExchangeLocation $mailboxes `
            -ContentMatchQuery $query `
            -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop
    }
    else {
        New-ComplianceSearch -Name $NewSearchName -Case $CaseName `
            -ExchangeLocation $mailboxes `
            -ContentMatchQuery $query `
            -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop
    }

    Write-Host "[Clone] Search created." -ForegroundColor Green
    Start-ComplianceSearch -Identity $NewSearchName -ErrorAction Stop
    Write-Host "[Clone] Start issued. Waiting for completion..." -ForegroundColor Yellow
    Wait-ForSearchCompletion -SearchName $NewSearchName -CaseName $CaseName | Out-Null

    $s = Get-SearchDetails -SearchName $NewSearchName -CaseName $CaseName
    $count = $s.PSObject.Properties['ItemsFound'] ? $s.ItemsFound : $s.Items
    Write-Host ("[Clone] Completed. Items={0}" -f $count) -ForegroundColor Green
    return [string]$NewSearchName
}

# --------------------------
# Guided purge (Preview -> SoftDelete -> HardDelete)
# --------------------------
function Invoke-GuidedPurge {
    param(
        [Parameter(Mandatory = $true)][string]$SearchName,
        [string]$CaseName,
        [string]$SessionMode,
        [string]$UserPrincipalName
    )

    # Ensure Completed
    if (-not (Wait-ForSearchCompletion -SearchName $SearchName -CaseName $CaseName)) { return }

    $s = Get-SearchDetails -SearchName $SearchName -CaseName $CaseName
    $count = $s.PSObject.Properties['ItemsFound'] ? $s.ItemsFound : $s.Items
    Write-Host ("[Info] Search '{0}' Completed. Items={1}" -f $SearchName, $count) -ForegroundColor Cyan

    # SoftDelete first?
    $soft = Read-Host "Proceed with SoftDelete purge? (Y/N)"
    if ($soft -match '^[Yy]$') {
        if (-not (Submit-Purge -SearchName $SearchName -PurgeType 'SoftDelete' -SessionMode $SessionMode -UserPrincipalName $UserPrincipalName)) {
            Write-Warning "[SoftDelete] Failed or cancelled."
            return
        }
    }

    # HardDelete?
    $hard = Read-Host "Proceed with HardDelete purge (permanent)? (Y/N)"
    if ($hard -match '^[Yy]$') {
        Submit-Purge -SearchName $SearchName -PurgeType 'HardDelete' -SessionMode $SessionMode -UserPrincipalName $UserPrincipalName | Out-Null
    }
}

# --------------------------
# Wait for purge completion
# --------------------------
function Wait-ForPurgeCompletion {
    param(
        [Parameter(Mandatory = $true)][string]$SearchName,
        [string]$CaseName,
        [int]$TimeoutSeconds = 600,   # 10 minutes default
        [int]$PollSeconds = 5,     # initial poll interval
        [switch]$VerboseLog
    )

    # Target action Identity pattern: <Search.Identity>_Purge
    $expectedPrefix = "{0}_Purge" -f $SearchName

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempt = 0
    [bool]$seenAny = $false

    while ((Get-Date) -lt $deadline) {
        $attempt++

        try {
            # Enumerate actions tied to the search; case-aware if provided
            $actions = if ([string]::IsNullOrWhiteSpace($CaseName)) {
                Get-ComplianceSearchAction -SearchName $SearchName -ErrorAction SilentlyContinue
            }
            else {
                Get-ComplianceSearchAction -SearchName $SearchName -ErrorAction SilentlyContinue
            }

            if ($actions) {
                $seenAny = $true
                $purgeAction =
                $actions |
                Where-Object {
                    $_.PSObject.Properties['Action'] -and $_.Action -eq 'Purge' -and
                    $_.PSObject.Properties['Identity'] -and
                    $_.Identity -like "$expectedPrefix*"
                } |
                Sort-Object -Property CreatedTime -Descending |
                Select-Object -First 1

                if ($purgeAction) {
                    $status = $purgeAction.Status
                    if ($VerboseLog) {
                        Write-Host ("[Watch] Attempt {0}: {1} Status={2}" -f $attempt, $purgeAction.Identity, $status) -ForegroundColor Yellow
                    }

                    switch ($status) {
                        'Completed' {
                            Write-Host ("[Purge] Action '{0}' Completed." -f $purgeAction.Identity) -ForegroundColor Green
                            return $true
                        }
                        'Failed' {
                            $msg = $purgeAction.PSObject.Properties['ErrorMessage'] ? $purgeAction.ErrorMessage : $null
                            Write-Host ("[Purge] Action '{0}' Failed. {1}" -f $purgeAction.Identity, ($msg ?? '')) -ForegroundColor Red
                            return $false
                        }
                        default {
                            # Continue polling for Queued/InProgress/NotStarted/etc.
                        }
                    }
                }
                else {
                    if ($VerboseLog) {
                        Write-Host "[Watch] No purge action found yet for this search." -ForegroundColor DarkYellow
                    }
                }
            }
            else {
                if ($VerboseLog) {
                    Write-Host "[Watch] Actions not visible yet; waiting..." -ForegroundColor DarkYellow
                }
            }
        }
        catch {
            # Transient reader errors—keep trying until deadline
            if ($VerboseLog) {
                Write-Host ("[Watch] Lookup error: {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
            }
        }

        Start-Sleep -Seconds $PollSeconds

        # Optional gentle backoff after first 10 attempts (avoid hammering)
        if ($attempt -eq 10 -and $PollSeconds -lt 10) { $PollSeconds = 10 }
        if ($attempt -eq 30 -and $PollSeconds -lt 20) { $PollSeconds = 20 }
    }

    Write-Host "[Purge] Timed out waiting for completion." -ForegroundColor Red
    return $false
}

# --------------------------
# Submit purge with fallback
# --------------------------
function Submit-Purge {
    param(
        [Parameter(Mandatory = $true)][string]$SearchName,
        [ValidateSet('SoftDelete', 'HardDelete')][string]$PurgeType,
        [string]$SessionMode,
        [string]$UserPrincipalName
    )

    Write-Host ("[Purge] Submitting {0}..." -f $PurgeType) -ForegroundColor Cyan
    $confirm = Read-Host "Type 'YES' to confirm"
    if ($confirm -ne 'YES') {
        Write-Host "[Purge] Cancelled by user." -ForegroundColor Yellow
        return $false
    }

    $attempt = 0
    $maxAttempts = 2
    while ($attempt -lt $maxAttempts) {
        $attempt++
        try {
            $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType $PurgeType -ErrorAction Stop
            Write-Host ("[Purge] Submitted: {0}" -f $action.Identity) -ForegroundColor Green

            # Replace the ad-hoc loop with the dedicated watcher
            $ok = Wait-ForPurgeCompletion -SearchName $SearchName -CaseName $null -TimeoutSeconds 900 -PollSeconds 5 -VerboseLog
            if ($ok) { return $true } else { throw "Purge action did not complete successfully." }
        }
        catch {
            $msg = $_.Exception.Message
            Write-Host "[Purge] Failed: $msg" -ForegroundColor Red

            $canFallback = ($SessionMode -eq "SearchOnly") -and ($attempt -eq 1) -and (
                $msg -match "Search-Only" -or
                $msg -match "not permitted" -or
                $msg -match "full compliance session"
            )
            if ($canFallback) {
                Write-Host "[Purge] Fallback to Full IPPSSession..." -ForegroundColor Yellow
                Disconnect-ExchangeOnline -Confirm:$false
                Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ErrorAction Stop
                $SessionMode = "Full"
                continue
            }
            throw
        }
    }
    Write-Host "[Purge] All attempts failed." -ForegroundColor Red
    return $false
}

# --------------------------
# Main
# --------------------------
try {
    Import-ExchangeOnlineModule

    $upn = Read-Host "Enter UPN (e.g., user@domain.com)"
    if ([string]::IsNullOrWhiteSpace($upn)) { throw "UPN cannot be empty." }

    $sessionMode = Connect-SearchSession -UserPrincipalName $upn

    Write-Host "`nChoose scope:" -ForegroundColor Cyan
    Write-Host "  1) Tenant-wide (Compliance searches not in a case)"
    Write-Host "  2) eDiscovery Case-scoped"
    $scopeChoice = Read-Host "Enter 1 or 2"
    if ($scopeChoice -notin @('1', '2')) { throw "Invalid scope selection." }

    $caseName = $null

    if ($scopeChoice -eq '1') {
        # ----- Tenant-wide path -----
        Show-RecentComplianceSearches -Top 10

        $searchName = Read-Host "Enter the Compliance Search Name/ID (tenant-wide)"
        if ([string]::IsNullOrWhiteSpace($searchName)) { throw "Search Name/ID cannot be empty." }

        # Read selected search details
        $searchObj = Get-SearchDetails -SearchName $searchName -CaseName $null
        
        # Check for non-mailbox workloads (OneDrice/SharePoint/etc.)
        $hasNonMailbox = Test-HasNonMailboxWorkloads -SearchObj $searchObj
        if ($hasNonMailbox) {
            Write-Warning "This search includes SharePoint/OneDrive sources. Purge supports Exchange mailboxes only."
            $cloneName = Read-Host "Create mailbox-only clone? Enter new search name (or press Enter to skip)"
            if (-not [string]::IsNullOrWhiteSpace($cloneName)) {
                # Optional: collision check (append timestamp if already exists)
                try {
                    Get-ComplianceSearch -Identity $cloneName -ErrorAction Stop | Out-Null
                    Write-Warning "Search '$cloneName' already exists. Appending timestamp."
                    $cloneName = '{0}-{1}' -f $cloneName, (Get-Date -Format 'yyyyMMddHHmmss')
                }
                catch { }

                # Create & start mailbox-only clone (returns new search name as [string])
                $cloneParams = @{
                    OriginalSearchName = $searchName
                    NewSearchName      = $cloneName
                    CaseName           = $null
                }
                $searchName = New-MailboxOnlyClone @cloneParams
            }
        }

        # Normalize and proceed with guided actions (clone or original)
        $searchName = ([string]$searchName).Trim()
        Invoke-GuidedPurge -SearchName $searchName -CaseName $caseName -SessionMode $sessionMode -UserPrincipalName $upn
    }
    else {
        # ----- Case-scoped path -----
        $caseName = Read-Host "Enter the eDiscovery Case Name/ID (e.g., #INC-128959)"
        if ([string]::IsNullOrWhiteSpace($caseName)) { throw "Case cannot be empty." }

        # Validate the case exists
        $case = Get-ComplianceCaseByName -CaseName $caseName

        # List searches in the case and prompt
        Show-CaseComplianceSearches -CaseName $caseName -Top 15

        $searchName = Read-Host "Enter the Compliance Search Name/ID (inside case '$caseName')"
        if ([string]::IsNullOrWhiteSpace($searchName)) { throw "Search Name/ID cannot be empty." }

        # Read selected search details
        $searchObj = Get-SearchDetails -SearchName $searchName -CaseName $caseName
        
        # Check for non-mailbox workloads (OneDrice/SharePoint/etc.)
        $hasNonMailbox = Test-HasNonMailboxWorkloads -SearchObj $searchObj
        if ($hasNonMailbox) {
            Write-Warning "This case search includes SharePoint/OneDrive sources. Purge supports Exchange mailboxes only."
            $cloneName = Read-Host "Create mailbox-only clone in this case? Enter new search name (or press Enter to skip)"
            if (-not [string]::IsNullOrWhiteSpace($cloneName)) {
                # Optional: collision check (append timestamp if exists)
                try {
                    Get-ComplianceSearch -Identity $cloneName -Case $caseName -ErrorAction Stop | Out-Null
                    Write-Warning "Search '$cloneName' already exists. Appending timestamp."
                    $cloneName = '{0}-{1}' -f $cloneName, (Get-Date -Format 'yyyyMMddHHmmss')
                }
                catch { }

                # Create & start mailbox-only clone (returns new search name as [string])
                $cloneParams = @{
                    OriginalSearchName = $searchName
                    NewSearchName      = $cloneName
                    CaseName           = $caseName
                }
                $searchName = New-MailboxOnlyClone @cloneParams
            }
        }

        # Normalize and proceed with guided actions (clone or original)
        $searchName = ([string]$searchName).Trim()
        Invoke-GuidedPurge -SearchName $searchName -CaseName $caseName -SessionMode $sessionMode -UserPrincipalName $upn
    }
}
catch {
    Write-Host "`n[ERROR] $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host ("At {0}:{1}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber) -ForegroundColor DarkRed
        Write-Host "Line: $($_.InvocationInfo.Line.Trim())" -ForegroundColor DarkRed
    }
}
finally {
    $disconnect = Read-Host "`nDisconnect session now? (Y to disconnect)"
    if ($disconnect -match '^[Yy]$') {
        Disconnect-ExchangeOnline -Confirm:$false
        Write-Host "Disconnected." -ForegroundColor Green
    }
    else {
        Write-Host "Session remains connected." -ForegroundColor Yellow
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCu/Co8TQuoYBy8
# 649XcoSsh7ks1CqajQI05kzJPfP+x6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDLRQZiAc3C
# JEHMODTgprHojFkF78mY1hefG9+lPDIKljANBgkqhkiG9w0BAQEFAASCAgBE5Klz
# I0HBSJSkH6p+IwDZSHl3B/ytr8vtZnEcy3n5oNWfWmaFddGFTDITrd+5URxg/klQ
# +5fQdjwobNk45IaVeyoTeM+HSaR3HRdIP/3OzBknV2buRr/TJFliOKq5sOtxyNQY
# 5uJep3vl/VFh1USc+MdMV384dT+c1semn7Q5Px77MPnLTbOc4EyNXLDpg6hsQxnp
# 9WAtwKeBZqiahmLG5rhLHu/iVWGuKLHneC6XgWOk58mZI8nQx8ovRqSoCEBoFJp6
# VYSm/IjzkvvP18qjvGkiP7FrXkG9ElSlj6hWY+QE/Vz0wxPtW7A6PlFSKJ8zEtl6
# aOkUGLu/RCL7HKLG73ro0lFZgxfBoMOk4KPmxXgj9EAGOeERY19a+XvGPPyWLf6G
# BSwfWHuQkOvne7azShZObdjK+YW0wKsC/8L0yZLd1/P6bkT4nIuKkf0D4a0cD1Q/
# ntAVfsfpxUeRKmO0igJqSLWBfZKD9OSJOaIoHZKDCaVeqTwQLfK7FCVpVBxgWkr8
# MuhjSWpJvq/ER4THInxPU+utnuxv/efQulLYrq7O+4bEOrEhmEvpbv00O3JzQsdG
# Hm3m4W4IWj9kptnfTjEWWNo5QOdhsqUCSO3far0f1Xt2D1F8ZhHnBrpkoKMsjKs6
# O+yggr0uqmANWSTWZ/cCkF6OEMEsTPqhnsPqI6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMDkyMDQyMjBaMC8GCSqGSIb3DQEJBDEiBCCsNOnL4fj4Ap5Qx1mt
# sAHvtLeIBcS8jJuq1SFHsJIS7jANBgkqhkiG9w0BAQEFAASCAgBjj3RrQI/euGtA
# Hn8JgQnf4M2CZ9UsPxI3LjpuGwqMY9/xHlk/fyqFx/1VgSC1quCIrHfHlOoEMoBZ
# pTeqv1/0W3Sh3gBtu0bvWe56RJJEH/Agi+oNQS74T1OFkuOTQ7bMi466D3wHNoPK
# XnyLALwd3htTtTY4Y5E+ehkJ2whCrGYp9TeP7FInIBvcheyPAJJoSEylpMkKEpss
# SsGe4uGVDhJfECTMgwKj4PWytOUyis03BNEsdtWIuGklZ3trl7cv3nBE833Lmyg+
# aY1gP1cqJ7nQq4LxbYqYEUUm97oPsHrJkCau5xhY+/GLSADsSzMkGPRNtcR+WQ11
# TjZbkjVT8GaiMwVcegpaAzzBWERCakTSKZUPC+MV9XvGgMLd10YWpn/6/J7C3DB+
# Yl0OhNvdkHpSpoxdqy5Mvv8t6enLWFal1X72UwBYy2S7eY3No8ZsP4mxBG32qtNW
# obBjDVtsTuPW+2pB+EssIJazKSflrg8BHMuqq+8tkK6lDFgAyTmBDWFQqipmS5Pz
# HJLxUHUoU/+J/xErPnVpASq8Af9O3HObUuVzSzZzKDoZayuGWz60wyZH5fOwQ9Oc
# PuufQZxEnH3RrZaSgsZLbB917awNbRBJA9NPtVz3HB35xQb6K9ABrfwtTWWLuMpY
# JasazkKA2eCGGam3J82XmCNsSH+e5w==
# SIG # End signature block
