function New-MailboxSearchClone {
    <#
    .SYNOPSIS
        Clones an existing Compliance Search (mailbox-only) or creates a new one
        with a user-provided KQL query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CaseName,
        [Parameter()][string]$OriginalSearchName
    )

    # --- Config (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $defaults = $cfg["settings"]["defaults"]

    # PS7 null-coalescing: default to $true if missing
    $promptKql = $defaults["promptForKqlQuery"] ?? $true

    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'

    # --- No original search name: prompt for KQL ---
    if ([string]::IsNullOrWhiteSpace($OriginalSearchName)) {

        if (-not $promptKql) {
            throw "OriginalSearchName missing and KQL prompting disabled by config."
        }

        Write-Log -Level Info -Message "No search name provided. Prompting for KQL query..."
        $customQuery = Read-Host "Enter KQL query"

        if ([string]::IsNullOrWhiteSpace($customQuery)) {
            throw "Custom query cannot be empty."
        }

        $newSearchName = "CMS-$timestamp"
        Write-Log -Level Info -Message "Creating mailbox-only search '$newSearchName'..."

        New-ComplianceSearch -Name $newSearchName -Case $CaseName -ExchangeLocation All `
            -ContentMatchQuery $customQuery -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop

        Start-ComplianceSearch -Identity $newSearchName
        return $newSearchName
    }

    # --- Clone path ---
    try {
        $orig = Get-ComplianceSearch -Identity $OriginalSearchName -Case $CaseName -ErrorAction Stop
        $query = $orig.ContentMatchQuery

        if ([string]::IsNullOrWhiteSpace($query)) {
            throw "Original search has no ContentMatchQuery."
        }

        $cloneName = "$OriginalSearchName-MO-$timestamp"
        Write-Log -Level Info -Message "Cloning mailbox-only search '$cloneName'..."

        New-ComplianceSearch -Name $cloneName -Case $CaseName -ExchangeLocation All `
            -ContentMatchQuery $query -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop

        Start-ComplianceSearch -Identity $cloneName
        return $cloneName
    }
    catch {
        Write-Log -Level Warn -Message "Search '$OriginalSearchName' not found or invalid. Prompting for KQL query..."

        if (-not $promptKql) {
            throw "Original search not found and KQL prompting disabled by config."
        }

        $customQuery = Read-Host "Enter KQL query"
        if ([string]::IsNullOrWhiteSpace($customQuery)) {
            throw "Custom query cannot be empty."
        }

        $newSearchName = "CMS-$timestamp"
        Write-Log -Level Info -Message "Creating mailbox-only search '$newSearchName'..."

        New-ComplianceSearch -Name $newSearchName -Case $CaseName -ExchangeLocation All `
            -ContentMatchQuery $customQuery -AllowNotFoundExchangeLocationsEnabled $true -ErrorAction Stop

        Start-ComplianceSearch -Identity $newSearchName
        return $newSearchName
    }
}