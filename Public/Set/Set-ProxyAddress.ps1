
function Set-ProxyAddress {
    <#
    .SYNOPSIS
    Sets the primary SMTP proxy address for an Active Directory user.

    .DESCRIPTION
    This function sets the primary SMTP proxy address for a specified Active
    Directory user. It ensures that the new primary address is added correctly
    and removes any existing primary SMTP addresses.

    .PARAMETER Username
    The username (sAMAccountName) of the Active Directory user.

    .PARAMETER ProxyAddress
    The new primary SMTP proxy address to set (e.g., user@example.com).
    #>
    param(
        [Parameter(Mandatory)][string]$Username,
        [Parameter(Mandatory)][ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')][string]$ProxyAddress
    )

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "The ActiveDirectory module is required to run this script. $_"
        return
    }
    $PrimarySMTP = "SMTP:$ProxyAddress"
    try {
        Set-ADUser -Identity $Username -Add @{ proxyAddresses = $PrimarySMTP } -ErrorAction Stop
        Write-Host "Primary SMTP address '$PrimarySMTP' added to user '$Username'."
    }
    catch {
        Write-Error "Failed to add primary SMTP address '$PrimarySMTP' to user '$Username'. Error: $($_.Exception.Message)"
    }
    $user = Get-ADUser -Identity $Username -Properties proxyAddresses
    $existingProxyAddresses = @()
    if ($user.proxyAddresses) {
        $existingProxyAddresses = @($user.proxyAddresses)
    }

    # Remove any existing primary SMTP entries and any duplicates of the new primary address (case-insensitive)
    $filteredProxyAddresses = $existingProxyAddresses | Where-Object {
        ($_ -notlike 'SMTP:*') -and
        ($_.ToLower() -ne $PrimarySMTP.ToLower())
    }

    # Add the new primary SMTP address
    $updatedProxyAddresses = $filteredProxyAddresses + $PrimarySMTP

    # Replace proxyAddresses to ensure there is a single, correct primary SMTP value
    Set-ADUser -Identity $Username -Replace @{ proxyAddresses = $updatedProxyAddresses }
    Write-Host "Primary SMTP address '$PrimarySMTP' set for user '$Username'."
}