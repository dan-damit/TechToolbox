
function Invoke-EXOReport {
    <#
    .SYNOPSIS
        Example function that connects to Exchange Online, performs an action,
        and disconnects.
    .DESCRIPTION
        This is a sample function demonstrating how to ensure the Exchange
        Online Management module is present, connect to EXO, perform some
        action, and then disconnect cleanly.
    .PARAMETER UserPrincipalName
        The user principal name (UPN) to connect as.
    .INPUTS
        None.
    .OUTPUTS
        None.
    .EXAMPLE
        Invoke-EXOReport -UserPrincipalName 'user@domain.com'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName
    )

    # Ensure EXO v3.9.0 is present & imported
    Ensure-ExchangeOnlineModule

    # Connect when needed; keep banner off for clean console
    Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$false

    try {
        $mbx = Get-Mailbox -Identity $UserPrincipalName
        # ...do work...
    }
    finally {
        Disconnect-ExchangeOnline -Confirm:$false
    }
}
