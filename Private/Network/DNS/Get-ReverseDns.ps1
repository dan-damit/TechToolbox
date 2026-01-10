
function Get-ReverseDns {
    <#
    .SYNOPSIS
        Retrieves the reverse DNS PTR record for a given IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        $ptr = Resolve-DnsName -Name $IP -Type PTR -ErrorAction Stop

        if ($ptr -and $ptr.NameHost) {
            return $ptr.NameHost
        }

        return $null
    }
    catch {
        # PTR not found or DNS server unreachable
        return $null
    }
}