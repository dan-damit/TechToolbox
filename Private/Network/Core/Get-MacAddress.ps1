
function Get-MacAddress {
    <#
    .SYNOPSIS
        Retrieves the MAC address for a given IP address from the ARP table.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # Query ARP table for the IP
        $arpOutput = arp -a | Where-Object { $_ -match "^\s*$IP\s" }

        if (-not $arpOutput) {
            return $null
        }

        # Extract MAC address pattern
        if ($arpOutput -match '([0-9a-f]{2}[-:]){5}[0-9a-f]{2}') {
            return $matches[0].ToUpper()
        }

        return $null
    }
    catch {
        Write-Log -Level Error -Message "Get-MacAddress failed for $IP $($_.Exception.Message)"
        return $null
    }
}