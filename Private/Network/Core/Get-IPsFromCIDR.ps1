
function Get-IPsFromCIDR {
    <#
    .SYNOPSIS
        Generates a list of IP addresses from a given CIDR notation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR
    )

    try {
        # Split CIDR into base IP + prefix
        $parts = $CIDR -split '/'
        $baseIP = $parts[0]
        $prefix = [int]$parts[1]

        # Convert base IP to UInt32
        $ipBytes = [System.Net.IPAddress]::Parse($baseIP).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)

        # Calculate host range
        $hostBits = 32 - $prefix
        $numHosts = [math]::Pow(2, $hostBits) - 2

        if ($numHosts -lt 1) {
            return @()
        }

        $startIP = $ipInt + 1

        $list = for ($i = 0; $i -lt $numHosts; $i++) {
            $cur = $startIP + $i
            $b = [BitConverter]::GetBytes($cur)
            [Array]::Reverse($b)
            [System.Net.IPAddress]::Parse(($b -join '.')).ToString()
        }

        return , $list
    }
    catch {
        Write-Log -Level Error -Message "Get-IPsFromCIDR failed for '$CIDR': $($_.Exception.Message)"
        return @()
    }
}