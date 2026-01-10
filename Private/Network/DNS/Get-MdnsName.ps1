
function Get-MdnsName {
    <#
    .SYNOPSIS
        Retrieves the mDNS name for a given IP address if available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # First attempt: look for .local names in ARP output
        # Some devices register their mDNS name in the ARP table
        $arpOutput = arp -a | Where-Object { $_ -match "^\s*$IP\s" }

        if ($arpOutput -and $arpOutput -match '([a-zA-Z0-9\-]+\.local)') {
            return $matches[1]
        }

        # Second attempt: reverse lookup for .local PTRs
        try {
            $ptr = Resolve-DnsName -Name $IP -Type PTR -ErrorAction Stop |
            Where-Object { $_.NameHost -like '*.local' } |
            Select-Object -ExpandProperty NameHost -First 1

            if ($ptr) {
                return $ptr
            }
        }
        catch {
            # ignore PTR failures
        }

        # Third attempt: heuristic fallback
        # Some devices respond to <ip>.local even if not registered
        $synthetic = "$IP.local"
        try {
            $probe = Resolve-DnsName -Name $synthetic -ErrorAction Stop
            if ($probe) {
                return $synthetic
            }
        }
        catch {
            # ignore
        }

        return $null
    }
    catch {
        return $null
    }
}