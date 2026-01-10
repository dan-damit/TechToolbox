
function Get-NetbiosName {
    <#
    .SYNOPSIS
        Retrieves the NetBIOS name for a given IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP
    )

    try {
        # Query NetBIOS table for the host
        $output = & nbtstat -A $IP 2>$null

        if (-not $output) {
            return $null
        }

        # Look for the <00> unique workstation service name
        # Example line:
        #   MYPC            <00>  UNIQUE      Registered
        $line = $output | Select-String "<00>" | Select-Object -First 1

        if ($line) {
            # Split on whitespace and take the first token (the hostname)
            $tokens = $line.ToString().Trim() -split '\s+'
            if ($tokens.Count -gt 0) {
                return $tokens[0]
            }
        }

        return $null
    }
    catch {
        # NetBIOS lookup failed or host not responding
        return $null
    }
}