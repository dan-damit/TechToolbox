
function Get-HttpInfo {
    <#
    .SYNOPSIS
        Retrieves HTTP headers from a specified IP address and port if
        available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutMs = 1000
    )

    try {
        # Build URL
        $url = "http://$IP`:$Port/"

        # Create request
        $req = [System.Net.WebRequest]::Create($url)
        $req.Timeout = $TimeoutMs
        $req.Method = "HEAD"
        $req.AllowAutoRedirect = $false

        # Execute
        $resp = $req.GetResponse()

        # Extract headers into a hashtable
        $headers = @{}
        foreach ($key in $resp.Headers.AllKeys) {
            $headers[$key] = $resp.Headers[$key]
        }

        $resp.Close()
        return $headers
    }
    catch {
        # No banner, no response, or port closed
        return $null
    }
}