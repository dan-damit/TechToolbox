
function Test-TcpPort {
    <#
    .SYNOPSIS
        Tests if a TCP port is open on a specified IP address within a given timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IP,

        [Parameter(Mandatory)]
        [int]$Port,

        [int]$TimeoutMs = 500
    )

    try {
        $client = New-Object System.Net.Sockets.TcpClient

        # Begin async connect
        $async = $client.BeginConnect($IP, $Port, $null, $null)

        # Wait for timeout
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.Close()
            return $false
        }

        # Complete connection
        $client.EndConnect($async)
        $client.Close()
        return $true
    }
    catch {
        return $false
    }
}