
function Get-WindowsProductKey {
    <#
    .SYNOPSIS
        Retrieves the Windows Product Key from a local or remote computer.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        $params = @{
            Class         = 'SoftwareLicensingService'
            ComputerName  = $ComputerName
            ErrorAction   = 'Stop'
        }

        if ($Credential) {
            $params.Credential = $Credential
        }

        $licensing = Get-CimInstance @params

        [pscustomobject]@{
            ComputerName = $ComputerName
            ProductKey   = $licensing.OA3xOriginalProductKey
        }
    }
    catch {
        Write-Warning "Failed to retrieve product key from $ComputerName $_"
    }
}