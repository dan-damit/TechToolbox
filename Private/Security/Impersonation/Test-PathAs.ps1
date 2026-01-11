
function Test-PathAs {
    <#
    .SYNOPSIS
        Tests the existence of a path under the context of specified user
        credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][pscredential]$Credential
    )

    Invoke-Impersonation -Credential $Credential -ScriptBlock {
        Test-Path -LiteralPath $Path
    }
}