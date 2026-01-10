
function Test-PathAs {
    <#
    .SYNOPSIS
    Tests whether a path exists using alternate credentials.

    .DESCRIPTION
    Test-PathAs uses the TechToolbox impersonation subsystem to evaluate whether
    a file system path exists under the security context of the specified
    credential. This is useful for validating SMB access, deployment accounts,
    service accounts, and cross-domain permissions.

    .PARAMETER Path
    The file system or UNC path to test.

    .PARAMETER Credential
    The credential to impersonate while testing the path.

    .EXAMPLE
    Test-PathAs -Path "\\server\share\installer.msi" -Credential $cred

    .EXAMPLE
    Test-PathAs -Path "C:\RestrictedFolder" -Credential $svc
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