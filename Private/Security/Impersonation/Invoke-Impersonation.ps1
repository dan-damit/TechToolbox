
function Invoke-Impersonation {
    <#
    .SYNOPSIS
        Executes a script block under the context of specified user credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    # Split domain\user if needed
    $parts = $Credential.UserName.Split('\', 2)
    if ($parts.Count -eq 2) {
        $domain   = $parts[0]
        $username = $parts[1]
    } else {
        $domain   = $env:USERDOMAIN
        $username = $parts[0]
    }

    $password = $Credential.GetNetworkCredential().Password

    # LOGON32_LOGON_NEW_CREDENTIALS = 9
    # LOGON32_PROVIDER_WINNT50      = 3
    $token = [IntPtr]::Zero
    $ok = [CredImpersonator]::LogonUser(
        $username, $domain, $password, 9, 3, [ref]$token
    )

    if (-not $ok) {
        return $null
    }

    $identity = [System.Security.Principal.WindowsIdentity]::new($token)
    $context  = $identity.Impersonate()

    try {
        & $ScriptBlock
    }
    finally {
        $context.Undo()
        $context.Dispose()
        [CredImpersonator]::CloseHandle($token) | Out-Null
    }
}