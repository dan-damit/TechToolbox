function Test-Administrator {
    <#
    .SYNOPSIS
        Tests if the current PowerShell session is running with Administrator
        privileges.
    .NOTES
        Reusable function for TechToolbox.
    #>
    [CmdletBinding()]
    param()

    try {
        $principal = New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        )
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}