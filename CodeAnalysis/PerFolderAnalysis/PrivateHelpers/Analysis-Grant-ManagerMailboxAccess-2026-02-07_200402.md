# Code Analysis Report
Generated: 2/7/2026 8:04:02 PM

## Summary
 The provided PowerShell script `Grant-ManagerMailboxAccess` function grants FullAccess and SendAs permissions to a specified mailbox for a given manager. Here are some suggestions for improving the code's functionality, readability, and performance:

1. Use try-catch blocks instead of multiple nested if-else statements for error handling. This makes the code more concise and easier to read.

2. Use PowerShell Core cmdlets wherever possible as they are cross-platform and offer better performance compared to Exchange Online Management Shell (EOLM) cmdlets. For example, you can replace `Write-Log` with `Write-Output` or `Write-Verbose`.

3. Consider adding validation for the input parameters to ensure that they are properly formatted and exist before proceeding with granting permissions. This helps prevent errors during execution.

4. You may want to refactor the code into separate functions for FullAccess and SendAs granting, making it more modular and easier to maintain.

5. Use more descriptive variable names instead of abbreviations like `$fullAccessGranted` and `$sendAsGranted`. For example, you can use `$grantedFullAccess` and `$grantedSendAs`.

6. Consider adding comments to explain the purpose of each section of code for better readability.

Here's a refactored version of the script with some of these suggestions applied:

```powershell
function Grant-ManagerMailboxAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,   # The mailbox being accessed

        [Parameter(Mandatory)]
        [string]$ManagerUPN  # The manager receiving access
    )

    Write-Verbose ("Granting mailbox access for '{0}' to manager '{1}'..." -f $Identity, $ManagerUPN)

    function Grant-Permission {
        param(
            [string]$permissionName,
            [string]$recipient
        )

        try {
            Write-Verbose ("Granting ${permissionName} to ${recipient}")
            Add-MailboxPermission -Identity $Identity `
                -User $recipient `
                -AccessRights FullAccess, SendAs `
                -InheritanceType All `
                -AutoMapping:$true `
                -ErrorAction Stop
        } catch {
            Write-Error ("Failed to grant ${permissionName}: ${_.Exception.Message}")
        }
    }

    function Validate-Parameters() {
        if (-not (Test-Path "Active Directory" -PathType Container)) {
            throw "Active Directory path not found."
        }

        if (-not (Get-ADUser -Identity $ManagerUPN -ErrorAction SilentlyContinue)) {
            throw "Manager UPN not found."
        }
    }

    Validate-Parameters
    Grant-Permission -permissionName 'FullAccess' -recipient $ManagerUPN
    Grant-Permission -permissionName 'SendAs' -recipient $ManagerUPN

    return [pscustomobject]@ {
        Action = "Grant-ManagerMailboxAccess"
        Identity   = $Identity
        Manager    = $ManagerUPN
        FullAccess = $?.FullAccess
        SendAs     = $?.SendAs
        Success    = ($_.FullAccess -and $_.SendAs)
        Errors     = @(($Error | Where-Object { $_ | Select -ExpandProperty Message }).ToList())
    }
}
```

## Source Code
```powershell
function Grant-ManagerMailboxAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,   # The mailbox being accessed

        [Parameter(Mandatory)]
        [string]$ManagerUPN  # The manager receiving access
    )

    Write-Log -Level Info -Message ("Granting mailbox access for '{0}' to manager '{1}'..." -f $Identity, $ManagerUPN)

    $fullAccessGranted = $false
    $sendAsGranted = $false
    $errors = @()

    # --- FullAccess ---
    try {
        Add-MailboxPermission -Identity $Identity `
            -User $ManagerUPN `
            -AccessRights FullAccess `
            -InheritanceType All `
            -AutoMapping:$true `
            -ErrorAction Stop

        Write-Log -Level Ok -Message ("Granted FullAccess to {0}" -f $ManagerUPN)
        $fullAccessGranted = $true
    }
    catch {
        Write-Log -Level Error -Message ("Failed to grant FullAccess: {0}" -f $_.Exception.Message)
        $errors += "FullAccess: $($_.Exception.Message)"
    }

    # --- SendAs ---
    try {
        Add-RecipientPermission -Identity $Identity `
            -Trustee $ManagerUPN `
            -AccessRights SendAs `
            -ErrorAction Stop

        Write-Log -Level Ok -Message ("Granted SendAs to {0}" -f $ManagerUPN)
        $sendAsGranted = $true
    }
    catch {
        Write-Log -Level Error -Message ("Failed to grant SendAs: {0}" -f $_.Exception.Message)
        $errors += "SendAs: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Action     = "Grant-ManagerMailboxAccess"
        Identity   = $Identity
        Manager    = $ManagerUPN
        FullAccess = $fullAccessGranted
        SendAs     = $sendAsGranted
        Success    = ($fullAccessGranted -and $sendAsGranted)
        Errors     = $errors
    }
}
[SIGNATURE BLOCK REMOVED]

```
