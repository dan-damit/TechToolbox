# Code Analysis Report
Generated: 2/7/2026 8:05:29 PM

## Summary
 Here's a breakdown of the PowerShell script, along with some suggestions for enhancements:

1. **Function and parameter documentation**: The function has good documentation using .SYNOPSIS and .DESCRIPTION attributes. It would be beneficial to add more detailed help for each parameter as well to make it easier for users to understand how they should be used.

2. **Variable naming**: In the script, some variables use camelCase (e.g., `cfg`), while others use PascalCase (e.g., `PSCmdlet`, `requireConfirm`). It is recommended to use consistent casing throughout the code for improved readability.

3. **Indentation and spacing**: The script's indentation could be improved to better align with PowerShell coding standards, such as using four spaces for indentation instead of two, and adding blank lines between sections of code for better readability.

4. **Error handling**: In the current implementation, if there is an error during the submission of the purge operation, it will throw an exception that terminates the script. Instead, you could consider capturing errors within a try/catch block and outputting more informative error messages to help users debug any issues.

5. **Code comments**: The script includes some helpful comments explaining what certain parts of the code do, but it would benefit from additional comments documenting complex sections or areas that may be difficult to understand at a glance.

6. **Use constants for configuration settings**: Instead of hard-coding values such as timeout and polling seconds in multiple places, consider defining them as constants at the top of the script, which makes it easier to update them if needed and improves readability.

7. **Logging**: The logging mechanism used in the script is simple but effective. However, you could consider using a more robust logging library, such as PSWriteProject or Log4Net, to make it easier to customize the logging output and add features like rotating log files.

8. **Parameter validation**: While the script validates that parameters are not null or empty, it does not provide any input validation for the parameter values themselves. Consider adding more robust input validation to ensure that the provided values meet certain criteria before proceeding with the purge operation.

9. **Functional improvements**: To further enhance the functionality of the code, you could consider implementing additional features such as:

   - Prompting users for confirmation when running in an automated environment (e.g., using environment variables to control whether user input is required)
   - Support for soft-deletes and other purge types
   - Options to run the script asynchronously or with progress reporting
   - The ability to cancel purges if needed

Overall, the provided code does a good job of implementing a HardDelete purge operation for Compliance Searches in PowerShell. By addressing the suggestions above, you can improve the script's readability, performance, and functionality, making it more useful for other users.

## Source Code
```powershell

function Invoke-HardDelete {
    <#
    .SYNOPSIS
        Submits a Purview HardDelete purge for a Compliance Search and waits for
        completion.
    .DESCRIPTION
        Optionally requires typed confirmation per config; honors
        -WhatIf/-Confirm for the submission step. Calls Wait-PurgeCompletion to
        monitor the purge status.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SearchName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CaseName
    )

    # --- Config (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $purv = $cfg["settings"]["purview"]

    # Confirmation gate (default to true for safety)
    $requireConfirm = $purv["purge"]["requireConfirmation"]
    if ($null -eq $requireConfirm) { $requireConfirm = $true }

    Write-Log -Level Info -Message ("Preparing HardDelete purge for '{0}' in case '{1}'." -f $SearchName, $CaseName)
    Write-Log -Level Warn -Message "This will permanently delete all items found by the search."

    if ($requireConfirm) {
        $confirm = Read-Host "Type 'YES' to confirm HardDelete purge"
        if ($confirm -notmatch '^(?i)(YES|Y)$') { throw "HardDelete purge cancelled by user." }
    }

    if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $SearchName), 'Submit HardDelete purge')) {
        $action = $null
        try {
            $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -ErrorAction Stop
            if ($action.Identity) {
                Write-Log -Level Ok -Message ("Purge submitted: {0}" -f $action.Identity)

                # Optional: pass config-driven timeouts/polling to Wait-PurgeCompletion
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -ActionIdentity $action.Identity -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
            else {
                Write-Log -Level Ok -Message "Purge submitted (no Identity returned). Monitoring by search name..."
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -SearchName $SearchName -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
        }
        catch {
            Write-Log -Level Error -Message ("Failed to submit purge: {0}" -f $_.Exception.Message)
            throw
        }
    }
    else {
        Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
    }
}

[SIGNATURE BLOCK REMOVED]

```
