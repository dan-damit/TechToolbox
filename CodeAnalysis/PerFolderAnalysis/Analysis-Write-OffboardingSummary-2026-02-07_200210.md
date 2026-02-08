# Code Analysis Report
Generated: 2/7/2026 8:02:10 PM

## Summary
 Here's a breakdown of the PowerShell script and some suggestions for improving its functionality, readability, and performance:

1. Variable Naming: The variable names could be more descriptive to better reflect their purpose in the code. For example, `$cfg` could be renamed to `$config`, `$off` could be renamed to `$offboardingSettings`, etc.
2. Error Handling: The error handling could be enhanced by using a custom exception class or at least providing more context about the error that occurred. This would make it easier for users to understand and debug any issues that may arise during execution.
3. Documentation: Adding comments to explain what each section of the code does and why certain decisions were made can greatly improve the readability and maintainability of the script.
4. Formatting: The formatting could be improved by using consistent indentation, spacing, and line breaks throughout the script. This would make it easier for others to understand the structure of the code and reduce potential errors due to misaligned code blocks.
5. Modularity: Breaking down the script into smaller, more modular functions can help improve readability and maintainability. For example, the logic for loading and determining the output directory could be extracted into a separate function.
6. Input Validation: Adding input validation to ensure that `$User` and `$Results` are properly formatted and contain valid data would help prevent potential errors and make the script more robust.
7. Error Reporting: Instead of simply writing error messages to the console, consider sending email notifications or writing detailed logs that include more information about the error, such as a stack trace. This can be helpful for debugging and troubleshooting issues.
8. Code Organization: Consider organizing the code into separate files for better organization and readability. For example, you could have one file containing the main logic, another file containing helper functions, and another file containing configuration settings.
9. Performance Optimization: While this script doesn't seem to have any obvious performance bottlenecks, consider using the Measure-Command cmdlet to measure the execution time of critical sections of the code and optimize them if necessary.
10. Error Handling in Parameter Binding: Instead of using Try/Catch blocks for parameter validation, consider using the `ValidateSet` attribute to ensure that only valid values are passed to the script. This can help simplify error handling and make the script more robust.

## Source Code
```powershell
function Write-OffboardingSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $User,

        [Parameter(Mandatory)]
        $Results
    )

    Write-Log -Level Info -Message ("Writing offboarding summary for: {0}" -f $User.UserPrincipalName)

    try {
        # Load config
        $cfg = Get-TechToolboxConfig
        $off = $cfg['settings']['offboarding']

        # Determine output directory from config
        $root = $off.logDir
        if (-not $root) {
            # Fallback for safety
            $root = Join-Path $env:TEMP "TechToolbox-Offboarding"
            Write-Log -Level Warn -Message "offboarding.logDir not found in config. Using TEMP fallback."
        }

        # Ensure directory exists
        if (-not (Test-Path $root)) {
            New-Item -Path $root -ItemType Directory | Out-Null
        }

        # Filename
        $file = Join-Path $root ("OffboardingSummary_{0}_{1}.txt" -f `
                $User.SamAccountName, (Get-Date -Format "yyyyMMdd_HHmmss"))

        # Build summary content
        $lines = @()
        $lines += "==============================================="
        $lines += " TechToolbox Offboarding Summary"
        $lines += "==============================================="
        $lines += ""
        $lines += "User:              {0}" -f $User.UserPrincipalName
        $lines += "Display Name:      {0}" -f $User.DisplayName
        $lines += "SamAccountName:    {0}" -f $User.SamAccountName
        $lines += "Timestamp:         {0}" -f (Get-Date)
        $lines += ""
        $lines += "-----------------------------------------------"
        $lines += " Actions Performed"
        $lines += "-----------------------------------------------"

        foreach ($key in $Results.Keys) {
            $step = $Results[$key]

            $lines += ""
            $lines += "[{0}]" -f $step.Action
            $lines += "  Success: {0}" -f $step.Success

            foreach ($p in $step.PSObject.Properties.Name) {
                if ($p -in @("Action", "Success")) { continue }
                $value = $step.$p
                if ($null -eq $value) { $value = "" }
                $lines += "  {0}: {1}" -f $p, $value
            }
        }

        $lines += ""
        $lines += "==============================================="
        $lines += " End of Summary"
        $lines += "==============================================="

        # Write file
        $lines | Out-File -FilePath $file -Encoding UTF8

        Write-Log -Level Ok -Message ("Offboarding summary written to: {0}" -f $file)

        return [pscustomobject]@{
            Action   = "Write-OffboardingSummary"
            FilePath = $file
            Success  = $true
        }
    }
    catch {
        Write-Log -Level Error -Message ("Failed to write offboarding summary: {0}" -f $_.Exception.Message)

        return [pscustomobject]@{
            Action  = "Write-OffboardingSummary"
            Success = $false
            Error   = $_.Exception.Message
        }
    }
}
[SIGNATURE BLOCK REMOVED]

```
