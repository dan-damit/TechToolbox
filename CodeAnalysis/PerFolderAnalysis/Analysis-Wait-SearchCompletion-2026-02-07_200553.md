# Code Analysis Report
Generated: 2/7/2026 8:05:53 PM

## Summary
 Here is a breakdown of the given PowerShell script named `Wait-SearchCompletion`. I will provide suggestions to enhance its functionality, readability, and performance, as well as analyze its syntax and structure.

1. Functions:
   - The code defines a single function called `Wait-SearchCompletion` that monitors compliance search status until it completes or times out.

2. Parameters:
   - Mandatory parameter: `$SearchName` (the name of the compliance search)
   - Optional parameters:
     - `$CaseName` (optional case scope for the search)
     - `$TimeoutSeconds` (default is 1200 seconds, or 20 minutes)
     - `$PollSeconds` (default is 5 seconds)

3. Logging:
   - The script uses a custom logging function called `Write-Log`, which logs informational, success, and error messages. However, there's no implementation of the function within the provided code.

4. Structure and Syntax:
   - Variable naming follows PowerShell conventions with proper casing (camelCase).
   - The script uses try-catch blocks to handle potential errors when searching for the compliance search.
   - The while loop checks whether the current time is before the deadline (defined as `$deadline`), which is calculated based on the provided timeout in seconds.
   - Inside the while loop, the script searches for the specified compliance search using optional parameters. If found, it retrieves the status and checks if the search has completed or failed. If not found, it logs an informational message.
   - After each iteration, there's a delay of `$PollSeconds` before checking the search status again.
   - Once the deadline is reached, the script throws a custom error message "Timed out waiting for search completion."

Suggestions for improvements:

1. Refactor the logging function into the script if it's being used exclusively within this function to avoid potential external dependencies.
2. Document any external dependencies and their installation requirements in comments at the beginning of the script.
3. Add more informative error messages when the compliance search cannot be found or encounters errors.
4. Use more descriptive variable names, especially for `$search` (currently unhelpful as it doesn't specify whether it's a single search object or multiple search objects) and `$status` (which could be named `$complianceSearchStatus` to better represent its purpose).
5. Consider adding support for asynchronous processing to improve performance when dealing with large numbers of compliance searches, especially when using shorter polling intervals.

## Source Code
```powershell

function Wait-SearchCompletion {
    <#
    .SYNOPSIS
        Waits for a Compliance Search to reach a terminal state
        (Completed/Failed) or timeout.
    .DESCRIPTION
        Polls the search status by name (and optional case scope) until timeout.
        Caller supplies TimeoutSeconds/PollSeconds; no config access here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchName,

        [Parameter()]
        [string]$CaseName,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 1200,

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$PollSeconds = 5
    )

    Write-Log -Level Info -Message ("Monitoring search '{0}' (Timeout={1}s, Poll={2}s)..." -f $SearchName, $TimeoutSeconds, $PollSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $search = if ([string]::IsNullOrWhiteSpace($CaseName)) {
                Get-ComplianceSearch -Identity $SearchName -ErrorAction SilentlyContinue
            }
            else {
                Get-ComplianceSearch -Identity $SearchName -Case $CaseName -ErrorAction SilentlyContinue
            }
        }
        catch {
            $search = $null
        }

        if ($null -ne $search) {
            $status = $search.Status
            Write-Log -Level Info -Message ("Search status: {0}" -f $status)

            switch ($status) {
                'Completed' {
                    Write-Log -Level Ok -Message "Search completed."
                    return $search
                }
                'Failed' {
                    Write-Log -Level Error -Message ("Search failed: {0}" -f $search.Errors)
                    return $search
                }
                default {
                    # In-progress statuses often include 'Starting', 'InProgress', etc.
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Search not found yet..."
        }

        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for search completion."
}

[SIGNATURE BLOCK REMOVED]

```
