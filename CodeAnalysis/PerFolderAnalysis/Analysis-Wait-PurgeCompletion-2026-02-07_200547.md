# Code Analysis Report
Generated: 2/7/2026 8:05:47 PM

## Summary
 The provided PowerShell script, named `Wait-PurgeCompletion`, is designed to monitor the status of a Purge ComplianceSearchAction until it completes or times out. Here are some suggestions for improving its functionality, readability, and performance:

1. Use custom objects instead of concatenating strings for logging messages. This will make the logs more structured and easier to parse if needed.

```powershell
function Write-Log {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Info", "Ok", "Warn", "Error")]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    # Your existing Write-Log implementation goes here
}
```

2. Utilize try-catch blocks to handle errors more gracefully and make the script more resilient. This can help prevent the script from terminating prematurely if an error occurs during execution.

```powershell
try {
    # Your existing code goes here
} catch {
    Write-Error $_
}
```

3. Instead of using `switch ($status)`, consider using a more expressive `if` statement to check the status and handle each outcome differently. This can help improve readability and make the code easier to understand.

4. For better organization, consider separating the logging functions into a separate module or file. This will keep your script cleaner and more focused on its primary functionality.

5. To further enhance performance, you may want to cache the results of `Get-ComplianceSearchAction` calls by storing them in a variable for subsequent checks. However, this might increase memory usage, so consider the trade-off between performance and resource utilization when deciding whether or not to implement caching.

6. Lastly, to improve readability, consider adding comments to explain the purpose of each section or important parts of the code. This will make it easier for others (or yourself in the future) to understand the script's functionality quickly.

## Source Code
```powershell

function Wait-PurgeCompletion {
    <#
    .SYNOPSIS
        Monitors a Purge ComplianceSearchAction until completion or timeout.
    .DESCRIPTION
        Supports two parameter sets: by action identity or by search name.
        Caller provides TimeoutSeconds and PollSeconds (no direct config reads).
    #>
    [CmdletBinding(DefaultParameterSetName = 'BySearch')]
    param(
        [Parameter(ParameterSetName = 'BySearch', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchName,

        [Parameter(ParameterSetName = 'ByAction', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ActionIdentity,

        [Parameter()]
        [string]$CaseName,

        [Parameter()]
        [ValidateRange(1, 86400)]
        [int]$TimeoutSeconds = 1200,

        [Parameter()]
        [ValidateRange(1, 3600)]
        [int]$PollSeconds = 5
    )

    # --- Caller-resolved defaults only (no config lookups here) ---
    $target = if ($PSCmdlet.ParameterSetName -eq 'ByAction') { $ActionIdentity } else { $SearchName }
    Write-Log -Level Info -Message ("Monitoring purge for '{0}' (Timeout={1}s, Poll={2}s)..." -f $target, $TimeoutSeconds, $PollSeconds)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $action = if ($PSCmdlet.ParameterSetName -eq 'ByAction') {
            Get-ComplianceSearchAction -Identity $ActionIdentity -ErrorAction SilentlyContinue
        }
        else {
            # If CaseName provided, scope to case; else search across all purges and pick latest
            $scope = if ([string]::IsNullOrWhiteSpace($CaseName)) {
                Get-ComplianceSearchAction -Purge -ErrorAction SilentlyContinue
            }
            else {
                Get-ComplianceSearchAction -Purge -Case $CaseName -ErrorAction SilentlyContinue
            }

            $scope |
            Where-Object { $_.SearchName -eq $SearchName } |
            Sort-Object CreatedTime -Descending |
            Select-Object -First 1
        }

        if ($action) {
            $status = $action.Status
            Write-Log -Level Info -Message ("Purge status: {0}" -f $status)
            switch ($status) {
                'Completed' { Write-Log -Level Ok   -Message "Purge completed successfully."; return $action }
                'PartiallySucceeded' { Write-Log -Level Warn -Message ("Purge partially succeeded: {0}" -f $action.ErrorMessage); return $action }
                'Failed' { Write-Log -Level Error -Message ("Purge failed: {0}" -f $action.ErrorMessage); return $action }
            }
        }
        else {
            Write-Log -Level Info -Message "No purge action found yet..."
        }

        Start-Sleep -Seconds $PollSeconds
    }

    throw "Timed out waiting for purge completion."
}

[SIGNATURE BLOCK REMOVED]

```
