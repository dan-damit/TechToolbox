# Code Analysis Report
Generated: 2/7/2026 8:27:15 PM

## Summary
 Here is a breakdown of the code and some suggestions for improvements:

1. **Naming conventions**: Maintaining consistent naming conventions throughout the script can make it more readable and easier to understand. Consider using PascalCase for variable names, camelCase for function names, and UPPER_SNAKE_CASE for constants. In this script, some variable names are in lowerCamelCase (e.g., `UserPrincipalName`, `ContentMatchQuery`) while others use underscores (e.g., `PurviewHardDeletePurge`).

2. **Comments**: Although the code is well-documented with comments, they could be made more consistent and informative. For example, consider adding a description for each function parameter and providing explanations for complex sections of the script.

3. **Modularization**: The script performs multiple tasks such as importing modules, creating a search, waiting for its completion, and purging items. Breaking these tasks into separate functions could make the code more modular and easier to maintain. For instance, you can create separate functions for connecting to Purview, creating a search, starting a search, waiting for completion, and purging items.

4. **Error handling**: Although the script uses try-catch blocks for error handling, it would be beneficial to centralize error handling by defining custom exception classes and using them throughout the script. This can make error messages more informative and help with debugging.

5. **Configuration**: The script reads configuration from a module-scope variable `$cfg`. To make the configuration more flexible and maintainable, consider creating a separate configuration file (e.g., JSON or YAML) and using a PowerShell module to load and manage it. This would allow you to easily modify the configuration without changing the actual script.

6. **Readability**: The script could benefit from better indentation, spacing, and line wrapping for improved readability. For example, the `while` loop in the query prompt section is hard to read due to long lines and lack of indentation.

7. **Performance**: To optimize performance, consider using asynchronous functions when available (e.g., `Start-Job`) instead of synchronous ones for tasks that can be run concurrently. This will help reduce the overall execution time of the script.

8. **Logging**: The logging function is used throughout the script to write log messages at various levels. To make it more flexible, consider creating a separate logging module or using an existing one like the `PSWriteActivity` module by Lee Holmes (https://github.com/Lee-Holmes/PSWriteActivity). This would provide more advanced features such as structured logs and customizable formatting.

9. **Code organization**: The script's code could be organized better by grouping related blocks of code together and using functions to reduce redundancy and improve readability. For instance, you can create separate sections for configuration, query prompt, search creation, registration, starting, waiting for completion, and purging.

10. **Documentation**: Although the script has comments documenting each section and parameter, it would be beneficial to provide a detailed README file that explains how to use the script, its requirements, and any known limitations or bugs. This will help other users understand and leverage your code more effectively.

## Source Code
```powershell

function Invoke-PurviewPurge {
    <#
    .SYNOPSIS
        End-to-end Purview HardDelete purge workflow: connect, clone search,
        wait, purge, optionally disconnect.
    .DESCRIPTION
        Imports ExchangeOnlineManagement (if needed), connects to Purview with
        SearchOnly session, prompts for any missing inputs (config-driven),
        clones an existing search (mailbox-only), waits for completion, and
        submits a HardDelete purge. Uses Write-Log and supports
        -WhatIf/-Confirm.
    .PARAMETER UserPrincipalName
        The UPN to use for connecting to Purview (Exchange Online).
    .PARAMETER CaseName
        The eDiscovery Case Name/ID containing the Compliance Search to clone.
    .PARAMETER ContentMatchQuery
        The KQL/keyword query to match items to purge (e.g.,
        'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned
        Assets"'). If omitted, a new mailbox-only search will be created via
        prompted KQL query.
    .PARAMETER Log
        A hashtable of logging configuration options to merge into the module-
        scope logging bag. See Get-TechToolboxConfig "settings.logging" for
        available keys.
    .PARAMETER ShowProgress
        Switch to enable console logging/progress output for this invocation.
    .EXAMPLE
        PS> Invoke-PurviewPurge -UserPrincipalName "user@company.com" `
            -CaseName "Legal Case 123" -ContentMatchQuery 'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets"'
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$UserPrincipalName,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$CaseName,

        # The KQL/keyword query to match items to purge (e.g., 'from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets"')
        [Parameter()][ValidateNotNullOrEmpty()][string]$ContentMatchQuery,

        # Optional naming override/prefix; the function will add a timestamp suffix to ensure uniqueness
        [Parameter()][ValidateNotNullOrEmpty()][string]$SearchNamePrefix = "TTX-Purge",

        [Parameter()][hashtable]$Log,
        [switch]$ShowProgress
    )

    # Global safety
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest

    try {
        # ---- Config & defaults ----
        $cfg = Get-TechToolboxConfig
        $purv = $cfg["settings"]["purview"]
        $defaults = $cfg["settings"]["defaults"]
        $exo = $cfg["settings"]["exchangeOnline"]

        # Support both legacy and purge.* keys in config
        $timeoutSeconds = [int]$purv["timeoutSeconds"]
        if ($timeoutSeconds -le 0) { $timeoutSeconds = 1200 }
        $pollSeconds = [int]$purv["pollSeconds"]
        if ($pollSeconds -le 0) { $pollSeconds = 5 }

        # Registration wait (configurable)
        $regTimeout = [int]$purv["registrationWaitSeconds"]
        if ($regTimeout -le 0) { $regTimeout = 90 }
        $regPoll = [int]$purv["registrationPollSeconds"]
        if ($regPoll -le 0) { $regPoll = 3 }
        
        # ----- Query prompt + validation/normalization -----
        $promptQuery = $defaults["promptForContentMatchQuery"] ?? $true

        while ($true) {
            if ([string]::IsNullOrWhiteSpace($ContentMatchQuery)) {
                if ($promptQuery) {
                    $ContentMatchQuery = Read-Host 'Enter ContentMatchQuery (e.g., from:("*@pm-bounces.broobe.*" OR "*@broobe.*") AND subject:"Aligned Assets")'
                }
                else {
                    throw "ContentMatchQuery is required but prompting is disabled by config."
                }
            }

            $normRef = [ref] $null
            $isValid = $false
            try {
                $isValid = Test-ContentMatchQuery -Query $ContentMatchQuery -Normalize -NormalizedQuery $normRef
            }
            catch {
                # If the validator ever throws, treat as invalid and re-prompt
                Write-Warning ("Validator error: {0}" -f $_.Exception.Message)
                $ContentMatchQuery = $null
                continue
            }

            if (-not $isValid) {
                Write-Warning "KQL appears invalid (unbalanced quotes/parentheses or unsupported property). Please re-enter."
                $ContentMatchQuery = $null
                continue
            }

            # Valid: commit normalized value (if provided) and break
            if ($normRef.Value) {
                $ContentMatchQuery = $normRef.Value
            }
            Write-Log -Level Info -Message ("Final ContentMatchQuery: {0}" -f $ContentMatchQuery)
            break
        }

        # ---- Module & session ----
        Import-ExchangeOnlineModule -ErrorAction Stop
        if ($autoConnect) {
            Connect-PurviewSearchOnly -UserPrincipalName $UserPrincipalName -ErrorAction Stop
        }
        else {
            Write-Log -Level Info -Message "AutoConnect disabled by config; ensure an active Purview session exists."
        }

        # ---- Build a unique search name ----
        $ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
        $baseName = "{0}-{1}" -f $SearchNamePrefix, $CaseName
        $searchName = "{0}-{1}" -f $baseName, $ts

        Write-Log -Level Info -Message ("Creating mailbox-only Compliance Search '{0}' in case '{1}'..." -f $searchName, $CaseName)
        Write-Log -Level Info -Message "Scope: ExchangeLocation=All"

        # ---- Create the mailbox-only search (ALL mailboxes) ----
        $newParams = @{
            Name              = $searchName
            Case              = $CaseName
            ExchangeLocation  = 'All'
            ContentMatchQuery = $ContentMatchQuery
        }

        # Create (respects WhatIf)
        if ($PSCmdlet.ShouldProcess(("Case '{0}'" -f $CaseName), ("Create compliance search '{0}' (mailbox-only / All mailboxes)" -f $searchName))) {
            $null = New-ComplianceSearch @newParams
            Write-Log -Level Ok -Message ("Search created: {0}" -f $searchName)
        }
        else {
            Write-Log -Level Info -Message "Creation skipped due to -WhatIf/-Confirm."
            return
        }

        # ---- Wait until the search object is registered/visible ----
        Write-Log -Level Info -Message ("Waiting for search '{0}' to register (timeout={1}s, poll={2}s)..." -f $searchName, $regTimeout, $regPoll)
        $registered = Wait-ComplianceSearchRegistration -SearchName $searchName -TimeoutSeconds $regTimeout -PollSeconds $regPoll
        if (-not $registered) {
            throw "Search object '$searchName' was not visible after creation (waited ${regTimeout}s). Aborting."
        }

        # ---- Start the search after registration ----
        if ($PSCmdlet.ShouldProcess(("Search '{0}'" -f $searchName), 'Start compliance search')) {
            Start-ComplianceSearch -Identity $searchName
            Write-Log -Level Info -Message ("Search started: {0}" -f $searchName)
        }
        else {
            Write-Log -Level Info -Message "Start skipped due to -WhatIf/-Confirm."
            return
        }

        # ---- Wait until completion ----
        Write-Log -Level Info -Message ("Waiting for search '{0}' to complete (timeout={1}s, poll={2}s)..." -f $searchName, $timeoutSeconds, $pollSeconds)
        $searchObj = Wait-SearchCompletion -SearchName $searchName -CaseName $CaseName -TimeoutSeconds $timeoutSeconds -PollSeconds $pollSeconds -ErrorAction Stop

        if ($null -eq $searchObj) { throw "Search object not returned for '$searchName' (case '$CaseName')." }
        Write-Log -Level Ok -Message ("Search status: {0}; Items: {1}" -f $searchObj.Status, $searchObj.Items)

        if ($searchObj.Items -le 0) {
            throw "Search '$searchName' returned 0 mailbox items. Purge aborted."
        }

        # ---- Purge (HardDelete) via your existing helper ----
        if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $searchName), 'Submit Purview HardDelete purge')) {
            $null = Invoke-HardDelete -SearchName $searchName -CaseName $CaseName -Confirm:$false -ErrorAction Stop
            Write-Log -Level Ok -Message ("[Done] Purview HardDelete purge submitted for '{0}' in case '{1}'." -f $searchName, $CaseName)
        }
        else {
            Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
        }

        # ---- Summary ----
        Write-Log -Level Ok -Message ("Summary: search='{0}' status='{1}' items={2} purgeSubmitted={3}" -f $searchName, $searchObj.Status, $searchObj.Items, $true)
    }
    catch {
        Write-Error ("[ERROR] {0}" -f $_.Exception.Message)
        if ($script:log["enableConsole"]) {
            Write-Log -Level Error -Message ("[ERROR] {0}" -f $_.Exception.Message)
        }
        throw
    }
    finally {
        [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo)
    }
}
[SIGNATURE BLOCK REMOVED]

```
