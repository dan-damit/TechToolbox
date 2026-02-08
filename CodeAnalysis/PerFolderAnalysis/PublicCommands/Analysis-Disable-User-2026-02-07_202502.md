# Code Analysis Report
Generated: 2/7/2026 8:25:02 PM

## Summary
 Here is a breakdown of the code with suggestions for improvements:

1. **Code organization and formatting**: The code could benefit from better structure, such as breaking it into smaller functions or classes to improve readability and maintainability. For example, the cloud offboarding tasks (Exchange Online and Teams) could be extracted into separate functions, which would make the main function more concise and easier to understand.

2. **Error handling**: The code uses try-catch blocks for certain operations but not for all parts of the script. It would be beneficial to ensure that the entire workflow is wrapped in a try-catch block to handle errors consistently throughout the script. Additionally, instead of rethrowing exceptions, consider logging detailed error messages and providing user-friendly error messages when appropriate.

3. **Parameter validation**: The script does some basic parameter validation, but there are areas where additional validation could help catch potential issues earlier in the process. For instance, the `disabledOU` property is checked for null or whitespace, but other properties such as `exchangeOnline` and `teams` could be validated to ensure that they exist and have the expected structure.

4. **Config file handling**: The script relies on a config file to determine default settings for cloud tasks, but the code does not appear to handle cases where the config file is missing or has an invalid schema. Consider adding more robust error checking and perhaps even implementing a way to gracefully fall back to sensible defaults if the config file is unavailable or corrupt.

5. **Logging**: The logging mechanisms used in the script are good, but they could be extended to provide more detailed information about the progress and results of each offboarding step. This would help with troubleshooting and monitoring the workflow's execution.

6. **Performance**: The script makes several external calls (e.g., Search-User, Connect-ExchangeOnlineIfNeeded) which may impact performance when handling a large number of users. Consider implementing some form of caching or asynchronous processing to improve performance in these cases.

7. **Code comments and documentation**: The script contains useful comments and documentation throughout, but additional comments explaining the purpose and behavior of certain variables or sections of code could help other developers understand the workflow more easily. Additionally, consider adding XML comments (i.e., `<# ... #>`) to document each parameter, including their default values and valid input types.

8. **Parameter naming**: Some parameter names in the script are not very descriptive or follow PowerShell conventions. For example, using `IncludeEXO` and `IncludeTeams` instead of `$EnableExchangeOnlineOffboarding` and `$EnableTeamsOffboarding` would make the parameters easier to understand for other developers.

Overall, the code appears well-written and functional. However, by implementing some of these suggestions, you can further enhance its readability, performance, and maintainability.

## Source Code
```powershell

function Disable-User {
    <#
    .SYNOPSIS
        Disables an Active Directory user account and performs offboarding
        tasks.
    .DESCRIPTION
        Disables an Active Directory user account, moves it to a specified OU,
        removes group memberships, and optionally performs cloud offboarding
        tasks such as converting Exchange Online mailboxes to shared and signing
        the user out of Microsoft Teams. This function is designed to be
        Graph-free, relying on other functions that do not require Microsoft
        Graph.
    .PARAMETER Identity
        The identity of the user to disable. Can be a sAMAccountName, UPN, or
        other identifier.
    .PARAMETER IncludeEXO
        Switch to include Exchange Online offboarding tasks (convert mailbox to
        shared, grant manager access). Default behavior can be set in the config
        file.
    .PARAMETER IncludeTeams
        Switch to include Microsoft Teams offboarding tasks (sign out user).
        Default behavior can be set in the config file.
    .PARAMETER TriggerAADSync
        Switch to trigger an Azure AD Connect delta sync after disabling the
        user in Active Directory.
    .INPUTS
        String (Identity)
    .OUTPUTS
        PSCustomObject containing the results of each offboarding step.
    .EXAMPLE
        Disable-User -Identity 'jdoe' -IncludeEXO -IncludeTeams
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        # Optional toggles for cloud tasks that don't require Graph
        [switch]$IncludeEXO,     # Convert mailbox to shared, grant manager access
        [switch]$IncludeTeams,   # Sign out / cleanup via Teams wrapper (if present)
        [pscredential]$Credential
    )

    # Ensure $user exists for safe logging even if resolution fails
    $user = $null

    try {
        Write-Log -Level Info -Message ("Starting Disable-User workflow for '{0}'..." -f $Identity)

        # --- Load config (block/dot)
        $cfg = Get-TechToolboxConfig
        if (-not $cfg) { throw "Get-TechToolboxConfig returned null. Check your config path and schema." }

        $settings = $cfg.settings
        if (-not $settings) { throw "Config missing 'settings' node." }

        $off = $settings.offboarding
        if (-not $off) { throw "Config missing 'settings.offboarding' node." }

        $exo = $settings.exchangeOnline
        if (-not $exo) { throw "Config missing 'settings.exchangeOnline' node." }

        # Respect config defaults for EXO/Teams/AADSync if caller didn't pass switches
        if (-not $PSBoundParameters.ContainsKey('IncludeEXO') -and $settings.exchangeOnline.includeInOffboarding) { $IncludeEXO = $true }
        if (-not $PSBoundParameters.ContainsKey('IncludeTeams') -and $settings.teams.includeInOffboarding) { $IncludeTeams = $true }

        # Validate keys used below
        if ($off.PSObject.Properties.Name -contains 'disabledOU' -and [string]::IsNullOrWhiteSpace($off.disabledOU)) {
            Write-Log -Level Warn -Message "settings.offboarding.disabledOU is empty; will skip OU move."
        }

        # --- Resolve user (Graph-free Search-User)
        Write-Log -Level Info -Message ("Offboarding: Resolving user '{0}'..." -f $Identity)
        try {
            $suParams = @{
                Identity     = $Identity
                IncludeEXO   = $IncludeEXO
                IncludeTeams = $IncludeTeams
            }
            if ($Credential) { $suParams.Credential = $Credential }
            $user = Search-User @suParams
        }
        catch {
            throw "Search-User threw an error while resolving '$Identity': $($_.Exception.Message)"
        }
        if (-not $user) { throw "User '$Identity' not found by Search-User." }

        $results = [ordered]@{}

        # --- AD Disable
        Write-Log -Level Info -Message ("Offboarding: Disabling AD account for '{0}'..." -f $user.SamAccountName)
        if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Disable AD account")) {
            $disableParams = @{
                SamAccountName = $user.SamAccountName
                DisabledOU     = $off.disabledOU
            }
            if ($Credential) { $disableParams.Credential = $Credential }   # NEW
            $results.ADDisable = Disable-ADUserAccount @disableParams
        }

        # Normalize return for safe property access
        $movedHandled = $false
        if ($results.ADDisable) {
            if ($results.ADDisable -is [hashtable]) {
                $movedHandled = [bool]$results.ADDisable['MovedToOU']
            }
            else {
                $movedHandled = [bool]$results.ADDisable.MovedToOU
            }
        }

        # --- Move to Disabled OU if needed
        if ($off.disabledOU -and -not $movedHandled) {
            Write-Log -Level Info -Message ("Offboarding: Moving '{0}' to Disabled OU..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Move AD user to Disabled OU")) {
                $moveParams = @{
                    SamAccountName = $user.SamAccountName
                    TargetOU       = $off.disabledOU
                }
                if ($Credential) { $moveParams.Credential = $Credential }  # NEW
                $results.MoveOU = Move-UserToDisabledOU @moveParams
            }
        }

        # --- Optional: Cleanup AD groups
        if ($off.cleanupADGroups) {
            Write-Log -Level Info -Message ("Offboarding: Cleaning AD group memberships for '{0}'..." -f $user.SamAccountName)
            if ($PSCmdlet.ShouldProcess($user.SamAccountName, "Cleanup AD group memberships")) {
                $grpParams = @{ SamAccountName = $user.SamAccountName }
                if ($Credential) { $grpParams.Credential = $Credential }   # NEW
                $results.ADGroups = Remove-ADUserGroups @grpParams
            }
        }

        # --- Hybrid auto-disable mode (Graph-free path)
        if ($off.useHybridAutoDisable) {
            Write-Log -Level Info -Message "Hybrid auto-disable enabled. Cloud actions will be handled by AAD Connect."
            Write-OffboardingSummary -User $user -Results $results
            Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
            return [pscustomobject]$results
        }

        # --- Cloud actions (Graph-free): EXO + Teams only
        Write-Log -Level Info -Message "Proceeding with cloud offboarding actions (Graph-free)..."

        # EXO
        if ($IncludeEXO) {
            if (Get-Command Connect-ExchangeOnlineIfNeeded -ErrorAction SilentlyContinue) {
                $showProgress = $settings?.exchangeOnline?.showProgress
                Connect-ExchangeOnlineIfNeeded -ShowProgress:$showProgress
            }
            # Convert mailbox to shared
            if ($user.UserPrincipalName -and (Get-Command Convert-MailboxToShared -ErrorAction SilentlyContinue)) {
                Write-Log -Level Info -Message ("Offboarding: Converting mailbox to shared for '{0}'..." -f $user.UserPrincipalName)
                $results.Mailbox = Convert-MailboxToShared -Identity $user.UserPrincipalName
            }
            # Grant manager access
            if ($user.UserPrincipalName -and (Get-Command Grant-ManagerMailboxAccess -ErrorAction SilentlyContinue)) {
                Write-Log -Level Info -Message ("Offboarding: Granting manager access for '{0}'..." -f $user.UserPrincipalName)
                $results.ManagerAccess = Grant-ManagerMailboxAccess -Identity $user.UserPrincipalName
            }
        }

        # Teams (no Graph)
        if ($IncludeTeams -and (Get-Command Remove-TeamsUser -ErrorAction SilentlyContinue)) {
            if (Get-Command Connect-MicrosoftTeamsIfNeeded -ErrorAction SilentlyContinue) {
                Connect-MicrosoftTeamsIfNeeded | Out-Null
            }
            if ($user.UserPrincipalName) {
                Write-Log -Level Info -Message ("Offboarding: Signing out of Teams / cleanup for '{0}'..." -f $user.UserPrincipalName)
                $results.Teams = Remove-TeamsUser -Identity $user.UserPrincipalName
            }
        }

        # --- Summary
        Write-Log -Level Info -Message ("Offboarding: Generating summary for '{0}'..." -f ($user.UserPrincipalName ?? $Identity))
        Write-OffboardingSummary -User $user -Results $results

        Write-Log -Level Info -Message ("Offboarding: Completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
        Write-Log -Level Ok -Message ("Disable-User workflow completed for '{0}'." -f ($user.UserPrincipalName ?? $Identity))
        return [pscustomobject]$results
    }
    catch {
        # SAFE: $user may be $null; fall back to $Identity
        $who = if ($user -and $user.UserPrincipalName) { $user.UserPrincipalName } else { $Identity }
        Write-Log -Level Error -Message ("Disable-User failed for '{0}': {1}" -f $who, $_.Exception.Message)
        throw  # rethrow to surface in console/CI
    }
    finally { [void](Invoke-DisconnectExchangeOnline -ExchangeOnline $exo) }
}

[SIGNATURE BLOCK REMOVED]

```
