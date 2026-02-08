# Code Analysis Report
Generated: 2/7/2026 8:25:14 PM

## Summary
 This PowerShell script is a function named `Search-User` that searches for a user in Active Directory (AD) and optionally Exchange Online (EXO) or Microsoft Teams. Here are some suggestions to enhance its functionality, readability, and performance:

1. **Modularization**: Break the script into smaller, reusable functions. This makes it easier to maintain, test, and debug each part independently. For example, you could create separate functions for AD searches, EXO/Teams queries, and user normalization.

2. **Error handling**: The current error handling only logs warnings when an operation fails. Consider returning more descriptive error messages or objects to help users troubleshoot issues. You can use custom errors with detailed information about the error type, cause, and suggested actions.

3. **Parameter validation**: Validate input parameters strictly to prevent unexpected behavior or failures. For example, ensure that `$Server` and `$SearchBase` are valid AD server names or DNs, and that `$Credential` is a valid PSCredential object.

4. **Use Get-Help cmdlet**: Document the function using the built-in `Get-Help` cmdlet for better discoverability and usability. Include examples of usage, detailed descriptions of each parameter, and links to related resources.

5. **Code formatting**: Improve readability by following PowerShell best practices for code formatting, such as consistent indentation, line length, and use of comments for explaining complex logic or important sections.

6. **Variable naming**: Use more descriptive variable names to make the script easier to understand for other users. For example, instead of `adUsers`, consider using `$adExactMatches` or `$adBroadMatchResults`.

7. **Use constants and enums**: Define constants and enums to make your code more readable and less error-prone. For example, you could create a constant for the default search scope or an enum for behavior toggles like `ResolveManager` or `ResolveGroups`.

8. **Optimize performance**: Minimize network traffic by only querying AD when necessary (e.g., avoid performing broader searches if exact match is possible). You can also cache results or use pagination to improve performance in large environments.

9. **Input validation**: Validate the input identity before executing the search to ensure it adheres to expected formats (UPN, SamAccountName, etc.). This helps avoid unnecessary network traffic and potential errors.

10. **Handle multiple matches**: When searching AD, consider returning an array of user objects instead of stopping with the first match if `-AllowMultiple` is set to true. This simplifies handling multiple results without having to deal with exception logic.

## Source Code
```powershell
function Search-User {
    <#
    .SYNOPSIS
        Searches for a user in AD (primary) and optionally EXO/Teams, returns a
        unified record.
    .DESCRIPTION
        Graph/Entra lookups are excluded. This function resolves the user from:
          - Active Directory (primary, with optional proxyAddresses/mail search)
          - Exchange Online (optional, if wrappers exist and
            requested/available)
          - Microsoft Teams (optional, if wrappers exist and
            requested/available) Normalizes via Format-UserRecord. Returns $null
            if no match unless -AllowMultiple.
    .PARAMETER Identity
        UPN or SamAccountName. If not found exactly, falls back to broader LDAP
        (displayName/mail/proxyAddresses).
    .PARAMETER IncludeEXO
        When present, attempts to query Exchange Online (Get-ExchangeUser
        wrapper).
    .PARAMETER IncludeTeams
        When present, attempts to query Teams (Get-TeamsUser wrapper).
    .PARAMETER Server
        Optional domain controller to target (overrides config).
    .PARAMETER SearchBase
        Optional SearchBase (overrides config).
    .PARAMETER SearchScope
        LDAP search scope (Base|OneLevel|Subtree). Default from config or
        Subtree.
    .PARAMETER Credential
        PSCredential used for AD queries (and for manager/group resolution).
    .PARAMETER EnableProxyAddressSearch
        Include proxyAddresses in fallback LDAP search. Default: On.
    .PARAMETER EnableMailSearch
        Include mail attribute in fallback LDAP search. Default: On.
    .PARAMETER ResolveManager
        Resolve Manager to UPN/Name/SAM/Mail. Default: On.
    .PARAMETER ResolveGroups
        Resolve MemberOf to Name/SAM/Scope/Category. Default: On.
    .PARAMETER AllowMultiple
        Return all matches when more than one user is found. Default: Off
        (throws).
    .EXAMPLE
        Search-User -Identity "jdoe"
    .EXAMPLE
        Search-User -Identity "jdoe@contoso.com" -IncludeEXO
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [string]$Server,
        [string]$SearchBase,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope,

        [pscredential]$Credential,

        [switch]$EnableProxyAddressSearch,
        [switch]$EnableMailSearch,

        [switch]$ResolveManager,
        [switch]$ResolveGroups,

        [switch]$AllowMultiple
    )

    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        # --- Config (block/dot) ---
        $cfg = Get-TechToolboxConfig
        $adCfg = $cfg.settings.ad
        $searchCfg = $cfg.settings.userSearch

        if (-not $adCfg) { throw "Config missing settings.ad node." }
        if (-not $searchCfg) { Write-Log -Level Warn -Message "Config missing settings.userSearch node (using defaults)." }

        # Defaults from config (override with parameters if provided)
        if (-not $Server) { $Server = $adCfg.domainController }
        if (-not $SearchBase) { $SearchBase = $adCfg.searchBase }
        if (-not $SearchScope) { $SearchScope = $adCfg.searchScope ? $adCfg.searchScope : 'Subtree' }

        # Behavior toggles (default ON unless explicitly disabled)
        if (-not $PSBoundParameters.ContainsKey('EnableProxyAddressSearch')) { $EnableProxyAddressSearch = $true }
        if (-not $PSBoundParameters.ContainsKey('EnableMailSearch')) { $EnableMailSearch = $true }
        if (-not $PSBoundParameters.ContainsKey('ResolveManager')) { $ResolveManager = $true }
        if (-not $PSBoundParameters.ContainsKey('ResolveGroups')) { $ResolveGroups = $true }

        # --- Resolve helper availability ---
        $hasAD = !!(Get-Module ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)
        if (-not $hasAD) { throw "ActiveDirectory module not found. Install RSAT or run on a domain-joined admin workstation." }

        # Import AD but suppress provider’s warning about default drive init
        $prevWarn = $WarningPreference
        try {
            $WarningPreference = 'SilentlyContinue'
            Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        finally {
            $WarningPreference = $prevWarn
        }

        # Optional: ensure the AD: drive isn’t lingering (prevents later re-init noise)
        Remove-PSDrive -Name AD -ErrorAction SilentlyContinue

        # --- Helpers ---
        function Escape-LdapFilterValue {
            param([Parameter(Mandatory)] [string]$Value)
            # RFC 4515 escaping: \ * ( ) NUL -> escaped hex
            $v = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
            # NUL not likely in user input; keep for completeness
            $v = ($v -replace '\x00', '\00')
            return $v
        }

        # AD property set needed by Format-UserRecord
        $props = @(
            'displayName', 'userPrincipalName', 'samAccountName', 'mail',
            'proxyAddresses', 'enabled', 'whenCreated', 'lastLogonTimestamp',
            'department', 'title', 'manager', 'memberOf', 'distinguishedName', 
            'objectGuid', 'msDS-UserPasswordExpiryTimeComputed'
        )

        $common = @{
            Properties  = $props
            ErrorAction = 'Stop'
        }
        if ($Server) { $common['Server'] = $Server }
        if ($SearchBase) { $common['SearchBase'] = $SearchBase }
        if ($SearchScope) { $common['SearchScope'] = $SearchScope }
        if ($Credential) { $common['Credential'] = $Credential }

        $adUsers = @()

        # --- 1) Exact match attempt (UPN or SAM) ---
        $isUPN = ($Identity -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
        $idEsc = Escape-LdapFilterValue $Identity
        $exactLdap = if ($isUPN) { "(userPrincipalName=$idEsc)" } else { "(sAMAccountName=$idEsc)" }

        try {
            $adUsers = Get-ADUser @common -LDAPFilter $exactLdap
        }
        catch {
            Write-Log -Level Warn -Message ("[Search-User][AD/Exact] {0}" -f $_.Exception.Message)
        }

        # --- 2) Fallback broader search (displayName/mail/proxyAddresses) if none found ---
        if (-not $adUsers -or $adUsers.Count -eq 0) {
            $terms = @(
                "(sAMAccountName=$idEsc)"
                "(userPrincipalName=$idEsc)"
                "(displayName=*$idEsc*)"
            )

            if ($EnableMailSearch) {
                $terms += "(mail=$idEsc)"
            }
            if ($EnableProxyAddressSearch) {
                # proxyAddresses is case-sensitive on the prefix; include both primary & aliases
                $terms += "(proxyAddresses=SMTP:$idEsc)"
                $terms += "(proxyAddresses=smtp:$idEsc)"
            }

            $ldap = "(|{0})" -f ($terms -join '')
            try {
                $adUsers = Get-ADUser @common -LDAPFilter $ldap
            }
            catch {
                Write-Log -Level Warn -Message ("[Search-User][AD/Fallback] {0}" -f $_.Exception.Message)
            }
        }

        if (-not $adUsers -or $adUsers.Count -eq 0) {
            Write-Log -Level Warn -Message ("No AD user found matching '{0}'." -f $Identity)
            return $null
        }

        # --- Handle multiplicity ---
        if (($adUsers | Measure-Object).Count -gt 1 -and -not $AllowMultiple) {
            $names = ($adUsers | Select-Object -First 5 | ForEach-Object { $_.SamAccountName }) -join ', '
            throw "Multiple AD users matched '$Identity' (e.g., $names). Use -AllowMultiple to return all."
        }

        # --- Normalize via Format-UserRecord ---
        if (-not (Get-Command Format-UserRecord -ErrorAction SilentlyContinue)) {
            throw "Format-UserRecord not found. Ensure it is dot-sourced from Private and available."
        }

        $normalized = $adUsers | ForEach-Object {
            Format-UserRecord -AD $_ -Server $Server -Credential $Credential `
                -ResolveManager:$ResolveManager -ResolveGroups:$ResolveGroups
        }

        if (-not $normalized) {
            Write-Log -Level Warn -Message ("No usable record produced for '{0}'." -f $Identity)
            return $null
        }

        if ($AllowMultiple) {
            Write-Log -Level Ok -Message ("{0} user(s) found and normalized." -f (($normalized | Measure-Object).Count))
            return $normalized
        }
        else {
            $one = $normalized | Select-Object -First 1
            Write-Log -Level Ok -Message ("User '{0}' found and normalized." -f $one.UserPrincipalName)
            return $one
        }
    }
    catch {
        Write-Log -Level Error -Message ("[Search-User] Failed: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}

[SIGNATURE BLOCK REMOVED]

```
