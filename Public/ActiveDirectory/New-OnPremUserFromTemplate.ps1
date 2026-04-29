function New-OnPremUserFromTemplate {
    <#
    .SYNOPSIS
    Provisions a new on-premises Active Directory user account by copying
    attributes and group memberships from a template user.

    .DESCRIPTION
    Creates a new Active Directory user account with characteristics derived
    from a template user. This function automates the repetitive task of user
    provisioning by duplicating standard configurations, organizational
    assignments, and group memberships.

    The function operates in the following sequence:
    1. Locates and validates the template user (by identity or search criteria)
    2. Derives the new user's naming convention (UPN, SAM account name) from
       config or explicit parameters
    3. Verifies idempotency (ensures user doesn't already exist)
    4. Creates the new AD user with enabled status and forced password change
    5. Copies specified attributes from the template (description, department,
       company, office, manager, or custom attributes)
    6. Configures proxy addresses with the primary SMTP address
    7. Adds the new user to all non-excluded groups from the template

    Naming derivation uses the TechToolbox configuration framework. If
    -SamAccountName or -UpnPrefix are not explicitly provided, the function
    calls Resolve-Naming to generate these values based on GivenName and
    Surname.

    Template location supports two parameter sets:
    - ByIdentity: Directly specify the template user (faster)
    - BySearch: Find template via attribute filters (flexible for complex
      scenarios)

    The function supports -WhatIf and -Confirm through ShouldProcess, allowing
    dry-run validation before actual modifications.

    .PARAMETER TemplateIdentity
    Specifies the identity of the template user to copy from. Accepts any valid
    Active Directory identity format: sAMAccountName, DistinguishedName (DN),
    ObjectSID (SID), or ObjectGUID (GUID).

    Used only with the ByIdentity parameter set. Mutually exclusive with
    -TemplateSearch.

    .PARAMETER TemplateSearch
    Specifies a hashtable of LDAP attribute=value pairs to locate the template
    user. All criteria are combined with AND logic; the first matching user is
    used.

    Example: @{ title='Software Engineer'; company='Acme Corp' }

    Used only with the BySearch parameter set. Mutually exclusive with
    -TemplateIdentity. Useful when template identity is unknown but
    characteristic attributes are available.

    .PARAMETER GivenName
    Specifies the first name (givenName attribute) of the new user.

    Mandatory parameter. Used in the naming derivation (Resolve-Naming) if
    -SamAccountName or -UpnPrefix are not provided.

    .PARAMETER Surname
    Specifies the last name (sn/surname attribute) of the new user.

    Mandatory parameter. Used in the naming derivation (Resolve-Naming) if
    -SamAccountName or -UpnPrefix are not provided.

    .PARAMETER DisplayName
    Specifies the display name (displayName attribute) of the new user.

    Mandatory parameter. This is the user-friendly name visible in address books
    and global distribution lists. Typically formatted as "FirstName LastName"
    or "LastName, FirstName" depending on organizational standards.

    .PARAMETER TargetOU
    Specifies the DistinguishedName (DN) of the organizational unit where the
    new user will be created.

    Optional. If omitted, defaults to the same OU as the template user. This
    allows consistent placement without explicit specification. Use this
    parameter to override and place the user in a different OU than the
    template.

    Example: "OU=Engineering,OU=Users,DC=company,DC=com"

    .PARAMETER SamAccountName
    Specifies the sAMAccountName (pre-Windows 2000 logon name) for the new user.

    Optional. If omitted, the value is derived by calling Resolve-Naming with
    the GivenName and Surname. The sAMAccountName must be unique within the
    domain and typically follows organizational naming conventions (e.g.,
    FirstinitialsLastname or FirstnameLastname, limited to 20 characters).

    .PARAMETER UpnPrefix
    Specifies the UPN prefix (left side of @) for the new user's
    UserPrincipalName.

    Optional. If omitted, the value is derived by calling Resolve-Naming with
    the GivenName and Surname. The full UPN is constructed as
    UpnPrefix@{Tenant.upnSuffix} where the UPN suffix is read from config. The
    UPN must be unique across all forests.

    Example: "john.smith" (results in "john.smith@company.com" if upnSuffix is
    "company.com")

    .PARAMETER CopyAttributes
    Specifies which attributes to copy from the template user to the new user.

    Optional. Accepts an array of attribute names. Default includes:
    - 'description'
    - 'department'
    - 'company'
    - 'office'
    - 'manager'

    Attribute names are case-insensitive and mapped to LDAP names internally
    (e.g., 'office' → 'physicalDeliveryOfficeName'). Unknown attributes are
    treated as raw LDAP names and applied via the -Replace parameter.

    If the user provides explicit -CopyAttributes, that list is used. Otherwise,
    the function checks config (settings.naming.copyAttributes) for a configured
    list, then falls back to the hardcoded defaults above.

    Special handling: The 'manager' attribute is only copied if the template's
    manager value is a valid DN (matching ^CN=.+,DC=.+).

    .PARAMETER ExcludedGroups
    Specifies group names to explicitly exclude when copying group memberships.

    Optional. Default is empty.

    Group copy behavior first allows all Distribution groups and only selected
    Security groups (controlled by -AllowedSecurityGroups). This parameter is an
    explicit deny-list applied after that selection.

    .PARAMETER AllowedSecurityGroups
    Specifies Security group names that are allowed to be copied from the
    template.

    Optional. Default is 'Domain Users'.

    By default, all Security groups are excluded from copy unless their name is
    present in this allow-list. Distribution groups are still copied.

    .PARAMETER InitialPasswordLength
    Specifies the length of the auto-generated initial password.

    Optional. Default is 16 characters. The password is generated with mixed
    case, numbers, and symbols (specifically 3 non-alphanumeric characters) to
    meet complexity requirements.

    The initial password is displayed in the function output and is subject to
    ChangePasswordAtLogon, forcing the user to choose a new password at first
    logon.

    .PARAMETER Credential
    Specifies the Active Directory credential under which all AD operations
    execute.

    Mandatory parameter. Typically a service account with appropriate AD
    permissions:
    - Create User objects (User-Force-Change-Password)
    - Modify user attributes
    - Add members to groups
    - Read template user and group properties

    .PARAMETER Server
    Specifies a specific domain controller to target for AD operations.

    Optional. Useful when:
    - Avoiding replication latency (create + immediate modifications on same DC)
    - Targeting specific datacenters or regions
    - Working around temporary replication issues
    - Consolidating operations during change windows

    If omitted, AD operations use the default domain controller selection logic
    (which typically targets the closest available DC).

    .PARAMETER ShowSummary
    Displays a formatted summary of the result object to the host.

    Optional switch. When provided, the function writes a human-readable
    Format-List summary to the console. The function still returns the result
    object to the pipeline for capture and further automation.

    .INPUTS
    None. This function does not accept pipeline input.

    Callers must supply all parameters explicitly.

    .OUTPUTS
    System.Management.Automation.PSCustomObject

    Returns a custom object with the following properties:
    - UserPrincipalName (string): Full UPN of the created user
    - SamAccountName (string): sAMAccountName of the created user
    - DisplayName (string): displayName of the created user
    - TargetOU (string): DistinguishedName of the OU where user was created
    - CopiedAttributes (string[]): List of attributes copied from template
    - GroupsAdded (string[]): List of group names the user was added to
    - InitialPassword (string): Auto-generated temporary password

    The output object is returned to the pipeline. Use -ShowSummary to display
    an additional formatted host summary during interactive use.

    .EXAMPLE
    $cred = Get-Credential
    $result = New-OnPremUserFromTemplate ` -TemplateIdentity 'john.smith' `
        -GivenName 'Jane' ` -Surname 'Doe' ` -DisplayName 'Jane Doe' `
        -Credential $cred

    Creates a new user "Jane Doe" based on the template user "john.smith", using
    AD credential from Get-Credential. All other parameters (naming, target OU,
    attributes, groups) are derived from the template or config defaults.

    .EXAMPLE
    $cred = Get-Credential
    $result = New-OnPremUserFromTemplate ` -TemplateSearch @{
        department='Engineering'; company='Acme' } ` -GivenName 'Bob' ` -Surname
        'Johnson' ` -DisplayName 'Bob Johnson' ` -SamAccountName 'bobj' `
        -UpnPrefix 'bob.johnson' ` -TargetOU
        'OU=Engineering,OU=Users,DC=company,DC=com' ` -CopyAttributes
        @('description', 'department', 'company') ` -Credential $cred ` -Server
        'DC01.company.com'

    Creates a new user using template search (flexible lookup), overrides naming
    and OU placement, specifies exact attributes to copy, and targets a specific
    DC.

    .EXAMPLE
    $cred = Get-Credential
    $result = New-OnPremUserFromTemplate ` -TemplateIdentity 'template.user' `
        -GivenName 'Alice' ` -Surname 'Williams' ` -DisplayName 'Alice Williams'
        ` -ExcludedGroups @('Domain Users', 'Sensitive Group') `
        -InitialPasswordLength 24 ` -Credential $cred ` -WhatIf

    Performs a dry-run (-WhatIf) to preview user creation and group assignments
    without making actual changes. Excludes two specific groups and uses a
    24-character password. Useful for validation before production execution.

    .EXAMPLE
    $cred = Get-Credential
    $result = New-OnPremUserFromTemplate ` -TemplateIdentity 'template.user' `
        -GivenName 'Jamie' ` -Surname 'Miller' ` -DisplayName 'Jamie Miller' `
        -Credential $cred ` -ShowSummary

    Creates the user and returns a PSCustomObject to the pipeline while also
    writing a formatted summary to the host for interactive visibility.

    .NOTES
    CONFIGURATION DEPENDENCY: This function requires TechToolbox configuration
    to be loaded via Initialize-TechToolboxRuntime. The following config
    sections must be present:
    - settings.tenant.upnSuffix: The primary UPN domain suffix (e.g.,
      "company.com")
    - settings.naming.copyAttributes (optional): Custom list of attributes to
      copy
    - settings.naming resolution functions for deriving SamAccountName and
      UpnPrefix

    IDEMPOTENCY: Before creation, the function checks if a user with the target
    UPN already exists. If found, the function logs a warning and returns
    without creating a duplicate. Plan accordingly when retrying failed
    provisioning operations.

    PERMISSIONS: The Credential account must have:
    - Create User Objects on the target OU
    - Reset Password permission (for setting initial password)
    - Write access to user attributes being modified
    - Read access to template user and all groups
    - Add Members permission on target groups

    NAMING DERIVATION: If -SamAccountName or -UpnPrefix are omitted,
    Resolve-Naming is called to derive these values. This function must exist
    and return an object with properties .Sam and .UpnPrefix. Consult your
    Resolve-Naming documentation for conformance to organizational naming
    standards.

    GROUP COPY BEHAVIOR: The function retrieves all groups from the template's
    memberOf property and evaluates each group category. Distribution groups are
    copied by default. Security groups are excluded by default unless the group
    name appears in -AllowedSecurityGroups. Any names in -ExcludedGroups are
    always skipped. If a group add fails, it is logged as a warning but does
    not stop provisioning. Check logs for partial group assignments.

    MANAGER ATTRIBUTE: The manager attribute is only copied if the template's
    manager value is a distinguished name (DN). If the template's manager is
    stored in a different format or is empty, it is skipped.

    PROXY ADDRESSES: A single primary proxyAddress is configured at creation
    time in the format "SMTP:UpnPrefix@UPN_SUFFIX". Additional proxy addresses
    or secondary SMTP addresses must be added separately or via directory
    synchronization.

    INITIAL PASSWORD: The auto-generated password is returned unencrypted in the
    output object. The caller is responsible for secure delivery (e.g.,
    encrypted email, secure portal). The password forces a reset on first logon
    via ChangePasswordAtLogon.

    PERFORMANCE: When targeting a specific domain controller via -Server,
    replication latency between create and modify operations is eliminated,
    improving reliability with rapid provisioning scripts.

    .RELATED LINKS
    Get-ADUser New-ADUser Set-ADUser Add-ADGroupMember Resolve-Naming
    Initialize-TechToolboxRuntime
    #>

    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByIdentity')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByIdentity')]
        [string]$TemplateIdentity,

        [Parameter(Mandatory, ParameterSetName = 'BySearch')]
        [hashtable]$TemplateSearch,

        [Parameter(Mandatory)]
        [string]$GivenName,

        [Parameter(Mandatory)]
        [string]$Surname,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        [string]$TargetOU,

        [string]$SamAccountName,
        [string]$UpnPrefix,

        [string[]]$CopyAttributes = @(
            'description', 'department', 'company', 'office', 'manager'
        ),

        [string[]]$ExcludedGroups = @(
            'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
            'Protected Users',
            'Server Operators', 'Account Operators', 'Backup Operators', 'Print Operators',
            'Group Policy Creator Owners',
            'Key Admins', 'Enterprise Key Admins',
            'DnsAdmins', 'DnsUpdateProxy',
            'Cert Publishers',
            'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers',
            'Allowed RODC Password Replication Group', 'Denied RODC Password Replication Group',
            'Cloneable Domain Controllers', 'Replicator'
        ),

        # Explicit per-run allow list (default = copy NO security groups)
        [string[]]$AllowedSecurityGroups = @(),

        [int]$InitialPasswordLength = 12,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [string]$Server,

        [switch]$ShowSummary
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Initialize-TechToolboxRuntime
        Get-ActiveDirectoryModule

        $cfg = $script:cfg
        $Tenant = $cfg.settings.tenant
        $Naming = $cfg.settings.naming

        # Apply config-driven copy list when caller does not explicitly pass -CopyAttributes.
        if (-not $PSBoundParameters.ContainsKey('CopyAttributes') -and $Naming.copyAttributes) {
            $CopyAttributes = @($Naming.copyAttributes | Where-Object { $_ -and $_.ToString().Trim() })
        }

        # Friendly attribute aliases -> LDAP names.
        $configToLdap = @{
            'description' = 'description'
            'department'  = 'department'
            'company'     = 'company'
            'office'      = 'physicalDeliveryOfficeName'
            'manager'     = 'manager'
        }

        # LDAP names -> Set-ADUser friendly parameter names.
        $LdapToParam = @{
            'description'                = 'Description'
            'department'                 = 'Department'
            'company'                    = 'Company'
            'physicalDeliveryOfficeName' = 'Office'
            'manager'                    = 'Manager'
        }

        # Properties to request from template during lookup.
        $CopyLdapAttrs = foreach ($attr in $CopyAttributes) {
            if (-not $attr) { continue }
            $key = $attr.ToString().ToLowerInvariant()
            if ($configToLdap.ContainsKey($key)) { $configToLdap[$key] }
            else { $attr.ToString() }
        }

        # Build AD splat EARLY
        $adBase = @{ Credential = $Credential }
        if ($Server) { $adBase['Server'] = $Server }

        if (-not $AllowedSecurityGroups -or $AllowedSecurityGroups.Count -eq 0) {
            Write-Log -Level Info -Message "No AllowedSecurityGroups provided; security group memberships will NOT be copied (distribution groups will still copy)."
        }

        $allowedSecDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $excludedDns = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($n in ($AllowedSecurityGroups | Where-Object { $_ -and $_.Trim() })) {
            $g = Get-ADGroup @adBase -Identity $n.Trim() -ErrorAction SilentlyContinue
            if ($g) { [void]$allowedSecDns.Add($g.DistinguishedName) }
            else { Write-Log -Level Warn -Message "AllowedSecurityGroup not found: $n" }
        }

        foreach ($n in ($ExcludedGroups | Where-Object { $_ -and $_.Trim() })) {
            $g = Get-ADGroup @adBase -Identity $n.Trim() -ErrorAction SilentlyContinue
            if ($g) { [void]$excludedDns.Add($g.DistinguishedName) }
            else { Write-Log -Level Warn -Message "ExcludedGroup not found: $n" }
        }

        # Always include these for later logic
        $templateProps = @($CopyLdapAttrs + 'memberOf' + 'adminCount') | Select-Object -Unique

        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' { $templateUser = Get-ADUser @adBase -Identity $TemplateIdentity -Properties $templateProps }
            'BySearch' {
                $clauses = foreach ($k in $TemplateSearch.Keys) {
                    $v = $TemplateSearch[$k]
                    if ($null -eq $v) { continue }
                    $v = ($v.ToString() -replace "'", "''")
                    "($k -eq '$v')"
                }
                if (-not $clauses) { throw "TemplateSearch is empty or contains only null values; provide at least one key/value." }
                $filter = ($clauses -join ' -and ')
                $templateUser = Get-ADUser @adBase -Filter $filter -Properties $templateProps | Select-Object -First 1
                if (-not $templateUser) { throw "Template user not found using exact-match filter: $filter" }
            }
        }

        if ($templateUser.adminCount -eq 1) {
            throw "Template user '$($templateUser.SamAccountName)' has adminCount=1 (protected/admin). Choose a non-privileged template."
        }

        Set-Variable -Name templateUser  -Value $templateUser  -Scope 1
        Set-Variable -Name adBase        -Value $adBase        -Scope 1
        Set-Variable -Name allowedSecDns -Value $allowedSecDns -Scope 1
        Set-Variable -Name excludedDns   -Value $excludedDns   -Scope 1
    }

    process {
        # Breadcrumb #1: entering function
        Write-Log -Level Info -Message ("Entering New-OnPremUserFromTemplate (ParamSet={0})" -f $PSCmdlet.ParameterSetName)

        # 1) Derive naming via config (unless caller overrides)
        if (-not $UpnPrefix -or -not $SamAccountName) {
            $nm = Resolve-Naming -Naming $Naming -GivenName $GivenName -Surname $Surname
            if (-not $UpnPrefix) { $UpnPrefix = $nm.UpnPrefix }
            if (-not $SamAccountName) { $SamAccountName = $nm.Sam }
        }

        $newUpn = "$UpnPrefix@$($Tenant.upnSuffix)"

        # 2) Resolve target OU (default to template's OU)
        if (-not $TargetOU) {
            $TargetOU = ($templateUser.DistinguishedName -replace '^CN=.*?,')
        }

        Write-Log -Level Info -Message ("Provisioning: DisplayName='{0}', Sam='{1}', UPN='{2}', OU='{3}'" -f $DisplayName, $SamAccountName, $newUpn, $TargetOU)

        # 3) Idempotency check
        $exists = Get-ADUser @adBase -LDAPFilter "(userPrincipalName=$newUpn)" -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Log -Level Warn -Message "User UPN '$newUpn' already exists. Aborting."
            return
        }

        # 4) Create new user
        $initialPassword = Get-NewPassword -length $InitialPasswordLength -nonAlpha 3
        $securePass = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        $newParams = @{
            Name                  = $DisplayName
            DisplayName           = $DisplayName
            GivenName             = $GivenName
            Surname               = $Surname
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $newUpn
            Enabled               = $false     # set $false if prefer disabled on creation
            Path                  = $TargetOU
            ChangePasswordAtLogon = $true
            AccountPassword       = $securePass
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Create AD user")) {
            New-ADUser @adBase @newParams
            Write-Log -Level Ok -Message ("Created AD user: {0}" -f $newUpn)
        }

        # 5) Copy selected attributes from template (uses mappings from begin{})
        $friendlyProps = @{}
        $otherAttrs = @{}

        foreach ($attr in $CopyAttributes) {
            if (-not $attr) { continue }
            $key = $attr.ToString()
            $ldapName = $configToLdap[$key.ToLowerInvariant()]
            if (-not $ldapName) { $ldapName = $key }  # treat unknown as raw LDAP (e.g., extensionAttribute1)

            $val = $templateUser.$ldapName
            if ($null -eq $val) { continue }
            if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { continue }

            if ($ldapName -eq 'manager') {
                # Manager must be DN; set via friendly param if it looks like a DN
                if ($val -is [string] -and $val -match '^CN=.+,DC=.+') {
                    $friendlyProps['Manager'] = $val
                }
                else {
                    Write-Verbose "Skipping manager; value is not a DN: $val"
                }
                continue
            }

            if ($LdapToParam.ContainsKey($ldapName)) {
                $friendlyProps[$LdapToParam[$ldapName]] = $val
            }
            else {
                $otherAttrs[$ldapName] = $val
            }
        }

        # Avoid double-setting Office via friendly and LDAP at once
        if ($friendlyProps.ContainsKey('Office') -and $otherAttrs.ContainsKey('physicalDeliveryOfficeName')) {
            $null = $otherAttrs.Remove('physicalDeliveryOfficeName')
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Apply copied attributes")) {
            if ($friendlyProps.Count -gt 0) {
                Set-ADUser @adBase -Identity $SamAccountName @friendlyProps
            }
            if ($otherAttrs.Count -gt 0) {
                Set-ADUser @adBase -Identity $SamAccountName -Replace $otherAttrs
            }
            Write-Log -Level Ok -Message "Copied attributes applied from template."
        }

        # 6) proxyAddresses — single primary at creation (idempotent)
        $primaryProxy = "SMTP:$UpnPrefix@$($Tenant.upnSuffix)"
        $proxiesToSet = @($primaryProxy)

        if ($PSCmdlet.ShouldProcess($newUpn, "Set primary proxyAddress")) {
            Set-ADUser @adBase -Identity $SamAccountName -Replace @{ proxyAddresses = $proxiesToSet }
            Write-Log -Level Ok -Message "Primary proxyAddress applied."
        }

        # 7) Copy group memberships (Distribution by default; Security via allow-list)
        $tmplGroupDNs = @($templateUser.memberOf)
        if (-not $tmplGroupDNs) { $tmplGroupDNs = @() }

        $tmplGroups = foreach ($dn in $tmplGroupDNs) {
            Get-ADGroup @adBase -Identity $dn -Properties GroupCategory -ErrorAction SilentlyContinue
        }

        $toAddGroups = $tmplGroups | Where-Object {
            $_ -and (
                $_.GroupCategory -eq 'Distribution' -or
                ($_.GroupCategory -eq 'Security' -and $allowedSecDns.Contains($_.DistinguishedName))
            ) -and (-not $excludedDns.Contains($_.DistinguishedName))
        }

        $toAdd = @(
            $toAddGroups |
                ForEach-Object { $_.Name } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique
        )

        if ($PSCmdlet.ShouldProcess($newUpn, "Add group memberships")) {
            $added = 0
            foreach ($grp in $toAddGroups) {
                try {
                    Add-ADGroupMember @adBase -Identity $grp.DistinguishedName -Members $SamAccountName -ErrorAction Stop
                    $added++
                    Write-Log -Level Info -Message ("Added to: {0}" -f $grp.Name)
                }
                catch {
                    Write-Log -Level Warn -Message ("Group add failed '{0}': {1}" -f $grp.Name, $_.Exception.Message)
                }
            }
            Write-Log -Level Ok -Message ("Group additions complete: {0} added" -f $added)
        }

        $skippedSecurity = $tmplGroups | Where-Object {
            $_ -and $_.GroupCategory -eq 'Security' -and (-not $allowedSecDns.Contains($_.DistinguishedName))
        }

        if ($skippedSecurity) {
            $skippedSecurityNames = @(
                $skippedSecurity |
                    ForEach-Object { $_.Name } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                    Select-Object -Unique
            )
            if ($skippedSecurityNames.Count -gt 0) {
                Write-Log -Level Info -Message ("Skipped security groups (not allow-listed): {0}" -f ($skippedSecurityNames -join ', '))
            }
        }

        # 8) Output summary (force visible + return)
        $result = [pscustomobject]@{
            UserPrincipalName = $newUpn
            SamAccountName    = $SamAccountName
            DisplayName       = $DisplayName
            Enabled           = $newParams.Enabled
            TargetOU          = $TargetOU
            CopiedAttributes  = $CopyAttributes
            GroupsAdded       = $toAdd
            InitialPassword   = $initialPassword  # caller is responsible for secure handling
        }

        if ($ShowSummary) {
            $result | Format-List | Out-Host
        }

        Write-Output $result
    }
    end { }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCzq+/e0NPWZI2m
# 7oVxIDGIiElD7MJXNSt5VdO9BMWIgaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAcMIYpEci9
# 4jUUQbyKJlBY4ABb/JvuiejVxovJ4/JIbDANBgkqhkiG9w0BAQEFAASCAgAHOnLc
# GNQtiTfr7tiD6Pf7CwQNiuAVxsi04LphPAALET6ixuIggp7EfHI1wc8grkyC6AT7
# jpQHA/D4MzgahRtM3sYRgzbWVt5gerZbxqhyYr6kYjtw47/gmgr7Re9bfl0xm3o0
# 3tugfQdG8EIIl/6AJ7eG2i9gfbDwapHKRg6mGKKSVmgnZlqnCC/HBSXmgvlReEqm
# 68OlQzqoJ/VyD9AhxmzYkdJcEVm8XILo5ULydlQ1yvmztYRwFMAzByD7QgwrP4ct
# vD7MLl9JgqPr8h+HxreCMEqh9B7a08rAXri8kw/ZZetF0/vtj8fMTZ2Gx6rkStx4
# 9V4w4JNXRdr4QMiONk+k54cFfmCavlY4l3bEsHbx/NCnJl8pMrHsVvSbc41+nNgl
# n39a/ftykQ95j4VMVx6NPSqO6M/p1ooXpg5QpU4kPFGE57bhwpl8tolxP187KlVh
# NqcmzR52FrYg9OGymEbNVo7W0NLGLY9pWxilfi/9l9UJbSX/5puEmWbKW3t90XvX
# 8Nn7whin17mGxIIDCCRt/kW45mBbHLqsprEs6a53816+fxyfjPBk2WcaAA6E4mNJ
# Q0I6uiVjVq0wYpmnyKXwAU+YQa7fK9zIf0fRphVruzKE4wWWfNZy+PmULDk7p5lr
# kzDRLNiYsuHz9L5PLt1ci5Fh4fy1wJc8JzIwSaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MjgxOTQ5MTRaMC8GCSqGSIb3DQEJBDEiBCDrlFaOVq7I+OrL+8vW
# 1UjFr+Ie3srN2pB+G4i+OwOK3DANBgkqhkiG9w0BAQEFAASCAgBL1EVv3OyFWrz1
# ORtfThopj+kSwzmgDy02VS4CufSPl/d6cbIg6hAqykqUkQarD3YW/Szu1x59Htnq
# 8R+lu7ryZcuDPVDzUgb3ZrN7g0lSjZV9p+fAO5UqSVR+Tplu/N+bGf3AjmyeTO/v
# aW0ZSd8YXY/Oghv4s+M0O+ypoN/6g+G2g9Dk4zByPr6JgSRlrL0p0DxCLrDdaTvs
# RJFPDRsfa70oHEMRE+8lZ2aKBCcwqhC/MxpDq0YhgZdpAbthwmAGLJTyXYLo8FZL
# 2uL30wICwEMVIGQsAGoBmFlliNMEsaQ7LIGWU2S4iylyav3/hsAmGh20NY30Z/c9
# ZlG9pX3h/x0kXf+Dh2Qvin1+v2cd19GcpnSaSTJEDHmXh7VwHSCJidHcIBpmfLaJ
# znd3nP3VATKrV/UblwSGjrKgYADOsmgG9jEmMZhNHIFWu5juzigEaNPXP1V5Yb++
# 8e+g3UliT+L7hT4kS61UX/r47kt66ouBmuVdvEre0j+T4TFI3zf5Moa+/PVga/sZ
# lyFmJEi57c/Hog0mFEO5V2Ya/qAsIBEj7FKWUgsoYvuV738j7uYBlN/r3GqXCRUx
# MVJC/C3NmFQfJTcfyocwZaGuJphEdrg9mJ3FbREWqoP3xAlNPyPNO++dWWJTfX3m
# UZuSgJ3UqxvJQzLN2uFk9dVnKzrwrg==
# SIG # End signature block
