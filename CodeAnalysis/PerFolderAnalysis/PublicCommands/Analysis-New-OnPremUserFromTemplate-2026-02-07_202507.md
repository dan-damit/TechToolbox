# Code Analysis Report
Generated: 2/7/2026 8:25:07 PM

## Summary
 This is a PowerShell script for creating and configuring an Active Directory (AD) user based on provided parameters. The script takes care of deriving the username, UPN, and naming based on configuration or user-provided values, and it applies selected attributes from a template user while excluding known admin/builtin groups.

Here's a brief explanation of the script sections:

1. Variables and constants: The beginning of the script defines variables and constants for holding various configurations and settings used throughout the script.

2. Begin block: This section initializes some required variables, sets up the naming convention based on provided values or configuration, and prepares to resolve the template user.

3. ProxyAddresses setup: The script sets the primary proxyAddress for the new user during creation using the configured UPN.

4. Idempotency check: Before creating a new user, the script checks if the provided UPN already exists in AD and returns if it does.

5. Create new user: This section creates the new user with the specified parameters, and sets the password using a generated secure string.

6. Copy selected attributes from template: The script copies the specified attributes (e.g., Office, Department) from the template user to the newly created user.

7. Apply primary proxyAddress: After creating the user, the script applies the primary proxyAddress.

8. Copy group memberships: This section copies the group memberships of the template user to the new user while excluding known admin/builtin groups.

9. End block: The final block outputs a summary of the created user, including UPN, SamAccountName, DisplayName, TargetOU, CopiedAttributes, GroupsAdded, and the generated initial password (caller is responsible for handling it securely).

## Source Code
```powershell

function New-OnPremUserFromTemplate {
    <#
    .SYNOPSIS
    Create a new on-premises AD user based on a template user.

    .DESCRIPTION
    Creates a new Active Directory user by copying attributes and group
    memberships from a specified template user. Naming (UPN, SAM, alias) derives
    from config unless overridden.

    .PARAMETER TemplateIdentity
    Identity (sAMAccountName, DN, SID, GUID) of the template user to copy.

    .PARAMETER TemplateSearch
    Hashtable of attribute=value pairs to locate the template (first match
    wins).

    .PARAMETER GivenName
    First name of the new user.

    .PARAMETER Surname
    Last name of the new user.

    .PARAMETER DisplayName
    Display name of the new user.

    .PARAMETER TargetOU
    DistinguishedName of the OU to create the user in. Defaults to template’s
    OU.

    .PARAMETER SamAccountName
    sAMAccountName for the new user. Derived if omitted.

    .PARAMETER UpnPrefix
    UPN prefix for the new user. Derived if omitted.

    .PARAMETER CopyAttributes
    Attributes to copy from template to the new user.

    .PARAMETER ExcludedGroups
    Group names to exclude when copying memberships.

    .PARAMETER InitialPasswordLength
    Length of the generated initial password.

    .PARAMETER Credential
    Directory credential to run AD operations as.

    .PARAMETER Server
    Optional DC to target (avoid replication latency during create+modify).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(ParameterSetName = 'ByIdentity')]
        [string]$TemplateIdentity,

        [Parameter(ParameterSetName = 'BySearch')]
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
            'Protected Users', 'Server Operators', 'Account Operators', 'Backup Operators',
            'Print Operators', 'Read-only Domain Controllers', 'Enterprise Read-only Domain Controllers'
        ),

        [int]$InitialPasswordLength = 16,

        [Parameter(Mandatory)]
        [pscredential]$Credential,

        [string]$Server
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Set-StrictMode -Version Latest

        Import-Module ActiveDirectory -ErrorAction Stop

        # Load config (throws if missing essentials)
        $cfg = Get-TechToolboxConfig
        $Tenant = $cfg['settings']['tenant']
        $Naming = $cfg['settings']['naming']
        # If caller did NOT pass -CopyAttributes, take it from config
        $callerSpecifiedCopyAttrs = $PSBoundParameters.ContainsKey('CopyAttributes')
        if (-not $callerSpecifiedCopyAttrs) {
            if ($Naming -and $Naming['copyAttributes']) {
                $CopyAttributes = @($Naming['copyAttributes'])
            }
            else {
                $CopyAttributes = @()
            }
        }
        # Ensure it's an array of strings
        $CopyAttributes = @($CopyAttributes | ForEach-Object { $_.ToString() }) | Where-Object { $_ -and $_.Trim() -ne '' }

        # Map config-friendly names -> LDAP names (keyed lowercase for case-insensitive lookup)
        $configToLdap = @{
            'description' = 'description'
            'department'  = 'department'
            'company'     = 'company'
            'office'      = 'physicalDeliveryOfficeName'
            'manager'     = 'manager'
        }

        # Compute the LDAP attributes to request for the template user
        $CopyLdapAttrs = foreach ($name in $CopyAttributes) {
            $key = $name.ToLowerInvariant()
            if ($configToLdap.ContainsKey($key)) { $configToLdap[$key] } else { $name }
        }
        $CopyLdapAttrs = $CopyLdapAttrs | Select-Object -Unique

        # Map LDAP -> friendly AD parameter where one exists (used later when applying)
        $LdapToParam = @{
            department                 = 'Department'
            physicalDeliveryOfficeName = 'Office'
            company                    = 'Company'
            description                = 'Description'
            # manager is special (DN) → friendly param 'Manager' but value must be DN
        }

        # --- Resolve template user (according to parameter set) ---
        $adBase = @{ Credential = $Credential }
        if ($Server) { $adBase['Server'] = $Server }

        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' {
                if ([string]::IsNullOrWhiteSpace($TemplateIdentity)) {
                    throw "Parameter set 'ByIdentity' requires -TemplateIdentity."
                }
                $templateUser = Get-ADUser @adBase -Identity $TemplateIdentity -Properties $CopyLdapAttrs
            }
            'BySearch' {
                if (-not $TemplateSearch -or $TemplateSearch.Count -eq 0) {
                    throw "Parameter set 'BySearch' requires -TemplateSearch (hashtable filter)."
                }
                # Build a -Filter from the hashtable (simple AND of equality clauses)
                $clauses = foreach ($k in $TemplateSearch.Keys) {
                    $v = $TemplateSearch[$k]
                    # Escape quotes in value
                    $v = ($v -replace "'", "''")
                    "($k -eq '$v')"
                }
                $filter = ($clauses -join ' -and ')
                $templateUser = Get-ADUser @adBase -Filter $filter -Properties $CopyLdapAttrs |
                Select-Object -First 1
                if (-not $templateUser) {
                    throw "Template user not found using search filter: $filter"
                }
            }
            default {
                throw "Unknown parameter set: $($PSCmdlet.ParameterSetName)"
            }
        }

        # Expose a couple of helper items for the process/end blocks
        Set-Variable -Name LdapToParam     -Value $LdapToParam     -Scope 1
        Set-Variable -Name CopyLdapAttrs   -Value $CopyLdapAttrs   -Scope 1
        Set-Variable -Name templateUser    -Value $templateUser    -Scope 1
        Set-Variable -Name adBase          -Value $adBase          -Scope 1
    }

    process {
        # Breadcrumb #1: entering function
        Write-Log -Level Info -Message ("Entering New-OnPremUserFromTemplate (ParamSet={0})" -f $PSCmdlet.ParameterSetName)

        # 1) Resolve template user
        $templateUser = $null
        switch ($PSCmdlet.ParameterSetName) {
            'ByIdentity' {
                $templateUser = Get-ADUser @adBase -Identity $TemplateIdentity -Properties $CopyLdapAttrs
            }
            'BySearch' {
                if (-not $TemplateSearch) { throw "Provide -TemplateSearch (e.g., @{ title='Engineer'; company='Company' })." }
                $ldapFilterParts = foreach ($k in $TemplateSearch.Keys) {
                    $val = [System.Text.RegularExpressions.Regex]::Escape($TemplateSearch[$k])
                    "($k=$val)"
                }
                $ldapFilter = "(&" + ($ldapFilterParts -join '') + ")"
                $templateUser = Get-ADUser @adBase -LDAPFilter $ldapFilter -Properties * -ErrorAction Stop |
                Select-Object -First 1
                if (-not $templateUser) { throw "No template user matched filter $ldapFilter." }
            }
            default { throw "Unexpected parameter set." }
        }

        Write-Log -Level Info -Message ("Template resolved: {0} ({1})" -f $templateUser.SamAccountName, $templateUser.UserPrincipalName)

        # 2) Derive naming via config (unless caller overrides)
        if (-not $UpnPrefix -or -not $SamAccountName) {
            $nm = Resolve-Naming -Naming $Naming -GivenName $GivenName -Surname $Surname
            if (-not $UpnPrefix) { $UpnPrefix = $nm.UpnPrefix }
            if (-not $SamAccountName) { $SamAccountName = $nm.Sam }
        }

        $newUpn = "$UpnPrefix@$($Tenant.upnSuffix)"

        # 3) Resolve target OU (default to template's OU)
        if (-not $TargetOU) {
            $TargetOU = ($templateUser.DistinguishedName -replace '^CN=.*?,')
        }

        Write-Log -Level Info -Message ("Provisioning: DisplayName='{0}', Sam='{1}', UPN='{2}', OU='{3}'" -f $DisplayName, $SamAccountName, $newUpn, $TargetOU)

        # 4) Idempotency check
        $exists = Get-ADUser @adBase -LDAPFilter "(userPrincipalName=$newUpn)" -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Log -Level Warn -Message "User UPN '$newUpn' already exists. Aborting."
            return
        }

        # 5) Create new user
        $initialPassword = Get-NewPassword -length $InitialPasswordLength -nonAlpha 3
        $securePass = ConvertTo-SecureString $initialPassword -AsPlainText -Force

        $newParams = @{
            Name                  = $DisplayName
            DisplayName           = $DisplayName
            GivenName             = $GivenName
            Surname               = $Surname
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $newUpn
            Enabled               = $true     # set $false if prefer disabled on creation
            Path                  = $TargetOU
            ChangePasswordAtLogon = $true
            AccountPassword       = $securePass
        }

        if ($PSCmdlet.ShouldProcess($newUpn, "Create AD user")) {
            New-ADUser @adBase @newParams
            Write-Log -Level Ok -Message ("Created AD user: {0}" -f $newUpn)
        }

        # 6) Copy selected attributes from template (uses mappings from begin{})
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

        # 7) proxyAddresses — single primary at creation (idempotent)
        $primaryProxy = "SMTP:$UpnPrefix@$($Tenant.upnSuffix)"
        $proxiesToSet = @($primaryProxy)

        if ($PSCmdlet.ShouldProcess($newUpn, "Set primary proxyAddress")) {
            Set-ADUser @adBase -Identity $SamAccountName -Replace @{ proxyAddresses = $proxiesToSet }
            Write-Log -Level Ok -Message "Primary proxyAddress applied."
        }

        # 8) Copy group memberships (exclude known admin/builtin)
        $tmplGroupDNs = (Get-ADUser @adBase -Identity $templateUser.DistinguishedName -Property memberOf).memberOf
        if (-not $tmplGroupDNs) { $tmplGroupDNs = @() }

        $tmplGroupNames = foreach ($dn in $tmplGroupDNs) {
            (Get-ADGroup @adBase -Identity $dn -ErrorAction SilentlyContinue).Name
        }

        $toAdd = $tmplGroupNames | Where-Object { $_ -and ($ExcludedGroups -notcontains $_) }

        if ($PSCmdlet.ShouldProcess($newUpn, "Add group memberships")) {
            $added = 0
            foreach ($gName in $toAdd) {
                try {
                    Add-ADGroupMember @adBase -Identity $gName -Members $SamAccountName -ErrorAction Stop
                    $added++
                    Write-Log -Level Info -Message ("Added to: {0}" -f $gName)
                }
                catch {
                    Write-Log -Level Warn -Message ("Group add failed '{0}': {1}" -f $gName, $_.Exception.Message)
                }
            }
            Write-Log -Level Ok -Message ("Group additions complete: {0} added" -f $added)
        }

        # 9) Output summary (force visible + return)
        $result = [pscustomobject]@{
            UserPrincipalName = $newUpn
            SamAccountName    = $SamAccountName
            DisplayName       = $DisplayName
            TargetOU          = $TargetOU
            CopiedAttributes  = $CopyAttributes
            GroupsAdded       = $toAdd
            InitialPassword   = $initialPassword  # caller is responsible for secure handling
        }

        # Force a visible summary even if caller pipes to Out-Null
        $result | Format-List | Out-Host
    }

    end { }
}

[SIGNATURE BLOCK REMOVED]

```
