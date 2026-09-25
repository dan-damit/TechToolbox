function New-OnPremUserFromTemplate {
    <#
    .SYNOPSIS
    Create a new on-prem AD user by copying attributes and group memberships
    from a template user.

    .DESCRIPTION
    Creates a new Active Directory user account using a template user as the
    source of standard attributes and group memberships.

    High-level workflow:
    - Resolve and validate the template user (ByIdentity or BySearch)
    - Derive naming (SAM/UPN) from parameters or Resolve-Naming + config
    - Enforce idempotency (do not create if target UPN already exists)
    - Create the user (enabled + ChangePasswordAtLogon)
    - Copy selected attributes from template
    - Configure primary proxyAddress (SMTP)
    - Copy group memberships with allow/deny controls

    Supports -WhatIf/-Confirm via ShouldProcess.

    .PARAMETER TemplateIdentity
    Template user identity (sAMAccountName, DN, SID, GUID). Used with ByIdentity
    only.

    .PARAMETER TemplateSearch
    Hashtable of LDAP attribute=value filters to locate the template. BySearch
    only. Criteria are ANDed; first match is used.

    .PARAMETER GivenName
    New user's first name. Used for naming derivation when SAM/UPN prefix not
    supplied.

    .PARAMETER Surname
    New user's last name. Used for naming derivation when SAM/UPN prefix not
    supplied.

    .PARAMETER DisplayName
    New user's display name (e.g. "First Last"). Used for address book friendly
    name.

    .PARAMETER TargetOU
    Destination OU DN. If omitted, defaults to template user's OU.

    .PARAMETER SamAccountName
    New user's sAMAccountName. If omitted, derived by Resolve-Naming.

    .PARAMETER UpnPrefix
    UPN prefix (left of @). If omitted, derived by Resolve-Naming. UPN suffix
    comes from config.

    .PARAMETER CopyAttributes
    Attributes to copy from template. If omitted, uses config list (if present),
    else defaults. See NOTES for default list and mapping behavior.

    .PARAMETER ExcludedGroups
    Explicit deny-list for groups when copying memberships (applies after allow
    rules).

    .PARAMETER AllowedSecurityGroups
    Allow-list for Security groups to copy. Distribution groups are copied by
    default.

    .PARAMETER InitialPasswordLength
    Length of generated initial password. Default: 16.

    .PARAMETER Credential
    Credential used for all AD operations.

    .PARAMETER Server
    Domain controller to target for AD operations (optional).

    .PARAMETER ShowSummary
    Writes a human-readable summary to host while still returning the result
    object.

    .INPUTS
    None.

    .OUTPUTS
    PSCustomObject. Properties typically include: UserPrincipalName,
    SamAccountName, DisplayName, TargetOU, CopiedAttributes, GroupsAdded,
    InitialPassword.

    .EXAMPLE
    $cred = Get-Credential
    New-OnPremUserFromTemplate -TemplateIdentity 'john.smith' ` -GivenName
      'Jane' -Surname 'Doe' -DisplayName 'Jane Doe' ` -Credential $cred

    .EXAMPLE
    $cred = Get-Credential
    New-OnPremUserFromTemplate -TemplateSearch @{ department='Engineering';
      company='Acme' } ` -GivenName 'Bob' -Surname 'Johnson' -DisplayName 'Bob
      Johnson' ` -SamAccountName 'bobj' -UpnPrefix 'bob.johnson' ` -TargetOU
      'OU=Engineering,OU=Users,DC=company,DC=com' ` -CopyAttributes
      @('description','department','company') ` -Server 'DC01.company.com'
      -Credential $cred

    .EXAMPLE
    $cred = Get-Credential
    New-OnPremUserFromTemplate -TemplateIdentity 'template.user' ` -GivenName
      'Alice' -Surname 'Williams' -DisplayName 'Alice Williams' `
      -ExcludedGroups @('Domain Users','Sensitive Group') `
      -InitialPasswordLength 24 -Credential $cred -WhatIf

    .NOTES
    CONFIG
    - Requires TechToolbox runtime/config via Initialize-TechToolboxRuntime.
    - Expected keys (typical):
      - settings.tenant.upnSuffix
      - settings.naming.copyAttributes (optional)

    NAMING
    - If -SamAccountName or -UpnPrefix is omitted, Resolve-Naming is used.
    - Resolve-Naming must return .Sam and .UpnPrefix.

    IDEMPOTENCY
    - If a user with the target UPN exists, the function returns without
      creating a duplicate.

    COPYATTRIBUTES DEFAULTS + MAPPING
    - Default attributes (if config not provided): description, department,
      company, office, manager
    - 'office' maps to physicalDeliveryOfficeName.
    - Unknown names are treated as LDAP attributes and applied via -Replace.
    - 'manager' is copied only when template manager is a valid DN.

    GROUP COPY RULES
    - Distribution groups: copied by default
    - Security groups: copied only if group name appears in
      -AllowedSecurityGroups
    - -ExcludedGroups always wins
    - Group-add failures log warnings but do not stop provisioning

    PROXYADDRESSES
    - Sets primary proxyAddress as: SMTP:<UpnPrefix>@<upnSuffix>
    - Additional aliases are not added by this function.

    SECURITY
    - InitialPassword is returned in plaintext in output. Deliver securely.
    - Credential must have rights to create users, set password, modify
      attributes, and add group memberships.

    .LINK
    https://dan-damit.github.io/TechToolbox-Docs/user-provisioning

    .LINK
    about_UserProvisioning
    Initialize-TechToolboxRuntime
    Resolve-Naming
    Get-ADUser
    New-ADUser
    Set-ADUser
    Add-ADGroupMember
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
            'description', 'department', 'company', 'office', 'manager', 'title'
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBSTTCCJxn1u/B
# 5ZKy78kkiHB6DfMFCA19w2up1k17LqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBAI6OzXk6u
# 06mMvKZW/+nnkzLU6trPn4ZZO5ymEQQ4QjANBgkqhkiG9w0BAQEFAASCAgAYt9oz
# eWJK1dw4JUIQWXkJi3rEOfcCwE3ABBvoKC82kiidk5qNAV41yOv98F+FRiTC7c1Q
# 3JPUlMJAW5Ns+zFMkup12jNUPc9XTQ4oY3UnvnbuYj1M+1tRKkDEVVqgcAmb7mwP
# YHglyeKkWjfyjPCGgvRoGamXSqFbeBiqJHpPGnPseTAEO6EJ6pjUHr7nVal5A6F7
# vnWGNFvVte6Oc/MGv2w2PHlyFAV1cycWS6Ztj/S1yb/avah+9zuC/0+4gm9O+3uy
# yIYqEGHiT/c0636FaLPMnUAiSOBohUmg9NPsQvx5C3VvNGJjsoxkDkU3r3e9k3DE
# n4JXEBSD3GQKtJ3GVbrMC1KPddwuem8frNDXbPAEgIGYU10W70ugxh1B0DrFsi9F
# dGboK+IH8FznymHL4cfK+IUDub4ErNw9RfKhM3I9aD6t7LNKbFl+QYRWcERqs2iu
# 16pC9asc0jFrCiqPun/lm/0RosHQqs91/pvhXUEGKoSD8hMIxM8ktjpXZKnzAALK
# KNekR2gZbvGlTWc14fttHwX/BJJFNS/teAEBWg0RutZLzeMcImE8ZkukcS2vHgMI
# qjl7ZLoTy+fTNn50+/PSA3avAq/7lgDKQC+yPM60MVHu3inDLPWZUqfH3LdkzPCq
# KWUe7Idzat0Xc7p6nIrk2y08Li+Ewyzp5wv/R6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MjUxODE0MzNaMC8GCSqGSIb3DQEJBDEiBCCSyRigawdRQm0WtDe9
# ndQxLMEUxxY5ApjDvaalsyk2uDANBgkqhkiG9w0BAQEFAASCAgCjnfg/LhpdvKb6
# XkBcbHlSAhy/2fmg0CduaeJ0U4+ACEDaR2HVrsF2mYHNPGc36E3aNB1WC9MEKmKi
# ZiPacH4oOJ/rI02RTLsSMhpK+X0RHC/m8okAwRqET82RTAxeW5RJFQdRvLArFeb3
# BA9AyMVMdvfbgcuMisvpVkI0BfATQFU1ddJSUR84zXKdMPRdVoGW94TmHjlp6PPm
# Ark3FMkUXRBWHWNmrCtP5SLoS1jPeDdcoR0kY9vSsZHcHllQPLn6Z5pDTAcnJUzV
# OMzGApBrqUovjBny8JKlIZP/EO7WiofnAuOwph0YNIjgWRg00KuFAhD6YRojvVnx
# J2rvYspmAt1L2kLpdvTfPsDicTqZegjtiq+qU1ePsnR4BmrC1ZU1twLhHYKtnHfl
# rp0bfoPyv0qpRslHxEtkm270E+N8rDHEbh/X0T84Eq9VhJ8itle0L6h41WEjZXTM
# t7729/USgxCEHPdmjcE76DyFqU7O60pTdcz1DWkGLDHAFSld6iPnCc5DWsdrvGw9
# frJi2cQg6S0TctUQA8OeP/OSvA9ZQ0cibO5Zq+ahMxMsEACzW8qu4JczLiNlGGHT
# L7S3S/Oktf2gaLzlKsdGsyzhqTmj0lk9ayd+U1z4MkRtMCmtjo9lhZ1LOk4tYLvq
# tdDVvEkAsXxZqYT74Su0zKVmvWvv8Q==
# SIG # End signature block
