<#
.SYNOPSIS
  Enumerate local group members with rich identity data (SID, ADSI path, etc.)
  and optional recursive expansion.
.DESCRIPTION
  Uses ADSI WinNT provider for authoritative local group membership enumeration.
  Optionally expands nested groups (local groups and domain groups) with cycle
  protection and depth limit.
.PARAMETER Group
  Local group name/alias (default: Administrators).
.PARAMETER Recurse
  Expand nested group membership.
.PARAMETER MaxDepth
  Maximum recursion depth (default: 5).
.PARAMETER IncludeGroups
  Include group objects in the output (default: $true). If $false, returns only
  non-group principals for recursive expansion (direct group members still
  appear as direct members).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $Group = 'Administrators',

    [Parameter()]
    [switch] $Recurse,

    [Parameter()]
    [ValidateRange(0, 50)]
    [int] $MaxDepth = 5,

    [Parameter()]
    [bool] $IncludeGroups = $true
)

Set-StrictMode -Version 2.0

function ConvertTo-SidString {
    param([object]$SidBytes)
    try {
        if ($null -eq $SidBytes) { return $null }
        $bytes = if ($SidBytes -is [byte[]]) { $SidBytes } else { [byte[]]$SidBytes }
        return ([System.Security.Principal.SecurityIdentifier]::new($bytes, 0)).Value
    }
    catch {
        return $null
    }
}

function Test-TranslateSidToNtAccount {
    param([string]$Sid)
    if (-not $Sid) { return $null }
    try {
        $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $null
    }
}

function Get-AdsiMembersOfWinNTGroup {
    param(
        [Parameter(Mandatory)] [string] $WinntGroupAdsPath
    )

    $groupObj = [ADSI]$WinntGroupAdsPath
    @($groupObj.psbase.Invoke('Members')) | ForEach-Object {
        $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)
    }
}

function Convert-AdsiPathToDisplayName {
    param([string]$AdsPath)
    if (-not $AdsPath) { return $null }

    # Common shapes:
    # WinNT://COMPUTER/Administrator
    # WinNT://DOMAIN/Domain Admins
    if ($AdsPath -match '^WinNT://([^/]+)/(.+)$') {
        $dom = $matches[1]
        $obj = $matches[2]
        $obj = $obj -replace '/', '\'
        return "$dom\$obj"
    }
    return $AdsPath
}

function Get-PrincipalFromAdsiPath {
    param(
        [Parameter(Mandatory)] [string] $AdsPath
    )

    $obj = $null
    try { $obj = [ADSI]$AdsPath } catch { $obj = $null }

    $name = Convert-AdsiPathToDisplayName -AdsPath $AdsPath
    $class = $null
    $sidBytes = $null
    $sid = $null

    if ($obj) {
        try { $class = $obj.Class } catch { $class = $null }
        try { $sidBytes = $obj.psbase.InvokeGet('ObjectSID') } catch { $sidBytes = $null }
        $sid = ConvertTo-SidString -SidBytes $sidBytes
    }

    $resolved = Test-TranslateSidToNtAccount -Sid $sid

    # Heuristics
    $computer = $env:COMPUTERNAME
    $isLocal = ($resolved -like "$computer\*") -or ($name -like "$computer\*")
    $isAzure = ($resolved -like "AzureAD\*") -or ($name -like "AzureAD\*") -or ($sid -like "S-1-12-1-*")

    [pscustomobject]@{
        Name              = $name
        AdsPath           = $AdsPath
        ADSIClass         = $class
        SID               = $sid
        ResolvedNTAccount = $resolved
        IsGroup           = ($class -eq 'Group')
        IsLocal           = $isLocal
        IsAzureAD         = $isAzure
    }
}

function Test-GetLocalAccountsEnrichment {
    param(
        [Parameter(Mandatory)] [string] $GroupName
    )

    $cmd = Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue
    if (-not $cmd) { return @{} }

    $map = @{}
    try {
        foreach ($m in (Get-LocalGroupMember -Group $GroupName -ErrorAction Stop)) {
            $sid = $null
            try { $sid = $m.SID.Value } catch { $sid = $null }
            if (-not $sid) { continue }
            $map[$sid] = [pscustomobject]@{
                ObjectClass     = $m.ObjectClass
                PrincipalSource = $m.PrincipalSource
                LocalName       = $m.Name
            }
        }
    }
    catch {
        # Ignore; ADSI remains authoritative
    }

    return $map
}

function Test-ExpandDomainGroupMembers {
    param(
        [Parameter(Mandatory)] [string] $GroupSid,
        [Parameter(Mandatory)] [int] $Depth,
        [Parameter(Mandatory)] [int] $MaxDepth,
        [Parameter(Mandatory)] [hashtable] $SeenGroupSids
    )

    if (-not $GroupSid) { return @() }
    if ($Depth -ge $MaxDepth) { return @() }
    if ($SeenGroupSids.ContainsKey($GroupSid)) { return @() }
    $SeenGroupSids[$GroupSid] = $true

    # Use AccountManagement to avoid requiring the AD module
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
    }
    catch {
        return @()
    }

    $out = New-Object System.Collections.Generic.List[object]
    try {
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext `
        ([System.DirectoryServices.AccountManagement.ContextType]::Domain)

        $gp = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(
            $ctx,
            [System.DirectoryServices.AccountManagement.IdentityType]::Sid,
            $GroupSid
        )

        if (-not $gp) { return @() }

        foreach ($m in $gp.GetMembers($false)) {
            $msid = $null
            try { $msid = $m.Sid.Value } catch { $msid = $null }

            $mname = $null
            try {
                if ($m.ContextType -eq 'Domain') {
                    $mname = "$($m.Context.Name)\$($m.SamAccountName)"
                }
                else {
                    $mname = $m.Name
                }
            }
            catch {
                $mname = $m.Name
            }

            $isGroup = $false
            try { $isGroup = ($m.StructuralObjectClass -eq 'group') } catch { $isGroup = $false }

            $resolved = Test-TranslateSidToNtAccount -Sid $msid

            $out.Add([pscustomobject]@{
                    Name              = $mname
                    AdsPath           = $null
                    ADSIClass         = if ($isGroup) { 'Group' } else { 'User' }
                    SID               = $msid
                    ResolvedNTAccount = $resolved
                    IsGroup           = $isGroup
                    IsLocal           = $false
                    IsAzureAD         = ($msid -like "S-1-12-1-*")
                }) | Out-Null

            if ($isGroup -and $msid) {
                foreach ($child in (Test-ExpandDomainGroupMembers -GroupSid $msid -Depth ($Depth + 1) -MaxDepth $MaxDepth -SeenGroupSids $SeenGroupSids)) {
                    $out.Add($child) | Out-Null
                }
            }
        }
    }
    catch {
        return @()
    }

    return $out
}

# --- Main ---
$computer = $env:COMPUTERNAME
$when = Get-Date
$enrichBySid = Test-GetLocalAccountsEnrichment -GroupName $Group

# Direct members from local group (authoritative)
$groupAdsPath = "WinNT://./$Group,group"
Write-Log -Level Info -Message "Enumerating direct members via ADSI: $groupAdsPath"

$directMemberPaths = Get-AdsiMembersOfWinNTGroup -WinntGroupAdsPath $groupAdsPath

# Output rows list
$rows = New-Object System.Collections.Generic.List[object]

# For recursion
$seenGroupSids = @{}   # group-sid cycle protection
$seenMemberKeys = @{}  # de-dupe (SID preferred, else AdsPath)

function Add-Row {
    param(
        [Parameter(Mandatory)] [pscustomobject] $Principal,
        [Parameter(Mandatory)] [bool] $IsDirect,
        [Parameter(Mandatory)] [string] $ParentGroup,
        [Parameter(Mandatory)] [int] $Depth
    )

    $sidKey = if ($Principal.SID) { "SID:$($Principal.SID)" } else { "PATH:$($Principal.AdsPath)" }
    $dedupeKey = "$IsDirect|$ParentGroup|$Depth|$sidKey"
    if ($seenMemberKeys.ContainsKey($dedupeKey)) { return }
    $seenMemberKeys[$dedupeKey] = $true

    $objClass = $null
    $src = $null
    $localName = $null
    if ($Principal.SID -and $enrichBySid.ContainsKey($Principal.SID)) {
        $objClass = $enrichBySid[$Principal.SID].ObjectClass
        $src = $enrichBySid[$Principal.SID].PrincipalSource
        $localName = $enrichBySid[$Principal.SID].LocalName
    }

    $rows.Add([pscustomobject]@{
            ComputerName      = $computer
            Group             = $Group
            ParentGroup       = $ParentGroup
            Depth             = $Depth
            IsDirect          = $IsDirect
            Name              = $Principal.Name
            LocalAccountsName = $localName
            SID               = $Principal.SID
            ResolvedNTAccount = $Principal.ResolvedNTAccount
            ADSIClass         = $Principal.ADSIClass
            ObjectClass       = $objClass
            PrincipalSource   = $src
            AdsPath           = $Principal.AdsPath
            IsGroup           = $Principal.IsGroup
            IsLocal           = $Principal.IsLocal
            IsAzureAD         = $Principal.IsAzureAD
            WhenQueried       = $when
        }) | Out-Null
}

foreach ($path in $directMemberPaths) {
    $p = Get-PrincipalFromAdsiPath -AdsPath $path

    # Always include direct members (including groups)
    Add-Row -Principal $p -IsDirect $true -ParentGroup $Group -Depth 0

    if ($Recurse -and $p.IsGroup -and $p.SID) {

        # If it's a local group (WinNT://COMPUTER/Group), expand via WinNT
        $isLocalGroupPath = ($p.AdsPath -match '^WinNT://\./') -or ($p.Name -like "$computer\*")

        if ($isLocalGroupPath) {
            if (-not $seenGroupSids.ContainsKey($p.SID)) {
                $seenGroupSids[$p.SID] = $true
                Write-Log -Level Info -Message "Expanding local nested group: $($p.Name) [$($p.SID)]"

                $nestedGroupPath = $p.AdsPath
                if (-not $nestedGroupPath) { continue }

                # Enumerate local group members
                try {
                    foreach ($childPath in (Get-AdsiMembersOfWinNTGroup -WinntGroupAdsPath $nestedGroupPath)) {
                        $cp = Get-PrincipalFromAdsiPath -AdsPath $childPath
                        if ($IncludeGroups -or (-not $cp.IsGroup)) {
                            Add-Row -Principal $cp -IsDirect $false -ParentGroup $p.Name -Depth 1
                        }
                    }
                }
                catch {
                    # ignore
                }
            }
        }
        else {
            # Domain group expansion using AccountManagement (recursive)
            Write-Log -Level Info -Message "Expanding domain nested group via AccountManagement: $($p.Name) [$($p.SID)]"
            foreach ($child in (Test-ExpandDomainGroupMembers -GroupSid $p.SID -Depth 0 -MaxDepth $MaxDepth -SeenGroupSids $seenGroupSids)) {
                if ($IncludeGroups -or (-not $child.IsGroup)) {
                    Add-Row -Principal $child -IsDirect $false -ParentGroup $p.Name -Depth 1
                }
            }
        }
    }
}

# Sort stable & return
$rows |
Sort-Object @{Expression = 'IsDirect'; Descending = $true }, @{Expression = 'Depth'; Ascending = $true }, @{Expression = 'Name'; Ascending = $true }

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDc9YUT+qFJ3JeO
# CvVT4MPjBu8DSYwq0blKdMvg3goIjaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCr0nxFavbR
# YdrJmeM27L/GAh9+EYaMhb/T9YvAB4N7ITANBgkqhkiG9w0BAQEFAASCAgA468MS
# aI/3X2/yGR1sndnjTzHkyxCsSwb0jy5ogQZQyi8CwjTe3CbisWnecks0WFRAdne0
# IYFuLwPK5ZVXAdPD4vcowa+546BOpPg9mb7oSycRiZA7jVKGblJrztN0akOQlPpu
# 7C7qPkLlDw3D2gPymqNq3DF106/tsa8spcNRDz6v4o690NJri7TU/n867jW5VN7S
# fSdGP51PYoZ0seLh6Sr+54LdcvggNnEyDAUqCiWJ1zjY7v72ri9lec3PsF2q4GbF
# SOtCNfM8aFEOHe0qXIgulljcXdVJOJPBs4/UTxw99MKesCY71y23oNa4ia7wq4pc
# B6sqmTZgybb0Io8PSegBWfMduidAWCaorLU9qhNuPDXaPaOr2UbTd1rSCNPPATxU
# swcO8uKTlHg8tFMGPzGugSN2FgTa1Kki6tqpEC99AGQltcfRR+YohRm04mPG+UgZ
# WTQe23JLlo7QYkGfOZD7peNKtOt4bJAfLUJW1ISOFEMyxinSIFUplz8ziuks0fIN
# jwY+qNFi2Nd8dHYaI40nIxUTXPWDmj83QHwZcM1VxCmprlGKiN6XN1IYMvOHGI+Q
# LizPgZNAPcIqHoLpM0/pozyF1x7ICj3cQwLGsdhtwLBz1iSoMVplC2TTjZYV+XfE
# U4eSg2IIA7BYP2evORxxuLl0Q91Lp1YH0+mNNqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMDMxNzAxMzBaMC8GCSqGSIb3DQEJBDEiBCBBH7NlUfCnGnov3ePY
# IXfdKUxMlWZgURJkbM8sMdMmbzANBgkqhkiG9w0BAQEFAASCAgCR8T9Kk2J+79ND
# fYFWpLkRsC+A2Tjyj2EKSdK8TXyGgow2r/vPfFTLjP2TlCK4ygvaHSknnCnBSUn3
# C5eRfE48m7ybWbV/xr4gUEp9WTAQEqwkckXMpBU7N8B3aBIMEXMiTBhyjvppB3q0
# WUKnNVbbh1JyAJVgUc8mPm1kG0V5qBT43iras1fMZgOIPdpPYvjIPp5Aid3Bc/j5
# B4nu++npL6BM8GN1yZAepw788GcoGN3Xglufn1u/J0wj3UbXSd2JnY2klm2TS+7W
# oOfvxFhsYZRHJcijqj0MZws6fcEuAQD/fJHoYPp0K6Ql33iOTvjH4wqxtLml5ocU
# i+WN8OLS6kVc2NMgnry5UEvqaHCYJyiYou2A3BgRx3Nn8G3NYNRtVbva7lSCNM1Y
# JR/8y8HDbNlhyEtCJvsfAk+qP0nXuPCDdY/jpiXBOzNEZSx18ovyuHfCT5SKLawh
# jYly6UXD/6eUp0+O9gQ/ik2tcfJRtd7BDdCo25yWhhuidLQ4dDAylnyDNRGNrhng
# 4zvu/ZptoedEUaDglEpaPA4ghyX/scLaHEuaFyf4JHHxrzVWGjJMw0NoHpDLW6G0
# HoROweC6cWONoRfDncZQXMZS7jWUG63Bh7hqO7Vno25TAeBIaH8rjrR2U3PAE3eX
# Gq917r8Ps50ynechm6WH2pQjl4HyPg==
# SIG # End signature block
