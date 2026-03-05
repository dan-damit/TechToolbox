function Get-WindowsTrustSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Templates
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ----------------------------
    # Local helpers (internal)
    # ----------------------------
    function Convert-DeviceGuardServiceIds {
        param([int[]]$Ids)

        if (-not $Ids) { return @() }

        $map = @{
            1 = 'CredentialGuard'
            2 = 'HVCI'
            3 = 'SystemGuardSecureLaunch'   # best-effort label
            4 = 'SMMFirmwareMeasurement'    # best-effort label
            5 = 'KernelDMAProtection'       # best-effort label
        }

        foreach ($id in $Ids) {
            if ($map.ContainsKey($id)) { $map[$id] } else { "Unknown($id)" }
        }
    }

    function Get-RegistryTrustSignals {
        # Best-effort registry reads (do not throw)
        $out = [ordered]@{
            DeviceGuard = $null
            Lsa         = $null
            HVCI        = $null
        }

        try {
            $out.DeviceGuard = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -ErrorAction Stop
        }
        catch { $out.DeviceGuard = $null }

        try {
            $out.Lsa = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
        }
        catch { $out.Lsa = $null }

        try {
            $out.HVCI = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction Stop
        }
        catch { $out.HVCI = $null }

        # Return only the values we care about to avoid huge property bags
        [pscustomobject]@{
            VbsEnableVirtualizationBasedSecurity = $out.DeviceGuard.EnableVirtualizationBasedSecurity
            VbsRequirePlatformSecurityFeatures   = $out.DeviceGuard.RequirePlatformSecurityFeatures
            VbsHypervisorEnforcedCodeIntegrity   = $out.DeviceGuard.HypervisorEnforcedCodeIntegrity
            LsaCfgFlags                          = $out.Lsa.LsaCfgFlags
            HvciEnabled                          = $out.HVCI.Enabled
            HvciWasEnabledBy                     = $out.HVCI.WasEnabledBy
        }
    }

    function Get-BitLockerOsVolumeStatus {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$MountPoint
        )

        $result = [ordered]@{
            Supported            = $false
            MountPoint           = $MountPoint
            ProtectionStatus     = $null   # On/Off/Unknown
            VolumeStatus         = $null   # FullyEncrypted/FullyDecrypted/EncryptionInProgress/etc.
            EncryptionPercentage = $null
            LockStatus           = $null
            KeyProtectorCount    = $null
            Method               = $null
            Error                = $null
            Raw                  = $null
        }

        # Preferred: Get-BitLockerVolume (BitLocker module)
        $gblv = Get-Command -Name Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($gblv) {
            try {
                $v = Get-BitLockerVolume -MountPoint $MountPoint -ErrorAction Stop
                $result.Supported = $true
                $result.Method = 'Get-BitLockerVolume'
                $result.Raw = $v

                # Normalize common values
                $result.ProtectionStatus = [string]$v.ProtectionStatus
                $result.VolumeStatus = [string]$v.VolumeStatus
                $result.EncryptionPercentage = $v.EncryptionPercentage
                $result.LockStatus = [string]$v.LockStatus
                $result.KeyProtectorCount = @($v.KeyProtector).Count

                return [pscustomobject]$result
            }
            catch {
                $result.Error = $_.Exception.Message
                # fall through to CIM method
            }
        }

        # Fallback: Win32_EncryptableVolume methods (works even when BitLocker cmdlets absent)
        try {
            $ns = 'root\cimv2\security\microsoftvolumeencryption'
            $drive = $MountPoint.TrimEnd('\')
            $vol = Get-CimInstance -Namespace $ns -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction Stop

            if ($null -eq $vol) {
                $result.Error = "Win32_EncryptableVolume returned null for $drive"
                return [pscustomobject]$result
            }

            $result.Supported = $true
            $result.Method = 'Win32_EncryptableVolume'
            $result.Raw = $vol

            # Protection status (0=Off, 1=On)
            $prot = Invoke-CimMethod -InputObject $vol -MethodName GetProtectionStatus -ErrorAction Stop
            if ($prot -and $prot.ProtectionStatus -ne $null) {
                $result.ProtectionStatus = if ($prot.ProtectionStatus -eq 1) { 'On' } elseif ($prot.ProtectionStatus -eq 0) { 'Off' } else { "Unknown($($prot.ProtectionStatus))" }
            }

            # Conversion status includes percent encrypted + state
            $conv = Invoke-CimMethod -InputObject $vol -MethodName GetConversionStatus -ErrorAction Stop
            if ($conv) {
                # ConversionStatus: 0=FullyDecrypted,1=FullyEncrypted,2=EncryptionInProgress,3=DecryptionInProgress,4=EncryptionPaused,5=DecryptionPaused
                $cs = $conv.ConversionStatus
                $result.VolumeStatus = switch ($cs) {
                    0 { 'FullyDecrypted' }
                    1 { 'FullyEncrypted' }
                    2 { 'EncryptionInProgress' }
                    3 { 'DecryptionInProgress' }
                    4 { 'EncryptionPaused' }
                    5 { 'DecryptionPaused' }
                    default { "Unknown($cs)" }
                }
                $result.EncryptionPercentage = $conv.EncryptionPercentage
            }

            # Lock status (0=Unlocked, 1=Locked)
            try {
                $lock = Invoke-CimMethod -InputObject $vol -MethodName GetLockStatus -ErrorAction Stop
                if ($lock -and $lock.LockStatus -ne $null) {
                    $result.LockStatus = if ($lock.LockStatus -eq 0) { 'Unlocked' } elseif ($lock.LockStatus -eq 1) { 'Locked' } else { "Unknown($($lock.LockStatus))" }
                }
            }
            catch { }

            # Key protectors count (best effort)
            try {
                $kps = Invoke-CimMethod -InputObject $vol -MethodName GetKeyProtectors -Arguments @{ KeyProtectorType = 0 } -ErrorAction Stop
                if ($kps -and $kps.VolumeKeyProtectorID) {
                    $result.KeyProtectorCount = @($kps.VolumeKeyProtectorID).Count
                }
            }
            catch { }

            return [pscustomobject]$result
        }
        catch {
            $result.Error = $_.Exception.Message
            return [pscustomobject]$result
        }
    }

    # ----------------------------
    # Collect evidence
    # ----------------------------
    $evidence = [ordered]@{
        DeviceGuardSupported = $false
        DeviceGuard          = $null
        Registry             = $null
        BitLockerOS          = $null
        Errors               = @()
    }

    # 1) Device Guard / VBS / CG / HVCI via CIM (primary)
    $dg = $null
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName 'Win32_DeviceGuard' -ErrorAction Stop
        if ($dg) {
            $evidence.DeviceGuardSupported = $true

            $evidence.DeviceGuard = [pscustomobject]@{
                VirtualizationBasedSecurityStatus            = $dg.VirtualizationBasedSecurityStatus
                SecurityServicesConfigured                   = @($dg.SecurityServicesConfigured)
                SecurityServicesConfiguredNames              = Convert-DeviceGuardServiceIds -Ids @($dg.SecurityServicesConfigured)
                SecurityServicesRunning                      = @($dg.SecurityServicesRunning)
                SecurityServicesRunningNames                 = Convert-DeviceGuardServiceIds -Ids @($dg.SecurityServicesRunning)
                RequiredSecurityProperties                   = @($dg.RequiredSecurityProperties)
                AvailableSecurityProperties                  = @($dg.AvailableSecurityProperties)
                CodeIntegrityPolicyEnforcementStatus         = $dg.CodeIntegrityPolicyEnforcementStatus
                UserModeCodeIntegrityPolicyEnforcementStatus = $dg.UserModeCodeIntegrityPolicyEnforcementStatus
            }
        }
    }
    catch {
        $evidence.Errors += "DeviceGuard CIM unavailable: $($_.Exception.Message)"
        $evidence.DeviceGuardSupported = $false
        $evidence.DeviceGuard = $null
    }

    # 2) Registry trust signals (support + diagnostic context)
    $evidence.Registry = Get-RegistryTrustSignals

    # 3) BitLocker (OS volume)
    $osDrive = ($env:SystemDrive.TrimEnd('\') + '\')
    $evidence.BitLockerOS = Get-BitLockerOsVolumeStatus -MountPoint $osDrive

    # ----------------------------
    # Evaluate health
    # ----------------------------
    # Defaults (Unknown -> treated as warning at most unless BitLocker says otherwise)
    $vbsOn = $null
    $cgOn = $null
    $hvciOn = $null
    $bitOn = $null
    $bitState = $null
    $bitPct = $null

    if ($evidence.DeviceGuardSupported -and $evidence.DeviceGuard) {
        # VBS: status >= 1 means enabled/running (best-effort)
        $vbsOn = ($evidence.DeviceGuard.VirtualizationBasedSecurityStatus -ge 1)

        # Services running: 1=CredentialGuard, 2=HVCI (common mapping)
        $running = @($evidence.DeviceGuard.SecurityServicesRunning)
        $cgOn = $running -contains 1
        $hvciOn = $running -contains 2
    }
    else {
        # Registry fallback (best-effort signals)
        # VBS enabled if EnableVirtualizationBasedSecurity = 1 (common)
        if ($evidence.Registry.VbsEnableVirtualizationBasedSecurity -ne $null) {
            $vbsOn = ($evidence.Registry.VbsEnableVirtualizationBasedSecurity -eq 1)
        }

        # Credential Guard often indicated by LsaCfgFlags (0=off, 1=on w/ UEFI lock? 2=on w/out lock?)
        if ($evidence.Registry.LsaCfgFlags -ne $null) {
            $cgOn = ($evidence.Registry.LsaCfgFlags -in 1, 2)
        }

        if ($evidence.Registry.HvciEnabled -ne $null) {
            $hvciOn = ($evidence.Registry.HvciEnabled -eq 1)
        }
    }

    if ($evidence.BitLockerOS -and $evidence.BitLockerOS.Supported) {
        $bitOn = ($evidence.BitLockerOS.ProtectionStatus -eq 'On')
        $bitState = $evidence.BitLockerOS.VolumeStatus
        $bitPct = $evidence.BitLockerOS.EncryptionPercentage
    }

    $warnings = New-Object System.Collections.Generic.List[string]
    $criticals = New-Object System.Collections.Generic.List[string]

    # Interpret trust posture (baseline-oriented but not overly strict)
    if ($vbsOn -eq $false) {
        $warnings.Add("VBS is Off")
    }
    elseif ($vbsOn -eq $null) {
        $warnings.Add("VBS status unknown")
    }

    if ($cgOn -eq $false) {
        $warnings.Add("Credential Guard is Off")
    }
    elseif ($cgOn -eq $null) {
        $warnings.Add("Credential Guard status unknown")
    }

    if ($hvciOn -eq $false) {
        $warnings.Add("HVCI (Memory Integrity) is Off")
    }
    elseif ($hvciOn -eq $null) {
        $warnings.Add("HVCI status unknown")
    }

    # BitLocker: treat lack of OS protection as Critical when feature is supported
    if ($evidence.BitLockerOS -and $evidence.BitLockerOS.Supported) {
        if (-not $bitOn) {
            $criticals.Add("BitLocker protection is Off on OS volume ($($evidence.BitLockerOS.MountPoint))")
        }
        else {
            # If encrypting/paused etc, degrade to Warning
            if ($bitState -and $bitState -notin @('FullyEncrypted')) {
                $warnings.Add("BitLocker volume status is $bitState")
            }
            if ($bitPct -ne $null -and $bitPct -lt 100) {
                $warnings.Add("BitLocker encryption is $bitPct%")
            }
        }
    }
    else {
        # If not supported, don't penalize; just report
        if ($evidence.BitLockerOS -and $evidence.BitLockerOS.Error) {
            $warnings.Add("BitLocker status unavailable")
        }
    }

    # Determine overall state
    $state = 'Healthy'
    if ($criticals.Count -gt 0) { $state = 'Critical' }
    elseif ($warnings.Count -gt 0) { $state = 'Warning' }

    # If we truly cannot determine anything meaningful, mark Unsupported
    $nothingUsable =
    (-not $evidence.DeviceGuardSupported) -and
    (($vbsOn -eq $null) -and ($cgOn -eq $null) -and ($hvciOn -eq $null)) -and
    (-not ($evidence.BitLockerOS -and $evidence.BitLockerOS.Supported))

    if ($nothingUsable) {
        $state = 'Unsupported'
    }

    # ----------------------------
    # Build Condition/Context
    # ----------------------------
    $condition = switch ($state) {
        'Healthy' { 'Windows trust posture appears healthy' }
        'Warning' { 'Windows trust posture has warnings' }
        'Critical' { 'Windows trust posture has critical findings' }
        'Unsupported' { 'Windows trust posture signals are unavailable or unsupported' }
    }

    $vbsTxt = if ($vbsOn -eq $true) { 'On' } elseif ($vbsOn -eq $false) { 'Off' } else { 'Unknown' }
    $cgTxt = if ($cgOn -eq $true) { 'On' } elseif ($cgOn -eq $false) { 'Off' } else { 'Unknown' }
    $hvciTxt = if ($hvciOn -eq $true) { 'On' } elseif ($hvciOn -eq $false) { 'Off' } else { 'Unknown' }

    $bitTxt = 'Unavailable'
    if ($evidence.BitLockerOS -and $evidence.BitLockerOS.Supported) {
        $bitTxt = "OS=$($evidence.BitLockerOS.ProtectionStatus)"
        if ($evidence.BitLockerOS.VolumeStatus) { $bitTxt += " ($($evidence.BitLockerOS.VolumeStatus))" }
        if ($evidence.BitLockerOS.EncryptionPercentage -ne $null) { $bitTxt += " $($evidence.BitLockerOS.EncryptionPercentage)%" }
    }

    $issues = @()
    if ($criticals.Count -gt 0) { $issues += $criticals }
    if ($warnings.Count -gt 0) { $issues += $warnings }

    $contextParts = @(
        "VBS=$vbsTxt"
        "CredentialGuard=$cgTxt"
        "HVCI=$hvciTxt"
        "BitLocker=$bitTxt"
    )

    if ($issues.Count -gt 0) {
        $contextParts += ("Findings=" + ($issues -join '; '))
    }

    $context = $contextParts -join '; '

    # ----------------------------
    # Return standardized section result
    # ----------------------------
    New-TrustSectionResult `
        -Name      'WindowsTrust' `
        -State     $state `
        -Condition $condition `
        -Context   $context `
        -Evidence  ([pscustomobject]$evidence) `
        -Templates $Templates
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYGOXh64C5TGMG
# 1rwqtjLPIa8wEWZfR9/el1Oq8y9uk6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDFgO7b/D1G
# joX6ZBRknOCo5qDGPo/4lS8buDUyR7PddzANBgkqhkiG9w0BAQEFAASCAgB2bNs3
# ArTlBjBa/QZN2pcniqPgXZkz6jL+BMCZt4ZrUznoHtGXPx2mWktRCtisTqPwr6I9
# lIyHFJj4d72wPLQFTDZ9MTZfC8jK7D9DU3aJwBIyJMmatbusdfwBveSzNXexqVaM
# TLCz0qrH1a1Nico6yl975jLSBo5hWSoZ7RzdWCwBhmM2yBZSefXO3jj4y8BK/zc1
# dHf1qAYcnwVG+bfQthRg0mSvSos6iG/OKzH/40VSalto8nTOOV+3GCk0J5m1nupl
# ymRV4Mp03hx0Lag2KKEH28UraKHrAdoIVKPsMxa59Cyk4mbc4PvxLK2UUvGCokI6
# /7N7NIr4t+VDbXQemCT75o+wRqVskdwtbbxK3LMdjPPm3+5CbvFKK/z6NSoAVWHl
# Vybrjii2JtUtfhK2jH1uMBf0lqOLPkUbaB2cAApduF3vUBaZQlaFLVIo3/G95cCf
# +JlBSSetnL78Xa408qBfCwD/qPavHFYcE3vVVsPECAO6W56eEZ7JjoPcnYcYUbsV
# gleArRVhxZaQlRdNwRC1uOKoZZggv/91otp3qwAY1MxunlDBWh73l/B97baa/C6H
# 3/yo0IQwfGQQQ1HazFOXDP0p1ReQHtgIc8CYOGSd7d104eQDSXEk87qXyRrjxWvf
# kQ5xGyc9NY6rsqSNkuIKoSmdRe0uGQJn0Ooi0aGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMDUyMTM5NTRaMC8GCSqGSIb3DQEJBDEiBCCQ9gRqx/6ZGykr4msh
# sNfWIQOyhNmdvMoHX8Rp1yXsujANBgkqhkiG9w0BAQEFAASCAgC2NLmqoLNOo0ud
# gKrgio/lcYuW40sDIvgBPGiXjLdUE1NhNjIIv4BE10Iahe4w1xOmCBIxQY/NcRFl
# BCdiO29lpeVJNJQLqYb6EEzB+DgG8szRreBl6dkcm5YZE2rjXyW+byXX/kWXdsXr
# 7FNugqOlfSX3CuuZuUJ9785n1oQ+hXRGkd5JmL06bnOen3Yr2ltoXPmv9IW+mrsr
# IP/vr1/XUdKeYpvecBvDi75I4+K992MPnH1dBk2Cj10zpOWokbgHUfu3wOUYFXpc
# pKDmIoA0Xq6lIw17Kg+YfcG2SdDVLIwUtKBouxxvOFSWS5sOB6Hzx6IHFagQoZid
# FiGK64MfyuJLur7RxEe/rWdp+NDr6S35jv9ZBfm74GZ0YpigMnw6AhrlH3vCiL+L
# OeT4sRaLZQWdcw+MUKuRwVYajfvi1rUHYn2gystYeDd1WjkQ388zDGOVldXN9mG8
# KGqecsye7fkjIVlNN53KL+lResWdO3IwOwbUrg1yraU4MtsmI2yifca/+sEGPa36
# t2NbwCqGXz/4lMXi1zzWZSRv1jHtPGBmVJTpvMFtznAoSDeUuGZsnLen1Euo9oVz
# ufAYtW3fCg57KCljgQEi58zeG1doGuoMspPycaZATBjmpkBzahDL0zBPyVyszdv3
# CKlucG5m3R26gmQ017r1Sbimx4UbIA==
# SIG # End signature block
