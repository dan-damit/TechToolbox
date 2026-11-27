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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYGOXh64C5TGMG
# 1rwqtjLPIa8wEWZfR9/el1Oq8y9uk6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDF
# gO7b/D1GjoX6ZBRknOCo5qDGPo/4lS8buDUyR7PddzANBgkqhkiG9w0BAQEFAASC
# AYBONqRxcmc3mD2L0nzduYyWOku9lyGgQ9G+8IaZsPmeIsbKnglskzxUtWkKCZbq
# 3wOzGvRSGNB5at/oiMOXw3Cs/vU/x15gq/CLugTUeSUZzljnDwA65UtFRbdo14pS
# H5OuOFSei0OBestSZyF3MeiuSLKEJrdigpQ7KoLH4uak35tD+0r+Oyncz/bkOJPH
# RIBitVKlSuVbqE+BmOVMhmVdoKbOyDKMhIdX4TLllYYM+hOpZN3Zi6nMLq1jOrs0
# zlh9qwSJUD6AmwLhILDkmFzV7e7niJVl+m9l6eopxH4gX6cbL277ceVSEunOie/N
# PkmYzt+5W99zWs9ILe7xmHMWYOMRwn5HZj8ByCCuKYpJljJJr78Hyxu9IFG40oAa
# WAnLpyHPi7CQTU+oUJ5hDqHXKrn3fmjv7rghvC/TNnhbw28E3faHr2Pdb/L7pliq
# s8/E15uBndcRDQElHIEsWAItBCcDCRbN2U4V4jPSSh1KLUZPllaO5aExbR5ZqGY9
# KTmhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxMTUwWjAvBgkqhkiG
# 9w0BCQQxIgQgjHDcISOD93SPd+XwbkS5nJgMJNsg1QZUsb55RMrARWowDQYJKoZI
# hvcNAQEBBQAEggIArAN3oX2f1e/4nZ1/OblpbTzraMLnVvwDdwJhjDRRPctvRo5l
# zO+Iw/NvzL6JoJvTMpj7JLOBwNOl3qjc83aXy2RgT/S58a1tB1VUyCdMdWwn0/gM
# bvyGK3IYRKHdJAuXDiEP56VcAbNE6vTLrCfHTj5R1I92ETjjFs/S6Ybk4SV/DxBU
# pXqg1+ljiay0Zcq07hxU8TYjalTztEuf2tOiQV/rDkPE1832lhHOncFibVK6MUkl
# YtLqcYtzCkWcHhzpYIYU2/jo56CxMv9W5vGYTmZBEFt4f4yeUyBCDqmx9xPZ3oO9
# tfJ5QMCcTkuFMw3wuqa1OLAxFTLGo/keGPGwbG3cVM5Pj4OCptxncEysFHAirM/G
# RfbDD2YEubjD/4F4+2ye/MYljr6LM2kSMxz4PAuee5LEOiEy6qdpQnxi0mmDtK6d
# PqYFE/UYnsTnJHF9jmg0Qp/cs598B4XZ9PUXuz7FqPe+44A2yUtK6ezHfbhO81t6
# 6pe3eEAUewOrkY/wTd6vayOkAplBJvTGqJqEp2kO8fqZAroA/fpLRACe5tHmF/K8
# 8pesXq3fOOhyTmvTOW9xC416Wlo1QLBrpko14fl/JP9LFy6pyBCAs8etzwt0y1oP
# bS0vlgDjic2n8wAcbMF7jdCUCtzCsepHSCLAW1p3/z4/euUGqkr/MafJSD8=
# SIG # End signature block
