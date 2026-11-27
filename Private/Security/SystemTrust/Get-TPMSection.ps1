function Get-TPMSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Templates
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ----------------------------
    # Evidence container
    # ----------------------------
    $evidence = [ordered]@{
        Query      = [ordered]@{
            UsedGetTpm = $false
            UsedCim    = $false
        }
        GetTpm     = $null
        CimTpm     = $null
        Normalized = [ordered]@{
            Present        = $null
            Ready          = $null
            Enabled        = $null
            Activated      = $null
            Owned          = $null
            SpecVersion    = $null
            Manufacturer   = $null
            ManufacturerId = $null
            Firmware       = $null
        }
        Errors     = New-Object System.Collections.Generic.List[string]
    }

    # ----------------------------
    # Try Get-Tpm (preferred)
    # ----------------------------
    try {
        $cmd = Get-Command -Name Get-Tpm -ErrorAction SilentlyContinue
        if ($cmd) {
            $t = Get-Tpm -ErrorAction Stop
            $evidence.Query.UsedGetTpm = $true
            $evidence.GetTpm = $t

            # Normalize from Get-Tpm where possible
            $evidence.Normalized.Present = $t.TpmPresent
            $evidence.Normalized.Ready = $t.TpmReady
            $evidence.Normalized.Enabled = $t.TpmEnabled
            $evidence.Normalized.Activated = $t.TpmActivated
            $evidence.Normalized.Owned = $t.TpmOwned

            # Get-Tpm does NOT always expose SpecVersion; we’ll pull that via CIM if possible
            # Manufacturer fields are also better from CIM.
        }
    }
    catch {
        $evidence.Errors.Add("Get-Tpm failed: $($_.Exception.Message)")
    }

    # ----------------------------
    # Try CIM Win32_Tpm (manufacturer/spec details + fallback)
    # ----------------------------
    try {
        $ns = 'root\cimv2\security\microsofttpm'
        $cim = Get-CimInstance -Namespace $ns -ClassName Win32_Tpm -ErrorAction Stop

        if ($cim) {
            $evidence.Query.UsedCim = $true

            # Keep raw-but-trimmed detail; Win32_Tpm has methods & many fields
            $evidence.CimTpm = [pscustomobject]@{
                IsEnabled_InitialValue      = $cim.IsEnabled_InitialValue
                IsActivated_InitialValue    = $cim.IsActivated_InitialValue
                IsOwned_InitialValue        = $cim.IsOwned_InitialValue
                SpecVersion                 = $cim.SpecVersion
                ManufacturerId              = $cim.ManufacturerId
                ManufacturerIdTxt           = $cim.ManufacturerIdTxt
                ManufacturerVersion         = $cim.ManufacturerVersion
                ManufacturerVersionInfo     = $cim.ManufacturerVersionInfo
                PhysicalPresenceVersionInfo = $cim.PhysicalPresenceVersionInfo
            }

            # Normalize CIM hints (use only if we don't already have values from Get-Tpm)
            if ($evidence.Normalized.Enabled -eq $null -and $cim.IsEnabled_InitialValue -ne $null) { $evidence.Normalized.Enabled = [bool]$cim.IsEnabled_InitialValue }
            if ($evidence.Normalized.Activated -eq $null -and $cim.IsActivated_InitialValue -ne $null) { $evidence.Normalized.Activated = [bool]$cim.IsActivated_InitialValue }
            if ($evidence.Normalized.Owned -eq $null -and $cim.IsOwned_InitialValue -ne $null) { $evidence.Normalized.Owned = [bool]$cim.IsOwned_InitialValue }

            if ($evidence.Normalized.SpecVersion -eq $null -and $cim.SpecVersion) {
                # SpecVersion can be like: "2.0, 1.38" or "1.2"
                # We'll keep the raw string and parse major.minor best-effort later.
                $evidence.Normalized.SpecVersion = [string]$cim.SpecVersion
            }

            if ($cim.ManufacturerIdTxt) {
                $evidence.Normalized.Manufacturer = [string]$cim.ManufacturerIdTxt
            }

            if ($cim.ManufacturerId -ne $null) {
                $evidence.Normalized.ManufacturerId = [string]$cim.ManufacturerId
            }

            if ($cim.ManufacturerVersionInfo) {
                $evidence.Normalized.Firmware = [string]$cim.ManufacturerVersionInfo
            }
            elseif ($cim.ManufacturerVersion) {
                $evidence.Normalized.Firmware = [string]$cim.ManufacturerVersion
            }

            # If Get-Tpm wasn't available, infer "present" from CIM existence
            if ($evidence.Normalized.Present -eq $null) { $evidence.Normalized.Present = $true }
        }
    }
    catch {
        $evidence.Errors.Add("Win32_Tpm CIM unavailable: $($_.Exception.Message)")
    }

    # ----------------------------
    # If we still don't know presence, treat as unknown/unsupported signals
    # ----------------------------
    $present = $evidence.Normalized.Present
    $ready = $evidence.Normalized.Ready
    $enabled = $evidence.Normalized.Enabled
    $activated = $evidence.Normalized.Activated
    $owned = $evidence.Normalized.Owned
    $specRaw = $evidence.Normalized.SpecVersion
    $mfg = $evidence.Normalized.Manufacturer
    $fw = $evidence.Normalized.Firmware

    # Best-effort: parse spec major (1.2 vs 2.0)
    $specMajor = $null
    $specMinor = $null
    if ($specRaw) {
        # Grab first occurrence of number.number
        $m = [regex]::Match($specRaw, '(\d+)\.(\d+)')
        if ($m.Success) {
            $specMajor = [int]$m.Groups[1].Value
            $specMinor = [int]$m.Groups[2].Value
        }
        else {
            # Sometimes "1.2" might not appear as x.y; still handle digits
            $m2 = [regex]::Match($specRaw, '(\d+)')
            if ($m2.Success) { $specMajor = [int]$m2.Groups[1].Value }
        }
    }

    # ----------------------------
    # Evaluate health
    # ----------------------------
    $warnings = New-Object System.Collections.Generic.List[string]
    $criticals = New-Object System.Collections.Generic.List[string]

    # Decide "unsupported" if we couldn't query anything meaningful
    $queriedAnything = ($evidence.Query.UsedGetTpm -or $evidence.Query.UsedCim)

    if (-not $queriedAnything) {
        $state = 'Unsupported'
    }
    else {
        # Presence first
        if ($present -eq $false) {
            $state = 'Critical'
            $criticals.Add('TPM is not present')
        }
        elseif ($present -eq $null) {
            # We queried but can't confirm presence (rare); keep as Warning
            $state = 'Warning'
            $warnings.Add('TPM presence is unknown')
        }
        else {
            # Present == true
            # Readiness is the best overall signal; if unknown, use enabled/activated/owned for clues
            if ($ready -eq $false) {
                $warnings.Add('TPM is present but not ready')
            }
            elseif ($ready -eq $null) {
                $warnings.Add('TPM readiness is unknown')
            }

            if ($enabled -eq $false) { $warnings.Add('TPM is not enabled') }
            if ($activated -eq $false) { $warnings.Add('TPM is not activated') }

            # Owned is not always required for modern provisioning, but it can still be useful
            if ($owned -eq $false) { $warnings.Add('TPM is not owned') }

            # Version guidance
            if ($specMajor -ne $null) {
                if ($specMajor -lt 2) {
                    $warnings.Add("TPM spec version appears to be $specRaw")
                }
            }
            else {
                $warnings.Add('TPM spec version is unknown')
            }

            # Determine state:
            # - Critical only if no TPM
            # - Warning if present but not ready/low spec/unknown signals
            # - Healthy if present, ready, and TPM 2.0+
            $state = 'Healthy'

            $isTpm2OrHigher = ($specMajor -ne $null -and $specMajor -ge 2)
            $readyOk = ($ready -eq $true)

            if (-not $readyOk -or -not $isTpm2OrHigher) {
                $state = 'Warning'
            }

            # If we have a lot of negative signals, allow bump to Critical (optional policy knob)
            # Uncomment if you want:
            # if (($enabled -eq $false) -or ($activated -eq $false)) { $state = 'Critical' }
        }

        # If we already set critical above, keep it
        if ($criticals.Count -gt 0) { $state = 'Critical' }
        elseif ($warnings.Count -gt 0 -and $state -ne 'Critical') { $state = 'Warning' }
    }

    # ----------------------------
    # Build Condition/Context
    # ----------------------------
    $condition = switch ($state) {
        'Healthy' { 'TPM appears present and healthy' }
        'Warning' { 'TPM has warnings or incomplete trust signals' }
        'Critical' { 'TPM has critical findings' }
        'Unsupported' { 'TPM information is unavailable or unsupported' }
    }

    $presentTxt = if ($present -eq $true) { 'True' } elseif ($present -eq $false) { 'False' } else { 'Unknown' }
    $readyTxt = if ($ready -eq $true) { 'True' } elseif ($ready -eq $false) { 'False' } else { 'Unknown' }
    $enabledTxt = if ($enabled -eq $true) { 'True' } elseif ($enabled -eq $false) { 'False' } else { 'Unknown' }
    $activatedTxt = if ($activated -eq $true) { 'True' } elseif ($activated -eq $false) { 'False' } else { 'Unknown' }
    $ownedTxt = if ($owned -eq $true) { 'True' } elseif ($owned -eq $false) { 'False' } else { 'Unknown' }

    $specTxt = if ($specRaw) { $specRaw } else { 'Unknown' }
    $mfgTxt = if ($mfg) { $mfg } else { 'Unknown' }
    $fwTxt = if ($fw) { $fw } else { 'Unknown' }

    $issues = @()
    if ($criticals.Count -gt 0) { $issues += $criticals }
    if ($warnings.Count -gt 0) { $issues += $warnings }

    $contextParts = @(
        "Present=$presentTxt"
        "Ready=$readyTxt"
        "Enabled=$enabledTxt"
        "Activated=$activatedTxt"
        "Owned=$ownedTxt"
        "SpecVersion=$specTxt"
        "Manufacturer=$mfgTxt"
        "Firmware=$fwTxt"
    )

    if ($issues.Count -gt 0) {
        $contextParts += ("Findings=" + ($issues -join '; '))
    }

    $context = $contextParts -join '; '

    # ----------------------------
    # Return standardized section result
    # ----------------------------
    New-TrustSectionResult `
        -Name      'TPM' `
        -State     $state `
        -Condition $condition `
        -Context   $context `
        -Evidence  ([pscustomobject]$evidence) `
        -Templates $Templates
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBuT1LhbvtnLnT
# 4o+gP22sL8oEGNWJR65/XS4+B90lTKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDL
# pRtlfaiduPriRoyrDKdpyjbdIu6Bzi0j5zWsoI9bNjANBgkqhkiG9w0BAQEFAASC
# AYCA+E3Ck89Ew2W6j1HhirvtZNH7lJSeCZPRFmoCIKcGtU5fUpnPQjvc5ucKfnMV
# DhGKU6lpJHIoPG1sJqGAoZHSSX7dhXyN3epcqm06njZYX14OtwbOnt9hfgQTw2tl
# OKUZoFTRJsGUq3lLjin1sBE9M4TGnkkGiLrHFfc6hHmELZqyv6CqHHih1y4Di42q
# PHsAgozzSJ34FOJMPQMFSu+jod3qa9V0mDJrCWR6di12eB11oMxH2UsIwNEl4oIC
# C+z9kMUbYnlmGkI7+vLmMP7IGkknzv25Rj5FpabI1aVPbrgSrO5kBrACxUek/d7x
# L790r83ivgEePKhEOfMt9cwi43HfeG1zLode+AetvA+V9biHhDfKLsQpQIE6sc7m
# iHsgIAVDavet3Yq0HunDlvREDk70cF29Qf/DPT/3A/k/Pe6/hbQCSjUO3t7T0agC
# kJou04WvFHoCQqBigt7+QEgLm+/dvxuapSHlaXgp6RMOy/ZiL+HV7AOlpsMXv4go
# 0+OhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxMTQ5WjAvBgkqhkiG
# 9w0BCQQxIgQgmDvArE8X3opuZ8ml7CpJtNEHMD2eFFevkE6KvoFuq/0wDQYJKoZI
# hvcNAQEBBQAEggIAtSgUE6LhJJZMNCGUfV28IvGfvemnEDvL+NOexg0okuhRoobh
# gbz6yUxuIOakIPCp7twPgHz4m5TkSnpcZRaauXKJ0ofp5ycxP/nvf9A3yQyqV6y9
# yZ3JCaPSxnHLe8Q5n1XgO8lzPjfusbIgvw84INAtPeBzuMqjLXqSbVPlEhUCFFWR
# Vbz+QR8hnjwB2795tJ6HjBYB01IGoyPecKeg1w6pxFpByWfKgtcCFsMcc/fc1MNm
# HUE78Gs8taKCd0Z0Ke+bb65KN4+4V0lFwMg0J7rVYW4t0ErZuJaSDmFS3KNYhKnD
# E54CHSE0lnoU6zAQjOOiBC10e4fOAtRMefKi5Ppm5MPa5XWqbjS4v+WuVO1yED3N
# kSOmkJCOYaWUKx0I89kcgLE6mr2JvPxYm9kXJ87SlyrE0Za2LThLsQe5BhwNRIwN
# XFbCYxaCDsHATQ47ak7gW+CrjCpMTI7bYaSzFxP+37cyVX9gCb5Y14sDyS+NfVLh
# z7+wyXNTh0dM6iJlJil1g8/Kx+FGQWd7xSm83rf7WvGrROKQJz0PBdqrSgXnrb72
# P7Lm6Xu7oglfFmuQBiqRDO2qzMc5RrPzx1Xy3A1qd5KGeEtxdWHXroTJ5vw71vIO
# VoGsQecYG6pOxoiN2/+HeRSoPf0CDcJXSJkWlPTasX6aN/UjZHbdFA+zfpI=
# SIG # End signature block
