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
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBuT1LhbvtnLnT
# 4o+gP22sL8oEGNWJR65/XS4+B90lTKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDLpRtlfaid
# uPriRoyrDKdpyjbdIu6Bzi0j5zWsoI9bNjANBgkqhkiG9w0BAQEFAASCAgAXw+s8
# 3HzvhFI4fdfeVy+zVzjNKNkGk9UDJ5VuNAc0susWRJ/746dM3gnPtq6kKhi2kkuq
# E7h7EEBTL2aYeIwKadg6Xad8uLi7Swqr1n07Tn4wEbFDFQgLt5DqnoGkSm81xqje
# wB4FWEx3pDcEqVX0NMitgnVkn5DPwUz0w6YHJwnZnVmW4pvThehq4Ua+Pm154mvD
# 3o/SKteGFH+BIZp53JhG0XKOxaARd7VYT/jh1Nl2UFgImiARe/A/+cieUh0bkUFo
# XK9ehR/mmEgL2O4hHMEAElcCJg9+KhSKh1864i0ZnkaM72n20ckoaVO/JZWaWaj3
# U7dG0H7c6/68lU0iOoCeat4szv4bz3V7y6haFqq8Pd11bDuGYfmUM7DLEvbYwDkU
# zSNyBOAEgC1O9KZYccLU47Xb8BxAk7BHS1ZwlW+RdqC3yBfEUxmrCnRW1oEVDcwx
# BfEmPxaTGdl1pUgaMtYbfYdDYLpTuA99zbMJe6tk5CMhiG959DhndXWDYcpZLsGb
# ZqcacojMucel20OMHDAirDjXYX2XqNmZydCvgEvxrImBH/affuVUfbmDubvxmCaO
# MDs9FRziWernv6UlS+fdZaAwRReIRmuUP82JscLNyuDIUajVyuh3y7Vv3zPqgbm4
# 8B1VGqD7hEnyRyUX67m0M/goNwpeeLcQqDs2aqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMDUyMTM5NTRaMC8GCSqGSIb3DQEJBDEiBCDE7J+1HhT/kokp5W58
# FOx8zhSMURR7ntHqquB7tFB6mzANBgkqhkiG9w0BAQEFAASCAgBEtKrp9IdJBmBY
# lhuunWYZq7PLmOy/OgRMzU5xI9+yQMYprhHb46aawLnreLzFCvzLElP789hGoLJ+
# hpIgaoGbQczXsnl5+4CyIBC4xcKdiehqihdr6x7oW1T/G231spvpwfvUIf5HupBp
# 1LukFbfR6Ij0FSJHmVHqUwMm0VcATOna0mlJhws+7tollMzZkBg5fiZHijeUein/
# HW9UCQXyh73ae6zXQ/YlojSiedWyumQoytzeZB3E/Kk7sHoQM+2c7IEPLdivd1gx
# sGAD4UsokaMZRaZR4hzpLsH4HrXVqXHsSmygZbb6fv8mwKxurrBaR//vGQ9p2LkY
# 3m97/ztHtJ9anhehntMEAmLzEKjU7n5p0j1kuqlDCy8UyY8iSmZ/TNmUWwDtLjFz
# os1Tq4n97TPHrXUv8eKg10RXjud4q5AxD8iXVAFEID9eR7s5NFuJ+RHwRezHa20g
# LrYnhHWYiC090wqjwzbeS2+aqn2igUq0Wn3fbonns9e59hogDuBq/S7C9Qqyozd+
# fTMAev+DqWnv1SpX/MiZrY5RarKbPCoaTPivWdhNiMmRWymkdVJPRtM9groMjO5t
# mNmznKiWm+SLNMpL9wFXbjzVClASLUFt42nFWUj6JoQYeXM7nowvxIZeOGN8vOdg
# m5VsOZVnl4vFYwO7yBYou2U2BKWtWw==
# SIG # End signature block
