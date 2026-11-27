function Get-SystemSection {
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
    function Convert-ToIsoOrNull {
        param([object]$DateTimeValue)
        if ($null -eq $DateTimeValue) { return $null }
        try {
            # CIM datetimes are already [datetime] in PS most of the time
            return ([datetime]$DateTimeValue).ToString('o')
        }
        catch {
            return $null
        }
    }

    function Convert-UptimeToString {
        param([TimeSpan]$Uptime)
        if ($null -eq $Uptime) { return $null }
        # e.g. "3d 04h 12m 09s"
        '{0}d {1:00}h {2:00}m {3:00}s' -f $Uptime.Days, $Uptime.Hours, $Uptime.Minutes, $Uptime.Seconds
    }

    function Get-FirmwareTypeInfo {
        # Best-effort firmware detection: registry PEFirmwareType (1=BIOS,2=UEFI)
        $out = [ordered]@{
            FirmwareType   = 'Unknown'   # UEFI | BIOS | Unknown
            PEFirmwareType = $null
            Source         = $null
            Error          = $null
        }

        try {
            $fw = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction Stop
            $pe = $fw.PEFirmwareType
            $out.PEFirmwareType = $pe
            $out.Source = 'Registry:HKLM\SYSTEM\CCS\Control\PEFirmwareType'

            $out.FirmwareType = switch ($pe) {
                2 { 'UEFI' }
                1 { 'BIOS' }
                default { 'Unknown' }
            }
        }
        catch {
            $out.Error = $_.Exception.Message
        }

        [pscustomobject]$out
    }

    function Get-VirtualizationHints {
        param(
            [object]$ComputerSystem,
            [object[]]$Processors
        )

        $hints = [ordered]@{
            HypervisorPresent    = $null
            VMVendorHint         = $null
            ModelHint            = $null
            ManufacturerHint     = $null
            ProcessorVirtCapable = $null
        }

        try {
            if ($ComputerSystem -and ($ComputerSystem.PSObject.Properties.Name -contains 'HypervisorPresent')) {
                $hints.HypervisorPresent = [bool]$ComputerSystem.HypervisorPresent
            }
        }
        catch { }

        try {
            if ($ComputerSystem) {
                $m = [string]$ComputerSystem.Model
                $man = [string]$ComputerSystem.Manufacturer
                $hints.ModelHint = $m
                $hints.ManufacturerHint = $man

                # Rough VM vendor hints
                $text = ($man + ' ' + $m).ToLowerInvariant()
                if ($text -match 'vmware') { $hints.VMVendorHint = 'VMware' }
                elseif ($text -match 'virtualbox|oracle') { $hints.VMVendorHint = 'VirtualBox' }
                elseif ($text -match 'hyper-v|microsoft corporation virtual') { $hints.VMVendorHint = 'Hyper-V' }
                elseif ($text -match 'qemu|kvm') { $hints.VMVendorHint = 'KVM/QEMU' }
                elseif ($text -match 'xen') { $hints.VMVendorHint = 'Xen' }
            }
        }
        catch { }

        try {
            if ($Processors) {
                # If any processor reports virtualization firmware enabled/capable
                $cap = $false
                foreach ($p in $Processors) {
                    if ($p.PSObject.Properties.Name -contains 'VirtualizationFirmwareEnabled') {
                        if ($p.VirtualizationFirmwareEnabled -eq $true) { $cap = $true }
                    }
                }
                $hints.ProcessorVirtCapable = $cap
            }
        }
        catch { }

        [pscustomobject]$hints
    }

    # ----------------------------
    # Evidence container
    # ----------------------------
    $evidence = [ordered]@{
        ComputerName   = $env:COMPUTERNAME
        Timestamp      = (Get-Date).ToString('o')

        OS             = $null
        Computer       = $null
        BIOS           = $null
        CPU            = $null
        Memory         = $null
        Firmware       = $null
        Network        = $null
        Virtualization = $null

        Errors         = New-Object System.Collections.Generic.List[string]
        Query          = [ordered]@{
            UsedCim = $true
        }
    }

    # ----------------------------
    # Collect info (best-effort per component)
    # ----------------------------
    $os = $null
    $cs = $null
    $bios = $null
    $cpu = $null

    # OS
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $evidence.OS = [pscustomobject]@{
            Caption          = $os.Caption
            Version          = $os.Version
            BuildNumber      = $os.BuildNumber
            OSArchitecture   = $os.OSArchitecture
            InstallDate      = Convert-ToIsoOrNull $os.InstallDate
            LastBootUpTime   = Convert-ToIsoOrNull $os.LastBootUpTime
            Locale           = $os.Locale
            MUILanguages     = @($os.MUILanguages)
            SystemDrive      = $os.SystemDrive
            WindowsDirectory = $os.WindowsDirectory
        }
    }
    catch {
        $evidence.Errors.Add("Win32_OperatingSystem query failed: $($_.Exception.Message)")
    }

    # Computer system
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $evidence.Computer = [pscustomobject]@{
            Manufacturer             = $cs.Manufacturer
            Model                    = $cs.Model
            SystemType               = $cs.SystemType
            Domain                   = $cs.Domain
            PartOfDomain             = $cs.PartOfDomain
            Workgroup                = $cs.Workgroup
            UserName                 = $cs.UserName
            TotalPhysicalMemoryBytes = $cs.TotalPhysicalMemory
            TotalPhysicalMemoryGB    = if ($cs.TotalPhysicalMemory) { [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2) } else { $null }
        }
    }
    catch {
        $evidence.Errors.Add("Win32_ComputerSystem query failed: $($_.Exception.Message)")
    }

    # BIOS
    try {
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        $evidence.BIOS = [pscustomobject]@{
            Manufacturer       = $bios.Manufacturer
            SMBIOSBIOSVersion  = $bios.SMBIOSBIOSVersion
            BIOSVersion        = @($bios.BIOSVersion)
            SerialNumber       = $bios.SerialNumber
            ReleaseDate        = Convert-ToIsoOrNull $bios.ReleaseDate
            SMBIOSMajorVersion = $bios.SMBIOSMajorVersion
            SMBIOSMinorVersion = $bios.SMBIOSMinorVersion
        }
    }
    catch {
        $evidence.Errors.Add("Win32_BIOS query failed: $($_.Exception.Message)")
    }

    # CPU
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $evidence.CPU = @(
            $cpu | ForEach-Object {
                [pscustomobject]@{
                    Name                                    = $_.Name
                    Manufacturer                            = $_.Manufacturer
                    NumberOfCores                           = $_.NumberOfCores
                    NumberOfLogicalProcessors               = $_.NumberOfLogicalProcessors
                    MaxClockSpeedMHz                        = $_.MaxClockSpeed
                    VirtualizationFirmwareEnabled           = if ($_.PSObject.Properties.Name -contains 'VirtualizationFirmwareEnabled') { $_.VirtualizationFirmwareEnabled } else { $null }
                    SecondLevelAddressTranslationExtensions = if ($_.PSObject.Properties.Name -contains 'SecondLevelAddressTranslationExtensions') { $_.SecondLevelAddressTranslationExtensions } else { $null }
                }
            }
        )
    }
    catch {
        $evidence.Errors.Add("Win32_Processor query failed: $($_.Exception.Message)")
    }

    # Firmware info (UEFI/BIOS)
    try {
        $fwInfo = Get-FirmwareTypeInfo
        $evidence.Firmware = $fwInfo
    }
    catch {
        $evidence.Errors.Add("Firmware detection failed: $($_.Exception.Message)")
    }

    # Network summary (lightweight, informational)
    try {
        $ip = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $evidence.Network = @(
            $ip | ForEach-Object {
                [pscustomobject]@{
                    Description    = $_.Description
                    MACAddress     = $_.MACAddress
                    DHCPEnabled    = $_.DHCPEnabled
                    IPAddress      = @($_.IPAddress)
                    DefaultGateway = @($_.DefaultIPGateway)
                    DNSServers     = @($_.DNSServerSearchOrder)
                }
            }
        )
    }
    catch {
        # Not critical to trust; keep best-effort
        $evidence.Errors.Add("Network summary query failed: $($_.Exception.Message)")
    }

    # Virtualization hints
    try {
        $evidence.Virtualization = Get-VirtualizationHints -ComputerSystem $cs -Processors $cpu
    }
    catch {
        $evidence.Errors.Add("Virtualization hints failed: $($_.Exception.Message)")
    }

    # ----------------------------
    # Derive uptime
    # ----------------------------
    $uptime = $null
    $uptimeText = $null
    $lastBootIso = $null

    try {
        if ($os -and $os.LastBootUpTime) {
            $lastBoot = [datetime]$os.LastBootUpTime
            $lastBootIso = $lastBoot.ToString('o')
            $uptime = (Get-Date) - $lastBoot
            $uptimeText = Convert-UptimeToString -Uptime $uptime

            # Add to OS evidence if present
            if ($evidence.OS) {
                $evidence.OS | Add-Member -NotePropertyName 'Uptime' -NotePropertyValue $uptimeText -Force
            }
        }
    }
    catch {
        $evidence.Errors.Add("Uptime calculation failed: $($_.Exception.Message)")
    }

    # ----------------------------
    # Determine section state (informational)
    # ----------------------------
    $collectedCore =
    ($null -ne $evidence.OS) -or
    ($null -ne $evidence.Computer) -or
    ($null -ne $evidence.BIOS)

    $state = if (-not $collectedCore) { 'Unsupported' }
    elseif ($evidence.Errors.Count -gt 0) { 'Warning' }
    else { 'Healthy' }

    $condition = switch ($state) {
        'Healthy' { 'System information collected successfully' }
        'Warning' { 'System information collected with some warnings' }
        'Unsupported' { 'System information could not be collected' }
        default { 'System information collected' }
    }

    # ----------------------------
    # Build Context string (human-readable summary)
    # ----------------------------
    $osCaption = $evidence.OS.Caption
    $osVer = $evidence.OS.Version
    $osBuild = $evidence.OS.BuildNumber
    $arch = $evidence.OS.OSArchitecture

    $man = $evidence.Computer.Manufacturer
    $model = $evidence.Computer.Model
    $dom = if ($evidence.Computer.PartOfDomain) { $evidence.Computer.Domain } else { $evidence.Computer.Workgroup }

    $fwType = $evidence.Firmware.FirmwareType
    if (-not $fwType) { $fwType = 'Unknown' }

    $serial = $evidence.BIOS.SerialNumber
    $serialTxt = if ($serial) { $serial } else { 'Unknown' }

    $ramGB = $evidence.Computer.TotalPhysicalMemoryGB

    $ctxParts = New-Object System.Collections.Generic.List[string]
    if ($osCaption) { $ctxParts.Add("OS=$osCaption") }
    if ($osVer -or $osBuild) { $ctxParts.Add("Version=$osVer (Build $osBuild)") }
    if ($arch) { $ctxParts.Add("Arch=$arch") }

    if ($man -or $model) { $ctxParts.Add("Model=$man $model") }
    if ($ramGB -ne $null) { $ctxParts.Add("RAM=${ramGB}GB") }
    $ctxParts.Add("Serial=$serialTxt")

    if ($dom) { $ctxParts.Add("Join=$dom") }
    $ctxParts.Add("Firmware=$fwType")

    if ($lastBootIso) { $ctxParts.Add("LastBoot=$lastBootIso") }
    if ($uptimeText) { $ctxParts.Add("Uptime=$uptimeText") }

    # Note warnings count briefly
    if ($evidence.Errors.Count -gt 0) {
        $ctxParts.Add("Warnings=$($evidence.Errors.Count)")
    }

    $context = ($ctxParts -join '; ')

    # ----------------------------
    # Return standardized section result
    # ----------------------------
    New-TrustSectionResult `
        -Name      'System' `
        -State     $state `
        -Condition $condition `
        -Context   $context `
        -Evidence  ([pscustomobject]$evidence) `
        -Templates $Templates
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnrWxM7cAd04C7
# YBnacfhlIyS96lPl1xWG8l1vOcUxiaCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCU
# Jmerfl9jaz0SBS6i9CoDUvheF0h3hD85d4gomYPfQTANBgkqhkiG9w0BAQEFAASC
# AYBWwGrKi0cSA/HDM9Jyv0fy49K5z54dX/7gN6yOfe29Otb84JESJQ+mDAc7C7zM
# JD5kGd+sdQrHaIxo26TMFDB0cZrfEGQAPoAgcvvpUF8CZQK2oZ5FhlCnRWEzb4dL
# YNkVfxfRHh11bGz1RZ8y+R1G/I67R1KRoEIuUzEDL700mX/c8/JAPgWRD4USUjsS
# W6x/T1QPrmVZKfO53wTmD5772lDapU+2RxzHxTWgWIjv3QRPhK8cYlykTIgkkG7v
# bFg4dIW8xMPTzvCkKL/K8ij2nH9KaHsS6E85lSlLq4hUPH9U4hSZbySKlGmoFiJS
# GxvNMBXtPuvjjHeJNcw+QDIKNgpXkbWO/Yg3bQHHtJVcp5HASg5acD8QuVNygJvg
# 7WaaLpaYVqiYKW4+buhRiuX1WZWMNmW3+C1oK5AF0EDiUXzuljfRwOnxWAKzIu26
# LUUafaWQra6/jAkjNSgoPCOEz5RfBQipQzzT1/HnO5Sw1eSc7x21q/+cn3j40IBa
# eKWhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxMTQ3WjAvBgkqhkiG
# 9w0BCQQxIgQgrWXwluNMmh/w8LjlOmG3tzsGwuo99ZYbbXWCxtmKObwwDQYJKoZI
# hvcNAQEBBQAEggIAqkiikyPjPFRO02HMYQgWVQP+hUiq3Ii29Ka+zDJ4lfBwb1Wk
# vI6HyanxhQNFKQusD1YS886P4u63Of/8SbhrBHvsRnng7trkwGhdSwGsKWSepI+6
# wVAZSI2qbKIFGRMEo4s42e3jfSuabl07S+lJSWBE1AcNiMCJoejpr+quELufkm0a
# yT4NsvkvDStqrH+R1SAAqdylJ6Q/+clyYWCPyF0LsWaG1W98fva/dmjhP4j2+pAB
# VVfVASDSq5k2sBRiuRDMfre+rA24Prd/jUzKGlS4/1PH9fzyAhVbuylpwDb8aiz8
# 2WKkw6x9fTvRH/FpVQGZyXGe2cWdafzommtfpg661lxiJegnYoQaKv5xEoQD1QAj
# BhTlA1wSCH6kcBDZKnaQiFxEh2igIP9bOlL9XKeUImaaag8phwxbQM+1tvPtCV1h
# jlobMv7U3ITI6bPPdcj4H8TM4LG05STbS7YB0yfE0YnSfmUwpaNugvwPgdOvxezx
# 2AwQWgpoMm/0gQJNeD7qZc/tP+nifi5SI678T0xq0OEWxDazv1mA6a5bSYtrFYxz
# jBV+GuChKMqXGQUHqxcMtqjtTz1C/rAdkeAiyCwqKSmjM8QIdkDs5nV7CjF4Pp5Q
# SzYmB9CkfvXtDfo6ncUhmFrd6pL1ItiMGcw+b6S2oTCP7PwTSONwJkyixvs=
# SIG # End signature block
