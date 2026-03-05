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
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnrWxM7cAd04C7
# YBnacfhlIyS96lPl1xWG8l1vOcUxiaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCUJmerfl9j
# az0SBS6i9CoDUvheF0h3hD85d4gomYPfQTANBgkqhkiG9w0BAQEFAASCAgAOdBIv
# ENvfLTQbRUrQSLZELBYunxn0W3mmEes3jqqytHejAi3OPoWuAKQdET/p16Xfqe5L
# Kd3Cr49JHAUMpVAy9SL7fkNNYF86GMe4CNsaXVqhm52pk1BhhV/KGe7HF6tyJTWC
# t8uZv1n6FGzwl2d1PjxaAl/EOoep0OZeoRhDEGPhOHMzAtUc5NsmXOe+UFjg77Hk
# gaGVPf4ye3nhc+a3ald7gi6LHvFSOdXkabkoCdEXBg7uREPQb3yupOrAkIMLsu8v
# nvMna3ANMY752hDPjWgdP72rjDIcP1GLJ3NE3aRYmn1Tg+D9nx+YFqdcac+qWwzZ
# w80bsf3NVX3FbocQ2QGEHQu9nVahc8LJyiE4Tid7D9e4CqdeMzjLm2ue12kqQ+nh
# K0jjT94W0LhoJBJUjiPNs28Fl3Qkx+TMUq+rhDtstSTzQa8b4vY11FGedYwoG+55
# fpHNLOLK9FjdvSRMLr/UWTR3rUqY1cZFj5eYuQapzwsYonn7ekdZ5xGV2pPGPaLI
# ys4zy8GlT4T0Zzoj5PxVCgGpD6FJnE9Pg6dEI/ArHZpTEDHzomUayC4DCxt4ZEsP
# oSXnHJOkU0PQaX1/iORaFWc8aN/Uj+HhYmR38i4P8kX5qgvD+UiRIuVRURSaYVYn
# BBislIdwwi5uE9vmasSi7eR1UD0+ZQYDRCm/VaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAzMDUyMTM5NTRaMC8GCSqGSIb3DQEJBDEiBCDuZCFf/GYFPW3REj1v
# AKwzoiWHh03zyBxPuAQYfXkWkzANBgkqhkiG9w0BAQEFAASCAgCHkQmxnj62FThw
# lH+eVuL8M+0PBhgxTx57y7GsXbj5oKwRoQ9QsRIA63UHc3ujnYJUB7Q4L3TiIb92
# lqV975GCcLV9vxGLr5QnsllgBpUWABdrwlZ/L1BnN7wonVpYbO/gtQ+SOhxQosJu
# tc7KIG5UzliO8xsm2sOYXl00aYSyL+ObsUIMe+ChPekfBydTzY+6C0iUiQ98Web7
# lUNVk7RNHcQpCMf+qd5dKtdP5ZocLfTltRT6yvSkefq118Fku549+TPUb8HzHXSb
# 7dEY0HEamAqRhbGfpJuIg7/50QfAraR+Z+xnYjFvZssuAOks59NxM4YllJfdLAg/
# ZrTadZnQlHWKoK8SMjNuv7EKFPd+thNHNu/IpSkAtswYGCZ7yoY3nmnWF+FJOTVT
# FS5Q6399yyX9JgCGYLcAOpBHzwULcowYKiD9JQkFY6tNSHaaHmzAXsXfsgHGOUfR
# 39DuVXv/MNpAN+OWa7eW5DGlkHY43X6zsWsoQf9pjpC4jMEYY72wv669RqQw1lUb
# xZv/ScHLrX6sW4R3tO89iCujqIgvCXaociQyh7/CBaagVEgeGiEj8Q7en4Kc5Lb5
# Z0FSh0XZP9kHid/8MFR73W+sS4GrHF3+hiadccByQFn4x0HQ0HkYAKEYd0g4Gc1k
# qDTO8+TxECz9TyO9mty2O04fyjwAAQ==
# SIG # End signature block
