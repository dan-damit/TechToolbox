
function Remove-Printers {
    <#
    .SYNOPSIS
        Removes all printers from the system, with optional removal of ports,
        drivers, and per-user mappings.
    .DESCRIPTION
        Uses Win32_Printer (CIM) to remove queues after resetting the spooler
        and clearing the spool folder. Optionally removes TCP/IP ports and
        printer drivers. Adds fallbacks for provider hiccups and frees common
        process locks (splwow64/PrintIsolationHost). Can also remove per-user
        connections across all profiles.
    .PARAMETER IncludePorts
        Also remove TCP/IP printer ports (non-standard).
    .PARAMETER IncludeDrivers
        Also remove printer drivers (after queues are gone).
    .PARAMETER Force
        Best-effort forced cleanup of driver packages via pnputil if standard
        removal fails.
    .PARAMETER AllUsers
        Attempt to remove per-user network printer connections for all user
        profiles.
    .PARAMETER PassThru
        Output a summary object with counts and failures.
    .EXAMPLE
        Remove-Printers -IncludePorts -IncludeDrivers -Force -AllUsers -PassThru
    .EXAMPLE
        Remove-Printers -WhatIf
    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Remove-Printers
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [switch] $IncludePorts,
        [switch] $IncludeDrivers,
        [switch] $Force,
        [switch] $AllUsers,
        [switch] $PassThru
    )

    Begin {
        # Load dependencies
        Initialize-TechToolboxRuntime
        $cfg = $script:cfg
        $defs = $cfg.defaults
        $log = $cfg.logging
        $paths = $cfg.paths

        # Counters
        $removedPrinters = 0; $failedPrinters = @()
        $removedPorts = 0; $failedPorts = @()
        $removedDrivers = 0; $failedDrivers = @()
        $removedUserMaps = 0; $failedUserMaps = @()

        Write-Log -Level Info -Message "=== Remove-Printers started ==="
    }

    Process {
        # Track original spooler state
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        $spoolerWasRunning = $false
        if ($spooler) { $spoolerWasRunning = $spooler.Status -eq 'Running' }

        # 1) Stop spooler and clear jobs
        if ($PSCmdlet.ShouldProcess("Spooler", "Stop and clear PRINTERS folder")) {
            Write-Log -Level Info -Message "Stopping Print Spooler..."
            Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue

            $spoolPath = Join-Path $env:WINDIR 'System32\spool\PRINTERS'
            if (Test-Path $spoolPath) {
                Write-Log -Level Info -Message "Clearing spool folder: $spoolPath"
                Get-ChildItem -Path $spoolPath -File -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue
            }

            Write-Log -Level Info -Message "Starting Print Spooler..."
            Start-Service -Name Spooler -ErrorAction SilentlyContinue
        }

        # (Optional) Remove per-user connections for all profiles
        if ($AllUsers) {
            Write-Log -Level Info -Message "Removing per-user network printer connections for all profiles..."
            # Enumerate mounted + offline hives under HKEY_USERS
            $userSids = Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'S-1-5-21-\d+-\d+-\d+-\d+$' } |
            ForEach-Object { $_.PSChildName }

            foreach ($sid in $userSids) {
                $connKey = "Registry::HKEY_USERS\$sid\Printers\Connections"
                if (Test-Path $connKey) {
                    Get-ChildItem $connKey -ErrorAction SilentlyContinue | ForEach-Object {
                        # Value names typically look like ,Server,Queue (commas)
                        $raw = $_.PSChildName.Trim()
                        # Normalize to \\server\queue if possible
                        $serverQueue = $raw -replace '^,', '' -replace ',', '\'
                        if ($serverQueue -notmatch '^\\\\') { $serverQueue = "\\$serverQueue" }
                        if ($PSCmdlet.ShouldProcess("User:${sid} Mapping '$serverQueue'", "Disconnect")) {
                            try {
                                # Current process context removes only for current user,
                                # so we invoke PrintUIEntry targeting the path (best-effort).
                                rundll32 printui.dll, PrintUIEntry /dn /q /n "$serverQueue"
                                $removedUserMaps++
                                Write-Log -Level Info -Message "  - Disconnected $serverQueue for ${sid}"
                            }
                            catch {
                                $failedUserMaps += $serverQueue
                                Write-Log -Level Warn -Message "    Failed to disconnect $serverQueue for ${sid}: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping per-user mapping removal (use -AllUsers to enable)."
        }

        # 2) Remove printers via Win32_Printer (bypasses MSFT_Printer provider issues)
        Write-Log -Level Info -Message "Removing all printers via Win32_Printer..."
        Get-CimInstance Win32_Printer | ForEach-Object {
            $name = $_.Name
            if ($PSCmdlet.ShouldProcess("Printer '$name'", "Remove")) {
                try {
                    $_ | Remove-CimInstance -ErrorAction Stop
                    $removedPrinters++
                    Write-Log -Level Info -Message "  - Removed $name"
                }
                catch {
                    $failedPrinters += $name
                    Write-Log -Level Warn -Message "    Failed to remove '$name': $($_.Exception.Message)"
                }
            }
        }

        # 3) Optional: remove ports (with WMI fallback)
        if ($IncludePorts) {
            Write-Log -Level Info -Message "Removing TCP/IP printer ports..."
            $standardPrefixes = @('FILE:', 'LPT', 'COM', 'WSD', 'XPS', 'SHRFAX:', 'PORTPROMPT:', 'NULL:')
            $ports = @()

            try {
                $ports = Get-PrinterPort -ErrorAction Stop
            }
            catch {
                Write-Log -Level Warn -Message "Get-PrinterPort failed, falling back to Win32_TCPIPPrinterPort..."
                $ports = Get-WmiObject -Class Win32_TCPIPPrinterPort -ErrorAction SilentlyContinue |
                ForEach-Object { New-Object psobject -Property @{ Name = $_.Name } }
            }

            $ports = $ports | Where-Object {
                $n = $_.Name
                -not ($standardPrefixes | ForEach-Object { $n.StartsWith($_, 'CurrentCultureIgnoreCase') }) `
                    -and ($n -notmatch '^(nul:|PDF:)')
            }

            foreach ($p in $ports) {
                if ($PSCmdlet.ShouldProcess("Port '$($p.Name)'", "Remove")) {
                    try {
                        Remove-PrinterPort -Name $p.Name -ErrorAction Stop
                        $removedPorts++
                        Write-Log -Level Info -Message "  - Removed port $($p.Name)"
                    }
                    catch {
                        $failedPorts += $p.Name
                        Write-Log -Level Warn -Message "    Failed to remove port '$($p.Name)': $($_.Exception.Message)"
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping port removal (use -IncludePorts to enable)."
        }

        # 4) Optional: remove drivers (free common locks first)
        if ($IncludeDrivers) {
            # Make sure spooler is running
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service Spooler -ErrorAction SilentlyContinue
            }

            # Free common locks
            Get-Process splwow64, PrintIsolationHost -ErrorAction SilentlyContinue | ForEach-Object {
                try { Stop-Process -Id $_.Id -Force -ErrorAction Stop } catch {}
            }

            Write-Log -Level Info -Message "Removing printer drivers..."
            $drivers = Get-PrinterDriver -ErrorAction SilentlyContinue
            foreach ($d in $drivers) {
                if ($PSCmdlet.ShouldProcess("Driver '$($d.Name)'", "Remove")) {
                    try {
                        Remove-PrinterDriver -Name $d.Name -ErrorAction Stop
                        $removedDrivers++
                        Write-Log -Level Info -Message "  - Removed driver '$($d.Name)'"
                    }
                    catch {
                        $failedDrivers += $d.Name
                        Write-Log -Level Warn -Message "    Failed to remove driver '$($d.Name)': $($_.Exception.Message)"

                        if ($Force) {
                            # Attempt package removal by published name (oemXX.inf)
                            Write-Log -Level Info -Message "    Enumerating driver packages via pnputil..."
                            $enum = & pnputil /enum-drivers 2>$null
                            if ($enum) {
                                # crude but effective matching
                                $blocks = ($enum -join "`n") -split "(?ms)^Published Name : "
                                $targets = $blocks | Where-Object { $_ -match [regex]::Escape($d.Name) -and $_ -match "Class\s*:\s*Printer" }
                                foreach ($blk in $targets) {
                                    if ($blk -match '^(oem\d+\.inf)') {
                                        $oem = $matches[1]
                                        try {
                                            Write-Log -Level Info -Message "    Forcing removal of ${oem} via pnputil..."
                                            & pnputil /delete-driver $oem /uninstall /force | Out-Null
                                        }
                                        catch {
                                            Write-Log -Level Warn -Message "    pnputil failed for ${oem}: $($_.Exception.Message)"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            Write-Log -Level Info -Message "Skipping driver removal (use -IncludeDrivers to enable)."
        }

        # Restore spooler to original state
        if ($spoolerWasRunning) {
            # ensure it's up
            if ((Get-Service Spooler).Status -ne 'Running') {
                Start-Service -Name Spooler -ErrorAction SilentlyContinue
            }
        }
        else {
            # it was stopped before we began; stop it again
            if ($PSCmdlet.ShouldProcess("Spooler", "Restore to Stopped state")) {
                Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
            }
        }
    }

    End {
        Write-Log -Level Info -Message "=== Remove-Printers completed ==="
        if ($PassThru) {
            [pscustomobject]@{
                PrintersRemoved = $removedPrinters
                PrintersFailed  = $failedPrinters
                PortsRemoved    = $removedPorts
                PortsFailed     = $failedPorts
                DriversRemoved  = $removedDrivers
                DriversFailed   = $failedDrivers
                UserMapsRemoved = $removedUserMaps
                UserMapsFailed  = $failedUserMaps
            }
        }
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAetlp4UunGJFUG
# JPA8pbLaMOrjcLo1AG5A/hhJL9yzYqCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB3
# fcCsqNqhCB44lZ8QnKYI1KDAyqpLLGgXT+h7GD+qdTANBgkqhkiG9w0BAQEFAASC
# AYAP6ZYEAEplD9M5gjtNQfbZeyQG1GNC2nmsrwZnk0v4Uu2gg8++HTd1z//TQHi4
# 1sJvY4Bjnn5ChavT3+13w6DdPynX3bBuKzJkWq63TI19YvR4iVmzIPKSQcu2n0GL
# 5sLa8Avh6do1ICaguKoWZ+O6Adx/2scxjVS8BNa/nw9C4FCavPqyZZ3oKD8RsbkX
# BTQNK0h/w+DpSL4SgL5hsv80O/l4zlZqhxnf2iRq9X1Q65AQbig30fwPVV+3jVfV
# jCFmOxBq7Ro2nvley9X/Q+bSvHcg/My3xeDwPG6pcjVBMO1PofuQETBzInMVF6PJ
# /LFN8gbgpF5q45co3HVDovFjTLU4jmEug6pHPOsiYl//SrSmNV0Shnhn1dRQE1Iq
# CrVf4I+J5GpSldAM94q8r6rNWatHM7m4qTivLT6SlRlnB7xsKWfGKRNiwRh2I+kV
# cVEews4ynB9UtLD1IUq8qhKuO37yGDc64M4s52f4kswWO4rRXOsGVIkONlXJbAWo
# ei2hggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNTEzWjAvBgkqhkiG
# 9w0BCQQxIgQg//RSmhl+p+hTxM9X0HQi3WgAVleI9BIRuGSNbSEw+UgwDQYJKoZI
# hvcNAQEBBQAEggIAIGg8liTEV8kC5ICjSDatL+q4bLEf34wttIJb7POnxXy+X3io
# wmBnL3TsB/SukmOfTb9fmspvXb/+BYvgVHG4g1jGyX9EibuQgS0wnGMORP1WwOSZ
# 3/XUkhw0H6u1CVascyrmL44UI0nUR8j8NK4n6aoMNf/4sYR17goZ8KVNwZx08XoE
# bE4XMeIT0dLlse/jExMd7qmOfznOZ7m0rlsyi/1cELwxX+msrTrl32e6AXJnm/6p
# vjsS25CdcFyPvi7x8WvtsT1iV7R6++Wf048UBXzoXHMUfgvXxbc4M6xEdhjjKa6L
# TqpqtwbKwsXa6Zid7zQ8uIhEhOIGQ3/rDLtXBNfWYNTFwmxOfcEHcqiImeAnYfuq
# FaQomgHhbvjOMIIEtgLB2pk1Khnp7aO669vJ2Xr8TMCAAyPyjy0D7X3p3C/X1bGa
# fzAdP5/+OTWFh+2n9JDFw/Nug74XxJUXWiHxxtpZ7iPAVFA29Nqkit35QyRQLiOY
# CC+rFixPGENp+A8EPSbz6hxCtAbAiRuRQq85URStKmJ2F3/riUuHj/K3/lt3erVY
# 79cYvwVG0bJGMdTKemCk1jw+DbSZVNUPJiAwj1GMS5mlgvT2J5xCQVvNMJk+uVf7
# fayBpfKTFyCAJI16uRl+1XtjbR/62y4dSR6za2K6go7GG60md6uPRr+310Y=
# SIG # End signature block
