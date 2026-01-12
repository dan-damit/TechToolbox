
function Get-RemoteInstalledSoftware {
<#
    .SYNOPSIS
    Collects installed software from remote Windows computers via PSRemoting
    (registry uninstall keys + optional Appx).

    .DESCRIPTION
    Connects to remote hosts with Invoke-Command, enumerates machine/user
    uninstall registry entries (x64/x86), optionally includes Appx/MSIX
    packages, returns objects, writes a summary table to the information stream,
    and exports per-host CSVs or a consolidated CSV.

    .PARAMETER ComputerName
    One or more remote computer names to query. (Requires WinRM enabled and
    appropriate permissions)

    .PARAMETER Credential
    Credentials used for the remote session. If omitted, current identity is
    attempted; you may be prompted.

    .PARAMETER IncludeAppx
    Include Windows Store (Appx/MSIX) packages. Can be slower and requires admin
    rights on remote hosts.

    .PARAMETER OutDir
    Output directory for CSV exports. Defaults to TechToolbox config
    RemoteSoftwareInventory.OutDir or current directory if not set.

    .PARAMETER Consolidated
    Write a single consolidated CSV for all hosts
    (InstalledSoftware_AllHosts_<timestamp>.csv). If omitted, writes one CSV per
    host.

    .PARAMETER ThrottleLimit
    Concurrency limit for Invoke-Command. Default 32.

    .INPUTS
        None. You cannot pipe objects to Get-RemoteInstalledSoftware.

    .OUTPUTS
    [pscustomobject]

    .EXAMPLE
    Get-RemoteInstalledSoftware -ComputerName server01,server02 -Consolidated

    .EXAMPLE
    Get-RemoteInstalledSoftware -ComputerName laptop01 -IncludeAppx -Credential (Get-Credential)

    .NOTES
    Avoids Win32_Product due to performance/repair risk. Requires PSRemoting
    (WinRM) enabled.

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$ComputerName,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$IncludeAppx,

        [Parameter()]
        [string]$OutDir,

        [Parameter()]
        [switch]$Consolidated,

        [Parameter()]
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 32
    )

    begin {
        # --- Config & Defaults ---
        $cfg = Get-TechToolboxConfig
        $defaults = $cfg["settings"]["remoteSoftwareInventory"] # may be $null if section not present

        # Apply config-driven defaults if provided
        if ($defaults) {
            if (-not $PSBoundParameters.ContainsKey('IncludeAppx') -and $defaults["IncludeAppx"]) { $IncludeAppx = [switch]::Present }
            if (-not $PSBoundParameters.ContainsKey('Consolidated') -and $defaults["Consolidated"]) { $Consolidated = [switch]::Present }
            if (-not $PSBoundParameters.ContainsKey('ThrottleLimit') -and $defaults["ThrottleLimit"]) { $ThrottleLimit = [int]$defaults["ThrottleLimit"] }
            if (-not $PSBoundParameters.ContainsKey('OutDir') -and $defaults["OutDir"]) { $OutDir = [string]$defaults["OutDir"] }
        }

        # No SSL/session certificate relaxations: sessionParams intentionally empty
        $sessionParams = @{}

        Write-Log -Level Info -Message "PSRemoting will use default WinRM settings (no SSL/certificate overrides)."

        # Credential Prompting
        if (-not $PSBoundParameters.ContainsKey('Credential')) {
            Write-Log -Level Info -Message 'No credential provided; you will be prompted (or current identity will be used if allowed).'
            try {
                $Credential = Get-Credential -Message 'Enter credentials to connect to remote computers (or Cancel to use current identity)'
            }
            catch {
                # If user cancels, $Credential remains $null; Invoke-Command will try current identity.
            }
        }
    }

    process {
        # Remote scriptblock that runs on each target
        $scriptBlock = {
            param([bool]$IncludeAppx)

            function Convert-InstallDate {
                [CmdletBinding()]
                param([string]$Raw)
                if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
                $s = $Raw.Trim()
                if ($s -match '^\d{8}$') {
                    try { return [datetime]::ParseExact($s, 'yyyyMMdd', $null) } catch {}
                }
                try { return [datetime]::Parse($s) } catch { return $null }
            }

            function Get-UninstallFromPath {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory)][string]$RegPath,
                    [Parameter(Mandatory)][string]$Scope,
                    [Parameter(Mandatory)][string]$Arch
                )
                $results = @()
                try {
                    $keys = Get-ChildItem -Path $RegPath -ErrorAction SilentlyContinue
                    foreach ($k in $keys) {
                        $p = Get-ItemProperty -Path $k.PSPath -ErrorAction SilentlyContinue
                        if ($p.DisplayName) {
                            $results += [PSCustomObject]@{
                                ComputerName    = $env:COMPUTERNAME
                                DisplayName     = $p.DisplayName
                                DisplayVersion  = $p.DisplayVersion
                                Publisher       = $p.Publisher
                                InstallDate     = Convert-InstallDate $p.InstallDate
                                UninstallString = $p.UninstallString
                                InstallLocation = $p.InstallLocation
                                EstimatedSizeKB = $p.EstimatedSize
                                Scope           = $Scope
                                Architecture    = $Arch
                                Source          = 'Registry'
                                RegistryPath    = $k.PSPath
                            }
                        }
                    }
                }
                catch {}
                return $results
            }

            $items = @()

            # Machine-wide installs
            $items += Get-UninstallFromPath -RegPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'Machine' -Arch 'x64'
            $items += Get-UninstallFromPath -RegPath "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'Machine' -Arch 'x86'

            # Current user hive
            $items += Get-UninstallFromPath -RegPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'User (Current)' -Arch 'x64'
            $items += Get-UninstallFromPath -RegPath "HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -Scope 'User (Current)' -Arch 'x86'

            # Other loaded user hives (HKU) - covers logged-on users
            try {
                $userHives = Get-ChildItem HKU:\ -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^HKEY_USERS\\S-1-5-21-' }
                foreach ($hive in $userHives) {
                    $sid = $hive.PSChildName
                    $x64Path = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                    $x86Path = "HKU:\$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                    $items += Get-UninstallFromPath -RegPath $x64Path -Scope "User ($sid)" -Arch 'x64'
                    $items += Get-UninstallFromPath -RegPath $x86Path -Scope "User ($sid)" -Arch 'x86'
                }
            }
            catch {}

            if ($IncludeAppx) {
                try {
                    $items += Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        [PSCustomObject]@{
                            ComputerName    = $env:COMPUTERNAME
                            DisplayName     = $_.Name
                            DisplayVersion  = $_.Version.ToString()
                            Publisher       = $_.Publisher
                            InstallDate     = $null
                            UninstallString = $null
                            InstallLocation = $_.InstallLocation
                            EstimatedSizeKB = $null
                            Scope           = 'Appx (AllUsers)'
                            Architecture    = 'Appx/MSIX'
                            Source          = 'Appx'
                            RegistryPath    = $_.PackageFullName
                        }
                    }
                }
                catch {}
            }

            $items
        }

        # Execute across one or many computers
        $results = $null
        try {
            $invocationParams = @{
                ComputerName  = $ComputerName
                ScriptBlock   = $scriptBlock
                ArgumentList  = @($IncludeAppx.IsPresent)
                ErrorAction   = 'Stop'
                ThrottleLimit = $ThrottleLimit
            }
            if ($Credential) { $invocationParams.Credential = $Credential }

            # sessionParams is empty now; kept for symmetry
            foreach ($k in $sessionParams.Keys) { $invocationParams[$k] = $sessionParams[$k] }

            $results = Invoke-Command @invocationParams
        }
        catch {
            Write-Log -Level Error -Message ("Remote command failed: {0}" -f $_.Exception.Message)
            return
        }

        if (-not $results -or $results.Count -eq 0) {
            Write-Log -Level Warn -Message 'No entries returned. Possible causes: insufficient rights, empty uninstall keys, or connectivity issues.'
        }

        # Write a tidy table to information stream (avoid Write-Host)
        $table = $results |
        Sort-Object ComputerName, DisplayName, DisplayVersion |
        Format-Table ComputerName, DisplayName, DisplayVersion, Publisher, Scope, Architecture -AutoSize |
        Out-String
        Write-Information $table

        # Export CSV(s) (honors -WhatIf/-Confirm)
        $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'

        if ($Consolidated) {
            $consolidatedPath = Join-Path $OutDir ("InstalledSoftware_AllHosts_{0}.csv" -f $stamp)
            if ($PSCmdlet.ShouldProcess($consolidatedPath, 'Export consolidated CSV')) {
                try {
                    $results |
                    Sort-Object ComputerName, DisplayName, DisplayVersion |
                    Export-Csv -Path $consolidatedPath -NoTypeInformation -Encoding UTF8
                    Write-Log -Level Ok -Message ("Consolidated export written: {0}" -f $consolidatedPath)
                }
                catch {
                    Write-Log -Level Warn -Message ("Failed to write consolidated CSV: {0}" -f $_.Exception.Message)
                }
            }
        }
        else {
            # Per-host export
            $grouped = $results | Group-Object ComputerName
            foreach ($g in $grouped) {
                $csvPath = Join-Path $OutDir ("{0}_InstalledSoftware_{1}.csv" -f $g.Name, $stamp)
                if ($PSCmdlet.ShouldProcess($csvPath, "Export CSV for $($g.Name)")) {
                    try {
                        $g.Group |
                        Sort-Object DisplayName, DisplayVersion |
                        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                        Write-Log -Level Ok -Message ("{0} export written: {1}" -f $g.Name, $csvPath)
                    }
                    catch {
                        Write-Log -Level Warn -Message ("Failed to write CSV for {0}: {1}" -f $g.Name, $_.Exception.Message)
                    }
                }
            }
        }

        # Return objects to pipeline consumers
        return $results
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA9VLGAnGEqISxI
# fiNQvEtEd2hfaQM4PjSifD2zh4r1+6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCKPxa9ObsJ
# iQqPnY7VrazBPVNXEBxlGArIN2MfG2h0jDANBgkqhkiG9w0BAQEFAASCAgDHcBqc
# gQXcUV+z5viukoNbHEbSZXxbR/OPIcMvVR6mgAcRLLyFf7Yp4ag5+wkmLctR9aMh
# 98220K+Qatp44oIj76omWONepMe/8JAz2QLPKaK/qvbg2v+YelyNDoLWGu2sqDPA
# MagrrQy+PTJ/3e8KFJqFONBXLRTZq6/Fd/finKlgtzLLcRX5XzqQvUqlLMiXvN2k
# REizSevKhDUIrhwT4I2QXIDBQxDUdBgeD/cV/xB9RiRIhuTC59aP7zyeYTOkkjth
# 7vT5LMiuBtJXI2EH4Ra6A5kV+ZEk817GF8M2I43WxSuqEVC3Pisn3Esgm4Nqday2
# /xcPvEM3lD0/bu+5KOaNyHL4eOazm3xGjhIQLxWZ1xCmgAN/CJnUoY/EjhGf68Vb
# 8lYCD5+fWFb4FVJWAoHjlr6N0OFYPWrpCB/W6uqhbApXLYaKjpG/2DCdSC4yJBCM
# XrA551jGuU4DBNfVCvH21EkAREbZL4LTzTdbZ+t3lUCQ1FzTbW1JXSKLzflJ6aWJ
# QKs1uuNIqjLeyQ9N9gKyrjG4N0/88VJI0DAqh0Y1dpN/nIG68aM6rr3sBVDHv5vX
# X/Pl2026QSKSqT0cnQgaEH99d41icBqsgQp46mKsdOXOEOiQLlvSZ5HMRcE3JETh
# HHXN2MaLChBLMKzaX/7GcDbfaz/Jpr1tWsY6YqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTIyMjE4MThaMC8GCSqGSIb3DQEJBDEiBCCYr+js8+bS+ebS76Ts
# 9DpYegMCAdLFPj5VNdL41TGC2DANBgkqhkiG9w0BAQEFAASCAgCsXW2dP7GujJiU
# Bhwbl3PGqsotbCK45pu/mqdib4BFyX5iVzxHS9LdXTcdswt5ijPfZU37af9L1Nyz
# CyNLZ2Fg+8rlfuVMVjIcefngLmxt7COY1EaQ7kaKQdj/S9p0K4Uu+U17XD152ZLj
# 82Ot5DVS5gJPy3f8zbH2pntVFaKpD8OjBn431V5adS9BPjfnurfeOyS1T6q4mra1
# 9RLlUbN1B4RAH9D/yDhwuavGCw0cyuE4MAQqOEoExdyXlYravOID1F1VhwbDvY0v
# D+pg5BYeepvD9FI++AYf5BDQScE1JuMrvUffAPeBkKPgAIhOVzP7VTKkBxHjpGGE
# PwkhCN7zVfisKlRon4TI7YAWgO0o8wBzx/VgoZLJuNC64qQ6njwwu2a0XH4/+Nf4
# ymt5LrFBKVK+npeqpP/TqfSZ4v0KZ7t9zRflcd4a+r/sJTTcJqKnNblbKyGtzTHZ
# gb4X/niyI9bjZSwbn3Gub0DBqaw9Qt6EnIAZXjVHqVuNszlPzpqZOKBiLhGPk1bv
# VMXRt9D/VTtjx1Y5JEkz8JCzM/lKbzCNHsnWSkyPBi9GXX0NHa4CRYq9zQwMGwki
# O0tYVwG2WMv1AgQ97ifbhCssSmw5rcwbtWPnIFOincLQR1CywuI/V9I6FivnUVWc
# 7hPN4ZAoJA3YXbci5h4XS+pZB6muhA==
# SIG # End signature block
