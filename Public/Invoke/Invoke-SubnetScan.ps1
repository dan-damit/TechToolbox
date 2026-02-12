function Invoke-SubnetScan {
    <#
    .SYNOPSIS
    Performs a subnet scan to discover hosts and gather network information.

    .DESCRIPTION
    Scans a subnet (specified in CIDR notation) to identify active hosts,
    retrieve MAC addresses, resolve DNS names, check TCP ports, and optionally
    fetch HTTP banner information. Can execute locally or on a remote computer
    via WSMan or SSH.

    .PARAMETER CIDR
    The subnet to scan in CIDR notation (e.g., '192.168.1.0/24').

    .PARAMETER ComputerName
    Remote computer on which to execute the scan. If not specified, the scan
    runs locally.

    .PARAMETER Transport
    Protocol for remote execution: 'WSMan' or 'SSH'. Default is 'WSMan'.

    .PARAMETER Credential
    PSCredential for remote authentication.

    .PARAMETER UserName
    Username for SSH authentication.

    .PARAMETER KeyFilePath
    Path to SSH private key file.

    .PARAMETER LocalOnly
    Forces local execution even if ComputerName is specified.

    .PARAMETER Port
    TCP port to check for availability. Default is read from config.

    .PARAMETER ResolveNames
    Attempts to resolve hostnames via DNS, NetBIOS, and mDNS.

    .PARAMETER HttpBanner
    Retrieves HTTP Server headers from discovered hosts.

    .PARAMETER ExportCsv
    Exports results to a CSV file.

    .PARAMETER ExportTarget
    Location to export results: 'Local' or 'Remote'. Default is 'Local'.

    .EXAMPLE
    Invoke-SubnetScan -CIDR "192.168.1.0/24" -Port 80 -ResolveNames -ExportCsv

    .EXAMPLE
    Invoke-SubnetScan -CIDR "10.0.0.0/25" -ComputerName "RemoteHost" -Transport WSMan -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        # Remote options
        [string]$ComputerName,
        [ValidateSet('WSMan', 'SSH')]
        [string]$Transport = 'WSMan',
        [pscredential]$Credential,
        [string]$UserName,
        [string]$KeyFilePath,
        [switch]$LocalOnly,

        # Scan behavior
        [int]$Port,
        [switch]$ResolveNames,
        [switch]$HttpBanner,

        # Export control
        [switch]$ExportCsv,
        [ValidateSet('Local', 'Remote')]
        [string]$ExportTarget = 'Local'
    )

    Initialize-TechToolboxRuntime
    $oldEAP = $ErrorActionPreference

    try {
        # --- CONFIG & DEFAULTS ---
        $cfg = $script:cfg
        if (-not $cfg) { throw "TechToolbox config is null/empty. Ensure Config\config.json exists and is valid JSON." }

        $scanCfg = $cfg.settings.subnetScan
        if (-not $scanCfg) { throw "Config missing 'settings.subnetScan'." }

        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $scanCfg.defaultPort ?? 80 }
        if (-not $PSBoundParameters.ContainsKey('ResolveNames')) { $ResolveNames = [bool]($scanCfg.resolveNames ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('HttpBanner')) { $HttpBanner = [bool]($scanCfg.httpBanner ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('ExportCsv')) { $ExportCsv = [bool]($scanCfg.exportCsv ?? $false) }

        $localExportDir = $scanCfg.exportDir
        if ($ExportCsv -and $ExportTarget -eq 'Local') {
            if (-not $localExportDir) { throw "Config 'settings.subnetScan.exportDir' is missing." }
            if (-not (Test-Path -LiteralPath $localExportDir)) {
                New-Item -ItemType Directory -Path $localExportDir -Force | Out-Null
            }
        }

        Write-Log -Level Info -Message ("SubnetScan: CIDR={0} Port={1} ResolveNames={2} HttpBanner={3} ExportCsv={4} Target={5}" -f `
                $CIDR, $Port, $ResolveNames, $HttpBanner, $ExportCsv, $ExportTarget)

        $runLocal = $LocalOnly -or (-not $ComputerName)
        $results = $null

        # --- LOCAL MODE ---
        if ($runLocal) {
            Write-Log -Level Info -Message "Executing subnet scan locally."

            $doRemoteExport = $false
            $results = Invoke-SubnetScanLocal `
                -CIDR $CIDR `
                -Port $Port `
                -ResolveNames:$ResolveNames `
                -HttpBanner:$HttpBanner `
                -ExportCsv:$doRemoteExport
        }
        else {
            Write-Log -Level Info -Message "Executing subnet scan on remote host: $ComputerName via $Transport"

            # --- Build session (reuse your existing transport logic) ---
            $session = $null
            try {
                if ($Transport -eq 'WSMan') {
                    $session = Start-NewPSRemoteSession -ComputerName $ComputerName -Credential $Credential
                }
                else {
                    if (-not $UserName -and $Credential) { $UserName = $Credential.UserName }
                    if (-not $UserName) { throw "For SSH transport, specify -UserName or -Credential." }

                    $sshParams = @{ HostName = $ComputerName; UserName = $UserName; ErrorAction = 'Stop' }
                    if ($KeyFilePath) { $sshParams['KeyFilePath'] = $KeyFilePath }
                    elseif ($Credential) { $sshParams['Password'] = $Credential.GetNetworkCredential().Password }

                    $session = New-PSSession @sshParams
                    Write-Log -Level Ok -Message "Connected to $ComputerName (SSH)."
                }
            }
            catch {
                Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
                return
            }

            try {
                $moduleRoot = Get-ModuleRoot
                $workerLocal = Join-Path $moduleRoot 'Workers\SubnetScan.worker.ps1'
                $workerRemote = 'C:\TechToolbox\Workers\SubnetScan.worker.ps1'

                # Helpers required by Invoke-SubnetScanLocal + its dependencies
                $helperFiles = @(
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Invoke-SubnetScanLocal.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-IPsFromCIDR.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-MacAddress.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-ReverseDns.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-NetbiosName.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-MdnsName.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Test-TcpPort.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Get-HttpInfo.ps1')
                    (Join-Path $moduleRoot 'Private\Network\SubnetScan\Show-ProgressBanner.ps1')
                )

                $pkg = New-HelpersPackage -HelperFiles $helperFiles

                $remoteExportDir = $null
                $doRemoteExport = $ExportCsv -and ($ExportTarget -eq 'Remote')
                if ($doRemoteExport) {
                    $remoteExportDir = $scanCfg.exportDir
                    if (-not $remoteExportDir) {
                        throw "Config 'settings.subnetScan.exportDir' is missing; required for remote export."
                    }
                }

                $results = Invoke-RemoteWorker `
                    -Session $session `
                    -HelpersZip $pkg.ZipPath `
                    -HelpersZipHash $pkg.ZipHash `
                    -WorkerRemotePath $workerRemote `
                    -WorkerLocalPath $workerLocal `
                    -EntryPoint 'Invoke-SubnetScanCore' `
                    -EntryParameters @{
                    CIDR         = $CIDR
                    Port         = $Port
                    ResolveNames = $ResolveNames
                    HttpBanner   = $HttpBanner
                    ExportCsv    = ($ExportCsv -and $ExportTarget -eq 'Remote')
                }
            }
            catch {
                Write-Log -Level Error -Message "Remote scan failed: $($_.Exception.Message)"
                return
            }
            finally {
                if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
            }
        }

        # --- Local export (if requested) ---
        if ($ExportCsv -and $ExportTarget -eq 'Local' -and $results) {
            try {
                $cidrSafe = $CIDR -replace '[^\w\-\.]', '_'
                $csvPath = Join-Path $localExportDir ("subnet-scan-{0}-{1}.csv" -f $cidrSafe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log -Level Ok -Message "Results exported to $csvPath"
            }
            catch {
                Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
            }
        }

        if ($results) {
            Write-Host "Discovered hosts:" -ForegroundColor DarkYellow
            $results |
            Select-Object IP, RTTms, MacAddress, NetBIOS, PTR, Mdns, PortOpen, ServerHdr |
            Format-Table -AutoSize
        }

        return $results
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBFI0Gm8z/3/3of
# Y9VHgRTQ/bkWtTimwMZZNlSfVp2zp6CCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC9p0fT2p/5
# lKpFqzWvmNUaG+avaYmGu9u62q37yGH2kTANBgkqhkiG9w0BAQEFAASCAgCnYMCc
# 0AsDgNN8HOxqeCivG2vS1oBGiE3cU/pfgsR9TrdL2dMA4axQCyy1T/mOR1dhvCgE
# 3fgMtqA0HBib4+f/4p1RdEcrpVdjpOcAqOI/zlfoxLXLthJnYV6W8Tb+R44HLT9I
# Y1VWhM5uapiu3rihn53zhoto/EuAk3asFQ93qLPbw2Dyx1B2hXzT+yd7t83+savU
# 3E7p3R7G2z4WPiTHWfvVOBbFlOpvcPi5Mwh45+8JUQJGs1LLjoCDKnQwiLwXJwal
# oyUmODRGxbE384dCFv2AgVCyvEcUKGcGVFldRdOMKzpgD/bqHiFFp98xq7o3NpTd
# N7X7iLL8hOlx+AS/9b4hDl7mo2VnbIIi4G/3ua8ODWWibvcM9iH0TyEDXx3k3yFr
# /2/JDlHBJbFAzZ28gHuKeZez5GqLV8nFZhcBvRzu3keueH+0AkRAIx2MUzNh1U2m
# zHLTG18vRgQnLiHajCRtQQHag6wAu4FQBxR9v3DYIUs3DkAhehKDrENrLEpqMJu9
# u9YrKITUkfbPDKBFUtAZ86I/M3QmCq7+0RyYyndh5u2aAqJG1WkMfrYu/xHF37u/
# kumEVx5SjiFeddS2RjnTNATnhN7kaf/MMYEYDw1B+fPDewroo7gZPO7jP7PqHPE4
# tsqAgowcaL16fCUwUGyJnMif0RPkPEVZmjx4MKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTIyMjAxMzBaMC8GCSqGSIb3DQEJBDEiBCA9mC3y+gUzuPCGGs3S
# 3EMIbmYAEZWVFbdeyFQwFrI7KzANBgkqhkiG9w0BAQEFAASCAgBORR5JchPia4yZ
# HMJ9zCD17tQUMim2WeGMI+UvIUhcBHFWDLrvmRpJ/scBg5oWINXA4uNGUJfPCDsO
# Iafx5iypx1LXnKoNBgfPpFzSpPC4mTkC8SIuDii2JwwrIgrqGwHwpSZTZVuTvFrO
# oM2c/LCigldgseE6HCLkmedhX3AdhLb/InklxO8Ly6TTAL17w0nLkI95m5gCmSfq
# jOv0GEOODgw8UHa3yffLPcluEkFyev3oTVgrpXxvghw/wiDZHvCj0E+tAAsy2pmP
# 5ofEome1cn02LDhbsrXXAHo1U0lKsugkn2UbgEN5/liCSGX9UqAMpT8t95OUXeFm
# T/WA0xaMhYUdWWmWGJAcea0oP1ssOGU5vyR/j+rvYW5o1AqX4LEXB2y20Pr9ytXw
# 8BaksebZWSNaqNGLpcRSVRHL4ueuGWlI/GpUZnpXIw1tqqmCv1Jn+cB79oO2bKKB
# +Yk8HHdysS6S0GUYyEFmsfqvYrHPamRQzaTNqausfT9kMM+yq8s33eHoOG/NvAiP
# u2+8Pe27+D2dYvrhTm+hyhTIGTykaESOV7OGrt1g5oLiPydZQqWozqQgOCAGTwly
# BYcysdv5G5XfjZUGksB+wzQA0MYWKWtW3hy0gX2ciANjCM+gcsYrGAgWoS9KGjIO
# lwpWQzw0A7hn68Sn7EzL/Ln5+G6CUw==
# SIG # End signature block
