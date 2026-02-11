function Get-SystemSnapshot {
    <#
    .SYNOPSIS
    Retrieves a system snapshot from one or more remote computers.
    .DESCRIPTION
    This cmdlet connects to remote computers and retrieves a system snapshot of
    their current state.
    .PARAMETER ComputerName
    Specifies the names of the computers from which to retrieve system
    snapshots.
    .PARAMETER Credential
    Specifies the credentials to use for connecting to the remote computers.
    .PARAMETER IncludeServices
    If specified, includes service information in the snapshot.
    .PARAMETER IncludeRoles
    If specified, includes role information in the snapshot.
    .PARAMETER OutDir
    Specifies the directory where the output files will be saved.
    .PARAMETER NoExport
    If specified, the cmdlet will not export the results to files.
    .PARAMETER PreferPS7
    If specified, the cmdlet will prefer PowerShell 7 for remote sessions.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [Parameter()][switch]$Report,

        [pscredential]$Credential,

        [switch]$IncludeServices,
        [switch]$IncludeRoles,

        [string]$OutDir,

        [switch]$NoExport,

        [switch]$PreferPS7
    )

    begin {
        # --- Load config defaults ---
        Initialize-TechToolboxRuntime

        $ss = $script:cfg.settings.systemSnapshot
        if (-not $PSBoundParameters.ContainsKey('IncludeServices')) { $IncludeServices = [bool]$ss.includeServices }
        if (-not $PSBoundParameters.ContainsKey('IncludeRoles')) { $IncludeRoles = [bool]$ss.includeRoles }
        if (-not $PSBoundParameters.ContainsKey('OutDir')) { $OutDir = if ($ss.exportPath) { [string]$ss.exportPath } else { Join-Path $script:ModuleRoot "Exports\\SystemSnapshot" } }

        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

        # Controller-side helper source and list (to zip)
        $helperSourceDir = if ($ss.helperPath) { [string]$ss.helperPath } else { Join-Path $script:ModuleRoot "Private\\System\\Snapshot" }
        $helperFilesFromCfg = @()
        if ($ss.helperFiles) { $helperFilesFromCfg = [string[]]$ss.helperFiles }

        # Resolve helper file full paths from the configured list
        $helperFiles = @()
        foreach ($name in $helperFilesFromCfg) {
            $p = Join-Path $helperSourceDir $name
            if (-not (Test-Path -LiteralPath $p)) {
                throw "Configured helper not found: $p"
            }
            $helperFiles += $p
        }

        # Prepare a temp zip of helpers
        $tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("TT_SnapshotHelpers_{0}" -f ([guid]::NewGuid()))
        New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
        try {
            foreach ($f in $helperFiles) { Copy-Item -LiteralPath $f -Destination $tmpRoot -Force }
            $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) ("TT_SnapshotHelpers_{0}.zip" -f ([guid]::NewGuid()))
            if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
            Compress-Archive -Path (Join-Path $tmpRoot '*') -DestinationPath $zipPath -Force
            $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
        }
        finally {
            if (Test-Path -LiteralPath $tmpRoot) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force }
        }

        # Worker remote path (from config)
        $workerRemotePath = if ($ss.workerPath) { [string]$ss.workerPath } else { "C:\\TechToolbox\\Workers\\Get-SystemSnapshot.Worker.ps1" }

        # Local flatteners (not shipped; used after results return)
        $convert1 = Join-Path $script:ModuleRoot "Private\\System\\Snapshot\\Convert-SnapshotToFlatObject.ps1"
        $convert2 = Join-Path $script:ModuleRoot "Private\\System\\Snapshot\\Convert-FlatSnapshotToRows.ps1"
        if ((-not (Test-Path $convert1)) -or (-not (Test-Path $convert2))) {
            Write-Verbose "Snapshot flatteners not found; NoExport will be forced."
            $NoExport = $true
        }

        $all = New-Object System.Collections.Generic.List[object]
    }

    process {
        foreach ($cn in $ComputerName) {
            $IsLocal = $cn -eq $env:COMPUTERNAME -or $cn -eq 'localhost' -or $cn -eq '127.0.0.1'
            $session = $null
            $remoteTmp = $null
            try {
                if ($IsLocal) {
                    Write-Log -Level Info -Message "Running snapshot in local mode for $cn"
                    $session = $null
                }
                else {
                    $session = Start-NewPSRemoteSession -ComputerName $cn -Credential $Credential
                }

                if (-not $IsLocal) {
                    Write-Log -Level Info -Message "Connected to $cn, preparing helpers"
                
                    # Remote temp and helper target path
                    $remoteTmp = Invoke-Command -Session $session -ScriptBlock {
                        $base = Join-Path $env:TEMP ("TT_Snapshot_{0}" -f ([guid]::NewGuid()))
                        New-Item -ItemType Directory -Path $base -Force | Out-Null
                        $base
                    }

                    $remoteZip = Join-Path $remoteTmp "helpers.zip"
                    $remoteHelpersPath = Join-Path $remoteTmp "helpers"

                    # Push the zip
                    Copy-Item -ToSession $session -Path $zipPath -Destination $remoteZip -Force

                    # Verify hash and expand
                    $expandedOk = Invoke-Command -Session $session -ScriptBlock {
                        param($remoteZipParam, $expectedHash, $remoteHelpersParam)
                        if (-not (Test-Path -LiteralPath $remoteZipParam)) { throw "Remote zip not found: $remoteZipParam" }
                        $actual = (Get-FileHash -LiteralPath $remoteZipParam -Algorithm SHA256).Hash
                        if ($actual -ne $expectedHash) {
                            throw "Hash mismatch for transferred helpers.zip. Expected $expectedHash, got $actual."
                        }
                        New-Item -ItemType Directory -Path $remoteHelpersParam -Force | Out-Null
                        try {
                            Expand-Archive -Path $remoteZipParam -DestinationPath $remoteHelpersParam -Force
                        }
                        catch {
                            # Fallback for older PS without Expand-Archive
                            Add-Type -AssemblyName System.IO.Compression.FileSystem
                            [System.IO.Compression.ZipFile]::ExtractToDirectory($remoteZipParam, $remoteHelpersParam, $true)
                        }
                        Test-Path -LiteralPath $remoteHelpersParam
                    } -ArgumentList $remoteZip, $zipHash, $remoteHelpersPath

                    if (-not $expandedOk) { throw "Failed to expand helpers on $cn" }

                    # Ensure worker exists at configured path on the remote.
                    $workerExists = Invoke-Command -Session $session -ScriptBlock {
                        param($p) [bool](Test-Path -LiteralPath $p)
                    } -ArgumentList $workerRemotePath

                    if (-not $workerExists) {
                        # Optional: push the worker from our module to the configured path
                        $localWorker = Join-Path $script:ModuleRoot "Workers\\Get-SystemSnapshot.worker.ps1"
                        if (Test-Path -LiteralPath $localWorker) {
                            $remoteDir = Split-Path -Path $workerRemotePath -Parent
                            Invoke-Command -Session $session -ScriptBlock { param($d) if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } } -ArgumentList $remoteDir
                            Copy-Item -ToSession $session -Path $localWorker -Destination $workerRemotePath -Force
                        }
                    }
                }
                # If local, run helpers directly. If remote, invoke the worker which will use the helpers on the remote side.
                if ($IsLocal) {
                    $localWorker = Join-Path $script:ModuleRoot "Workers\\Get-SystemSnapshot.worker.ps1"
                    if (-not (Test-Path -LiteralPath $localWorker)) {
                        throw "Local worker not found: $localWorker"
                    }

                    Write-Log -Level Info -Message "Running snapshot helpers locally..."

                    $osInfo = Get-SnapshotOS -IncludeRoles:$IncludeRoles
                    $cpuInfo = Get-SnapshotCPU
                    $memoryInfo = Get-SnapshotMemory
                    $diskInfo = Get-SnapshotDisk
                    $netInfo = Get-SnapshotNetwork
                    $identity = Get-SnapshotIdentity
                    $services = if ($IncludeServices) { Get-SnapshotServices } else { $null }

                    $snapshot = [pscustomobject]@{
                        ComputerName = $env:COMPUTERNAME
                        Timestamp    = Get-Date
                        OS           = $osInfo
                        CPU          = $cpuInfo
                        Memory       = $memoryInfo
                        Disks        = $diskInfo
                        Network      = $netInfo
                        Identity     = $identity
                        Services     = $services
                    }
                }
                else {
                    # Remote mode
                    $args = @('-HelpersPath', $remoteHelpersPath)
                    if ($IncludeServices) { $args += '-IncludeServices' }
                    if ($IncludeRoles) { $args += '-IncludeRoles' }

                    $snapshot = Invoke-Command -Session $session -FilePath $workerRemotePath -ArgumentList $args
                }

                if ($snapshot) {
                    if (-not $NoExport) {
                        . $convert1
                        . $convert2
                        $flat = Convert-SnapshotToFlatObject -Snapshot $snapshot
                        $rows = Convert-FlatSnapshotToRows -FlatObject $flat
                        $name = "SystemSnapshot_{0}_{1:yyyyMMdd_HHmmss}.csv" -f $cn, (Get-Date)
                        $csvPath = Join-Path $OutDir $name
                        if ($PSCmdlet.ShouldProcess($csvPath, "Export system snapshot CSV")) {
                            $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                        }
                    }
                    $all.Add($snapshot)
                }
                if ($Report) {
                    Show-SystemSnapshotReport -Snapshot $snapshot
                }
            }
            catch {
                Write-Warning ("{0}: {1}" -f $cn, $_.Exception.Message)
            }
            finally {
                if ($session) {
                    try {
                        if ($remoteTmp) {
                            Invoke-Command -Session $session -ScriptBlock {
                                param($p)
                                if (Test-Path -LiteralPath $p) {
                                    Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            } -ArgumentList $remoteTmp -ErrorAction SilentlyContinue
                        }
                    }
                    catch {}
                    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                }
            }
        }
    }

    end {
        $all.ToArray() | Out-Null
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2qSyuvvoLaK0G
# goFotIMdQ6HQUEU10XaDa8y7n3jtfaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBBU4j/D7Dl
# Xe91sUU8CUi6utWjcKDuilm7u/PqEdjptzANBgkqhkiG9w0BAQEFAASCAgBLMhcQ
# +N7yYK3vt+jzORWif+EY50ugeTuBg9SxF9y2FRC4Yl8QKTqwT9Nnjy4OKaym/eY2
# tvQp6WLDaKt9YdW0iE/Jk6Aym3BXLH4A9+PttNBq2jz3DMQmtJCOgkTBzIDLauw3
# r4wZJssTtgq2FX9x+RPCYoQLjla7aU0IzZl9J1OzQ7aok9SY0LM62vyRwAFz3loR
# c3ckuqtwqTNnkEaLriqLHupHZIaKQMlJeP5V2kIpmyvJMwYw+yCrw7PWklBnIvcn
# qf5saRn+5oEbcAhIHSpUNR/k2OEFeZUVKNxpZ7aQ9IcJDimsn6yKJM65FzQCTNne
# 7Xta+f2LOb8oeKyZMs9mPAQhYpF2wEgRd6urqMpYqaeVOSoe4s3TDLuqQQqYD0Ea
# l9lp0XK4gAcdwk8Ox/TeLLlUG/b8YRF8U7RishDGsOarebLGgzZGLPiTwBEXSvk9
# qyTEWvulHCz130vUfLO//JcoroOUBGQ0Y59sez9BFGlzrebr//Uhpq2gAlPvNkI1
# D7yTHIbfuRWgHRbZSz6SjMTapPUtCu9rWLOJJKGLCYHq+LxuGetWJZhVk9R7wYHS
# Lo7gk/c4o9JzQgRcePcckovNTzeDhq5cPWBkXjsSPpNW05ImZ67058wARjiiJIqQ
# Wmk56dVisaIkMr4XaKGRXhDmCp2/qxNp3T5nlqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTEwNDE5NDZaMC8GCSqGSIb3DQEJBDEiBCBrxU7CEbBnRjnhTtC/
# gjFdT/7lyXMbultLc0CaL1b8HDANBgkqhkiG9w0BAQEFAASCAgAruALJzrpj62OB
# uVXwEsO+tSCaMQDoar/t7euF9DgoH9dvMwqD4hCihR1XSaLlKocJa2M9BkgylMSN
# rykqrxpZESRtIectcJQm205r0QGEWROrxVF1fDxLJT3M/QHX4DCWIVV0oTMshAyF
# LfBaIKeDiPIWjjInayN0r/Fu30gpj0InF56hdMtUgtsFYDvPdiy/WCvmmkAf6477
# oNyroG5cw2+t3RJhlm+Wy3td1xhfHe4vakX+tjRDgJp11vpeqOTR1Jc/audPTrq9
# Wq+Gxy9RoF2imYS2mD+nsmIQ8tab65veC5PQNtrYfaFdYP3rBTIWgIXqD50XBeHi
# 5RrfsbLUQZTIJLeFt/x/3Rj6D8LD+2IFPM7BXd9GtEr5YYM9xrL/n36t87z5lPHX
# eoqYZ77cP70NhTYbtzUXwcCX3GO2T9Xqmv3ItQp8xbV/K9CoEXv9Wu9k/zEr4FwA
# /5+c6UIL7awI93zvrylYWYBf6nyelMNFKxvix+pqQYiN/7yZaA76l2WJi4eK3tK3
# Ywm+fbxsKNcG/JQ05vchoEKvN6S3DHkc2oBqr8r9OBOqHyLcXn1CU2w/oAp499Xy
# lgWfOKbiM07nyjLsNIClwspFkk7FNi7+DIsK69Okx8xRaUJOgvDhWHjtSTqJWMyp
# qakN1epQKhca7GtR/QID95w86jII0Q==
# SIG # End signature block
