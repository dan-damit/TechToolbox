
function Enable-NetFx3 {
    <#
    .SYNOPSIS
        Enables .NET Framework 3.5 (NetFx3) locally or on remote computers.

    .DESCRIPTION
        Local mode (default): runs on the current machine; enforces optional
        timeout via DISM path; returns exit 0 on success (including
        3010/reboot-required), 1 on failure (PDQ-friendly). Remote mode: when
        -ComputerName is provided, runs via WinRM using -Credential (or falls
        back to $script:domainAdminCred if not supplied). Returns per-target
        result objects (no hard exit).

    .PARAMETER ComputerName
        One or more remote computers to run against. If omitted, runs locally.

    .PARAMETER Credential
        PSCredential to use for remoting. If omitted and $script:domainAdminCred
        exists, it will be used. Otherwise remoting requires your current
        credentials to have access.

    .PARAMETER Source
        Optional SxS source for offline/WSUS-only environments. Prefer a UNC
        path for remoting (e.g., \\server\share\Win11\sources\sxs).

    .PARAMETER Quiet
        Reduce chatter (maps to NoRestart for cmdlet path; DISM already uses
        /Quiet).

    .PARAMETER NoRestart
        Do not restart automatically.

    .PARAMETER TimeoutMinutes
        For DISM path, maximum time to wait. Default 45 minutes. (Local:
        controls DISM path selection; Remote: enforced on target.)

    .PARAMETER Validate
        AAfter enablement, query feature state to confirm it is Enabled (best
        effort).

    .OUTPUTS
        Local: process exit code (0 or 1) via 'exit'. Remote: [pscustomobject]
        per target with fields ComputerName, ExitCode, Success, RebootRequired,
        State, Message.

    .EXAMPLE
        # Local machine, online
        Enable-NetFx3 -Validate

    .EXAMPLE
        # Local machine, offline ISO mounted as D:
        Enable-NetFx3 -Source "D:\sources\sxs" -Validate

    .EXAMPLE
        # Remote machine(s) with stored domain admin credential
        $cred = Get-DomainAdminCredential Enable-NetFx3 -ComputerName "PC01","PC02"
        -Credential $cred -Source "\\files\Win11\sources\sxs" -TimeoutMinutes 45
        -Validate
        # Returns per-target objects instead of a hard exit.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [string]$Source,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 45,
        [switch]$Validate
    )

    Initialize-TechToolboxRuntime
    Initialize-PrivateFunctions

    # If ComputerName provided → Remote mode
    if ($ComputerName -and $ComputerName.Count -gt 0) {
        # Resolve credential: explicit > module default > none
        if (-not $Credential -and $script:domainAdminCred) {
            $Credential = $script:domainAdminCred
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] Using module domainAdminCred for remoting."
        }

        # Warn if Source looks like a local drive path (prefer UNC for remote)
        if ($Source -and -not ($Source.StartsWith('\\'))) {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] -Source '$Source' is not a UNC path. Ensure it exists on EACH target."
        }

        Write-Log -Level 'Info' -Message "[Enable-NetFx3] Remote mode → targets: $($ComputerName -join ', ')"

        # Build the remote scriptblock (self-contained; no dependency on local functions)
        $sb = {
            param($src, $timeoutMinutes, $validate, $noRestart, $quiet)

            $ErrorActionPreference = 'Stop'
            $overallSuccess = $false
            $exit = 1
            $state = $null
            $msg = $null

            try {
                # Prefer DISM to enforce timeout and consistent exit code
                $argsList = @(
                    '/online',
                    '/enable-feature',
                    '/featurename:NetFx3',
                    '/All',
                    '/Quiet',
                    '/NoRestart'
                )
                if ($src) { $argsList += "/Source:`"$src`""; $argsList += '/LimitAccess' }

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'dism.exe'
                $psi.Arguments = ($argsList -join ' ')
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true

                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $psi

                if (-not $proc.Start()) {
                    $msg = "Failed to start DISM."
                    throw $msg
                }

                $proc.BeginOutputReadLine()
                $proc.BeginErrorReadLine()

                $timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, $timeoutMinutes)).TotalMilliseconds
                if (-not $proc.WaitForExit($timeoutMs)) {
                    try { $proc.Kill() } catch {}
                    $msg = "Timeout after $timeoutMinutes minutes."
                    $exit = 1
                }
                else {
                    $exit = $proc.ExitCode
                    if ($exit -in 0, 3010) {
                        $overallSuccess = $true
                    }
                    else {
                        $msg = "DISM failed with exit code $exit."
                    }
                }

                if ($overallSuccess -and $validate) {
                    try {
                        $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
                        if ($state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                            $overallSuccess = $false
                            if (-not $msg) { $msg = "Feature state after enablement: $state" }
                            if ($exit -in 0, 3010) { $exit = 1 } # normalize to failure if state isn't right
                        }
                    }
                    catch {
                        if (-not $msg) { $msg = "Validation failed: $($_.Exception.Message)" }
                    }
                }
            }
            catch {
                $msg = $_.Exception.Message
            }

            [pscustomobject]@{
                ComputerName   = $env:COMPUTERNAME
                ExitCode       = $exit
                Success        = [bool]$overallSuccess
                RebootRequired = ($exit -eq 3010)
                State          = $state
                Message        = $msg
            }
        }

        $icmParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $sb
            ArgumentList = @($Source, $TimeoutMinutes, [bool]$Validate, [bool]$NoRestart, [bool]$Quiet)
        }
        if ($Credential) { $icmParams.Credential = $Credential }

        $results = Invoke-Command @icmParams

        # Log summary and return objects (no hard exit in remote mode)
        foreach ($r in $results) {
            if ($r.Success) {
                if ($r.RebootRequired) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Success (reboot required)."
                }
                else {
                    Write-Log -Level 'Ok' -Message "[Enable-NetFx3][$($r.ComputerName)] Success."
                }
            }
            else {
                $tail = if ($r.Message) { " - $($r.Message)" } else { "" }
                Write-Log -Level 'Error' -Message "[Enable-NetFx3][$($r.ComputerName)] Failed (Exit $($r.ExitCode))$tail"
            }
        }

        return $results
    }

    # ----------------------------
    # Local mode (original logic)
    # ----------------------------
    Write-Log -Level 'Info' -Message "[Enable-NetFx3] Starting enablement (local)."

    $params = @{
        Online      = $true
        FeatureName = 'NetFx3'
        All         = $true
    }
    if ($PSBoundParameters.ContainsKey('Source') -and $Source) {
        $params.Source = $Source
        $params.LimitAccess = $true  # Avoid WU/WSUS when explicit source is provided
    }
    if ($Quiet) { $params.NoRestart = $true }
    if ($NoRestart) { $params.NoRestart = $true }

    $useDirectDism = ($TimeoutMinutes -gt 0)
    Write-Log -Level 'Info'  -Message "[Enable-NetFx3] Enabling .NET Framework 3.5 (NetFx3)..."
    Write-Log -Level 'Debug' -Message ("[Enable-NetFx3] Using {0} path." -f ($(if ($useDirectDism) { 'DISM (timeout)' } else { 'Enable-WindowsOptionalFeature' })))

    $overallSuccess = $false
    $dismExit = $null

    try {
        if (-not $useDirectDism) {
            $result = Enable-WindowsOptionalFeature @params -ErrorAction Stop
            Write-Log -Level 'Ok' -Message "[Enable-NetFx3] State: $($result.State)"
            $overallSuccess = $true
        }
        else {
            $argsList = @(
                '/online', '/enable-feature', '/featurename:NetFx3', '/All', '/Quiet', '/NoRestart'
            )
            if ($params.ContainsKey('Source')) {
                $argsList += "/Source:`"$($params.Source)`""
                $argsList += '/LimitAccess'
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'dism.exe'
            $psi.Arguments = ($argsList -join ' ')
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi

            if (-not $proc.Start()) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed to start DISM."
                exit 1
            }

            $proc.add_OutputDataReceived({ param($s, $e) if ($e.Data) { Write-Log -Level 'Info' -Message $e.Data } })
            $proc.add_ErrorDataReceived( { param($s, $e) if ($e.Data) { Write-Log -Level 'Warn' -Message $e.Data } })
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()

            $timeoutMs = [int][TimeSpan]::FromMinutes($TimeoutMinutes).TotalMilliseconds
            if (-not $proc.WaitForExit($timeoutMs)) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Timeout after $TimeoutMinutes minutes. Attempting to terminate DISM..."
                try { $proc.Kill() } catch {}
                exit 1
            }

            $dismExit = $proc.ExitCode
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] DISM exit code: $dismExit"

            if ($dismExit -in 0, 3010) {
                $overallSuccess = $true
                if ($dismExit -eq 3010) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Reboot required to complete NetFx3 enablement."
                }
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] DISM reported failure."
            }
        }
    }
    catch {
        Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed: $($_.Exception.Message)"
        $overallSuccess = $false
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
            Write-Log -Level 'Info' -Message "[Enable-NetFx3] Feature state: $state"
            if ($state -in 'Enabled', 'EnablePending', 'EnabledPending') {
                Write-Log -Level 'Ok' -Message "[Enable-NetFx3] NetFx3 enablement validated."
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] NetFx3 state not enabled after operation."
                $overallSuccess = $false
            }
        }
        catch {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Validation skipped: $($_.Exception.Message)"
        }
    }

    if ($overallSuccess) { exit 0 } else { exit 1 }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDoUspvsHiSL+DG
# fLeA5pVynL+B1L85AaWziBkepDVWbqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAuyw4kEPop
# D76P5TTHi+8haKAA4AW397SsudlcjfF2XTANBgkqhkiG9w0BAQEFAASCAgBXW5hX
# WK3NMl659DtLeyPvLnD53M/qeL0uJb68NZdMpn06RM2QSnqvBln8kSM8VHIfSMzO
# 5orN14eEpJW0d/qJG6568x10bMaY6N8zWDbnS1ovMHmZAKMo9h838oiGkXf12FEY
# +6Zma87VvsDIPd7X55/tbxeC2UCwQFYkSx6+/wWfdpOBhk/02MZ8BV5AjgzCumsR
# v0hQUogAVwXg27UjuGLKRy2KDcrFXGWnXXnEXA7vewCQacXelTGPuUi9cA45pWnT
# /OqWJmTbGc2HWI0dkAkzD9NuhOK1peiRjiD49Gi94q8sLmyW3KQenZ5L+GXCrfoX
# xyx0bwZs/MePmUk79psxMZI1QBtbzoRtizkT8sagAyZlERgkFXztS7tPxwDv5CIZ
# iKXTx+PUhozMGCWw0HPFgR/up4FzfuSlVY1XB/FcoxkGbZs9rD3MaMXqmThheME/
# lojy2Av8hP1uTYNfQB67U0pjpaDmQx8bWPQA6qv2jJgJmZqgKNtmFZ2IpK0mJWJF
# 6/oMYgt1pg+EjyThCO/DtmPTsyJyG9eFWwHZ+XILybwAdAtC8LXhAhsAIq7g48Ce
# bE6q5+Om4MFpIVbHrv7NfW2al0IkZrm0iBeevbWLtwdROtkGDL4pKU3KhZaDOEM4
# 2MRosTqonRJmZHjMmZCZu4p1wB2sH3PbapYxr6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMTEwMDQ3MDNaMC8GCSqGSIb3DQEJBDEiBCDKBsG8BWy4NZa2IHWo
# 0h4c0+Hd6Cqo/w/jOLnwDksC4TANBgkqhkiG9w0BAQEFAASCAgBDYxCEs4JPStoz
# Q17VpiFETaU3VRKV0Xfp0ZMJtitO1AOylSOZn7aep4fKBDGdAStFLLDSuIN8s+/F
# qtlEHYGNsxmIF2urW2q+lLVjk1d4TLsCCu4Fk64e/Klj4VN7Vd3xvV+1hVl/uuqa
# t7oDw5fSFNeE9EE/Jt2ok/uqxEl1OHrCSrtuxeHtTNo7KC0r3zRNaBidIqB9bPs4
# r4iKkIW9TU/cmnkVAEpFiRLGJuzTlj0ATiKLusYnDwohLhU5OCbbEcx54YzZL3RZ
# W7bm5dSoamPus8VO2kOEbgmqXbG50v5jU79bJpDpEPdPfobKPkTy3sreR+k8WBuf
# z0X2/FcmyQdhLe4RGm7DJZaL1/1VYf62XdwFEHJbhZm+jSNLM3N8fjir4SFt+mo+
# guILHPYz/7yON0FveK5R0YCwizrij4rdnBq+IN9MX77KzOJzOy354/qfCTE5b3rJ
# rQWZf7vzDyhcNmgpDeyUomhVq3UInckCEF3ymrc2trTcuAOlWX9P5WV+PuXTSrc2
# t2ouD5IgGrwYwTliUIyxqwOjt0rcXjz1i8EsniZfkDyOMFxD2YW7L4qYRK5/5duB
# Jj9/IloerAhPI7HQJLL0OtwCOahwGW7Z1K8lUpRYlkpApicBqJ6ojdbgAwmMJvch
# lvM4ZvvdG6nckQuh4Ma+X7rbJ4RR5w==
# SIG # End signature block
