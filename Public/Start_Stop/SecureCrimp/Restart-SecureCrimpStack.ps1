function Restart-SecureCrimpStack {
    <#
    .SYNOPSIS
        Restarts the Secure Crimp stack on a remote server.
    .DESCRIPTION
        This function stops and starts the Secure Crimp backend and frontend
        services on a specified remote server.
    .PARAMETER Server
        The remote server to connect to. Default comes from
        settings.secureCrimp.server in config.json.
    .PARAMETER Credential
        The credentials to use for the remote session.
    .PARAMETER TaskList
        The list of scheduled tasks to restart. Default comes from
        settings.secureCrimp.stackTasks in config.json.
    .PARAMETER BackendPorts
        The list of backend ports to check and stop processes on.
    .PARAMETER FrontendPorts
        The list of frontend ports to check and stop processes on.
    .PARAMETER StopTimeoutSec
        The timeout in seconds to wait for tasks to stop.
    .PARAMETER SleepSeconds
        The number of seconds to sleep between operations.
    #>
    [CmdletBinding()]
    param(
        [string]$Server,
        [pscredential]$Credential,

        # Start backend first (avoids nginx proxying to a dead upstream)
        [string[]]$TaskList = @("Secure Crimp - Run Server", "Secure Crimp - Nginx"),

        [int[]]$BackendPorts = @(5000, 8000),
        [int[]]$FrontendPorts = @(80, 443),

        [int]$StopTimeoutSec = 20,
        [int]$SleepSeconds = 2,
        [int]$StartValidationSec = 15,
        [int]$StartValidationPollMs = 500
    )

    Initialize-TechToolboxRuntime

    $secureCrimpCfg = $null
    if ($script:cfg -and $script:cfg.settings) {
        $secureCrimpCfg = $script:cfg.settings.secureCrimp
    }

    if (-not $PSBoundParameters.ContainsKey('Server')) {
        $configuredServer = [string]$secureCrimpCfg.server
        if (-not [string]::IsNullOrWhiteSpace($configuredServer)) {
            $Server = $configuredServer
        }
    }

    if (-not $PSBoundParameters.ContainsKey('TaskList')) {
        $configuredTaskList = @($secureCrimpCfg.stackTasks | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($configuredTaskList.Count -gt 0) {
            $TaskList = @($configuredTaskList)
        }
    }

    $sessParams = @{ ComputerName = $Server }
    if ($PSBoundParameters.ContainsKey('Credential')) { $sessParams.Credential = $Credential }
    $writeTaskLogShimSource = Get-RemoteWriteTaskLogShimSource

    $session = $null
    try {
        $session = Start-NewPSRemoteSession @sessParams

        Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $TaskList, $BackendPorts, $FrontendPorts, $StopTimeoutSec, $SleepSeconds, $StartValidationSec, $StartValidationPollMs, $writeTaskLogShimSource -ScriptBlock {
        param($TaskList, $BackendPorts, $FrontendPorts, $StopTimeoutSec, $SleepSeconds, $StartValidationSec, $StartValidationPollMs, $WriteTaskLogShimSource)

        . ([ScriptBlock]::Create($WriteTaskLogShimSource))

        function Stop-ProcessByPort {
            param([int[]]$Ports)

            foreach ($port in $Ports) {
                $pids = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -eq $port } |
                Select-Object -ExpandProperty OwningProcess -Unique

                foreach ($processId in $pids) {
                    if (-not $processId -or $processId -eq 0) { continue }
                    try {
                        $proc = Get-Process -Id $processId -ErrorAction Stop
                        Write-TaskLog -Level "INFO" -Message "Stopping PID $processId ($($proc.ProcessName)) owning port $port"
                        Stop-Process -Id $processId -Force -ErrorAction Stop
                    }
                    catch {
                        Write-TaskLog -Level "WARN" -Message "Failed stopping PID $processId for port ${port}: $($_.Exception.Message)"
                    }
                }
            }
        }

        function Restart-LongRunningTask {
            param(
                [Parameter(Mandatory)][string]$TaskName,
                [int]$TimeoutSec = 20,
                [int]$ValidationSec = 15,
                [int]$ValidationPollMs = 500
            )

            try {
                $null = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            }
            catch {
                Write-TaskLog -Level "ERROR" -Message "Scheduled task not found: '$TaskName'"
                return $false
            }

            try {
                $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
                if ($info.State -eq 'Running') {
                    Write-TaskLog -Level "INFO" -Message "Stopping scheduled task: $TaskName"
                    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Milliseconds 500
                        $info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
                    } while ($info -and $info.State -eq 'Running' -and $sw.Elapsed.TotalSeconds -lt $TimeoutSec)

                    if ($info -and $info.State -eq 'Running') {
                        Write-TaskLog -Level "WARN" -Message "Task still Running after $TimeoutSec sec: $TaskName (continuing to Start anyway)"
                    }
                    else {
                        Write-TaskLog -Level "INFO" -Message "Task stopped: $TaskName"
                    }
                }

                Write-TaskLog -Level "INFO" -Message "Starting scheduled task: $TaskName"
                Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop

                $startWatch = [Diagnostics.Stopwatch]::StartNew()
                $post = $null
                do {
                    Start-Sleep -Milliseconds $ValidationPollMs
                    $post = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue

                    if (-not $post) {
                        continue
                    }

                    if ($post.State -eq 'Running') {
                        Write-TaskLog -Level "INFO" -Message "Task healthy: $TaskName :: Running"
                        return $true
                    }

                    if ($post.State -eq 'Ready' -and $post.LastTaskResult -eq 0) {
                        Write-TaskLog -Level "INFO" -Message "Task healthy: $TaskName :: Ready (LastTaskResult: 0)"
                        return $true
                    }

                    if ($post.State -eq 'Ready' -and $post.LastTaskResult -ne 0) {
                        Write-TaskLog -Level "ERROR" -Message "Task unhealthy after start: $TaskName :: Ready (LastTaskResult: $($post.LastTaskResult))"
                        return $false
                    }
                } while ($startWatch.Elapsed.TotalSeconds -lt $ValidationSec)

                if ($post) {
                    if ($post.State -eq 'Running') {
                        Write-TaskLog -Level "INFO" -Message "Task healthy after wait: $TaskName :: Running"
                        return $true
                    }

                    if ($post.State -eq 'Ready' -and $post.LastTaskResult -eq 0) {
                        Write-TaskLog -Level "INFO" -Message "Task healthy after wait: $TaskName :: Ready (LastTaskResult: 0)"
                        return $true
                    }

                    Write-TaskLog -Level "ERROR" -Message "Task did not become healthy after start: $TaskName :: State=$($post.State), LastTaskResult=$($post.LastTaskResult)"
                    return $false
                }

                Write-TaskLog -Level "ERROR" -Message "Task info unavailable after start: $TaskName"
                return $false
            }
            catch {
                Write-TaskLog -Level "ERROR" -Message "Failed restarting task '$TaskName': $($_.Exception.Message)"
                return $false
            }
        }

        # Stop backend first, then nginx
        Write-TaskLog -Level "INFO" -Message "Stopping backend by ports: $($BackendPorts -join ', ')"
        Stop-ProcessByPort -Ports $BackendPorts
        Start-Sleep -Seconds $SleepSeconds

        Write-TaskLog -Level "INFO" -Message "Stopping frontend by ports: $($FrontendPorts -join ', ')"
        Stop-ProcessByPort -Ports $FrontendPorts
        Start-Sleep -Seconds $SleepSeconds

        # Restart tasks (long-running safe)
        $failedTasks = [System.Collections.Generic.List[string]]::new()
        foreach ($t in $TaskList) {
            Write-TaskLog -Level "INFO" -Message "Restarting task: $t"
            $ok = Restart-LongRunningTask -TaskName $t -TimeoutSec $StopTimeoutSec -ValidationSec $StartValidationSec -ValidationPollMs $StartValidationPollMs
            if (-not $ok) {
                $failedTasks.Add($t) | Out-Null
            }
            Start-Sleep -Seconds $SleepSeconds
        }

        if ($failedTasks.Count -gt 0) {
            throw "SecureCrimp stack task restart failed for: $($failedTasks -join ', ')"
        }

        # Verify ports are listening again
        Start-Sleep -Seconds 3
        $expected = @($BackendPorts + $FrontendPorts) | Sort-Object -Unique
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in $expected } |
        Select-Object -ExpandProperty LocalPort -Unique

        $missing = $expected | Where-Object { $_ -notin $listening }
        if ($missing) {
            Write-TaskLog -Level "WARN" -Message "Restart finished but ports not listening yet: $($missing -join ', ')"
        }
        else {
            Write-TaskLog -Level "INFO" -Message "Restart successful. Ports listening: $($expected -join ', ')"
        }
        }
    }
    finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDDwc2b8wArMH3W
# j+f7UiRgCqZmyZgfCyu3grq7+9wvfKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCArrCa8Aimo
# tSnQpyWH+/HvArQLvc/d1sG3zF+wqsAm8DANBgkqhkiG9w0BAQEFAASCAgDQk4jL
# UBcS/KoAS50r7DKzfW4rcAnpOXWkiI+nednP0tDd8xpqPdag+FFHvL5opHpM4Mzd
# 3Fa6QDBwvx4BauoEZmPrguzgyvVyEj1tB8IvofQ6eSxNSE4H1WYs8Z1LNahLzB68
# FBNTjfRs8d9laZqv4UmhPnWJfi9meM4zUt8Td8Hm74nSEJnUsT0Uwu0qbstegvx6
# 1nG2bLmVv5WVk+ovxA/Homt80SxH9F4RJueWFuFHAgIhrgUPzsrtduIlOkgS1TJb
# IErJeR2q2ChN2jDIvUAcjtAZsknrYR/XC5/u7JMKuYRvDp9T2dYePdn4l1os9a8t
# VJKf4B1e/wIRWIFCMni+XHszUv8MOmfw6oLpNCzroid993LhlQel3DEiHLdh8ZGl
# bUxnZIv7qhGps7wifx5Z2MZ3IVawacIfNtAxeTDns9nC1lAv8J7xRqWu5+stOJop
# Tp0PAa/LePgwaR1cUoBhYdwnkyg6UBHTXLhM1STqtVEzzzHCwCuMNwKhDCdPilHR
# dl75UPWr8amiK5ic1FQvKWmn7K+M4edFUwzCALDDwg0GVYvpLtSZlkOP4CnoFq9T
# oMvfkYVxgJHacYFkTOb6StgxoitoBEYHDX/elnW3xq6Qf30JTAE4Ozwa+fDYnO2E
# yakiOhyDHcUFMkzZGShV3fRskHCe38mAmHx4maGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA2MDQyMTEwNDJaMC8GCSqGSIb3DQEJBDEiBCBvh13/amgeTW53SYuj
# yw+MIIRqgHkZmf8kot3/eaz+ezANBgkqhkiG9w0BAQEFAASCAgCtdFsC9W8TgfoN
# pPG26aeL5YjK16wZB61C9ny0AK3cuh+pBfSwVwrOhmACai0ODN14oklyItkWFt66
# gFFMwXQwhzzpOXHpjMTSXf3hte3dNOmc0iNrRcLLSWMJMHiXZS9Cqtb57IBc5TV5
# q/3TSvRFxBIjp2kbSrnoEwPQ4FRIgUQJU2nONp3m1o2FFu6OEQfuf1vAc3jmhAlv
# JYe6uf2GH5t1PMH/TQPYvXnC/Z1bK0vfzS+8BkgD6JDz5t+SqzxPKcWkiqDaTJO3
# G+ldW7LyG8Lc/Bx6AunsNFGQa9zXV/0G/c2/YXxyJypwNz+vDvgON6Ndnq9a/erV
# xa+crSww8UvjoVaID7qFda07oo5pKuSiqR+eZKQBCYl/XuseYWYtDVQJP0m1bK1/
# dfHoaSxrN6pwBpDPj2/+0b6hgJC7Bss3lC4RmUQaUwpow4klS6JfNITjkRhXMM7b
# I5c1DnTAj7ew8Qw6pG6YJCwcCIKmeG8ZsZlV/z+gI4J5zt0xCLltPARa2RTkQ7br
# cCNWKW06x87tRBVJwzbYInks+OqsDJ6BKDCNVNVXQAP4/S72N/0iAJ8iSUfh3b+o
# GldB+hxcY/MWqDKf4C1f7QUi8mcbA8ovC3+V8ePnL/KVNtqUIB5+gcKb6mlf6Qso
# 4qITD9T9Y2CaK85HodlQeDx0bwEuRQ==
# SIG # End signature block
