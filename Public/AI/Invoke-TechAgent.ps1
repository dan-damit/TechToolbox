function Invoke-TechAgent {
    <#
    .SYNOPSIS
        Sends a prompt to the TechToolbox local agent.

    .DESCRIPTION
        This function calls the Python-based agent located in AI/Agent/.
        It passes the user prompt and prints the agent's response.

    .PARAMETER Prompt
        The natural-language instruction for the agent.

    .PARAMETER Model
        Optional Ollama model name (for example: llama3, mistral, qwen2.5-coder).

    .PARAMETER MaxIterations
        Maximum number of tool/reasoning iterations before the agent concludes.

    .PARAMETER Quiet
        Legacy compatibility switch. Agent traces are now suppressed by default.

    .PARAMETER ConfirmDestructive
        Explicitly authorizes destructive operations for this run.

    .EXAMPLE
        Invoke-TechAgent "Run system diagnostics and summarize findings."
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Model,

        [Parameter()]
        [ValidateRange(1, 500)]
        [int]$MaxIterations = 15,

        [Parameter()]
        [switch]$Quiet,

        [Parameter()]
        [switch]$ConfirmDestructive
    )

    # Initialize the TechToolbox runtime and load agent configuration
    Initialize-TechToolboxRuntime
    $cfg = $script:cfg.settings.agent
    if ([string]::IsNullOrWhiteSpace($Model) -and $cfg -and -not [string]::IsNullOrWhiteSpace($cfg.model)) {
        $Model = $cfg.model
    }

    $waitTimeoutSeconds = [Math]::Max(300, ($MaxIterations * 180))
    $waitPollSeconds = 5
    $waitHeartbeatSeconds = 60

    if ($cfg -and $cfg.wait) {
        $timeoutCfg = $cfg.wait.timeoutSeconds -as [int]
        if ($null -ne $timeoutCfg -and $timeoutCfg -gt 0) {
            $waitTimeoutSeconds = $timeoutCfg
        }

        $pollCfg = $cfg.wait.pollSeconds -as [int]
        if ($null -ne $pollCfg -and $pollCfg -gt 0) {
            $waitPollSeconds = $pollCfg
        }

        $heartbeatCfg = $cfg.wait.heartbeatSeconds -as [int]
        if ($null -ne $heartbeatCfg -and $heartbeatCfg -ge 0) {
            $waitHeartbeatSeconds = $heartbeatCfg
        }
    }

    $agentProc = $null

    try {
        # Resolve agent path from module root (Public/AI is not the module root).
        $moduleRoot = Get-ModuleRoot
        $agentPath = Join-Path $moduleRoot 'AI\Agent\tech_agent.py'

        if (-not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
            throw "Tech agent entry script not found: $agentPath"
        }

        $pythonCommand = $null
        $pythonArgsPrefix = @()

        # Prefer repo-local virtual environment for deterministic dependencies.
        $venvPython = Join-Path $moduleRoot '.venv\Scripts\python.exe'
        if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
            $pythonCommand = @{ Source = $venvPython }
        }

        if (-not $pythonCommand) {
            $pythonCommand = Get-Command -Name python -ErrorAction SilentlyContinue
        }

        if (-not $pythonCommand) {
            $pythonCommand = Get-Command -Name py -ErrorAction SilentlyContinue
            if ($pythonCommand) {
                $pythonArgsPrefix = @('-3')
            }
        }

        if (-not $pythonCommand) {
            throw "Python executable not found. Install Python or add it to PATH (python/py)."
        }

        if (-not [string]::IsNullOrWhiteSpace($Model)) {
            $ollamaCommand = Get-Command -Name ollama -ErrorAction SilentlyContinue
            if (-not $ollamaCommand) {
                throw "Ollama executable not found. Install Ollama or add it to PATH."
            }

            $ollamaListOutput = & $ollamaCommand.Source list 2>&1
            if ($LASTEXITCODE -ne 0) {
                $ollamaError = ($ollamaListOutput | Out-String).Trim()
                throw ("Unable to query local Ollama models: {0}" -f $ollamaError)
            }

            $availableModels = @()
            foreach ($line in $ollamaListOutput) {
                $trimmed = "$line".Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) {
                    continue
                }

                if ($trimmed -match '^NAME\s+') {
                    continue
                }

                $parts = $trimmed -split '\s+'
                if ($parts.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($parts[0])) {
                    $availableModels += $parts[0]
                }
            }

            if (-not $availableModels) {
                throw ("No local Ollama models were found. Pull the requested model first: ollama pull {0}" -f $Model)
            }

            if ($availableModels -notcontains $Model) {
                $knownModels = ($availableModels | Sort-Object -Unique) -join ', '
                throw (
                    "Ollama model '{0}' is not available locally. Run: ollama pull {0}. Available models: {1}" -f $Model, $knownModels
                )
            }
        }

        Write-Log -Level Info -Message ("Invoking local tech agent: {0}" -f $agentPath)

        $pythonArgs = @()
        $pythonArgs += $pythonArgsPrefix
        $pythonArgs += @($agentPath, '--prompt', $Prompt, '--max-iterations', $MaxIterations)

        if (-not [string]::IsNullOrWhiteSpace($Model)) {
            $pythonArgs += @('--model', $Model)
        }

        # Suppress LangChain/LangGraph debug traces by default so the console only shows
        # the agent's final response instead of raw model metadata.
        $pythonArgs += '--quiet'

        if ($ConfirmDestructive.IsPresent) {
            Write-Log -Level Warn -Message 'Destructive operations explicitly authorized for this run.'
            $pythonArgs += '--destructive-confirmed'
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = [string]$pythonCommand.Source
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.Environment['PYTHONIOENCODING'] = 'utf-8'

        foreach ($arg in $pythonArgs) {
            [void]$startInfo.ArgumentList.Add([string]$arg)
        }

        $agentProc = [System.Diagnostics.Process]::new()
        $agentProc.StartInfo = $startInfo
        if (-not $agentProc.Start()) {
            throw "Failed to start Python process for tech agent."
        }

        $agentDeadline = (Get-Date).AddSeconds($waitTimeoutSeconds)
        $agentState = [ordered]@{
            TimedOut = $false
        }

        $poll = {
            if (-not $agentProc.HasExited) {
                if ((Get-Date) -ge $agentDeadline) {
                    $agentState.TimedOut = $true
                    try { $agentProc.Kill() } catch { }
                    return @{ Status = 'Timeout' }
                }

                return @{ Status = 'Running' }
            }

            $stdoutText = ''
            $stderrText = ''

            try { $stdoutText = [string]$agentProc.StandardOutput.ReadToEnd() } catch { }
            try { $stderrText = [string]$agentProc.StandardError.ReadToEnd() } catch { }

            return @{
                Status = 'Done'
                Code   = [int]$agentProc.ExitCode
                StdOut = $stdoutText
                StdErr = $stderrText
            }
        }

        $getStatus = {
            param($obj)

            switch ($obj.Status) {
                'Timeout' { return 'Timeout' }
                'Done' {
                    if ($obj.Code -eq 0) { return 'Success' }
                    return 'Error'
                }
                default { return 'Running' }
            }
        }

        $terminal = @{
            'Success' = @{ Level = 'Ok'; Message = 'Tech agent completed successfully.'; Return = $true }
            'Error'   = @{ Level = 'Error'; Message = { param($obj, $status) "Tech agent failed with exit code $($obj.Code)." }; Return = $true }
            'Timeout' = @{ Level = 'Error'; Message = "Tech agent timed out after ${waitTimeoutSeconds} seconds."; Return = $true }
        }

        $final = Wait-TerminalState `
            -Target 'TechAgent' `
            -PollScript $poll `
            -GetStatus $getStatus `
            -TerminalStates $terminal `
            -TimeoutSeconds ($waitTimeoutSeconds + 60) `
            -PollSeconds $waitPollSeconds `
            -HeartbeatSeconds $waitHeartbeatSeconds `
            -NotFoundMessage 'Tech agent process not discovered yet...' `
            -WaitingMessage 'Tech agent working '

        if ($agentState.TimedOut) {
            throw ("Tech agent timed out after {0} seconds." -f $waitTimeoutSeconds)
        }

        if ([int]$final.Code -ne 0) {
            $errorText = [string]$final.StdErr
            if ([string]::IsNullOrWhiteSpace($errorText)) {
                $errorText = [string]$final.StdOut
            }
            $errorText = $errorText.Trim()
            throw ("Tech agent exited with code {0}: {1}" -f $final.Code, $errorText)
        }

        $message = ([string]$final.StdOut).Trim()
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = 'Tech agent completed successfully with no output.'
        }

        return $message
    }
    catch {
        Write-Log -Level Error -Message ("Invoke-TechAgent failed: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        if ($agentProc -and -not $agentProc.HasExited) {
            try { $agentProc.Kill() } catch { }
        }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCObga0xXf/zZVT
# ZWREIGfGEzxjasHXeWnCQwSWqj4h1aCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCzGcilv2VF
# llnimpc5F6eKScysi6Os7uJ+ISP9F9boGzANBgkqhkiG9w0BAQEFAASCAgBFVOkm
# b/dATW+5iCxWkESKMRr2J+QEQYelfcQxgD6TBgMTM9JCnwwEOfBPTOLV+7jUe+MT
# T+lsYCjrTDGQyEOnVgS/EpX46E+Bb9e/o7xADd0jVX/oDuFmhMarqrEqjkOHu9L1
# lKJOk+tiLijzLTzWgKhWWqpY/H50MbF0E3zXsPR9DB/+IOjuMiZI4pGzzlgb4L36
# 77ciZkk1PRErFhD+zizAEsQGAlOuRU+Ag3ZvxAAd8wOq35G1eptVx15pKpbqZHxB
# EgENi9YLoBBqqE5wyDm9yZMzn8pFSIGEvEgjyQ9DMPblnUUQxxN9THnJ5Bj7hmdC
# KN41TURxtw4bQmeZlH2AgYhvOGMuNqhsfJFdM5DUuJAQV1TFDM4il4+8XGcK0Ujz
# ZJ/QDGOBcb1IagQOGDdMaDaWhFFAYI0rdXWXNDDfo9sqlin1f1vyol0dNDXIb/p2
# +qmKX5HWW94QhHclPq2NHcs8bYrw0c5Xe8oXf6kj2JJ6fke+r0CW7roG8kmyT9tw
# TFKqgl5xriXyqB5rIpypD9Q35tkB7NRYviovjwP1WhFBPYIvfkF+zNpu/qf2kQ6C
# x6hlpJPqsiVZANdltFfe6hpnG+sW6F73j97nhzxuGow5wC1EMQDQjcpuQNGN6qxR
# B5jwa6mZW8okN6lM8UYP2S9dO8CfEGyS5KFBc6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA1MDIxNDQ0MDhaMC8GCSqGSIb3DQEJBDEiBCDD9kztiXQbT91T+hG9
# 4x1rqXh0HEBxbrOPHzUtIs8jfjANBgkqhkiG9w0BAQEFAASCAgAN95NnIrHKMCA3
# KwlZAyqsRp1oJwc7rHTvdWBhyeaKYuafX0ZG4r0XkOCnBfDUkG5kzJtfKWsnK2LT
# bZE2C2/H1HYTnH9Go05sAQmMd/+cMqUaYnKCrx3a6M4lh2VOcAG0r7pwbhcH/9Aq
# +T2UwM1vQyij9dfLM1RDFDAAuJ72QFXd2Km3vQU2d9OtDaFHqkH8Kax/q+m4b3pV
# umrY/bMP/q43SXVyRV7l5CtWXmP2V75Ua6sij0z2pKvWG27JVFyNIDtcyXOLUOaD
# jVHn/wTGApNbLVdePKY81i4MkhY56e2xoV78zFrIMJILKCcG/Q7SV+yeYESlyzsm
# HDzTZAthfwQHjBTSG0bjKl9ULL++zINnuWu9g2+ih+MWPwcr4zAZMweASKhXY5lY
# 721djIuszLMNFFaZnlnOqlBX0YDSZeDsfnFcOoEfFF4911UPMghzNiKHiYOcWLIv
# 03FEq4vGmEF3ErXHLZm1BrCfVhb+yBPcZK/XZzGDPNdEOrWrKFpHRBKPVtu6nD/Z
# BU8/0Xfq8C1J9LtsvcIDqpxyhixjL/zQoPUwwofR+c91/CcZjDndiQejJ/Ai+qHY
# jCFvJ5KkG+0WHGYFUPt2otLwXo4oYgrFa/PxE3hFXSlTbDpgLPEF82vIpk/Km4V6
# u2tMFQDklU+p5A9tRKgsNtajCyngCA==
# SIG # End signature block
