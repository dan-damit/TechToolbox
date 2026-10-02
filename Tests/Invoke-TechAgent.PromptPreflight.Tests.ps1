Describe "Invoke-TechAgent Prompt Preflight" {
    BeforeAll {
        Import-Module -Name "$PSScriptRoot/../TechToolbox.psd1" -Force -ErrorAction Stop
    }

    It "Does not emit common false warnings for conversational weather prompts" {
        InModuleScope TechToolbox {
            $result = Invoke-TTAgentPromptPreflight `
                -PromptText "Please check the weather for today and tomorrow in Green Bay Wisconsin. Output the details to console in markdown." `
                -Mode "chat"

            $result.Critical.Count | Should -Be 0
            $result.Warnings | Should -Not -Contain "Missing clear task verb (for example: update, analyze, fix, plan)."
            $result.Warnings | Should -Not -Contain "Missing concrete target (file, function, module, system, URL, website, or path)."
            $result.Warnings | Should -Not -Contain "Missing explicit constraints or preferences (style, safety, formatting, scope)."
            $result.Score | Should -BeGreaterThan 40
        }
    }

    It "Still warns for truly ambiguous short prompts" {
        InModuleScope TechToolbox {
            $result = Invoke-TTAgentPromptPreflight -PromptText "help with this?" -Mode "chat"

            $result.Warnings | Should -Contain "Missing clear task verb (for example: update, analyze, fix, plan)."
            $result.Warnings | Should -Contain "Missing concrete target (file, function, module, system, URL, website, or path)."
            $result.Critical | Should -Contain "Prompt is too short for reliable execution."
        }
    }

    It "Accepts read-only web research prompts as concrete targets in execute mode" {
        InModuleScope TechToolbox {
            $result = Invoke-TTAgentPromptPreflight `
                -PromptText "Use the web search tool to find the official Green Bay Packers 2026 schedule, then output the schedule to console in markdown." `
                -Mode "execute"

            $result.Critical.Count | Should -Be 0
            $result.Warnings | Should -Not -Contain "Missing concrete target (file, function, module, system, URL, website, or path)."
            $result.Warnings | Should -Not -Contain "Missing clear task verb (for example: update, analyze, fix, plan)."
            $result.Warnings | Should -Not -Contain "Missing expected outcome details (what successful output should look like)."
        }
    }

    It "Accepts direct research-and-print prompts in execute mode" {
        InModuleScope TechToolbox {
            $result = Invoke-TTAgentPromptPreflight `
                -PromptText "Research the Green Bay Packers 2026 schedule from the official NFL website and print a markdown summary to the console." `
                -Mode "execute"

            $result.Critical.Count | Should -Be 0
            $result.Warnings | Should -Not -Contain "Missing clear task verb (for example: update, analyze, fix, plan)."
            $result.Warnings | Should -Not -Contain "Missing expected outcome details (what successful output should look like)."
        }
    }

    It "Formats tool traces with source attribution for MCP and built-in tools" {
        InModuleScope TechToolbox {
            $toolTrace = Convert-TTAgentToolTrace -ToolNames @(
                'SEARCH-WEB',
                'mcp.tavily.search',
                'READ-FILE'
            )

            $toolTrace | Should -Contain 'SEARCH-WEB [Built-in web tool]'
            $toolTrace | Should -Contain 'mcp.tavily.search [MCP]' 
            $toolTrace | Should -Contain 'READ-FILE [Built-in file/system tool]'
        }
    }

    It "Collapses adjacent duplicate long lines in agent output" {
        InModuleScope TechToolbox {
            $input = @(
                'Clarification needed: I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.',
                'Clarification needed: I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.'
            ) -join "`n"

            $result = Remove-TTAgentAdjacentDuplicateLines -Text $input -MinimumLineLength 24

            $result | Should -Be 'Clarification needed: I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.'
        }
    }

    It "Preserves adjacent duplicate short lines when below minimum length" {
        InModuleScope TechToolbox {
            $input = @('ok', 'ok') -join "`n"

            $result = Remove-TTAgentAdjacentDuplicateLines -Text $input -MinimumLineLength 24

            $result | Should -Be $input
        }
    }

    It "Infers expected output path from directory and named-file phrasing" {
        InModuleScope TechToolbox {
            $tempRoot = Join-Path -Path $env:TEMP -ChildPath ('tt-agent-path-parse-' + [guid]::NewGuid().ToString('N'))
            $prompt = "Please create a PowerShell script. Output the script to $tempRoot and name the file Invoke-RebootRemoteHost.ps1"

            $resolved = Resolve-TTAgentExpectedOutputPath -PromptText $prompt

            $resolved | Should -Be (Join-Path -Path $tempRoot -ChildPath 'Invoke-RebootRemoteHost.ps1')
        }
    }

    It "Combines a directory sentence with a separate Name the script phrase" {
        InModuleScope TechToolbox {
            $prompt = 'Please create a PowerShell script. Output the script to C:\\repos\\TechToolbox\\Bin. Name the script `Invoke-RemoteRebootHost.ps1`'

            $resolved = Resolve-TTAgentExpectedOutputPath -PromptText $prompt

            $resolved | Should -Be (Join-Path -Path 'C:\\repos\\TechToolbox\\Bin' -ChildPath 'Invoke-RemoteRebootHost.ps1')
            $resolved | Should -Not -Match 'Bin\. Name'
        }
    }
    It "Resolves wildcard directory shorthand to a concrete output path" {
        InModuleScope TechToolbox {
            $prompt = 'Please create a PowerShell script named Get-NewPSRemoteSession.ps1 to accompany the other two PSRemote session related scripts in C:\repos\TechToolbox\Public\Start_Stop\*. I want the script to get and output a list of all available PSSessions. After the list is enumerated and output as a PSCustomObject, I want the script to pick the first one to bring into a session variable. Output the script to the same directory as the other two PSSession related scripts.'

            $resolved = Resolve-TTAgentExpectedOutputPath -PromptText $prompt

            $resolved | Should -Be 'C:\repos\TechToolbox\Public\Start_Stop\Get-NewPSRemoteSession.ps1'
            $resolved | Should -Not -Match '\*'
        }
    }
    It "Does not resolve a malformed path containing prose" {
        InModuleScope TechToolbox {
            $prompt = 'Please create a script and write it to C:\\repos\\TechToolbox\\Bin. Name the script later.'

            $resolved = Resolve-TTAgentExpectedOutputPath -PromptText $prompt

            $resolved | Should -BeNullOrEmpty
        }
    }

    It "Rejects generated PowerShell files that fail parser validation" {
        InModuleScope TechToolbox {
            $path = Join-Path $env:TEMP ('tt-agent-invalid-ps-' + [guid]::NewGuid().ToString('N') + '.ps1')
            Set-Content -LiteralPath $path -Value @'
[CmdletBinding()]
param(
    [string]$Name

foreach ($item in 1..2) {
    Write-Host $item
}
'@

            $result = Test-TTAgentExpectedOutputFile -Path $path

            $result.IsValid | Should -BeFalse
            $result.Error | Should -Match 'Unexpected|Missing|parameter|closing|syntax'

            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    It "Normalizes recovered invalid-json envelope to finalAnswer text" {
        InModuleScope TechToolbox {
            $message = 'Agent returned invalid JSON twice. Last response: {"needsTool":false,"finalAnswer":"## Ready\nScript created.","reason":"done"}'

            $resolved = Resolve-TTAgentRecoveredOutputMessage -KnownFailureMessage $message -ExpectedOutputPath 'C:\Temp\Invoke-RebootRemoteHost.ps1'

            $resolved | Should -Be "## Ready`nScript created."
        }
    }

    It "Builds fallback recovered summary when envelope cannot be parsed" {
        InModuleScope TechToolbox {
            $message = 'DECISION_NO_PROGRESS_GUARD: bounded recent-history progress did not change.'

            $resolved = Resolve-TTAgentRecoveredOutputMessage -KnownFailureMessage $message -ExpectedOutputPath 'C:\Temp\Invoke-RebootRemoteHost.ps1'

            $resolved | Should -Match 'Run Recovered'
            $resolved | Should -Match 'C:\\Temp\\Invoke-RebootRemoteHost.ps1'
        }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBjJL/9UFtc6KDI
# g+H9vntXchdztfU9OlfB1FYfDDH87KCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# ubdcMIIG7TCCBNWgAwIBAgIQCE/cM09+RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAwMDAwMFoXDTM3MTEwNDIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz
# /TjGMPh8CQ6RucZCLv5anHzWJjF/NWJrFIhy24fcpKXlgRiky4WAawDfU3YP0BMx
# t9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZBcmJCcN0ASURML5uFIS80sZsDwO3BSkU
# xDjLJhBI+qiZP3aixAC/qEGLjsBNlLol9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZE
# eoy/0B8Zm+nzKBgSWG52lCO1w+nCg6XpCtklTJXeIg283hw7TmmsZXR+SMbjbrEO
# vZ3fP2VxIgeR28Y90ZStd3F9VuA5RVynb/whITPAo9b75Zr4Ta6Mj3URm26QZYMn
# /FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74lIT/ug0eeOzmZ6QTFg33otX+bFRsIolv
# ykE1jive4PuESaT8zzVeFWDAMDtozNgLctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZ
# CZVl6pNUOCybMc/kxC6EAmSJY24L0yYKD1Nkddsnb/ItVKi/2nXpQNMu1PT5prW8
# 3vV8d67WowuUs0HdY4H8AMLGvdL/WHEj3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjd
# zi0xlp70W+ow63/0++YDEX1M0iwgUHwbrJvfpklkZQvw3+kv3vUPItdwroczk9ic
# flf55W1zOEKAcJVAIXpcMCU9AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBQUyWOKMC7USvtulPPm40B+9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQCNxTphHp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQI
# ENoyKqxrFbJblzCVP/pkXmwXOdrOpWygLzlT12os5ipDCy35RBCg2UMeApEtrfGh
# z45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfH
# hHv1mx9EVh71SJelcEN/oORSjXzdjfw1iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA
# 02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3GhTiy0PxpawPtGRyaBVGzq+UiTfM8pD7K
# VyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA/+t0YcT2oRVBm3JETjajHug2AL+v5jht
# KVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+qbceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvK
# qzpAec9etE14jOQAzLKWdE3w/TCaKtLRaRT7LCkRYVnhA2D73FLje1O5b3HR5eHs
# 0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg/JgwtKfZM5dqO94lbUveOiJBI+xZEbGR
# sMNbXmMREUTgu+Oca7Y73MPWcslIx2VhkSKSXjDbD6rgg39H5Mh7QfieAIjWagkJ
# Nt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6jATlWJdYeeDRGCyatf8R1hSjzSvdN8yW
# QPT9gzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBUrGKA3Bic
# HKGUhfIxcNjci2HJpTUHTMS88XnftWHlITANBgkqhkiG9w0BAQEFAASCAgBFL22P
# u5mAmlzQjFk7xp9ZMHKbBqKnZkUKdjM0qJjngw/WRUvc23sCjpJNyfjhUcwWxhxK
# 9TVlvT4w4dxQVZE7serfocqKWE95qIjFVNpbFcCnTcFky3qWnmu/Hfkjc2weMM1/
# hYcJqbb6d8depQkLUVe4fiKu+vnFczlI1Gy7EaBspxQPG3XfedT6lrrmOZx1l+u+
# +UjRFkew6W6rjBKFJCAHWHhj0aAqh1xy0yBlyp0dlH4BiK5yfAA2B2kMDqZx4BWD
# uUBWz33SxK5QEw8YDZLxeT4bRJbn8pq87pp1vtYNyYClRoknW53k7ZTJ9TSFKLMY
# rYfUAyqdu0HU5tpc0LYxwRp97GJcVWAgQq2r5lEdfRckPpW4RH2CjIbMfl9+z3iw
# o0CPPONHVvMQekbCkepdvZYFOq2+Q5qZCJVh0WKkxjCDqNCdq5eEle/a3BX5v91F
# 6vKqxeXQrJX30h6/+eez8jDN3rOUyzltUhIi56WyB9doutRvcUQCdq+eFfH8a4gp
# hCeJdNFaSEm9PBKUzMjdq83iWibYL9fza+wCzXz7gMvfqYQhZGA4uLNw+5J8vnYk
# iV0DPuqzBNPWrFt5uRwMLmAEUId50lOe3QmLTSACE9+35uvBR8h7gZTqU80zoPMQ
# qD0ip0bGKvu92kKlwTpSgypb94Ba6ppLnihbiaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjEwMDIwMjIwNDFaMC8GCSqGSIb3DQEJBDEiBCDh27vBMv5s8swgBo7j
# iiG3ilwIRbdHKYJA6d1io6SWkTANBgkqhkiG9w0BAQEFAASCAgAeY04yAUIgJNtF
# JTad/1b1Ys1WyXozU5WPimwODwNtLnsuxck7a/e7xqhU8bqIEYHpAaF9QZdZ13r5
# W6oySsRC8piz4gVRFwDd2aJwR1cekfY7paZjn+4CNXPivBu+Fi0E0JKWypzusMFj
# t74VpLGgzq6yG3f378caE+aIqPFMIj38wzfXIiDOLNe32JsboG5HfNVmBdbbhjW3
# gWw91tRHUFXGgjgxPcuF7KQ8EPEFwUdaFUya3LcZWtOYX4LXdCTMXQ9TKbl6ehwm
# z/dJ7O4fC/W+S71BC8RK/GlHoVfcTozaJvho2Dd6XdzXni7pYl505Be+WELrmnXd
# hWsBUEcfS+YSlYt9kyxJ7+N9vSWJpNqWc3qBa00G+UgyUzu6dqI+wgOYoEtBUvba
# 6o8u+9NZMZ6j26yWnZQMZQXDdhFetSUyQwxUQNJ+Pa3bgO9l+Zzbo0ugPOWMRu4O
# 3goDU/+BRV/YavZqYT4dYFx5OfXRPnwpn9nPeSq3msRuxage/fJbuHSUquy6VLxI
# 5IpdOicognXMVSsGDRu40nu9DFBoGRAJSJ+qPkULlLUJGVeR/vE4r8SUyk5J4z5o
# 75tOHYtFp1dYZtJJWh8PogZ4vXlzbtFfWQyPSS+uoalBQ/n0o31UZPJLI2yf5qXl
# Dv/91FbFS8/rumW5h3eQLAwCZkdOzA==
# SIG # End signature block
