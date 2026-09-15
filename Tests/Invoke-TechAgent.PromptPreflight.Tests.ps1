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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOm8PoVR123AHQ
# NBhZBAgjop/6M3wYj8lhhIcXQbcHSKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBigvapGfyH
# fFhmQ1SuPgQoEXLF3hF3zSsoghApr/Ta2DANBgkqhkiG9w0BAQEFAASCAgBsp/8S
# TPf2p8ZxBCv43S4hrmiEZvWnPNt4wakkeiyrv1iDM2tX/RGx4AsFitziWVDecrB2
# vCkVdrIY7WXOAHIKFCe7o6Ds5DlpwDRTutbKvBsf40zir7Kv83JRzQGmoV5id3i2
# ChlRJRR0HF2GSkaTYcQIKlarIA96/vgp32mQH0F6Y+DvGxIAYK46cHuFSCQKr3p2
# xlDxG832lIx37kC+uOUHmN3m1gzqJLbuXvx4Lycz77X6IIZoPyMMuiaQ/K686WSs
# +sZguc/mKlY+Retw6+eATixgQNY+gz6jG86k3OuoJLKuV4/CBr1v5FwiTSHczVuB
# K1yHjq545ycfojZGavt5OHycGG/sYGRlQHbvfU9SI6i0yKWSgbaJNNV8xIdA9gX8
# ngmn4Y5pc/GNdZB9Kh4jE4hircA4FqHfxhlayUxqmRsApjPIU9F7F3tyk9110Rwx
# gcJAYNhJ+zOhk05S1N0wB7A86pnJkZ7HYxiMu4JOhOkbRQg2ToLvJFYWpy6/1cc+
# Azzz06zMoXnRRIeFum1IJKJ72S/RNDDMRxDp6pISJNXc5rUkw/qzyQ5e4G+gBLDQ
# uTXHYSBFc47Br7QQBvJrL2JSjwCD8XIt7zzwY8FoRgWrOCefpSY4Viy7CVsGa4B7
# irHxeamaK6esNbyzBc7uzuyKaUmX5HqsGtayaKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA5MTUwNDAwMTJaMC8GCSqGSIb3DQEJBDEiBCA2rRa2lPVwG5kAnd1q
# naN6eGoTcsnq/mk7W2IqNFL9ozANBgkqhkiG9w0BAQEFAASCAgCvPyFV0PCsLVw/
# XV8XAsK0Ip5nMwqVl+WHB1VajC1SxmNnq1Fh6R5A+JLoQ3PtyE1ihMxcWRRemNL0
# /rMyd/aIFmTo4V/E1wqMdfB19pzBKjYVrXjJ0QRB+5pRgKcWzlXCLCGs4vd5wXRx
# T1RmWGczYl1bBKC10XgBMxx+mzlv8+sAsvAOQ0s+cfC6qV8QyYRJlb4KRPrX+Z4d
# fUzbvnVSSS/d9svteitgtvJJCk1RqGuvMGzMnK4LQg+eoqofyBfFw54lHe0Qfj0z
# pMHDCwy+4KYeg41yRE4eTMjToVR61F6ukC2gbLVi/pztR2X9ygdOobzVKR4HzY33
# 8ZgSYzNcyeeg5zsEYYOq1kBaKOuz8Wz7gPeS3/cBQyBL4cNX8bn/YlT+NK4MD4fK
# D34N38arpCItdknEsssf4WazlP/UdcBn5FpZDE5yBIP2iSFBLtRSv3Moc60pBA7N
# H4hGhRtf/nNPjj7d+1dnMtdoZzwaf61kCGi0g3GrkDLkVg+CNJZ71VOeV33vTHq9
# 4PKCHRtJIGMNQIS8IeS7qdXdKWwijEpoYv5ex8RxxeQBmDIy3flw8bsrcfxfsnKe
# u2Cq0+LTBQbE+jmoWNUENulCLICsYHhW6oACwp9rhkxqz2MdoM/IwuLdxhBWchkA
# TQz7ISzpZMwaXBo9dzxZlwDMt1fm+g==
# SIG # End signature block
