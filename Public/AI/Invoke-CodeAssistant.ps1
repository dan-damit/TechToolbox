function Invoke-CodeAssistant {
    <#
    .SYNOPSIS
        Analyzes PowerShell code using a local LLM and generates a Markdown
        report.

    .DESCRIPTION
        This function:
        - Accepts raw PowerShell code and a filename.
        - Removes signature blocks and PEM blocks.
        - Builds a mode-specific analysis prompt (General, Static, Security,
          Refactor, Tests, Combined).
        - Sends the prompt to a local LLM via Invoke-LocalLLM.
        - Saves a timestamped Markdown report to C:\TechToolbox\CodeAnalysis.

    .PARAMETER Code
        The raw PowerShell code to analyze.

    .PARAMETER FileName
        The name of the file the code came from. Used for naming the output
        report.

    .PARAMETER Mode
        The type of analysis to perform:
        - General  : High-level review (readability, structure, performance,
          best practices).
        - Static   : Lint-style static analysis (unused vars, error handling,
          structure).
        - Security : Security-focused review (unsafe patterns, secrets,
          injection, etc.).
        - Refactor : Proposes a refactored version of the code.
        - Tests    : Generates Pester test ideas or scaffolding.
        - Combined : Performs all of the above in a structured, multi-section
          response.

    .PARAMETER Encoding
        Optional output encoding for the Markdown file. Defaults to UTF8.

    .OUTPUTS
        System.String – The path to the generated Markdown report.

    .NOTES
        Part of the TechToolbox AI subsystem.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Code,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName,

        [ValidateSet('General', 'Static', 'Security', 'Refactor', 'Tests', 'Combined')]
        [string]$Mode = 'General',

        [ValidateSet('UTF8', 'ASCII', 'Unicode', 'UTF7', 'UTF32', 'Default', 'OEM')]
        [string]$Encoding = 'UTF8'
    )

    # -------------------------------------------------------------------------
    # Helper: Remove signature blocks and PEM blocks
    # -------------------------------------------------------------------------
    function Remove-SignatureBlocks {
        param([string]$InputCode)

        # Remove Authenticode-style signature regions (commented SIG markers)
        $clean = $InputCode -replace '(?s)#\s*SIG-BEGIN(.+?)#\s*SIG-END', '[SIGNATURE BLOCK REMOVED]'

        # Also normalize any explicit placeholder you already use
        $clean = $clean -replace '\[SIGNATURE BLOCK REMOVED\]', '[SIGNATURE BLOCK REMOVED]'

        # Remove PEM-style blocks
        $clean = $clean -replace '(?s)-----BEGIN [A-Z0-9 ]+-----(.+?)-----END [A-Z0-9 ]+-----', '[PEM BLOCK REMOVED]'

        return $clean
    }

    # -------------------------------------------------------------------------
    # Helper: Prompt builders for each mode
    # -------------------------------------------------------------------------
    function New-GeneralPrompt {
        param([string]$CleanCode)

        @"
You are a senior PowerShell engineer.

Please review the following code and provide a concise, practical analysis focused on:
- functionality
- readability
- performance
- structure
- maintainability
- use of PowerShell best practices

Do NOT explain or expand on cryptographic signatures or PEM blocks. They are represented as placeholders.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-StaticAnalysisPrompt {
        param([string]$CleanCode)

        @"
You are a PowerShell static analysis engine.

Perform a static code analysis of the following script. Focus on:
- unused variables
- unreachable code
- missing or weak error handling
- missing parameter validation
- pipeline misuse
- quoting and path handling issues
- missing CmdletBinding / SupportsShouldProcess where appropriate
- missing or weak comment-based help

Provide your findings in a structured, bullet-point format.

Do NOT explain or expand on cryptographic signatures or PEM blocks. They are represented as placeholders.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-SecurityPrompt {
        param([string]$CleanCode)

        @"
You are a PowerShell security auditor.

Review the following script and identify potential security issues, including:
- hardcoded credentials, tokens, or secrets
- insecure file or registry access
- unvalidated user input
- unsafe use of Invoke-Expression or external commands
- insecure network usage (e.g., HTTP instead of HTTPS, weak TLS)
- missing -ErrorAction Stop where failures must not be ignored
- privilege escalation risks
- logging of sensitive data

Provide your findings in a structured format:
- High-risk issues
- Medium-risk issues
- Low-risk issues
- Recommended mitigations

Do NOT explain or expand on cryptographic signatures or PEM blocks. They are represented as placeholders.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-RefactorPrompt {
        param([string]$CleanCode)

        @"
You are a senior PowerShell engineer.

Refactor the following script to improve:
- readability
- structure and modularity
- parameter validation
- error handling
- logging
- adherence to PowerShell best practices

Return:
1. A short summary of the main refactoring goals.
2. A fully refactored version of the script in a fenced ```powershell code block.
3. Any notes about trade-offs or assumptions you made.

Do NOT expand or reconstruct cryptographic signatures or PEM blocks. Leave placeholders as-is.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-TestsPrompt {
        param([string]$CleanCode)

        @"
You are a PowerShell test engineer.

Generate Pester test ideas and example tests for the following script. Focus on:
- parameter validation
- expected behavior for typical inputs
- edge cases and error conditions
- security-relevant behaviors
- interactions with the file system, registry, or network (use mocks where appropriate)

Return:
1. A list of recommended test scenarios.
2. Example Pester test code in a fenced ```powershell code block.

Do NOT expand or reconstruct cryptographic signatures or PEM blocks. Leave placeholders as-is.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-CombinedPrompt {
        param([string]$CleanCode)

        @"
You are a senior PowerShell engineer, static analysis engine, and security auditor.

Perform a comprehensive analysis of the following script and return your findings in these sections:

## General Review
- Readability
- Structure
- Performance
- Maintainability
- Best practices

## Static Analysis
- Unused variables
- Unreachable code
- Error handling
- Parameter validation
- Pipeline usage
- Comment-based help

## Security Review
- Potential vulnerabilities
- Hardcoded secrets
- Unsafe patterns
- Risk level and mitigations

## Refactor Suggestions
- High-level refactoring ideas
- Specific improvements to structure and style

## Pester Test Ideas
- Key scenarios to test
- Example Pester tests (in a fenced ```powershell code block)

Do NOT expand or reconstruct cryptographic signatures or PEM blocks. Leave placeholders as-is.

Here is the code:

<<<CODE>>>
$CleanCode
<<<ENDCODE>>>
"@
    }

    function New-CodeAnalysisPrompt {
        param(
            [string]$CleanCode,
            [string]$Mode
        )

        switch ($Mode) {
            'General' { return New-GeneralPrompt       -CleanCode $CleanCode }
            'Static' { return New-StaticAnalysisPrompt -CleanCode $CleanCode }
            'Security' { return New-SecurityPrompt      -CleanCode $CleanCode }
            'Refactor' { return New-RefactorPrompt      -CleanCode $CleanCode }
            'Tests' { return New-TestsPrompt         -CleanCode $CleanCode }
            'Combined' { return New-CombinedPrompt      -CleanCode $CleanCode }
            default { return New-GeneralPrompt       -CleanCode $CleanCode }
        }
    }

    # -------------------------------------------------------------------------
    # Helper: Create output folder safely
    # -------------------------------------------------------------------------
    function Ensure-OutputFolder {
        param([string]$Path)

        if (-not (Test-Path -LiteralPath $Path)) {
            try {
                New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Log -Level Error -Message "Failed to create output folder '$Path': $($_.Exception.Message)"
                throw
            }
        }
    }

    # -------------------------------------------------------------------------
    # Begin main function logic
    # -------------------------------------------------------------------------
    try {
        # Clean the code
        $cleanCode = Remove-SignatureBlocks -InputCode $Code

        # Build mode-specific prompt
        $prompt = New-CodeAnalysisPrompt -CleanCode $cleanCode -Mode $Mode

        # Call local LLM
        $result = Invoke-LocalLLM -Prompt $prompt

        # Prepare output folder
        $folder = "C:\TechToolbox\CodeAnalysis"
        Ensure-OutputFolder -Path $folder

        # Build output path
        $timestamp = (Get-Date).ToString("yyyy-MM-dd_HHmmss")
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        $path = Join-Path $folder "Analysis-$baseName-$Mode-$timestamp.md"

        # Build Markdown
        $md = @'
# Code Analysis Report
Generated: {0}

## Mode
{3}

## Summary
{1}

## Source Code
```powershell
{2}
```
'@ -f (Get-Date), $result, $cleanCode, $Mode
        # Save file
        $md | Out-File -FilePath $path -Encoding $Encoding

        Write-Log -Level OK -Message "Saved analysis ($Mode) to: $path"
        return $path
    }
    catch {
        Write-Log -Level Error -Message "Invoke-CodeAssistant ($Mode) failed: $($_.Exception.Message)"
        throw
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAvoBTgtxZofJeT
# BgauESyHLL4I/X3UzVm+DV2STBuZGKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBNIWRjq6NN
# bVobFdH79eFS1AXrDLJmlfFiY38yCfPbFzANBgkqhkiG9w0BAQEFAASCAgDKmC0W
# OobXBOyY0Y3qoCdibXe9kRg4mdWpcJ0BcuUhnfHpaU7sVWu7iwQBJ6ZOj4Zc0Y2Q
# VGuJY3xAmyha5XrYxeZLBFLpKZy1aakOwpCf/SdrIh1KaR0e7MWtHrYMD3tCcUsE
# Q54GJLvEWJLiwOGLU3lbcZXCG4rVHTL4OI0a3Qac7c6i6Ikt66YvSbzxrLbH/Y8M
# W7/m8UnS8+MVrYD6SdG2oXuCcdRsuiutXoMxHm8ADI8ChYXeB/YxaQyakaaHB3QP
# /tRnm0L1ilhBYDCS2+NilfYdn9MmwlGH3YJUPqrKV3SjlK4DFmCdBlwouuquY2y/
# Rw5p5/C9EasyNhrnHeYzzrZko2LHRKe3Bl/xK48RgbVowFh6qfrSjz3Cwv5am4t9
# OeKhDcR13TLKNprtniABFmQZ54c4x4gqlB9Hvc/aT3rqMUwBoalgG2B9FaX917OT
# TZ/twN0jJn2LpU1+eSn8gR08/9Rwgn+b6MURk1xitoAhacWWbpnm+NLJfWb2d7kx
# 2PrV92XkVXSvczBYO7YWK0BbOIZ/eHtkNxABg7LBEWeMvgvJyZ2wXlvCAXx95coS
# yJhUwl3wmILN/WC/93QSFiRPozG5rqjqsxlcFZzIN7LXVP67zfc+pvXuoYS1WBcj
# bqH7O7sbxao4+NhTaA9QvJKW4d2COeZE2U2PrqGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAyMDgwMzM2NTJaMC8GCSqGSIb3DQEJBDEiBCBZNqvAc+T7hTo1V4Gq
# RVibgC7r17AGVbRScqf35Dva6DANBgkqhkiG9w0BAQEFAASCAgCT1TrPOanNPM8m
# kR43D9ctvbi14d1PASwfyFbmPap8jJX1dULFGl4IM/y/KPqQEf+6aYyvje5WiACo
# G+uiG/IdYScycf3zZkR4cCL49ZWOv6jTDQsV+OTkKAlqH400cEOIiaFCWnO2fxUX
# esTlwWu9JIyfmYrdyQJBd+Bbx75uD1Ftzj6YWYrlThHWLTIwKiiIBE3yF/QpHXfi
# s4XyyfyjveLkdU2S0CFLxe82HSFi5wXQfu0edFBUMbp3osVRBRGqJScvCuoMXvnZ
# dbvXINW/xbq8SIcwQIDa1ODyJpr+bJWuFRnXh6fS8MWTLBP9WvX7SWykC77m4mVY
# 99JXjAAV9C5asKlo++aboKwW5firK4b/4RkN/ZvnpgGXmbHb6NqQDEw0zlD+m3G5
# n3Xl84GApUo9lScOAxsQgjvtMF1AbYruRTDOkKsp6mwpWF7X2HC8Bm5YX4frIrp5
# wn8BI+RwYYwOlULpHsC4e3fAN/cWvT0KWfBbO9Qveme72ASR4S7xgSe5gmyXaxX4
# j7pxrJoOB5nURQ+4FRqbLRqjl8b7hUFD/f4JZkj7+bltxul3oBXU9zCJavF/ZcZm
# 0yeArkjeVMQwfEDbqw88H3hnmUA9cnvU9tumJmkzq3g+Osh0NO5ciCOIajNHveHy
# zUOcoQk+yhZcDh7FV0zGVxAHzVTd8A==
# SIG # End signature block
