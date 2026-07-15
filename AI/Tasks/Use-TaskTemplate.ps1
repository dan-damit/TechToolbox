#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Lists available task templates and copies a chosen template into a
    destination file.

.DESCRIPTION
    Helps reuse prompt templates stored under AI/Tasks/Templates by listing them
    or copying one template into AI/Tasks/CurrentTask.txt or another destination
    path.

.PARAMETER Template
    File name of the template to copy, for example CSharp-BugFix-InPlace.txt.

.PARAMETER Destination
    Destination file path for the copied template. Defaults to
    AI/Tasks/CurrentTask.txt.

.PARAMETER List
    Lists available templates and exits.

.PARAMETER Show
    Writes the selected template content to the console.

.PARAMETER Open
    Opens the selected template file in VS Code when available, otherwise in the
    default associated application.

.PARAMETER Pick
    Presents an interactive numbered picker to choose a template.

.PARAMETER SelectionNumber
    Selects a template by its 1-based number in the picker list. Intended for
    automation or testing.

.PARAMETER Category
    Filters templates by category name before listing, picking, showing,
    opening, or copying.

.PARAMETER Force
    Overwrites an existing destination file without prompting.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -List

    Lists the available task templates.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -Template PowerShell-BugFix-InPlace.txt

    Copies the selected template into AI/Tasks/CurrentTask.txt.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -Template CSharp-BugFix-InPlace -Show

    Prints the selected template to the console.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -Template PowerShell-HelpAuthoring-Review -Open

    Opens the selected template file.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -Pick

    Presents an interactive picker and copies the selected template into AI/Tasks/CurrentTask.txt.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -Pick -Show

    Presents an interactive picker and prints the selected template to the console.

.EXAMPLE
    .\AI\Tasks\Use-TaskTemplate.ps1 -List -Category PowerShell

    Lists only PowerShell-related templates.
#>

[CmdletBinding()]
param(
    [string]$Template,
    [string]$Destination,
    [switch]$List,
    [switch]$Show,
    [switch]$Open,
    [switch]$Pick,
    [int]$SelectionNumber,
    [string]$Category,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$taskRoot = Join-Path $moduleRoot 'AI\Tasks'

if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $taskRoot 'CurrentTask.txt'
}

$templateRoot = Join-Path $taskRoot 'Templates'

if (-not (Test-Path -LiteralPath $templateRoot)) {
    throw "Template directory not found: $templateRoot"
}

$templates = @(
    Get-ChildItem -LiteralPath $templateRoot -File -Filter '*.txt' | Sort-Object Name
)

$categoryMap = [ordered]@{
    'CSharp'     = @('CSharp-')
    'PowerShell' = @('PowerShell-')
    'General'    = @('General-')
    'Docs'       = @('Docs-')
    'Tests'      = @('Tests-')
    'Release'    = @('Release-')
    'CI'         = @('CI-')
    'Security'   = @('Security-')
}

$activeModes = @(@($List.IsPresent, $Show.IsPresent, $Open.IsPresent) | Where-Object { $_ })
if ($activeModes.Count -gt 1) {
    throw 'Specify only one of -List, -Show, or -Open.'
}

if ($Pick.IsPresent -and -not [string]::IsNullOrWhiteSpace($Template)) {
    throw 'Specify either -Template or -Pick, not both.'
}

if ($SelectionNumber -lt 0) {
    throw 'SelectionNumber must be zero or a positive integer.'
}

function Resolve-TemplatePath {
    param(
        [Parameter(Mandatory)]
        [string]$TemplateName,

        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$AvailableTemplates,

        [Parameter(Mandatory)]
        [string]$RootPath
    )

    $candidates = @($TemplateName)
    if ([System.IO.Path]::GetExtension($TemplateName) -eq [string]::Empty) {
        $candidates += "$TemplateName.txt"
    }

    foreach ($candidate in $candidates) {
        $match = $AvailableTemplates | Where-Object {
            $_.Name.Equals($candidate, [System.StringComparison]::OrdinalIgnoreCase)
        } | Select-Object -First 1

        if ($null -ne $match) {
            return $match.FullName
        }
    }

    return (Join-Path $RootPath $TemplateName)
}

function Get-AvailableCategoryNames {
    param(
        [Parameter(Mandatory)]
        [hashtable]$TemplateCategoryMap
    )

    return @($TemplateCategoryMap.Keys | Sort-Object)
}

function Get-TemplateCategory {
    param(
        [Parameter(Mandatory)]
        [string]$TemplateName,

        [Parameter(Mandatory)]
        [hashtable]$TemplateCategoryMap
    )

    foreach ($entry in $TemplateCategoryMap.GetEnumerator()) {
        foreach ($prefix in $entry.Value) {
            if ($TemplateName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $entry.Key
            }
        }
    }

    return 'Other'
}

function Filter-TemplatesByCategory {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$AvailableTemplates,

        [string]$RequestedCategory,

        [Parameter(Mandatory)]
        [hashtable]$TemplateCategoryMap
    )

    if ([string]::IsNullOrWhiteSpace($RequestedCategory)) {
        return $AvailableTemplates
    }

    $matchedCategory = Get-AvailableCategoryNames -TemplateCategoryMap $TemplateCategoryMap |
    Where-Object { $_.Equals($RequestedCategory, [System.StringComparison]::OrdinalIgnoreCase) } |
    Select-Object -First 1

    if ($null -eq $matchedCategory) {
        $availableCategories = (Get-AvailableCategoryNames -TemplateCategoryMap $TemplateCategoryMap) -join ', '
        throw "Unknown category '$RequestedCategory'. Available categories: $availableCategories"
    }

    return @(
        $AvailableTemplates | Where-Object {
            (Get-TemplateCategory -TemplateName $_.Name -TemplateCategoryMap $TemplateCategoryMap).Equals(
                $matchedCategory,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
    )
}

$templates = Filter-TemplatesByCategory -AvailableTemplates $templates -RequestedCategory $Category -TemplateCategoryMap $categoryMap

function Select-TemplateFile {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$AvailableTemplates,

        [int]$PreselectedNumber = 0
    )

    if ($AvailableTemplates.Count -eq 0) {
        throw 'No task templates found.'
    }

    Write-Host 'Available task templates:' -ForegroundColor Cyan
    for ($index = 0; $index -lt $AvailableTemplates.Count; $index++) {
        Write-Host ('[{0}] {1}' -f ($index + 1), $AvailableTemplates[$index].Name)
    }

    $selectedIndex = -1
    while ($selectedIndex -lt 0) {
        $rawChoice = if ($PreselectedNumber -gt 0) {
            [string]$PreselectedNumber
        }
        else {
            Read-Host 'Enter template number'
        }

        if (-not [int]::TryParse($rawChoice, [ref]$selectedIndex)) {
            $selectedIndex = -1
            if ($PreselectedNumber -gt 0) {
                throw "SelectionNumber '$PreselectedNumber' is not valid."
            }

            Write-Warning 'Enter a valid number from the list.'
            continue
        }

        $selectedIndex--
        if ($selectedIndex -lt 0 -or $selectedIndex -ge $AvailableTemplates.Count) {
            $selectedIndex = -1
            if ($PreselectedNumber -gt 0) {
                throw "SelectionNumber '$PreselectedNumber' is out of range."
            }

            Write-Warning 'Enter a number that matches one of the listed templates.'
        }
    }

    return $AvailableTemplates[$selectedIndex].FullName
}

if ($List.IsPresent) {
    if ($templates.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($Category)) {
            Write-Host 'No task templates found.'
        }
        else {
            Write-Host ("No task templates found for category '{0}'." -f $Category)
        }
        return
    }

    if ([string]::IsNullOrWhiteSpace($Category)) {
        Write-Host 'Available task templates:' -ForegroundColor Cyan
    }
    else {
        Write-Host ("Available task templates for category '{0}':" -f $Category) -ForegroundColor Cyan
    }
    foreach ($item in $templates) {
        $templateCategory = Get-TemplateCategory -TemplateName $item.Name -TemplateCategoryMap $categoryMap
        Write-Host ("- {0} [{1}]" -f $item.Name, $templateCategory)
    }

    return
}

if ([string]::IsNullOrWhiteSpace($Template)) {
    if (-not $Pick.IsPresent) {
        throw 'Specify -Template <FileName>, use -Pick, or use -List to see available templates.'
    }
}

$sourcePath = if ($Pick.IsPresent) {
    Select-TemplateFile -AvailableTemplates $templates -PreselectedNumber $SelectionNumber
}
else {
    Resolve-TemplatePath -TemplateName $Template -AvailableTemplates $templates -RootPath $templateRoot
}
if (-not (Test-Path -LiteralPath $sourcePath)) {
    $available = if ($templates.Count -gt 0) {
        ($templates.Name -join ', ')
    }
    else {
        '(none)'
    }

    throw "Template not found: $Template. Available templates: $available"
}

$resolvedTemplateName = Split-Path -Leaf $sourcePath

if ($Show.IsPresent) {
    Get-Content -LiteralPath $sourcePath -Raw | Write-Output
    return
}

if ($Open.IsPresent) {
    $codeCommand = Get-Command code -ErrorAction SilentlyContinue
    if ($null -ne $codeCommand) {
        & $codeCommand.Source --reuse-window $sourcePath | Out-Null
    }
    else {
        Invoke-Item -LiteralPath $sourcePath
    }

    Write-Host ("Opened template '{0}'." -f $resolvedTemplateName) -ForegroundColor Green
    return
}

$destinationDirectory = Split-Path -Parent $Destination
if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -LiteralPath $destinationDirectory)) {
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
}

if ((Test-Path -LiteralPath $Destination) -and -not $Force.IsPresent) {
    Write-Warning "Overwriting existing destination: $Destination"
}

$content = Get-Content -LiteralPath $sourcePath -Raw
Set-Content -LiteralPath $Destination -Value $content -NoNewline

Write-Host ("Copied template '{0}' to '{1}'." -f $resolvedTemplateName, $Destination) -ForegroundColor Green

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBG6b2HGvcoRF7N
# KiuTgpGS1gTmqCMqkKO4il5WoWuCTKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCgdSRy7IAR
# 4rS3APji1R2ggCHMr1CKVdSypQgMW5pgiDANBgkqhkiG9w0BAQEFAASCAgAZItza
# XjtWgrlxg8SRV1sQQGrZWogz9QsR2LX5dhPENBO92TCehsx5t2J2ygN8a4aDBRtG
# W0Z+gQOU6V/FDPcO36i2Ryl+u5C3bfwqV6LlXMPUpAzuExulFAMLABD2srr+p+7b
# czwp9H7wwcBx7i+AOPNHbzYOT7A5oaZNbg6fQ8tc7pZtMfMZNfbEdLmvihswJaCn
# M01IPRTHMUHhj9n53rMnRAltL82rekf2t5GA+mlTNuGnHFLSZk9AxANVigKF56Sp
# WRKrUacoWVOcyz5+R5wgoLf/PZl4dwjJ/2qtDoaWqJTjXcqjj+2uBun3MbHUZ9wf
# /ZpLo/WhYlaMyZguRyWTc7Zsww1FwAfRUs4XXfphf0+fXfQkSeXRINkKfJQ8tyS/
# Xcbq4x4l9X64otoCa+dv4qv0jz0vB+8AJbrcdJnnixvHCrINN7dfmDMyKEBw0HL6
# tmZOYzVmQIJgWz4/qS3Mrz6pF7S/r0MB2MB81hsczCLKsTerAdSY/DPllPLzfk4w
# ZBqllFaLl3x5Yz7WVHYO64TCwnJdNspNYp8Bn7pipDP73O3EtToDVdBw4Lx+zmmq
# pu4yz0/RE36ftfb6qu7wgv8ElbEipp0A0XbuG3Vkn56ADtqMP5xT2/yYBJk9ccoX
# 8k/jw7LiVf9MIBdZKbaHrRMe4HRvJe6hDht8JKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MTUwMzQyMjlaMC8GCSqGSIb3DQEJBDEiBCBhHdf6j4jXiQlDcvcg
# FWWGy6EosYNh9sTP4X2K0iwTnzANBgkqhkiG9w0BAQEFAASCAgBON1XJxCsKA143
# rQQYpx2c6IahrgGVGb72lL2V9RTH4IN1UHMjAR0VEvYHhVILFcn2g/1HjgoNWU21
# miXtxusFsoVyYVGssgkG6bLxRfVQsueLDd4FNESsIm1oJ0+c2kn84xhkYXWdhpX0
# ABukFLmi15y3lTqeWxNAXXGoBq69ag/MCsFPzvywD30VOVWwlG9W82ohZqYncdNq
# ufa9d52UP6qhWW3W5HnuRrXB1uhDf17q1At24S6SHbQ35tZ+V/Hhls4wP3I18fC9
# wI9V9HgjbFZuW/QiLFTVbXuDNaJm3iHsBqdN2SGW/s2AvUWyP/+33Zq9iaGVySXI
# k5cxBKP8cniuHi9ku+Z9fL9QEnjbRWtQBB3SS2zAdqBN/oa3ti9AO1Okjam1OMmU
# YJsrtEc+Sq2G4PltfmoQRa6v6xmIu9Wga/OwxIrkI8pdeb0e4wD/E06yuA++8feH
# MP2wZFDfQYQXuC2tI4CgDGVpiEaVS8kg0vrPPaUCB5sbox7pSLxxle6qPmLhOyWK
# agLD7rAiDjCfRiM8EFFSTWmSkWGFmZMb53cVbZvWv6gWJGv2ROMXS5zYU6UZ47sx
# VwHLPuVHEcYMjbtflQnpW06QP8TaJaauBO3uiXD5Z2sixabieUAYweVHThhJ36P1
# 4LeDjCXeRdCM+2u78xnEmG0tGehRqQ==
# SIG # End signature block
