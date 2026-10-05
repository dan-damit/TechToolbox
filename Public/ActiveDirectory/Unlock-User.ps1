function Unlock-User {
    <#
    .SYNOPSIS
    Unlocks an Active Directory user account if it is currently locked out.

    .DESCRIPTION
    Resolves the target identity using Search-User, checks the current lock state,
    and calls Unlock-ADAccount only when needed. The command supports WhatIf/Confirm
    and returns a summary object describing the operation outcome.

    .PARAMETER Identity
    AD user identity to unlock. Accepts sAMAccountName, UPN, or other identities
    supported by Search-User.

    .PARAMETER Credential
    Optional credential used for Search-User and AD unlock operations.

    .EXAMPLE
    Unlock-User -Identity jdoe

    .EXAMPLE
    Unlock-User -Identity jdoe@company.com -Credential (Get-Credential)

    .EXAMPLE
    Unlock-User -Identity jdoe -WhatIf

    .LINK
    Search-User

    .LINK
    https://dan-damit.github.io/TechToolbox-Docs/Unlock-User
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [System.Management.Automation.PSCredential]$Credential
    )

    Initialize-TechToolboxRuntime
    Write-Log -Level Info -Message ("Starting Unlock-User for '{0}'" -f $Identity)

    Get-ActiveDirectoryModule
    if (-not (Get-Module ActiveDirectory) -and -not (Get-Module ActiveDirectory -ListAvailable)) {
        Write-Log -Level Error -Message "ActiveDirectory module unavailable. Install RSAT or ensure AD tools are accessible."
        throw "Missing ActiveDirectory module."
    }

    $suParams = @{ Identity = $Identity }
    if ($Credential) { $suParams.Credential = $Credential }

    $user = Search-User @suParams
    if (-not $user) {
        throw "User '$Identity' not found."
    }

    $lockedBefore = [bool]$user.Locked
    if (-not $lockedBefore) {
        Write-Log -Level Ok -Message ("Account is already unlocked: {0}" -f $user.SamAccountName)
        return [pscustomobject]@{
            SamAccountName    = $user.SamAccountName
            UserPrincipalName = $user.UserPrincipalName
            DistinguishedName = $user.DistinguishedName
            WasLocked         = $false
            UnlockAttempted   = $false
            UnlockSucceeded   = $true
            LockedAfter       = $false
            Timestamp         = (Get-Date)
        }
    }

    if ($PSCmdlet.ShouldProcess($user.SamAccountName, 'Unlock AD account')) {
        try {
            $unlockParams = @{
                Identity    = $user.DistinguishedName
                ErrorAction = 'Stop'
            }
            if ($Credential) { $unlockParams['Credential'] = $Credential }

            Unlock-ADAccount @unlockParams
            Write-Log -Level Ok -Message ("Account unlocked: {0}" -f $user.SamAccountName)
        }
        catch {
            Write-Log -Level Error -Message ("Failed to unlock account '{0}': {1}" -f $user.SamAccountName, $_.Exception.Message)
            throw
        }
    }

    $verifyParams = @{
        Identity    = $user.DistinguishedName
        Properties  = @('LockedOut')
        ErrorAction = 'Stop'
    }
    if ($Credential) { $verifyParams['Credential'] = $Credential }

    $postUser = Get-ADUser @verifyParams
    $lockedAfter = if ($postUser.PSObject.Properties['LockedOut']) { [bool]$postUser.LockedOut } else { $false }

    [pscustomobject]@{
        SamAccountName    = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        DistinguishedName = $user.DistinguishedName
        WasLocked         = $lockedBefore
        UnlockAttempted   = $true
        UnlockSucceeded   = (-not $lockedAfter)
        LockedAfter       = $lockedAfter
        Timestamp         = (Get-Date)
    }
}

# SIG # Begin signature block
# MIIcLwYJKoZIhvcNAQcCoIIcIDCCHBwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABr/4qIivVQWZI
# fPRwJrUPgX4tdvxUNtLInSi79ouGaKCCFmgwggMqMIICEqADAgECAhAUclYcLlB0
# o0+hlxGb32/OMA0GCSqGSIb3DQEBCwUAMC0xKzApBgNVBAMMIlRlY2hUb29sYm94
# IFRlY2hTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYxMDAzMDE0MjMyWhcNMjgxMDAz
# MDE1MjMxWjAtMSswKQYDVQQDDCJUZWNoVG9vbGJveCBUZWNoU2hlbGwgQ29kZSBT
# aWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXcCV9CPSwPJ
# 42duP85fSh0jCkJWIov+AYymeKQzBLgsz6jCkhuuKBf7gpsStULwAJuBtFztT/XI
# 0jK0e+3SIzYCaG+1nn0rzBsB4YisBtMykS+EtRgmjcu2h1YMGiQ/FScDak5h707Z
# hQ/VBXZ/+rZ7Wd08wUnWHAsNRz75wz/kiWGEoCDIuLsl4uy+gQmXlQVBFn8ALEh0
# AtJk0B7c6qzz1y0So8y4Lq1IXvCEnN61HYSJ5zaopOMvNo3pNsrr0sM7m9DyEzu4
# Ci3EWtuyXbPegoV62qC62MRllrFJNzV6dJBUuXqCAhgMFGaT6Mj2/qRlBiVVmTFe
# FXTX9pHvxQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFB8+5HahBP9rHFC1mG3OWbTh3WwxMA0GCSqGSIb3DQEB
# CwUAA4IBAQAOdqNp/5ce+dpVcp2FivGK7FpYroSWaeOoEDEDLnxq58mDEZKBwfYM
# SduDQ4AHZQ3U1WRrvHWyiPpFI5lOt1utiw9WHrA4sHuvxGmFkcfH4J8AsRtlVK94
# yUX16UZhLPXWItGM75rUz/uRSBcyXQWOzq5gfwNL22F5Z8AljAicEBAZLUhuQBpd
# 9rE3JWZ0rZzbRZNd4Hb4/DP53KaiA7zfZyXmuEfLCCwyGtcPn3Mqxu6IsCU8LmzH
# 2fClU7OGxte+VxaczuFaPqmIBtChvxj4ZoluHWgWOIXqyOsSc9v9qzYeHM6i4pY4
# pRkjpGU/2NWfwVbOkyJxQlE9XdhO3IXGMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG
# 9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVz
# dGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+
# PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxe
# Lho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2D
# Z0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJB
# YgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7G
# b5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS
# 3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7C
# coKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUm
# s+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN
# +nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqE
# G1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhG
# NKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQI
# MAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQY
# MBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUE
# DDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDww
# OjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0G
# CSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/D
# m1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO4
# 1P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFS
# goR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSL
# ANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJ
# DMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cva
# iIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+
# U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6
# bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+
# Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhL
# ULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3
# XDCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggUdMIIFGQIBATBBMC0xKzApBgNVBAMMIlRlY2hUb29sYm94IFRlY2hTaGVs
# bCBDb2RlIFNpZ25pbmcCEBRyVhwuUHSjT6GXEZvfb84wDQYJYIZIAWUDBAIBBQCg
# gYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYB
# BAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0B
# CQQxIgQg2ymKO3+k36rbJc+bkcPi7uiVuKSH2m8TFWlMTDm4iBgwDQYJKoZIhvcN
# AQEBBQAEggEAGCpw5Dm4REk4yEKW5c7a+4OeJfy9KC7OWMrfYojJRFVGmxp+H4hN
# i8KPKQRL6ecspZl72m+eLvKgYbNkFA72UeVsgaHItKeMJ5sCTLcONzOp9/u6PlGg
# lf9VFgYNxcbMK0HeY5m0qUo3AVbfE18X08UUVT9UDaRqd2ZqjmJCRCC135hI20rn
# Cg24IjWlmSIPpq+//j15mK8XnAmArekOkGr256h9F4mbA31W42Ixw+7DMU+WA9B2
# FmiaQ6S2CKc30l4gyLhM4boaTNXKRfyuU0SZqIYH/019mJUUpYXGRSsdJDYziQvh
# bL0p9DA9U8Eo0dCFJGdIfEP8DP8wHrWDvqGCAyYwggMiBgkqhkiG9w0BCQYxggMT
# MIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUwDQYJYIZIAWUD
# BAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP
# Fw0yNjEwMDUwMjQ3MTJaMC8GCSqGSIb3DQEJBDEiBCDKbmW6/EYj1j218pJuteeA
# J63SGWPr73uz0AxgSMspzDANBgkqhkiG9w0BAQEFAASCAgA+XogEAxjGa5RWxpsy
# Zs1YFuCQBU1R7QOSBzswF8mhFSeTydfw9U3r8yBkTPLSEnjLsiJmVLC2GM9t0txc
# JwTzKYM9cbEaSq++Q4HirRAg63QDEW6SN2zoyVlvA4b4PumKtcjtkCKY4pRz0ztF
# W3vjPnB69SspwWRXOEOVkb/uKZCOMiF8h4CSez4zv9Xku4XFA0mg1HuEjM9Rl9Sf
# AWaaOcz97xmJjj2H/YHWubbKbRWI9yiYhnSPiDYq5EdR7TEqHeHuFcrBj205vggL
# AueHwfvw4WvZXOOyK5hNvUcB7QZ5gRfHQdNGDZQ5ARZMnP+NpQBUjXgzgto2gRuB
# 4f6XJ7uBaPXaZbSGCvw+q9irm4XRGaUbZ0N/1XSgnzrU2vYM5QggwbWGqdmmrUR5
# wgaS9EKYD3U7/QvWZ2s8lCkeRBSohPyNcUr1rdPZLv4LJLt82DiLHbOQJQOu7QTL
# lW6NMUkANMAZCdvTFYnv+B5qW9+4Qw1aKl40ArloDtDKEE0UFJRBlex1VQvcmP8S
# 2CsALVlwC8P/RGzT6KbvvbTfCCSCawaOE8KApcgiVVGgNoAFf/g9SS6DQkP9eFkd
# +VXS4WxHt9jvrUirbtMcb1G7yQf4R0CAmQmYzaTh36TA1IrG+DonMxRm0RY8MxkC
# IYeJCvy3bEu20duUxpNxMk9YuA==
# SIG # End signature block
