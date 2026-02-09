@{
    IncludeRules = @(
        'PSUseApprovedVerbs'
        'PSAvoidGlobalVars'
        'PSAvoidUsingCmdletAliases'
        'PSUseConsistentWhitespace'
        'PSProvideCommentHelp'
        'PSUseShouldProcessForStateChangingFunctions'
    )

    ExcludeRules = @(
        # add exclusions if needed
    )

    Rules        = @{
        PSUseConsistentWhitespace = @{
            Enable                                  = $true
            CheckInnerBrace                         = $true
            CheckOpenBrace                          = $true
            CheckOpenParen                          = $true
            CheckOperator                           = $false
            CheckPipe                               = $true
            CheckPipeForRedundantWhitespace         = $false
            CheckSeparator                          = $true
            CheckParameter                          = $false
            IgnoreAssignmentOperatorInsideHashTable = $false
        }
    }
}

# SIG # Begin signature block
# MIIIngYJKoZIhvcNAQcCoIIIjzCCCIsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCF152IPkZtz5sU
# JQIBHc8tSM1OfJghkzOsnw7PAx+UY6CCBRAwggUMMIIC9KADAgECAhAR+U4xG7FH
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
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95ExggLkMIIC4AIBATAyMB4xHDAaBgNV
# BAMME1ZBRFRFSyBDb2RlIFNpZ25pbmcCEBH5TjEbsUeqTKpL00i3uXkwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQguKD+UKZSwP7X4/3e/Wre56NrsiX4xIzyirzPQUGvseYw
# DQYJKoZIhvcNAQEBBQAEggIA05WRcBj44Kdr/Ypo1cKcCo1RhyBJFe92U0WQLa/5
# cnpT6PW1I4uo6i+YGMH7qiwwh9R7LifB0S3tDSxFWL98IjLEcC66kSRYh2K56tlm
# fvqkvE0aYSWKYsKh2VQaaxwJyTMu87Amksfh0yFa+uSkC663/ue01v44xIHxvuU4
# Ec+sDe22Me30r7pNQUaM0wpq73hkJkq0sNrsep2rnDGabmeccVBOWj5R7dMG2yWK
# aUN7O/Y0L+D335LYZe14JYv3ePJ7v3YxMM66BHMRaQdPk/uJI4TAseZ3qrNouLwZ
# IIojg74B8hNK0ALhovYowpjF/aqKYN2bukRkZT6ExCzIQ+n1pZl01qjlnREXk0rs
# N38ObgaODM/IRuyLDBBIVAZgwBqudbSTwfhdWd9x0o+VNFsevXJ1tSqs5f1GsSSl
# biID5ugD0xya5xE2XaFY0g1vzQ0PYxR7Lf7YEfheh7BPAg6R53M8jJv21F5UyJWp
# aMwCM4cW94Z2QvIsoqhwUqGLrfAG00Gk8InwQE5I4UQLy06iKRRGRR+e/IUj2QqH
# cVOYHqrR3o513+JV7D2eqQa+AVYVq4DtG0ip0/uB6NVVs8wDcsSkCZtff17fI0Ij
# Lf6d8HIKa8FqtuehcIUGycpTZsbOtj9HzXEZi3QYorkBZa9zI3McwGyugmrCeJnT
# TXM=
# SIG # End signature block
