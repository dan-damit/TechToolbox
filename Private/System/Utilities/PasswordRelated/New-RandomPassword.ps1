
function New-RandomPassword {
    <#
    .SYNOPSIS
        Generates passwords that meet AD "complexity" (3/4 categories) using Random, Readable, or Passphrase styles.

    .DESCRIPTION
        - Random: cryptographically-random with optional symbols; exact length.
        - Readable: Two (or more) capitalized words + digits (+ optional symbol); length is a minimum.
        - Passphrase: 3–4 lower/Title words with separators + digits; length is a minimum.
        All styles avoid ambiguous characters when -NoAmbiguous is set. You can provide -DisallowTokens
        to prevent generating passwords that include user-related tokens (e.g., given/surname fragments).

    .PARAMETER Length
        For Random: exact length. For Readable/Passphrase: *minimum* length; will be padded if shorter.

    .PARAMETER NonAlpha
        Number of required symbols (Random style only). Set to 0 to omit symbols entirely.

    .PARAMETER NoAmbiguous
        Excludes look-alike chars and, for Readable/Passphrase, filters out words containing ambiguous letters.

    .PARAMETER Style
        Random | Readable | Passphrase

    .PARAMETER Words
        Number of words for Readable/Passphrase (Readable defaults 2; Passphrase defaults 3).

    .PARAMETER Digits
        Number of digits to include (ensures numeric category).

    .PARAMETER Separator
        Character(s) used between words for Readable/Passphrase (e.g., '-', '.', '').

    .PARAMETER IncludeSymbol
        Adds exactly one symbol in Readable/Passphrase styles (not required for AD).

    .PARAMETER WordListPath
        Optional path to a newline-delimited word list. If not supplied or not found, a built-in list is used.

    .PARAMETER DisallowTokens
        Array of strings to avoid (case-insensitive). If any token of length >= 3 appears, regenerates.

    .EXAMPLE
        New-RandomPassword -Style Readable -Length 12 -Digits 2
        # Example: RiverStone88

    .EXAMPLE
        New-RandomPassword -Style Passphrase -Length 16 -Separator '-' -Digits 3
        # Example: tiger-forest-echo721

    .EXAMPLE
        New-RandomPassword -Style Random -Length 16 -NonAlpha 0 -NoAmbiguous
        # Example: Hw7t9GZxFv3K2QmN
    #>
    [CmdletBinding(DefaultParameterSetName = 'Random')]
    param(
        [ValidateRange(8, 256)]
        [int]$Length = 16,

        # Random style only: number of required non-alphanumeric (symbols)
        [Parameter(ParameterSetName = 'Random')]
        [ValidateRange(0, 64)]
        [int]$NonAlpha = 0,

        [switch]$NoAmbiguous,

        [ValidateSet('Random', 'Readable', 'Passphrase')]
        [string]$Style = 'Random',

        # Word-based styles
        [ValidateRange(2, 6)]
        [int]$Words = 2,

        [ValidateRange(1, 6)]
        [int]$Digits = 2,

        [string]$Separator = '',

        [switch]$IncludeSymbol,

        [string]$WordListPath,

        [string[]]$DisallowTokens = @(),

        [ValidateRange(1, 200)]
        [int]$MaxRegenerate = 50
    )

    # Character sets
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lower = 'abcdefghijklmnopqrstuvwxyz'
    $digits = '0123456789'
    $symbols = '!@#$%^&*_-+=?'

    if ($NoAmbiguous) {
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ'     # no I, O
        $lower = 'abcdefghijkmnpqrstuvwxyz'     # no l, o
        $digits = '23456789'                     # no 0, 1
        # symbols: keep as-is (generally fine)
    }

    # Crypto RNG helpers
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $hasGetInt32 = ([System.Security.Cryptography.RandomNumberGenerator].GetMethod('GetInt32', [type[]]@([int], [int])) -ne $null)

    function Get-RandomIndex {
        param([int]$MaxExclusive)
        if ($MaxExclusive -le 0) { return 0 }
        if ($hasGetInt32) {
            return [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $MaxExclusive)
        }
        else {
            $b = New-Object byte[] 4
            $rng.GetBytes($b)
            return [Math]::Abs([BitConverter]::ToInt32($b, 0) % $MaxExclusive)
        }
    }

    function Get-RandomChar {
        param([string]$Set)
        $Set[(Get-RandomIndex $Set.Length)]
    }

    function Get-RandomFromList {
        param([string[]]$List)
        $List[(Get-RandomIndex $List.Count)]
    }

    function Shuffle([char[]]$arr) {
        for ($i = $arr.Length - 1; $i -gt 0; $i--) {
            $j = Get-RandomIndex ($i + 1)
            if ($j -ne $i) {
                $tmp = $arr[$i]; $arr[$i] = $arr[$j]; $arr[$j] = $tmp
            }
        }
        -join $arr
    }

    function Load-WordList {
        param([string]$Path, [switch]$NoAmbiguous)
        $list = @()
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            $list = Get-Content -LiteralPath $Path -ErrorAction Stop | Where-Object { $_ -match '^[A-Za-z]{3,10}$' }
        }
        if (-not $list -or $list.Count -lt 100) {
            # Fallback mini list if wordlist.txt fails to load
            $list = @(
                'river', 'stone', 'blue', 'green', 'tiger', 'forest', 'echo', 'delta', 'nova', 'ember', 'maple', 'cedar', 'birch', 'pine',
                'silver', 'shadow', 'crimson', 'cobalt', 'onyx', 'raven', 'falcon', 'otter', 'fox', 'wolf', 'lynx', 'badger', 'eagle',
                'harbor', 'summit', 'meadow', 'prairie', 'canyon', 'valley', 'spring', 'autumn', 'winter', 'summer', 'breeze', 'cloud',
                'storm', 'thunder', 'rain', 'snow', 'frost', 'glacier', 'aurora', 'comet', 'meteor', 'orbit', 'quartz', 'granite', 'basalt',
                'pebble', 'coral', 'reef', 'tide', 'delta', 'lagoon', 'moss', 'fern', 'willow', 'aspen', 'spruce', 'hemlock', 'elm',
                'copper', 'iron', 'nickel', 'zinc', 'amber', 'topaz', 'agate', 'jade', 'opal', 'pearl', 'sapphire', 'ruby', 'garnet',
                'swift', 'brisk', 'rapid', 'steady', 'bold', 'bright', 'quiet', 'gentle', 'keen', 'vivid', 'lively', 'nimble', 'solid',
                'lofty', 'noble', 'true', 'prime', 'vantage', 'zenith', 'apex', 'vertex', 'vector', 'gamma', 'omega', 'alpha', 'sigma',
                'orbit', 'photon', 'quark', 'ion', 'pixel', 'matrix', 'cipher', 'beacon', 'signal', 'kernel', 'crypto', 'evergreen', 'lake'
            )
        }
        $list = $list | ForEach-Object { $_.ToLowerInvariant().Trim() } | Where-Object { $_ -ne '' } | Select-Object -Unique
        if ($NoAmbiguous) {
            $list = $list | Where-Object { $_ -notmatch '[ilo10]' } # filter words with ambiguous chars
        }
        return $list
    }

    function Violates-Tokens {
        param([string]$Text, [string[]]$Tokens)
        foreach ($t in $Tokens) {
            if ([string]::IsNullOrWhiteSpace($t)) { continue }
            $tok = $t.Trim()
            if ($tok.Length -lt 3) { continue } # AD typically flags 3+ char sequences
            if ($Text -imatch [regex]::Escape($tok)) { return $true }
        }
        return $false
    }

    try {
        switch ($Style) {
            'Random' {
                # Ensure at least: 1 upper, 1 lower, 1 digit, + NonAlpha symbols
                $minRequired = 3 + $NonAlpha
                if ($Length -lt $minRequired) {
                    throw "Requested Length $Length is less than required minimum $minRequired (1 upper + 1 lower + 1 digit + $NonAlpha symbol(s))."
                }

                # Collect mandatory characters
                $chars = New-Object System.Collections.Generic.List[char]
                $chars.Add((Get-RandomChar $upper))
                $chars.Add((Get-RandomChar $lower))
                $chars.Add((Get-RandomChar $digits))
                for ($i = 0; $i -lt $NonAlpha; $i++) {
                    $chars.Add((Get-RandomChar $symbols))
                }

                # Fill remaining with union of sets (respecting NonAlpha=0 if you want no symbols)
                $all = ($upper + $lower + $digits + ($NonAlpha -gt 0 ? $symbols : '')).ToCharArray()
                while ($chars.Count -lt $Length) {
                    $chars.Add($all[(Get-RandomIndex $all.Length)])
                }

                # Shuffle & return
                $pwd = Shuffle ($chars.ToArray())
                return $pwd
            }

            'Readable' {
                # Make at least 2 words capitalized to ensure Upper+Lower, plus digits -> meets 3/4
                $wl = Load-WordList -Path $WordListPath -NoAmbiguous:$NoAmbiguous
                if ($Words -lt 2) { $Words = 2 } # enforce sane min for readability

                for ($attempt = 0; $attempt -lt $MaxRegenerate; $attempt++) {
                    $picked = for ($i = 1; $i -le $Words; $i++) { Get-RandomFromList $wl }
                    $capIdx = Get-RandomIndex $picked.Count
                    $wordsOut = for ($i = 0; $i -lt $picked.Count; $i++) {
                        if ($i -eq $capIdx) {
                            # TitleCase one word for uppercase category
                            ($picked[$i].Substring(0, 1).ToUpperInvariant() + $picked[$i].Substring(1).ToLowerInvariant())
                        }
                        else {
                            $picked[$i].ToLowerInvariant()
                        }
                    }

                    $digitsStr = -join (1..$Digits | ForEach-Object { Get-RandomChar $digits })
                    $parts = @($wordsOut -join $Separator, $digitsStr)

                    if ($IncludeSymbol) {
                        # Insert symbol at a random position among parts
                        $sym = Get-RandomChar $symbols
                        $insertPos = Get-RandomIndex ($parts.Count + 1)
                        $parts = ($parts[0..($insertPos - 1)] + $sym + $parts[$insertPos..($parts.Count - 1)]) -join ''
                    }
                    else {
                        $parts = -join $parts
                    }

                    $candidate = $parts

                    # Ensure minimum length (pad with lowercase if short)
                    if ($candidate.Length -lt $Length) {
                        $padCount = $Length - $candidate.Length
                        $pad = -join (1..$padCount | ForEach-Object { Get-RandomChar $lower })
                        $candidate += $pad
                    }

                    if ($DisallowTokens.Count -gt 0 -and (Violates-Tokens -Text $candidate -Tokens $DisallowTokens)) {
                        continue
                    }

                    # Sanity: ensure categories: upper, lower, digit
                    if (($candidate -cmatch '[A-Z]') -and ($candidate -cmatch '[a-z]') -and ($candidate -match '\d')) {
                        return $candidate
                    }
                }
                throw "Failed to generate a Readable password after $MaxRegenerate attempts. Consider relaxing DisallowTokens/length."
            }

            'Passphrase' {
                # Typically 3+ words, lower/title with separator, + digits; length is a minimum
                if ($Words -lt 3) { $Words = 3 }
                $wl = Load-WordList -Path $WordListPath -NoAmbiguous:$NoAmbiguous

                for ($attempt = 0; $attempt -lt $MaxRegenerate; $attempt++) {
                    $picked = for ($i = 1; $i -le $Words; $i++) { Get-RandomFromList $wl }
                    # Capitalize one random word to ensure uppercase category
                    $capIdx = Get-RandomIndex $picked.Count
                    for ($i = 0; $i -lt $picked.Count; $i++) {
                        if ($i -eq $capIdx) {
                            $picked[$i] = $picked[$i].Substring(0, 1).ToUpperInvariant() + $picked[$i].Substring(1).ToLowerInvariant()
                        }
                        else {
                            $picked[$i] = $picked[$i].ToLowerInvariant()
                        }
                    }

                    $core = ($picked -join $Separator)
                    $digitsStr = -join (1..$Digits | ForEach-Object { Get-RandomChar $digits })
                    $candidate = $core + $digitsStr

                    if ($IncludeSymbol) {
                        $candidate += (Get-RandomChar $symbols)
                    }

                    if ($candidate.Length -lt $Length) {
                        $padCount = $Length - $candidate.Length
                        $pad = -join (1..$padCount | ForEach-Object { Get-RandomChar $lower })
                        $candidate += $pad
                    }

                    if ($DisallowTokens.Count -gt 0 -and (Violates-Tokens -Text $candidate -Tokens $DisallowTokens)) {
                        continue
                    }

                    # Ensure categories: upper, lower, digit
                    if (($candidate -cmatch '[A-Z]') -and ($candidate -cmatch '[a-z]') -and ($candidate -match '\d')) {
                        return $candidate
                    }
                }
                throw "Failed to generate a Passphrase after $MaxRegenerate attempts. Consider relaxing DisallowTokens/length."
            }
        }
    }
    finally {
        $rng.Dispose()
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeBiV/XCpVxbst
# OcB22yPmSaJ9rI4KEZ9arrxVkvd5jKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBF2h1UMJMW
# Oy1foueWj6mDgCcuH3fOHN5L35B7gZp8STANBgkqhkiG9w0BAQEFAASCAgBI+fP+
# 54oJbnW7rw3R8OlPDHS/Ybt7MZGHKI3dUdL5wjmZkrThgj5O/VziTL4MORN7w2DZ
# Gy/7PvEQ98fPAbJ4YLJ7cJ8zXZjPqdal/E90Hxb52idHdxGzJbjpPgRpkvSzMR72
# QsUvITFe/l1KzrqUN437giYcNfmzly0HR+h8ywlZIGHbvN+xNd6i2PAOcw64FpAZ
# /IVl9ZBpKlgPx+ZOhOvQzgrIof+lgtEv5iZBueZMDfpAnK46jXUHJVkBFnRJ3a56
# ykwk4LimUpRFKw21NJ1MKlv7xxRq6WDExWynDsX6MTa04TcQU56phN2uw25butPl
# WO/MnIHVMaUD5EuoPI8vjdbd1A2ACE524gZR2VbtIddgcP3gWILF70cUzNmKqsNs
# 3XaSj1IYz7m3Z/MUsZZzVhBcGGs5ch4RISuUJHgAvlZu8zBBpIBNQ91hnoqE0/yd
# oGY34aaMUlnufyPx+IDHpTv+WeVP1eLYV9DZy7/b96f2CMyotUikY0l6WTvi+kpW
# pW93ME2ooJIRMw6UCRaLjR6FHKnkCVTo9iBnEyx2zcf+QgUaaVQj70gE+Uedm1mW
# 8TZxBjR1uEBXaFKnFJxxNLIr2F7E7bCZrJetMEvmON8ZOHIMf1hHB4kk+feVxq/S
# IyWqYX94kqmXrcalGlOCmb7ufbcecGDoVKqV4KGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMjIxOTU4NThaMC8GCSqGSIb3DQEJBDEiBCD4Vf8lC+ImTZvO/Snj
# I7FieHOKlElsZLyJbVMxr/luITANBgkqhkiG9w0BAQEFAASCAgDFKE5xxg2jxj/I
# Tsv28g5AnXyBI90Si+mJTe8kYtUb+hEYN/4RfXDrw5lLr4pWj4ACPR4YIjjC5cfN
# YBfvZ6xpx81Rk8VjBU+fEakMy2Sg20nPRlC99MfqjJrPHTBtCv+bTlBtiFjmLDUK
# M5V5IDX8U6wavWMQzVV3sUearyCmOxpAH66K1M+1wtmBi26WHKzszmYUFrIfyYrY
# yuZiU/Vz0DX/RIFsRflGli8Q5cmkeKR4/s9qIr2wZAM4i1cbD1zt3ruDB6d7WeLt
# ZFyxW25g+TP+/RVpCk+GGxtymf/0RJpkUv9CqcHk/GQj+IyYTckj20bva2Io8Vdj
# drwvSrVxfS8upq+mBNmSwXBA4bLtNWAzfh7kHCd/7S+gH+mfXnWf1jCu4Q2zsoA9
# pTYSMadbE7fYQbVsbvj/PY+/wFz4M/zlKff5o4sKCe9lKItlU3L+1/8XPUyUmFrG
# O5xwyI19D/1tviJuHVZ3UorK3phfLhjsPFe4EhwdhXAB4OOeb3ucJ7MVsCbU1o0C
# Q07ZDMldvB/mwZGStBMo/cbvrhPNue7Tcs6QnpKeflskEcnP7wkUm3Zh+4KU2OeF
# Pels3FGqexioYQ/16pBqL5wvHF3/pjNhUL7YJg4Dx4jXa+iHhoeHTSS2hu4GrKZx
# Hu0Va2UdlK38h0Pyx7Ua4NhFqAJfUg==
# SIG # End signature block
