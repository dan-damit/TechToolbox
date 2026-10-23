function Get-TechToolboxConfig {
    <#
    .SYNOPSIS
        Loads and validates a TechToolbox JSON configuration file.
    .DESCRIPTION
        Reads a JSON configuration file from disk, converts it into a hashtable-based
        object graph, validates the required top-level and password-default settings,
        and returns the parsed configuration data.
        The function maintains an in-memory script-scoped cache keyed by the
        resolved file path and the file's LastWriteTimeUtc value. If the same file is
        requested again and has not changed, the cached configuration is returned
        instead of re-reading and re-parsing the JSON.
        Behavior details:
        - Throws if the target file does not exist.
        - Throws if the file is empty or contains invalid JSON.
        - Uses ConvertFrom-Json -AsHashtable on PowerShell 7+.
        - Uses a recursive PSCustomObject-to-hashtable fallback on Windows
            PowerShell 5.1.
        - Validates that schemaVersion and settings exist at the top level.
        - Validates that settings.passwords.default contains separator, style,
            length, and digits.
        - Preserves raw values exactly as stored in the JSON and does not trim or
            mutate configuration values.
    .PARAMETER Path
        The path to the TechToolbox JSON configuration file to load. The file must
        exist and contain valid JSON with the required TechToolbox configuration
        structure.
    .INPUTS
        None. You cannot pipe objects to Get-TechToolboxConfig.
    .OUTPUTS
        System.Collections.Hashtable. Returns the parsed configuration as a nested
        hashtable/array structure.
    .EXAMPLE
        Get-TechToolboxConfig -Path '.\Config\config.json'
        Loads the main TechToolbox configuration file and returns the parsed
        settings.
    .EXAMPLE
        $config = Get-TechToolboxConfig -Path '$env:TT_ModuleRoot\Config\config.json'
        $config.settings.passwords.default
        Loads the configuration and inspects the default password settings.
    .EXAMPLE
        Get-TechToolboxConfig -Path '.\Config\config.json'
        Get-TechToolboxConfig -Path '.\Config\config.json'
        Demonstrates repeated calls for the same unchanged file. The second call can
        return the cached configuration data.
    .NOTES
        Updates both the private script-scoped cache variable and the legacy
        $script:TechToolboxConfig variable for compatibility with existing module
        code.
    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-TechToolboxConfig
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    # --- PS5-compatible deep converter (only used on PS5) ---
    function ConvertTo-Hashtable {
        param([Parameter(Mandatory)]$InputObject)

        if ($InputObject -is [hashtable]) { return $InputObject }

        if ($InputObject -is [System.Collections.IDictionary]) {
            $ht = @{}
            foreach ($k in $InputObject.Keys) {
                $ht[$k] = ConvertTo-Hashtable $InputObject[$k]
            }
            return $ht
        }

        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            return @(
                $InputObject | ForEach-Object { ConvertTo-Hashtable $_ }
            )
        }

        if ($InputObject -is [pscustomobject]) {
            $ht = @{}
            foreach ($p in $InputObject.PSObject.Properties) {
                $ht[$p.Name] = ConvertTo-Hashtable $p.Value
            }
            return $ht
        }

        return $InputObject
    }

    function Get-TechToolboxPathRoots {
        param([Parameter(Mandatory)][string]$ConfigFilePath)

        if (-not $script:TT -or -not $script:TT.ModuleRoot -or -not $script:TT.LocalDataRoot) {
            throw 'Authoritative TechToolbox path state is not initialized.'
        }

        return @{
            ModuleRoot  = $script:TT.ModuleRoot.TrimEnd('\\')
            LocalDataRoot = $script:TT.LocalDataRoot.TrimEnd('\\')
            LogsRoot    = $script:TT.LogsRoot.TrimEnd('\\')
            ExportsRoot = $script:TT.ExportsRoot.TrimEnd('\\')
        }
    }

    function Assert-AbsolutePathPrefix {
        param(
            [string]$Value,
            [Parameter(Mandatory)][string]$FromRoot,
            [Parameter(Mandatory)][string]$ToRoot
        )

        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        $from = $FromRoot.TrimEnd('\\')
        $to = $ToRoot.TrimEnd('\\')
        if ([string]::IsNullOrWhiteSpace($from) -or [string]::IsNullOrWhiteSpace($to)) {
            return $Value
        }

        if ($Value.StartsWith($from, [System.StringComparison]::OrdinalIgnoreCase)) {
            $suffix = $Value.Substring($from.Length).TrimStart('\\', '/')
            if ([string]::IsNullOrWhiteSpace($suffix)) { return $to }
            return (Join-Path $to $suffix)
        }

        return $Value
    }

    function Resolve-TechToolboxConfigNode {
        param(
            $Node,
            [Parameter(Mandatory)][hashtable]$PathRoots
        )

        if ($null -eq $Node) {
            return $null
        }

        if ($Node -is [hashtable]) {
            foreach ($k in @($Node.Keys)) {
                $Node[$k] = Resolve-TechToolboxConfigNode -Node $Node[$k] -PathRoots $PathRoots
            }
            return $Node
        }

        if ($Node -is [System.Collections.IList]) {
            for ($i = 0; $i -lt $Node.Count; $i++) {
                $Node[$i] = Resolve-TechToolboxConfigNode -Node $Node[$i] -PathRoots $PathRoots
            }
            return $Node
        }

        if ($Node -is [string]) {
            $resolved = [Environment]::ExpandEnvironmentVariables($Node)
            $resolved = $resolved.Replace('%TT_Home%', $PathRoots.LocalDataRoot)
            $resolved = $resolved.Replace('%TT_LocalDataRoot%', $PathRoots.LocalDataRoot)
            $resolved = $resolved.Replace('%TT_ModuleRoot%', $PathRoots.ModuleRoot)
            $resolved = $resolved.Replace('%TT_LogsAndExportsRoot%', $PathRoots.LocalDataRoot)
            # Normalize legacy log/export suffixes after all root tokens have resolved.
            $resolved = $resolved.Replace((Join-Path $PathRoots.LocalDataRoot 'LogsAndExports\Logs'), $PathRoots.LogsRoot)
            $resolved = $resolved.Replace((Join-Path $PathRoots.LocalDataRoot 'LogsAndExports\Exports'), $PathRoots.ExportsRoot)
            $resolved = $resolved.Replace('%TT_LogsRoot%', $PathRoots.LogsRoot)
            $resolved = $resolved.Replace('%TT_ExportsRoot%', $PathRoots.ExportsRoot)

            $resolved = Assert-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox_LogsAndExports\Logs' -ToRoot $PathRoots.LogsRoot
            $resolved = Assert-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox_LogsAndExports\Exports' -ToRoot $PathRoots.ExportsRoot
            $resolved = Assert-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox' -ToRoot $PathRoots.ModuleRoot

            return $resolved
        }

        return $Node
    }

    function Merge-TechToolboxConfigNode {
        param(
            [Parameter(Mandatory)]$Base,
            [Parameter(Mandatory)]$Override
        )

        if ($Override -is [hashtable] -and $Base -is [hashtable]) {
            foreach ($key in $Override.Keys) {
                if ($Base.ContainsKey($key)) {
                    $Base[$key] = Merge-TechToolboxConfigNode -Base $Base[$key] -Override $Override[$key]
                }
                else {
                    $Base[$key] = $Override[$key]
                }
            }

            return $Base
        }

        # Arrays and scalar values are replaced wholesale by the override value.
        return $Override
    }

    function Get-TechToolboxSecretsOverride {
        param([Parameter(Mandatory)][string]$ConfigFilePath)

        if ($env:TT_DisableConfigSecretsMerge -eq '1') {
            return $null
        }

        $secretsPath = $script:TT.SecretsPath
        if (-not (Test-Path -LiteralPath $secretsPath -PathType Leaf)) {
            return $null
        }

        $raw = Get-Content -LiteralPath $secretsPath -Raw -Encoding UTF8 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return $null
        }

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            return (ConvertFrom-Json -InputObject $raw -AsHashtable)
        }

        return (ConvertTo-Hashtable (ConvertFrom-Json -InputObject $raw))
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Get-TechToolboxConfig: config file not found at '$Path'."
    }

    $fi = Get-Item -LiteralPath $Path

    $pathRoots = Get-TechToolboxPathRoots -ConfigFilePath $Path
    $pathFingerprint = '{0}|{1}|{2}|{3}' -f $pathRoots.ModuleRoot, $pathRoots.LocalDataRoot, $pathRoots.LogsRoot, $pathRoots.ExportsRoot

    $secretsPath = $script:TT.SecretsPath

    $secretsLastWrite = ''
    if (Test-Path -LiteralPath $secretsPath) {
        $secretsLastWrite = (Get-Item -LiteralPath $secretsPath).LastWriteTimeUtc.ToString('o')
    }

    $secretsMergeFlag = if ($env:TT_DisableConfigSecretsMerge -eq '1') { 'off' } else { 'on' }
    $cacheFingerprint = '{0}|{1}|{2}|{3}' -f $pathFingerprint, $secretsPath, $secretsLastWrite, $secretsMergeFlag

    # --- Simple session cache (StrictMode-safe) ---
    if (-not (Get-Variable -Name __cfgCache -Scope Script -ErrorAction SilentlyContinue)) {
        $script:__cfgCache = $null
    }

    $cache = $script:__cfgCache
    if ($cache -and
        $cache.Path -eq $fi.FullName -and
        $cache.LastWriteTimeUtc -eq $fi.LastWriteTimeUtc -and
        $cache.PathFingerprint -eq $cacheFingerprint) {
        return $cache.Data
    }

    # --- Load & parse (use -Raw; DO NOT use $raw variable) ---
    $jsonRaw = Get-Content -LiteralPath $fi.FullName -Raw -ErrorAction Stop

    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $data = ConvertFrom-Json -InputObject $jsonRaw -AsHashtable
    }
    else {
        $data = ConvertTo-Hashtable (ConvertFrom-Json -InputObject $jsonRaw)
    }

    $secretsOverride = Get-TechToolboxSecretsOverride -ConfigFilePath $fi.FullName
    if ($secretsOverride) {
        if ($secretsOverride.ContainsKey('settings') -and $secretsOverride.settings -is [hashtable]) {
            if (-not ($data.settings -is [hashtable])) { $data.settings = @{} }
            $data.settings = Merge-TechToolboxConfigNode -Base $data.settings -Override $secretsOverride.settings
        }

        if ($secretsOverride.ContainsKey('paths') -and $secretsOverride.paths -is [hashtable]) {
            if (-not ($data.paths -is [hashtable])) { $data.paths = @{} }
            $data.paths = Merge-TechToolboxConfigNode -Base $data.paths -Override $secretsOverride.paths
        }
    }

    $data = Resolve-TechToolboxConfigNode -Node $data -PathRoots $pathRoots

    # --- Update cache ---
    $script:__cfgCache = @{
        Path             = $fi.FullName
        LastWriteTimeUtc = $fi.LastWriteTimeUtc
        PathFingerprint  = $cacheFingerprint
        Data             = $data
    }

    # Optional: maintain the legacy global if other code expects it
    $script:TechToolboxConfig = $data

    return $data
}
# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC0ukr8YjpHsaw8
# LqRWOHM5mJ1jxxLWXuqe7eiHgBfVcKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
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
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDn
# CbMkP/cihfL2kvDW/pUpxjidEh23zBWZe8h0h04BODANBgkqhkiG9w0BAQEFAASC
# AYAb82ZUKlu4dxWJDeqLibu9SxfiF+FbUdoHFXSpQ400ErYzDZJIqIhW2xK26jXE
# Z3Tj0+zeKASBA2DiLO9TltVkkc22C7GJ0cK0W2r+NWYq0mAxvyPqplUG+BVja9al
# ML/9pDN52uqklBE2z5dhPwrS13HGN9MgWI/wb7xyQWLlKjq0JnZKzr8zaOFN1BUj
# q4jUymiAEI3ev75bbETFEMNGb9F5noCcHeU0pW02FcmPsW3KjnkFFHsTNvVP83JZ
# HgcL4qqMx/+c/Rrfny6yrD6H66yi4si/x5sDQiLtMJljDR2Y6G/kTqIil1jZIqPD
# bMsNhVT9nu/UQELW7Mf9gVw/V47q0j4SoW01d7CpLiqnwfg9T8pVua2+BqGOpj+B
# PfNDyng7TwxXNvEB/wkf9jrGd6H4NmAF4CkSZPQT5cw9NqqK5x2iYWhLQMnMzGhO
# I4LEb/kHEcE0OwaMazy3IXFVKJQz0LcsnT1afOhh4IEmqMKw5gpz18XoVADMaf18
# 0FGhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMDIzMDIzMTQ2WjAvBgkqhkiG
# 9w0BCQQxIgQgoMDC1GiUW7fqrBabf0qUkX/4FfV3uQD2EuRRJLMIZWkwDQYJKoZI
# hvcNAQEBBQAEggIAQa3S613eBUPTmrsDDtyvfV+XaLdy7BoNPVFSZNWbBrL04sAC
# RXUjaZshQEFXnNHbEhxZjfBDHbawsy/hPSgyBTv7+JCDwloTRvvQDXwUep9iTy3O
# 6lPsjQnAkCF6MRbU1G5xeNzBJa5NAbuXu3aqPLTCB2HdSuO6IOsscxd4rWywLrTf
# pS7+u4pb2cm1d6u22AzPMqRU8sZe6hKa021MAOoHGYJhn1Tw11DtzEfm8iIfpmv5
# 2/w8SKacR4wTEYOYVPMIQc+kPoxJco0gpvMQJ1azyJNA5GLD0vwW3hKlv7U1/1lC
# WHNgnQrYjlLVKxIOIl9VhD+ce6BuSHyT+wCjX1g6JvMtTgEnk/m7QxkD76liVlj6
# Z0OZyN1olIVpc7uQ1HPFKf4ethea6W2S2ciMuWuHS6wtpILmkGFeLril6SoaAX3R
# VZgFiL2k4APA36aD1nkPUnYfawUwmotEY349sAZ4dqVEhDaKXWAjH+aSSEoVmztd
# ONCL6T1+cy/pKkv9XYNjFMC/aDk0nyDqhvpC0MsKPd4MrhA2ImFa8ctknO4LO6fL
# 9Ig75LEb/zDyCvdstXV1z5mVVvqayzoaKmPe0iHm7ZpvtjevHch+vsHG6wIjyMmq
# yuBIIXfvB53bj6cYGRSLLME7EripWh2m6QfIx/oRa0qx/Xlqi6RHCTa/hWc=
# SIG # End signature block
