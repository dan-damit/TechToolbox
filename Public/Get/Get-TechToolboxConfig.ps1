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

        $oneDriveRoot = $env:OneDriveCommercial
        if (-not $oneDriveRoot) { $oneDriveRoot = $env:OneDrive }
        if (-not $oneDriveRoot) { $oneDriveRoot = $env:OneDriveConsumer }
        if (-not $oneDriveRoot) { $oneDriveRoot = $env:USERPROFILE }

        $ttHome = if ($env:TT_Home) {
            $env:TT_Home
        }
        else {
            Join-Path $oneDriveRoot 'TechStuff\TechToolbox'
        }

        $defaultModuleRoot = Split-Path -Parent (Split-Path -Parent $ConfigFilePath)
        $moduleRoot = if ($env:TT_ModuleRoot) { $env:TT_ModuleRoot } else { $defaultModuleRoot }

        $logsRoot = if ($env:TT_LogsRoot) {
            $env:TT_LogsRoot
        }
        else {
            Join-Path (Join-Path $ttHome 'LogsAndExports') 'Logs'
        }

        $exportsRoot = if ($env:TT_ExportsRoot) {
            $env:TT_ExportsRoot
        }
        else {
            Join-Path (Join-Path $ttHome 'LogsAndExports') 'Exports'
        }

        return @{
            ModuleRoot  = $moduleRoot.TrimEnd('\\')
            LogsRoot    = $logsRoot.TrimEnd('\\')
            ExportsRoot = $exportsRoot.TrimEnd('\\')
            HomeRoot    = $ttHome.TrimEnd('\\')
        }
    }

    function Rebase-AbsolutePathPrefix {
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
            $resolved = $resolved.Replace('%TT_Home%', $PathRoots.HomeRoot)
            $resolved = $resolved.Replace('%TT_ModuleRoot%', $PathRoots.ModuleRoot)
            $resolved = $resolved.Replace('%TT_LogsAndExportsRoot%', (Join-Path $PathRoots.HomeRoot 'LogsAndExports'))
            $resolved = $resolved.Replace('%TT_LogsRoot%', $PathRoots.LogsRoot)
            $resolved = $resolved.Replace('%TT_ExportsRoot%', $PathRoots.ExportsRoot)

            $resolved = Rebase-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox_LogsAndExports\Logs' -ToRoot $PathRoots.LogsRoot
            $resolved = Rebase-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox_LogsAndExports\Exports' -ToRoot $PathRoots.ExportsRoot
            $resolved = Rebase-AbsolutePathPrefix -Value $resolved -FromRoot 'C:\TechToolbox' -ToRoot $PathRoots.ModuleRoot

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

        $configDir = Split-Path -Parent $ConfigFilePath
        $secretsPath = if ([string]::IsNullOrWhiteSpace($env:TT_ConfigSecretsPath)) {
            Join-Path $configDir 'config.secrets.json'
        }
        else {
            [Environment]::ExpandEnvironmentVariables($env:TT_ConfigSecretsPath)
        }

        if (-not (Test-Path -LiteralPath $secretsPath)) {
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
    $pathFingerprint = '{0}|{1}|{2}|{3}' -f $pathRoots.ModuleRoot, $pathRoots.LogsRoot, $pathRoots.ExportsRoot, $pathRoots.HomeRoot

    $secretsPath = if ([string]::IsNullOrWhiteSpace($env:TT_ConfigSecretsPath)) {
        Join-Path (Split-Path -Parent $fi.FullName) 'config.secrets.json'
    }
    else {
        [Environment]::ExpandEnvironmentVariables($env:TT_ConfigSecretsPath)
    }

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
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAcJ3njA+rTMCfH
# GElJobYAZ1h3vByr75b5nWbAPq+ZfaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCLvJDQX5o8
# b1Ju8joFYCaQGM1Kqop9lIifybul8Q8rQzANBgkqhkiG9w0BAQEFAASCAgBhTJcF
# k0fCi4wyqbOPg7mcKLWmYHkRD62Kk0hQwZmwYwk6pcPASZfwuhe9qOG8wPQ1XNs3
# Jj/F5+1p2DlE/lVwFyJKXp8QhHP8b5uuscOGzlNbxIkxg+9YNQ3h2h32OWIUtyxb
# 3dM66Fv3PNy5r37/iITRhl1pvdB64MWoqolJkyUggtJCRN+pIAHGF5rOJ/5eSyiN
# v1mX8iVP+bUxjqAd8ZRs+Wsv8kFDlp8esslChXiZw/yRsd6CbNzlKk4qTf9WhZoL
# 0kXBwqJqUcdcYIMzYGwkg46Wmq7PZyWf+BibCtoLPHVJ/F4eHdMW/9oOaYvz6b4z
# G+DUnck1B/VDqXHcj183YM+p0t2+tKUgECdt/MF16LD+yPgkAZTdzLZBTvu/KDUR
# T0jQtZs8QqGK7JYz1A54T7dOC5jhsXJvMwnzpnkPymzjIh3OXOEumasLqBPloI6R
# dtHNQejcTrouaCEKkdY/rW6HWeoLXSdIhBOMcbWuAI/93pDikAdpwZq+0LOuhPJQ
# 8JlOp+Bd0e94xTSROSlTLC7lSCkARseXgaISzp7HPGkEEG/3mrRve7DPLOv73P4v
# glUWcKtf0hWZR825q9bztfgQo9Xyw3/DG53IHKsSi8YBNSPFeMaFrXriUkoCFsY5
# 8zH80k0+6DLkqLKHJjTydUL/bDUeOZUf0syQJ6GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA2MDEyMTE4MjlaMC8GCSqGSIb3DQEJBDEiBCDOyZFCKD8uR2yIdoKB
# 3HECof5TsN3qLjpHWkG8BdJW8DANBgkqhkiG9w0BAQEFAASCAgCvw5+zVUwS/o8Y
# 26nrZfI9CAHt0vMcFZ+j5Beukl6QbNDON9WlxIAFE8pyDgTPj/YAIKR8bO/GQBFE
# 9Owi3t6Xziuv1NZzWQ/FwSDfTJ0J1TU/kPP0KT6Vd1FcJhNYWHIDIy2OcKlmdkp/
# f0kCEVpmYLU52zHvyHhqE8oPK1yAI7GRm2s6WD/h6ZK65GDFKKCWyKN1qJoTfEBn
# lKfz0CHAAwH+PKKASeoiLRupZhtXN61ibStlmn1zyMVB5cBnZSzES0UUVGuzcFq3
# +aYJpoiYNYkB0Yh+476Gk/aV0mf9qBAQ02r+vfQrWKhw+EJVStVG1/MRdce+0alZ
# 6twkt24LMsCd6oRkqWxjxgdCLdvcQBJv9jk2izwIKEmDJeBcPnBPSUObsiLdQnxg
# 2sVggaTbpgtSzv4G5rr9es0ghmjUdIIdvSsWNEkm/HCgyki7dYu68kRNzfTQ3PbV
# D9jnH9K8UjgE06XIUSibygw6Dn7Ha/BaGxf5bS7QvbhGt2LrryQXzGFoETkHcKzQ
# 3xCDJL7z3BMOaivAv12bXIB61kOgu3o8V6bHLvgGMkibAnibX8pIdVH4ubVLX5Wr
# UEs3MBtI1nRNFzyocB5kt9HQVE2QeYr2biPLJGxThdbyoHk1GDvKiLkOijUr5PmO
# WVbHSNm+xdx1ECQ5TWbjwcT38Xpj1A==
# SIG # End signature block
