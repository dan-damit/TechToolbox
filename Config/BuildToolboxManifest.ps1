<#
.SYNOPSIS
    Update the TechToolbox module manifest (TechToolbox.psd1) to export all
    public functions and configured aliases.

.DESCRIPTION
    - Discovers all public functions under the Public folder.
    - Reads the existing manifest and preserves all fields unless explicitly
      changed.
    - Optionally bumps the patch version.
    - Optionally regenerates the GUID.
    - Reads aliases to export from Config\AliasesToExport.json, unless an
      explicit -AliasesToExport parameter is provided (which overrides the
      JSON).

.PARAMETER ModuleRoot
    The root directory of the TechToolbox module (e.g., C:\TechToolbox).

.PARAMETER ManifestPath
    The path to the module manifest file. Defaults to 'TechToolbox.psd1' under
    the ModuleRoot.

.PARAMETER RegenerateGuid
    If specified, a new GUID will be generated for the module.

.PARAMETER AutoVersionPatch
    If specified, the patch version (x.y.Z) of the module will be incremented.

.PARAMETER AliasesToExport
    An explicit array of alias names to export from the module. If not supplied,
    aliases will be loaded from Config\AliasesToExport.json.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ModuleRoot,

    [switch]$AutoVersionPatch,

    [string]$ManifestPath = (Join-Path $ModuleRoot 'TechToolbox.psd1'),

    [switch]$RegenerateGuid,

    [string[]]$AliasesToExport
)

function Update-ModuleListEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Manifest,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$Version,

        [bool]$Bundled = $true,
        [bool]$Required = $true,
        [bool]$Defer = $true
    )

    # Normalize the existing ModuleList to an array of hashtables
    $current = @()
    if ($Manifest.ContainsKey('ModuleList') -and $Manifest.ModuleList) {
        $raw = $Manifest.ModuleList
        if ($raw -is [System.Collections.IEnumerable]) {
            foreach ($item in $raw) {
                # Accept either hashtables or psd1-typed dictionaries
                if ($item -is [hashtable]) { $current += $item }
                else {
                    # Convert to hashtable as best-effort
                    $ht = @{}
                    foreach ($prop in $item.PSObject.Properties) { $ht[$prop.Name] = $prop.Value }
                    $current += $ht
                }
            }
        }
    }

    # Upsert entry for ExchangeOnlineManagement
    $updated = $false
    for ($i = 0; $i -lt $current.Count; $i++) {
        $itm = $current[$i]
        if (($itm.Name -eq $Name) -or ($itm['Name'] -eq $Name)) {
            $itm['Name'] = $Name
            $itm['Version'] = $Version
            $itm['Bundled'] = [bool]$Bundled
            $itm['Required'] = [bool]$Required
            $itm['Defer'] = [bool]$Defer
            $current[$i] = $itm
            $updated = $true
            break
        }
    }

    if (-not $updated) {
        $current += @{
            Name     = $Name
            Version  = $Version
            Bundled  = [bool]$Bundled
            Required = [bool]$Required
            Defer    = [bool]$Defer
        }
    }

    return $current
}

function Get-AliasesFromJson {
    param([string]$ConfigDir)

    $path = Join-Path $ConfigDir 'AliasesToExport.json'
    if (-not (Test-Path $path)) {
        Write-Warning "Alias config not found at '$path'; no aliases will be exported from JSON."
        return @()
    }

    try {
        $json = Get-Content -Raw -Path $path | ConvertFrom-Json
        $aliases = @($json.aliases)
        $exportable = $aliases |
        Where-Object { $_.export -and $_.name } |
        Select-Object -ExpandProperty name

        return ($exportable | Sort-Object -Unique)
    }
    catch {
        Write-Warning "Failed to parse alias config '$path': $($_.Exception.Message)"
        return @()
    }
}

function Get-PublicFunctionNames {
    param([string]$PublicDir)

    if (-not (Test-Path $PublicDir)) {
        Write-Warning "Public directory '$PublicDir' not found."
        return @()
    }

    Get-ChildItem -Path $PublicDir -Recurse -Filter *.ps1 -File |
    Select-Object -ExpandProperty BaseName |
    Sort-Object -Unique
}

# --- 1) Discover public functions ---
$publicDir = Join-Path $ModuleRoot 'Public'
$publicFunctions = Get-PublicFunctionNames -PublicDir $publicDir

if (-not $publicFunctions) {
    Write-Warning "No public functions found under '$publicDir'. FunctionsToExport will be empty."
}

# --- 2) Load existing manifest ---
if (-not (Test-Path $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

$manifest = Import-PowerShellDataFile -Path $ManifestPath

# --- 3) Determine GUID ---
$guid = if ($RegenerateGuid -or -not $manifest.Guid) {
    [guid]::NewGuid().Guid
}
else {
    $manifest.Guid
}

# --- 4) Determine ModuleVersion (optionally bump patch) ---
$moduleVersion = $manifest.ModuleVersion
if ($AutoVersionPatch) {
    try {
        $ver = [version]$moduleVersion
        $build = if ($ver.Build -lt 0) { 0 } else { $ver.Build + 1 }
        $moduleVersion = "{0}.{1}.{2}" -f $ver.Major, $ver.Minor, $build
    }
    catch {
        Write-Warning "ModuleVersion '$moduleVersion' is not a valid [version]; keeping as-is."
    }
}

# --- 5) Determine aliases to export ---
$configDir = Join-Path $ModuleRoot 'Config'

if ($PSBoundParameters.ContainsKey('AliasesToExport')) {
    # Caller explicitly provided aliases; use them as-is
    $resolvedAliasesToExport = $AliasesToExport
}
else {
    # Load from JSON config
    $resolvedAliasesToExport = Get-AliasesFromJson -ConfigDir $configDir
}

# --- 5.1) Ensure ModuleList carries EXO 3.9.0 (bundled/pinned) ---
$moduleListUpdated = Update-ModuleListEntry -Manifest $manifest `
    -Name 'ExchangeOnlineManagement' -Version '3.9.0' `
    -Bundled $true -Required $true -Defer $true



# --- 6) Build a complete manifest descriptor for Update-ModuleManifest ---
$newManifest = @{
    Path              = $ManifestPath
    RootModule        = $manifest.RootModule
    ModuleVersion     = $moduleVersion
    Guid              = $guid
    Author            = $manifest.Author
    CompanyName       = $manifest.CompanyName
    Copyright         = $manifest.Copyright
    Description       = $manifest.Description
    PowerShellVersion = $manifest.PowerShellVersion
    RequiredModules   = $manifest.RequiredModules
    CmdletsToExport   = $manifest.CmdletsToExport
    VariablesToExport = $manifest.VariablesToExport
    PrivateData       = $manifest.PrivateData
    ModuleList        = $moduleListUpdated
}


# Optional fields — only include if non-null
$optionalKeys = @(
    'PowerShellHostName',
    'PowerShellHostVersion',
    'DotNetFrameworkVersion',
    'ClrVersion',
    'ProcessorArchitecture',
    'RequiredAssemblies',
    'ScriptsToProcess',
    'TypesToProcess',
    'FormatsToProcess',
    'NestedModules',
    'FileList',
    #'ModuleList',
    'TypesToExport',
    'FormatsToExport'
)

foreach ($key in $optionalKeys) {
    $value = $manifest.$key
    if ($null -ne $value -and $value -ne '') {
        $newManifest[$key] = $value
    }
}

# Always set FunctionsToExport to the discovered public functions (even if empty)
$newManifest['FunctionsToExport'] = $publicFunctions

# Only set AliasesToExport if we actually have any
if ($resolvedAliasesToExport) {
    $newManifest['AliasesToExport'] = $resolvedAliasesToExport
}
else {
    # If the existing manifest had aliases and is now none, Can choose to clear
    # them or preserve them. Here the choice was to clear them explicitly for
    # deterministic builds.
    $newManifest['AliasesToExport'] = @()
}

# --- 7) Apply changes via Update-ModuleManifest ---

if ($PSCmdlet.ShouldProcess($ManifestPath, "Update module manifest")) {
    Update-ModuleManifest @newManifest

    Write-Host "Manifest updated:" -ForegroundColor Green
    Write-Host "  Path:        $ManifestPath"
    Write-Host "  GUID:        $guid"
    Write-Host "  Version:     $moduleVersion"
    Write-Host "  Functions:   $($publicFunctions -join ', ')"
    Write-Host "  Aliases:     $($resolvedAliasesToExport -join ', ')"
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrt1n2xSklwcRr
# jMV7d/xef1Ete6CDsnYpeufD3KWGsKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCALex2ob+Ve
# ZJ6CLq1bnvvhI0uFvJuYWwluMGprYtGZGzANBgkqhkiG9w0BAQEFAASCAgBJbhTn
# Lv8yLGMKGQF9iFvwMMJTJ6owOWQETrjsLKQ6sONbhPCe/lnfj2S2D4y//4/FXXc+
# IwPpxZBRha7ZplzlT4raTjufgD7+Blrh3l2CPNLhSCuk75eMIE+3Tt9R6RIrT2o3
# bgB0zWN9+arxtfXOwOQ7o1ogVds/XNRKw5T33gaz7SVCXNBMe5W6kaVKdYtK7rta
# 9vVpTV2ziDPTcHPP5JnVAwXVTvH+gy08Y6FY2HzETg8nq9U4e5PWIbi5c6LrGIV1
# ly39F695lUjFQ7Hrp/YmE6ZZktqjH2IzlgkeL4FNh3TnGCrOZjGtzAtVnONgBvz8
# Az9bPz6cHQCVs46nKJCg1zcyE/wZ2jBBdkdPcYSrAkqpca4qcYQQB3Q9yHT/xJMG
# PCqMbYnzqEFZbGpPDn9pk0Ij2x8d+jHXf56i9k5GFFOtopc9mLjIZUuiu1VxRZ7r
# 0qjdGdWrI2Uv34Th1rTGgwdmYy4Mf3GUeZg8r4cG0FIIVFfFM9KC2WAgzbPdmdvt
# z2c0neROxR3SNKbpnxxzp5YlkCPfSEvqs9/vwTdNCXXFplE3yeNTO7ykErILky4i
# XGfVoyowx9IDzeyD1gnEf3SWsrR5HJ57ThwxJtcJYRPJ7QsZ8ShwUGf+0X34Fynn
# AHCnRKMNFKQALYTt1JwHpT0aqj2hKAMhKfE5YKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjAxMTMxNzU0NTdaMC8GCSqGSIb3DQEJBDEiBCBlNg7B9ACAkUkxhnib
# 6nyXUcXFsC+y0EILTnk5HjJ97jANBgkqhkiG9w0BAQEFAASCAgAWI0IbVw2NiQmJ
# RYde5jkUtE80jSH0e3DG8GZXxDD7kGVPFEXyfgpxhznMpmJyJsaXqOLF+997OeyA
# WNY2GjvqG8o6Mdok3OAhWhhsuqwBcCVjgYZGuFRRy/sl8CYbz5KNCSwmSLyRZqWA
# IHhxBg446IfLFCLdlfpksBU1HYmqMKqVQv7Dwb/zJ9CGnA7k8NkjQwvK2VBXi6Mx
# Vpu6qzJd7BKrMQjcYkp9LCMGUfff6bWBGRGWDlx+QiApFS3Xc5SzoqHb0qTvSuTx
# OWa67VVnmMcjYHh4dSFm6rvYT/WnSGUCEpYRq0kkRY46fBI7YGQIb+yjiiH6LRT0
# 1bPyqrHMf5R5Ql2ryDCq/epI1equGSE3DjH61crNPfZacRDrz/ZAJp6sBar6WmhP
# XYb59iTH6fFwZrGx9P16QjNPr6BZMr9gKmb3mAiX26ytiBf4lv5EqBc9VlwIAWR8
# GBUgjvyNo704Efl0P5DbUXI1Hq2z9ISmGEnFQ6wvA6yJIAtGUvU8q5Qzl9PE5iqV
# i72XdyhWNA4+UM4/k+lsQmdpJBl0IH2GbbsYT55ISa15OlStpTaWB4QnBP3f2DoA
# O7leWI0pyTUCKCaDwgMaJhX+QQsk2WPsmazkiF4iH7/H7E1sreyGQp8PAml2ZgLc
# sicBgsGHHG/t3cYPWueYvgq4GcPZzg==
# SIG # End signature block
