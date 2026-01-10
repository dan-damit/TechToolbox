
function Get-TechToolboxConfig {
    <#
    .SYNOPSIS
        Loads and returns the TechToolbox configuration from config.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [object] $Config,
        [Parameter()] [string] $Path
    )

    # If caller passed -Config, skip loading/caching entirely
    if ($PSBoundParameters.ContainsKey('Config')) {
        return $Config
    }

    # If cached and no -Path override, reuse it
    if ($script:TechToolboxConfig -and -not $PSBoundParameters.ContainsKey('Path')) {
        return $script:TechToolboxConfig
    }

    # Build candidate paths
    $candidatePaths = @()
    if ($Path) { $candidatePaths += $Path }

    if ($PSCommandPath) {
        $moduleDir = Split-Path -Parent $PSCommandPath
        $candidatePaths += (Join-Path $moduleDir '..\Config\config.json')
    }

    $candidatePaths += (Join-Path (Get-Location).Path 'config.json')

    # Find first existing config.json
    $found = $candidatePaths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $found) {
        throw "config.json not found. Provide -Path or ensure a config.json exists in the module or current directory."
    }

    # Load JSON
    try {
        $raw = Get-Content -Path $found -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to read or parse config.json from '$found': $($_.Exception.Message)"
    }

    # Validate required root keys
    $names = $raw.PSObject.Properties.Name
    if (-not ($names -contains 'settings')) {
        throw "Missing required key 'settings' in config.json."
    }

    # Normalize entire config into hashtables
    $Config = ConvertTo-Hashtable $raw

    # Cache and return
    $script:TechToolboxConfig = $Config
    return $Config
}