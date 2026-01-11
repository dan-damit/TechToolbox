function Get-TechToolboxConfig {
    <#
    .SYNOPSIS
        Loads and returns the TechToolbox configuration from config.json.
    .PARAMETER Path
        Optional path to the config.json file. If not provided, the default
        location relative to the module is used.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [string] $Path
    )

    # Determine config path (explicit override wins)
    if ($Path) {
        $configPath = $Path
    }
    else {
        # Resolve module directory
        $moduleDir = Split-Path -Parent $PSScriptRoot
        $configPath = Join-Path $moduleDir 'Config\config.json'
    }

    # Validate path
    if (-not (Test-Path -LiteralPath $configPath)) {
        throw "config.json not found at '$configPath'. Provide -Path or ensure the module's Config folder contains config.json."
    }

    # Load JSON
    try {
        $raw = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to read or parse config.json from '$configPath': $($_.Exception.Message)"
    }

    # Validate required root keys
    $rootNames = $raw.PSObject.Properties.Name | ForEach-Object { $_.ToLower() }
    if (-not ($rootNames -contains 'settings')) {
        throw "Missing required key 'settings' in config.json."
    }

    # Recursive normalizer
    function ConvertTo-Hashtable {
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            if ($null -eq $InputObject) { return $null }

            if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
                $hash = @{}
                foreach ($prop in $InputObject.PSObject.Properties) {
                    $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
                }
                return $hash
            }

            if ($InputObject -is [System.Collections.IDictionary]) {
                $hash = @{}
                foreach ($key in $InputObject.Keys) {
                    $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
                }
                return $hash
            }

            if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
                $list = @()
                foreach ($item in $InputObject) {
                    $list += ConvertTo-Hashtable $item
                }
                return $list
            }

            return $InputObject
        }
    }

    # Always normalize to nested hashtables
    $script:TechToolboxConfig = ConvertTo-Hashtable $raw

    return $script:TechToolboxConfig
}