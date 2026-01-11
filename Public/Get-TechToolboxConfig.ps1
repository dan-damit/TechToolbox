
function Get-TechToolboxConfig {
    <#
    .SYNOPSIS
        Loads and returns the TechToolbox configuration from config.json.
    #>
    [CmdletBinding()]
    param(
        [Parameter()] [string] $Path,
        [switch] $PreserveRoot
    )

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
        Write-Host $raw
    }
    catch {
        throw "Failed to read or parse config.json from '$found': $($_.Exception.Message)"
    }

    # Validate required root keys case-insensitively
    $rootNames = $raw.PSObject.Properties.Name | ForEach-Object { $_.ToLower() }
    if (-not ($rootNames -contains 'settings')) {
        throw "Missing required key 'settings' in config.json."
    }

    # Recursive normalizer: PSCustomObject, IDictionary, arrays -> hashtables/arrays
    function ConvertTo-Hashtable {
        param([Parameter(ValueFromPipeline)] $InputObject)

        process {
            if ($null -eq $InputObject) {
                return $null
            }

            # PSCustomObject (JSON objects)
            if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
                $hash = @{}
                foreach ($prop in $InputObject.PSObject.Properties) {
                    $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
                }
                return $hash
            }

            # IDictionary / Hashtable
            if ($InputObject -is [System.Collections.IDictionary]) {
                $hash = @{}
                foreach ($key in $InputObject.Keys) {
                    $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
                }
                return $hash
            }

            # Enumerable (arrays) but not string
            if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
                $list = @()
                foreach ($item in $InputObject) {
                    $list += (ConvertTo-Hashtable $item)
                }
                return $list
            }

            # Scalar
            return $InputObject
        }
    }

    # Normalize entire config or preserve root as PSCustomObject with normalized children
    if ($PreserveRoot) {
        $obj = [PSCustomObject]@{}
        foreach ($prop in $raw.PSObject.Properties) {
            $value = ConvertTo-Hashtable $prop.Value
            $obj | Add-Member -NotePropertyName $prop.Name -NotePropertyValue $value
        }
        $script:TechToolboxConfig = $obj
    }
    else {
        $script:TechToolboxConfig = & ConvertTo-Hashtable $raw
    }

    return $script:TechToolboxConfig
}