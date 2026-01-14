function Get-ModuleDependencies {
    <#
    .SYNOPSIS
        Returns the module dependency list for TechToolbox.

    .DESCRIPTION
        Priority:
        1. Manifest PrivateData.TechToolbox.Dependencies
        2. Config.json (settings.dependencies)
        3. Hardcoded fallback (ExchangeOnlineManagement 3.9.0)
    #>
    [CmdletBinding()]
    param(
        [string]$ManifestPath = (Join-Path $script:ModuleRoot 'TechToolbox.psd1'),
        [string]$ConfigPath = $script:ConfigPath
    )

    # --- 1) Manifest PrivateData ---
    try {
        if (Test-Path $ManifestPath) {
            $m = Import-PowerShellDataFile -Path $ManifestPath
            $pd = $m.PrivateData
            if ($pd -and $pd.TechToolbox -and $pd.TechToolbox.Dependencies) {
                return $pd.TechToolbox.Dependencies
            }
        }
    }
    catch {
        Write-Verbose "Get-ModuleDependencies: manifest read failed: $($_.Exception.Message)"
    }

    # --- 2) Config.json ---
    try {
        if (Test-Path $ConfigPath) {
            $cfg = Get-TechToolboxConfig -Path $ConfigPath
            if ($cfg.settings.dependencies) {
                return $cfg.settings.dependencies
            }
        }
    }
    catch {
        Write-Verbose "Get-ModuleDependencies: config read failed: $($_.Exception.Message)"
    }

    # --- 3) Hardcoded fallback ---
    return @(
        @{
            Name     = 'ExchangeOnlineManagement'
            Version  = '3.9.0'
            Bundled  = $true
            Required = $true
            Defer    = $true
        }
    )
}