<#
.SYNOPSIS
Builds and updates the TechToolbox module manifest.
#>

param(
    [switch]$AutoVersionPatch,
    [switch]$RegenerateGuid,
    [string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot)
)

function Build-ToolboxManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ModuleRoot,
        [switch]$AutoVersionPatch,
        [switch]$RegenerateGuid
    )

    # Determine module root if not provided
    if (-not $ModuleRoot) {
        $ModuleRoot = Split-Path -Parent $PSScriptRoot
    }

    # Dot-source builder helpers
    $builderRoot = Join-Path $ModuleRoot 'Private\Builder'
    if (Test-Path $builderRoot) {
        Get-ChildItem -Path $builderRoot -Filter *.ps1 -File |
        ForEach-Object { . $_.FullName }
    }

    $manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'
    $publicDir = Join-Path $ModuleRoot 'Public'
    $configDir = Join-Path $ModuleRoot 'Config'

    $manifest = Import-PowerShellDataFile $manifestPath

    # --- Compute new values ---
    $functions = Get-PublicFunctionNames $publicDir

    $guid = if ($RegenerateGuid) { [guid]::NewGuid().Guid } else { $manifest.Guid }

    $version = if ($AutoVersionPatch) {
        Bump-Version $manifest.ModuleVersion
    }
    else {
        $manifest.ModuleVersion
    }

    $dependencies = @(
        @{ Name = 'ExchangeOnlineManagement'; Version = '3.9.0'; Bundled = $true; Required = $true; Defer = $true }
    )

    $moduleList = Build-ModuleList $dependencies
    $privateData = Merge-PrivateData -Existing $manifest.PrivateData -Dependencies $dependencies

    # --- Clone and update ---
    $new = $manifest.Clone()
    $new['Path'] = $manifestPath
    $new.ModuleVersion = $version
    $new.Guid = $guid
    $new.FunctionsToExport = $functions
    $new.ModuleList = $moduleList
    $new.PrivateData = $privateData

    # --- Compute change summary BEFORE writing ---
    $result = [pscustomobject]@{
        Version     = [pscustomobject]@{
            Old = $manifest.ModuleVersion
            New = $version
        }

        Guid        = [pscustomobject]@{
            Old = $manifest.Guid
            New = $guid
        }

        Functions   = [pscustomobject]@{
            Added   = $functions | Where-Object { $_ -notin $manifest.FunctionsToExport }
            Removed = $manifest.FunctionsToExport | Where-Object { $_ -notin $functions }
        }

        ModuleList  = [pscustomobject]@{
            Old = $manifest.ModuleList
            New = $moduleList
        }

        PrivateData = [pscustomobject]@{
            Old = $manifest.PrivateData
            New = $privateData
        }
    }

    # --- Write manifest ---
    if ($PSCmdlet.ShouldProcess($manifestPath, "Update manifest")) {
        Update-ModuleManifest -Path $manifestPath `
            -ModuleVersion $new.ModuleVersion `
            -Guid $new.Guid `
            -FunctionsToExport $new.FunctionsToExport `
            -PrivateData $new.PrivateData `
            -ModuleList $new.ModuleList
    }

    # --- Output summary object ---
    return $result | Format-List *
}

# --- Execute function with script parameters ---
Build-ToolboxManifest `
    -ModuleRoot $ModuleRoot `
    -AutoVersionPatch:$AutoVersionPatch `
    -RegenerateGuid:$RegenerateGuid 