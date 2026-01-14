function Build-ToolboxManifest {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$ModuleRoot = (Split-Path -Parent $PSScriptRoot),
        [switch]$AutoVersionPatch,
        [switch]$RegenerateGuid,
        [string[]]$AliasesToExport
    )

    # Determine module root if not provided
    if (-not $ModuleRoot) {
        $ModuleRoot = Split-Path -Parent $PSScriptRoot
    }

    # Dot-source loader helpers
    $loaderRoot = Join-Path $ModuleRoot 'Private\Loader'
    $builderRoot = Join-Path $ModuleRoot 'Private\Builder'

    foreach ($root in @($loaderRoot, $builderRoot)) {
        if (Test-Path $root) {
            Get-ChildItem -Path $root -Filter *.ps1 -File |
            ForEach-Object { . $_.FullName }
        }
    }

    $manifestPath = Join-Path $ModuleRoot 'TechToolbox.psd1'
    $publicDir = Join-Path $ModuleRoot 'Public'
    $configDir = Join-Path $ModuleRoot 'Config'

    $manifest = Import-PowerShellDataFile $manifestPath

    # --- Compute new values ---
    $functions = Get-PublicFunctionNames $publicDir

    if (-not $AliasesToExport) {
        $AliasesToExport = Get-AliasesFromJson $configDir
    }

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
    $new.AliasesToExport = $AliasesToExport
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
        Aliases     = [pscustomobject]@{
            Old = $manifest.AliasesToExport
            New = $AliasesToExport
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
        Update-ModuleManifest @new
    }

    # --- Output summary object ---
    return $result | Format-List *
}
Build-ToolboxManifest @PSBoundParameters