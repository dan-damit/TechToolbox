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

# --- 6) Build a complete manifest descriptor for Update-ModuleManifest ---
# Start with a hashtable preserving as much as possible
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
    'ModuleList',
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