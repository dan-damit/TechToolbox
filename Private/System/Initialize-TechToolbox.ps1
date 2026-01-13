
function Initialize-TechToolbox {
    <#
    .SYNOPSIS
        Initializes TechToolbox module dependencies.
    .DESCRIPTION
        This function ensures that all required and optional modules for
        TechToolbox are loaded, preferring bundled versions when available.
        It supports configuration via an external JSON file to customize
        which modules to load, their versions, and whether to defer loading.
    .PARAMETER ToolboxRoot
        Optional override to your TechToolbox root (defaults to module root).
    .PARAMETER ConfigPath
        Optional path to config.json (defaults to
        C:\TechToolbox\Config\config.json).
    .PARAMETER VerboseLogging
        Enable verbose diagnostics.
    .INPUTS
        None.
    .OUTPUTS
        None.
    .EXAMPLE
        Initialize-TechToolbox
    .EXAMPLE
        Initialize-TechToolbox -ConfigPath 'D:\Configs\myconfig.json' -VerboseLogging
    #>
    [CmdletBinding()]
    param(
        # Optional override to your TechToolbox root (defaults to module root)
        [string]$ToolboxRoot = $PSScriptRoot,

        # Optional path to config.json (defaults to C:\TechToolbox\Config\config.json)
        [string]$ConfigPath = (Join-Path 'C:\TechToolbox\Config' 'config.json'),

        # Enable verbose diagnostics
        [switch]$VerboseLogging
    )

    function Write-Diag {
        param([string]$Message)
        if ($VerboseLogging) { Write-Verbose $Message }
    }

    # 1) Ensure bundled Modules path is in PSModulePath
    $modulesPath = Join-Path $ToolboxRoot 'Modules'
    if (Test-Path $modulesPath) {
        if (-not ($env:PSModulePath -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -eq $modulesPath })) {
            $env:PSModulePath = "$modulesPath;$env:PSModulePath"
            Write-Diag "Prepended bundled Modules path: $modulesPath"
        }
        else {
            Write-Diag "Bundled Modules path already in PSModulePath: $modulesPath"
        }
    }
    else {
        Write-Verbose "Bundled Modules path not found: $modulesPath"
    }

    # 2) Read module list from config.json (optional), otherwise use hardcoded list
    $ModuleList = @()

    function Get-ModulesFromConfig {
        param([string]$Path)
        if (-not (Test-Path $Path)) {
            Write-Diag "Config not found: $Path. Falling back to hardcoded ModuleList."
            return $null
        }
        try {
            $cfg = Get-Content -Raw -Path $Path | ConvertFrom-Json
            if ($cfg.Modules) { return $cfg.Modules }
            Write-Diag "No 'Modules' section in config; fallback to hardcoded list."
            return $null
        }
        catch {
            Write-Warning "Failed to parse config '$Path': $($_.Exception.Message)"
            return $null
        }
    }

    $modulesFromConfig = Get-ModulesFromConfig -Path $ConfigPath
    if ($modulesFromConfig) {
        $ModuleList = @($modulesFromConfig)
    }
    else {
        # Hardcoded default — Option A with EXO v3.9.0
        $ModuleList = @(
            @{
                Name     = 'ExchangeOnlineManagement'
                Version  = '3.9.0'
                Bundled  = $true
                Required = $true
                Defer    = $true    # defer import until Ensure-ExchangeOnlineModule or when first needed
            }
        )
    }

    # 3) Generic loader — ensures an exact version, tries bundled path first
    function Initialize-TechToolboxModules {
        [CmdletBinding()]
        param([switch]$ForceReload)

        foreach ($m in $ModuleList) {
            $name = $m.Name
            $version = [version]$m.Version
            $bundled = [bool]$m.Bundled
            $required = [bool]$m.Required
            $defer = [bool]$m.Defer

            # Defer means: don't import now; availability check only
            if ($defer -and -not $ForceReload) {
                Write-Diag "Deferred import for $name $version."
                continue
            }

            # Is exact version already available?
            $available = Get-Module -ListAvailable $name |
            Where-Object { $_.Version -eq $version }

            if (-not $available -and $bundled) {
                # Prefer direct import from the bundled folder if version-specific path exists
                $bundledPath = Join-Path $modulesPath (Join-Path $name $m.Version)
                if (Test-Path $bundledPath) {
                    Write-Diag "Found bundled path for $name $version $bundledPath"
                }
                else {
                    Write-Warning "Bundled path missing for $name $version at '$bundledPath'."
                }
            }

            try {
                Import-Module $name -RequiredVersion $version -Force -ErrorAction Stop
                Write-Diag "Imported $name $version."
            }
            catch {
                Write-Warning "Failed to import $name $version $($_.Exception.Message)"
                if ($required) { throw "Required module missing: $name $($version.ToString())" }
            }
        }
    }

    # 4) On module import, we do not force-load deferred modules (keeps initial import light)
    Initialize-TechToolboxModules

    # 5) Helper: Ensure EXO is loaded exactly (deferred until first EXO use)
    function Ensure-ExchangeOnlineModule {
        [CmdletBinding()]
        param(
            [string]$RequiredVersion = '3.9.0'
        )

        $name = 'ExchangeOnlineManagement'
        $version = [version]$RequiredVersion

        $alreadyLoaded = Get-Module -Name $name | Where-Object { $_.Version -eq $version }
        if ($alreadyLoaded -and $alreadyLoaded.Count -gt 0) {
            Write-Diag "EXO $version already loaded."
            return
        }

        # Make sure it's available, then import
        $available = Get-Module -ListAvailable $name | Where-Object { $_.Version -eq $version }
        if (-not $available) {
            # Attempt a one-time initialization with ForceReload to import now
            Initialize-TechToolboxModules -ForceReload
            $available = Get-Module -ListAvailable $name | Where-Object { $_.Version -eq $version }
            if (-not $available) {
                throw "ExchangeOnlineManagement $($version.ToString()) is not available in PSModulePath. Check your bundled Modules folder."
            }
        }

        Import-Module $name -RequiredVersion $version -Force
        Write-Diag "Loaded ExchangeOnlineManagement $version."

        # Optional: show a friendly banner suppressed
        # Connect-ExchangeOnline -ShowBanner:$false  # Call only when you actually need to connect
    }

    Export-ModuleMember -Function Ensure-ExchangeOnlineModule
}