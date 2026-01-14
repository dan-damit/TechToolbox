function Initialize-Modules {
    $modulesPath = Join-Path $script:ModuleRoot 'Modules'
    if (Test-Path $modulesPath) {
        if (-not ($env:PSModulePath -split ';' | ForEach-Object Trim | Contains $modulesPath)) {
            $env:PSModulePath = "$modulesPath;$env:PSModulePath"
        }
    }

    $list = $script:TechToolboxConfig.Dependencies
    if (-not $list) { return }

    foreach ($m in $list) {
        if ($m.Defer) { continue }

        try {
            Import-Module $m.Name -RequiredVersion $m.Version -Force -ErrorAction Stop
        }
        catch {
            if ($m.Required) { throw }
        }
    }
}