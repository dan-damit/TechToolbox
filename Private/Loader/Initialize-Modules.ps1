function Initialize-Modules {
    param([array]$Dependencies)

    $modulesPath = Join-Path $script:ModuleRoot 'Modules'
    if (Test-Path $modulesPath) {
        if (-not ($env:PSModulePath -split ';' | ForEach-Object Trim | Contains $modulesPath)) {
            $env:PSModulePath = "$modulesPath;$env:PSModulePath"
        }
    }

    if (-not $Dependencies) { return }

    foreach ($m in $Dependencies) {
        if ($m.Defer) { continue }

        try {
            Import-Module $m.Name -RequiredVersion $m.Version -Force -ErrorAction Stop
        }
        catch {
            if ($m.Required) { throw }
        }
    }
}