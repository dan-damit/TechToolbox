function Initialize-Config {
    $path = Join-Path $script:ModuleRoot 'Config\config.json'

    if (Test-Path $path) {
        try {
            $script:TechToolboxConfig = Get-TechToolboxConfig -Path $path
        }
        catch {
            $script:TechToolboxConfig = $null
        }
    }
    else {
        $script:TechToolboxConfig = $null
    }
}