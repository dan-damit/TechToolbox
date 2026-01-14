function Initialize-Aliases {
    $path = Join-Path $script:ModuleRoot 'Config\AliasesToExport.json'
    if (-not (Test-Path $path)) { return @() }

    $items = (Get-Content -Raw -Path $path | ConvertFrom-Json).aliases

    foreach ($a in $items) {
        if ($a.name -and $a.target -and (Get-Command $a.target -ErrorAction SilentlyContinue)) {
            Set-Alias -Name $a.name -Value $a.target
        }
    }

    return $items | Where-Object export | Select-Object -ExpandProperty name
}