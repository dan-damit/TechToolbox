function Initialize-Interop {
    $interopRoot = Join-Path $script:ModuleRoot 'Private\Interop'
    if (-not (Test-Path $interopRoot)) { return }

    Get-ChildItem $interopRoot -Filter *.cs -Recurse | ForEach-Object {
        try { Add-Type -Path $_.FullName -ErrorAction Stop }
        catch { }
    }
}