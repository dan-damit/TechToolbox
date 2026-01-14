function Initialize-PrivateFunctions {
    $privateRoot = Join-Path $script:ModuleRoot 'Private'
    Get-ChildItem -Path $privateRoot -Recurse -Filter *.ps1 |
    Where-Object { $_.FullName -notlike '*\Loader\*' } |
    ForEach-Object { . $_.FullName }
}