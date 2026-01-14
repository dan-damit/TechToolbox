function Get-PublicFunctionNames {
    param([string]$PublicDir)

    if (-not (Test-Path $PublicDir)) { return @() }

    Get-ChildItem -Path $PublicDir -Recurse -Filter *.ps1 -File |
    Select-Object -ExpandProperty BaseName |
    Sort-Object -Unique
}