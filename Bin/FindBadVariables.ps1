$root = 'C:\TechToolbox'

$hits = Get-ChildItem -Path $root -Recurse -File -Include *.ps1, *.psm1, *.psd1 |
Select-String -Pattern '\$Args\b|param\s*\([^)]*\$Args\b'

$hits |
Group-Object Path |
ForEach-Object {
    "`n=== $($_.Name) ==="
    $_.Group | Sort-Object LineNumber | ForEach-Object {
        "{0,5}: {1}" -f $_.LineNumber, $_.Line.TrimEnd()
    }
}
