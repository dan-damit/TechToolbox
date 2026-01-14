function Initialize-PublicFunctions {
    $publicRoot = Join-Path $script:ModuleRoot 'Public'
    $files = Get-ChildItem -Path $publicRoot -Recurse -Filter *.ps1

    $names = foreach ($f in $files) {
        . $f.FullName
        $f.BaseName
    }

    return $names
}