function Get-AliasesFromJson {
    param([string]$ConfigDir)

    $path = Join-Path $ConfigDir 'AliasesToExport.json'
    if (-not (Test-Path $path)) {
        Write-Warning "Alias config not found at '$path'; no aliases will be exported from JSON."
        return @()
    }

    try {
        $json = Get-Content -Raw -Path $path | ConvertFrom-Json
        $aliases = @($json.aliases)
        $exportable = $aliases |
        Where-Object { $_.export -and $_.name } |
        Select-Object -ExpandProperty name

        return ($exportable | Sort-Object -Unique)
    }
    catch {
        Write-Warning "Failed to parse alias config '$path': $($_.Exception.Message)"
        return @()
    }
}