function Resolve-Aliases {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Aliases
    )

    $resolved = @()

    foreach ($alias in $Aliases) {
        $target = (Get-Alias -Name $alias -ErrorAction SilentlyContinue).Definition
        if (-not $target) {
            Write-Log -Level Warn -Message "Alias '$alias' has no valid target."
            continue
        }

        if (-not (Get-Command -Name $target -ErrorAction SilentlyContinue)) {
            Write-Log -Level Warn -Message "Alias '$alias' target '$target' not found."
            continue
        }

        $resolved += $alias
    }

    return $resolved
}