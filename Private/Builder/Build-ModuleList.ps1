function Build-ModuleList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Dependencies
    )

    $list = foreach ($d in $Dependencies) {
        @{
            ModuleName      = $d.Name
            RequiredVersion = $d.Version
        }
    }

    return $list
}