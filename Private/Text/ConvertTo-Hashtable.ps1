
function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Recursively converts an object to a hashtable.
    #>
    param([Parameter(ValueFromPipeline)] $InputObject)

    process {
        if ($InputObject -is [System.Collections.IDictionary]) {
            $hash = @{}
            foreach ($key in $InputObject.Keys) {
                $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
            }
            return $hash
        }
        elseif ($InputObject -is [System.Collections.IEnumerable] -and
            -not ($InputObject -is [string])) {
            return $InputObject | ForEach-Object { ConvertTo-Hashtable $_ }
        }
        else {
            return $InputObject
        }
    }
}