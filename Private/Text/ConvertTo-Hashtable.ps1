
function ConvertTo-Hashtable {
    <#
    .SYNOPSIS
        Recursively converts an input object (PSCustomObject, IDictionary,
        IEnumerable) into a hashtable or array of hashtables.
    #>
    param([Parameter(ValueFromPipeline)] $InputObject)

    process {
        if ($null -eq $InputObject) {
            return $null
        }

        # PSCustomObject (JSON objects)
        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $hash = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
            }
            return $hash
        }

        # IDictionary / Hashtable
        if ($InputObject -is [System.Collections.IDictionary]) {
            $hash = @{}
            foreach ($key in $InputObject.Keys) {
                $hash[$key] = ConvertTo-Hashtable $InputObject[$key]
            }
            return $hash
        }

        # Enumerable (arrays) but not string
        if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
            $list = @()
            foreach ($item in $InputObject) {
                $list += (ConvertTo-Hashtable $item)
            }
            return $list
        }

        # Scalar
        return $InputObject
    }
}