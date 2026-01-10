
function Move-ToCamelKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Label)

    $map = @{
        'Design Capacity'      = 'designCapacity'
        'Full Charge Capacity' = 'fullChargeCapacity'
        'Chemistry'            = 'chemistry'
        'Serial Number'        = 'serialNumber'
        'Manufacturer'         = 'manufacturer'
        'Name'                 = 'name'
        'Battery Name'         = 'batteryName'
        'Cycle Count'          = 'cycleCount'
        'Remaining Capacity'   = 'remainingCapacity'
    }

    # Normalize input
    if (-not $Label -or [string]::IsNullOrWhiteSpace($Label)) {
        return $null
    }

    # Try direct map match
    foreach ($k in $map.Keys) {
        if ($Label -match ('^(?i)' + [regex]::Escape($k) + '$')) {
            return $map[$k]
        }
    }

    # Fallback: sanitize and split
    $fallback = ($Label -replace '[^A-Za-z0-9 ]', '' -replace '\s+', ' ').Trim()
    if (-not $fallback) { return $null }

    $parts = $fallback.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($parts.Count -eq 0) { return $null }
    if ($parts.Count -eq 1) { return $parts[0].ToLower() }

    $first = $parts[0].ToLower()
    $rest = $parts[1..($parts.Count - 1)] | ForEach-Object {
        $_.Substring(0, 1).ToUpper() + $_.Substring(1).ToLower()
    }

    return ($first + ($rest -join ''))
}