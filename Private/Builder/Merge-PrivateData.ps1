function Merge-PrivateData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Existing,

        [Parameter(Mandatory)]
        [array]$Dependencies
    )

    # --- Normalize PrivateData root ---
    # If it's not a hashtable, replace it with a clean one.
    if (-not ($Existing -is [hashtable])) {
        $pd = @{}
    }
    else {
        # Clone to avoid modifying the original reference
        $pd = @{} + $Existing
    }

    # --- Ensure TechToolbox node exists and is a hashtable ---
    if (-not $pd.ContainsKey('TechToolbox') -or -not ($pd['TechToolbox'] -is [hashtable])) {
        $pd['TechToolbox'] = @{}
    }

    # --- Assign dependencies safely ---
    $pd['TechToolbox']['Dependencies'] = $Dependencies

    return $pd
}