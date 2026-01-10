
function Read-Int {
    <#
    .SYNOPSIS
        Prompts the user to enter an integer within specified bounds.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [Parameter()][int]$Min = 16,
        [Parameter()][int]$Max = 2097152
    )

    while ($true) {
        $value = Read-Host $Prompt
        if ([int]::TryParse($value, [ref]$parsed)) {
            if ($parsed -ge $Min -and $parsed -le $Max) {
                return $parsed
            }
            Write-Log -Level Warning -Message "Enter a value between $Min and $Max."
        }
        else {
            Write-Log -Level Warning -Message "Enter a whole number (MB)."
        }
    }
}