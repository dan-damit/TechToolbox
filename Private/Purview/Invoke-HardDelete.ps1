
function Invoke-HardDelete {
    <#
    .SYNOPSIS
        Submits a Purview HardDelete purge for a Compliance Search and waits for
        completion.
    .DESCRIPTION
        Optionally requires typed confirmation per config; honors
        -WhatIf/-Confirm for the submission step. Calls Wait-PurgeCompletion to
        monitor the purge status.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SearchName,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$CaseName
    )

    # --- Config (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $purv = $cfg["settings"]["purview"]

    # Confirmation gate (default to true for safety)
    $requireConfirm = $purv["purge"]["requireConfirmation"]
    if ($null -eq $requireConfirm) { $requireConfirm = $true }

    Write-Log -Level Info -Message ("Preparing HardDelete purge for '{0}' in case '{1}'." -f $SearchName, $CaseName)
    Write-Log -Level Warn -Message "This will permanently delete all items found by the search."

    if ($requireConfirm) {
        $confirm = Read-Host "Type 'YES' to confirm HardDelete purge"
        if ($confirm -notmatch '^(?i)(YES|Y)$') { throw "HardDelete purge cancelled by user." }
    }

    if ($PSCmdlet.ShouldProcess(("Case '{0}' Search '{1}'" -f $CaseName, $SearchName), 'Submit HardDelete purge')) {
        $action = $null
        try {
            $action = New-ComplianceSearchAction -SearchName $SearchName -Purge -PurgeType HardDelete -ErrorAction Stop
            if ($action.Identity) {
                Write-Log -Level Ok -Message ("Purge submitted: {0}" -f $action.Identity)

                # Optional: pass config-driven timeouts/polling to Wait-PurgeCompletion
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -ActionIdentity $action.Identity -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
            else {
                Write-Log -Level Ok -Message "Purge submitted (no Identity returned). Monitoring by search name..."
                $timeout = $purv["purge"]["timeoutSeconds"]
                $poll = $purv["purge"]["pollSeconds"]
                Wait-PurgeCompletion -SearchName $SearchName -CaseName $CaseName `
                    -TimeoutSeconds $timeout -PollSeconds $poll
            }
        }
        catch {
            Write-Log -Level Error -Message ("Failed to submit purge: {0}" -f $_.Exception.Message)
            throw
        }
    }
    else {
        Write-Log -Level Info -Message "Purge submission skipped due to -WhatIf/-Confirm."
    }
}
