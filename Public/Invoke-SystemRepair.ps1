function Invoke-SystemRepair {
    <#
    .SYNOPSIS
        Runs DISM/SFC/system repair operations locally or via PSRemoting.
    .DESCRIPTION
        Wraps common repair operations (DISM RestoreHealth,
        StartComponentCleanup, ResetBase, SFC, and Windows Update component
        reset) in a TechToolbox-style function with optional remote execution
        and credential support.
    .PARAMETER RestoreHealth
        Runs DISM /RestoreHealth.
    .PARAMETER StartComponentCleanup
        Runs DISM /StartComponentCleanup.
    .PARAMETER ResetBase
        Runs DISM /StartComponentCleanup /ResetBase.
    .PARAMETER SfcScannow
        Runs SFC /scannow.
    .PARAMETER ResetUpdateComponents
        Resets Windows Update components.
    .PARAMETER ComputerName
        Specifies the remote computer name to run the operations on. If not
        specified, and -Local is not set, the function will check the config for
        a default computer name.
    .PARAMETER Local
        If set, forces local execution regardless of ComputerName or config
        settings.
    .PARAMETER Credential
        Specifies the credentials to use for remote execution. Ignored if -Local
        is set.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -SfcScannow
        Runs DISM RestoreHealth and SFC /scannow locally.
    .EXAMPLE
        Invoke-SystemRepair -RestoreHealth -ComputerName "Client01" -Credential (Get-Credential)
        Runs DISM RestoreHealth on the remote computer "Client01" using the
        specified credentials.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [switch]$RestoreHealth,

        [Parameter()]
        [switch]$StartComponentCleanup,

        [Parameter()]
        [switch]$ResetBase,

        [Parameter()]
        [switch]$SfcScannow,

        [Parameter()]
        [switch]$ResetUpdateComponents,

        [Parameter()]
        [string]$ComputerName,

        [Parameter()]
        [switch]$Local,

        [Parameter()]
        [pscredential]$Credential
    )

    # Short-circuit: nothing selected
    if (-not ($RestoreHealth -or $StartComponentCleanup -or $ResetBase -or $SfcScannow -or $ResetUpdateComponents)) {
        Write-Log -Level Warn -Message "No operations specified. Choose at least one operation to run."
        return
    }

    # --- Config hook (future-friendly) ---
    $cfg = Get-TechToolboxConfig
    $settings = $cfg["settings"]
    $repair = $settings["systemRepair"] 

    $runRemoteDefault = $repair["runRemote"] ?? $true

    # Decide local vs remote
    $targetComputer = $ComputerName
    if (-not $Local) {
        if (-not $targetComputer -and $repair.ContainsKey("defaultComputerName")) {
            $targetComputer = $repair["defaultComputerName"]
        }
    }

    $runRemoteEffective =
    -not $Local -and
    -not [string]::IsNullOrWhiteSpace($targetComputer) -and
    $runRemoteDefault

    $targetLabel = if ($runRemoteEffective) {
        "remote host $targetComputer"
    }
    else {
        "local machine"
    }

    Write-Log -Level Info -Message ("Preparing system repair operations on {0}." -f $targetLabel)

    # Build a friendly description for ShouldProcess
    $ops = @()
    if ($RestoreHealth) { $ops += "DISM RestoreHealth" }
    if ($StartComponentCleanup) { $ops += "DISM StartComponentCleanup" }
    if ($ResetBase) { $ops += "DISM ResetBase" }
    if ($SfcScannow) { $ops += "SFC /scannow" }
    if ($ResetUpdateComponents) { $ops += "Reset Windows Update Components" }

    $operationDesc = $ops -join ", "

    if ($PSCmdlet.ShouldProcess($targetLabel, "Run: $operationDesc")) {

        if ($runRemoteEffective) {
            Write-Log -Level Info -Message ("Executing repair operations remotely on [{0}]." -f $targetComputer)

            Invoke-SystemRepairRemote `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents `
                -ComputerName $targetComputer `
                -Credential $Credential
        }
        else {
            Write-Log -Level Info -Message "Executing repair operations locally."

            Invoke-SystemRepairLocal `
                -RestoreHealth:$RestoreHealth `
                -StartComponentCleanup:$StartComponentCleanup `
                -ResetBase:$ResetBase `
                -SfcScannow:$SfcScannow `
                -ResetUpdateComponents:$ResetUpdateComponents
        }

        Write-Log -Level Ok -Message ("System repair operations completed on {0}." -f $targetLabel)
    }
}