# Code Analysis Report
Generated: 2/7/2026 8:26:25 PM

## Summary
 The provided PowerShell script, `Get-SystemSnapshot`, is a well-written function that collects and exports a system snapshot of various information such as OS, hardware, CPU, memory, disk, network, identity, and services/roles. Here are some suggestions for enhancing the code's functionality, readability, and performance:

1. **Modularize helper functions**: The current implementation includes several helpers (`Get-SnapshotOS`, `Get-SnapshotCPU`, etc.) as part of the main function. To improve readability and reusability, consider moving these helper functions to a separate module or script file. This will make the main function more concise and easier to maintain.

2. **Error handling**: Although error handling is already implemented in some areas, it could be further improved by using custom exceptions instead of hard-coding error messages. This would provide better context for debugging when errors occur.

3. **Parameter validation**: Adding parameter validation would ensure that the function only runs with valid input. For example, checking if `$ComputerName` is a string or an array of strings and verifying if `$Credential` is a valid PSCredential object.

4. **Input validation**: The function description mentions that no objects can be piped to it. To enforce this restriction, you could use the `CmdletBinding()` attribute's `ValidateSet` parameter property to restrict input. This would make the function behave more like a cmdlet and provide clearer error messages when invalid input is provided.

5. **Parameter defaults**: Providing default values for parameters would make it easier for users who only want to collect information from the local system. For example, setting `$ComputerName` to `$env:COMPUTERNAME` if it's not specified in the function call.

6. **Caching**: To improve performance, consider caching the collected data (e.g., by using a dictionary) and only re-collecting data that has changed since the last snapshot was taken. This would reduce the time required to generate the snapshot.

7. **Code formatting**: The provided code is well-formatted, but adhering to a consistent style guide (such as PowerShell style guide) would make it even easier to read and maintain. Additionally, consider using multi-line strings for longer sections of code to improve readability.

8. **Output format**: The function currently exports the data in CSV format, which is useful for analysis but not ideal for interactive use. Adding an option to display the snapshot object in a table format would make it easier for users to inspect the collected data without having to export it first.

9. **Documentation**: Although the code already includes detailed documentation, adding additional comments explaining the purpose of each helper function and their inputs/outputs would further improve readability.

10. **Parameter grouping**: Grouping related parameters together using parameter sets would make it easier for users to specify the desired options when calling the function. For example, creating a parameter set called `-Local` that only collects data from the local system and another parameter set called `-Remote` that requires both the `ComputerName` and `Credential` parameters.

## Source Code
```powershell
function Get-SystemSnapshot {
    <#
    .SYNOPSIS
        Collects a technician-grade system snapshot from a local or remote
        machine.

    .DESCRIPTION
        Gathers OS, hardware, CPU, memory, disk, network, identity, and
        service/role information from a target system. Returns a structured
        object and exports a CSV to the configured snapshot export directory.

    .PARAMETER ComputerName
        Optional. If omitted, collects a snapshot of the local system.

    .PARAMETER Credential
        Optional. Required only for remote systems when not using current
        credentials.

    .EXAMPLE
        Get-SystemSnapshot

    .EXAMPLE
        Get-SystemSnapshot -ComputerName SERVER01 -Credential (Get-Credential)
    .INPUTS
        None. You cannot pipe objects to Get-SystemSnapshot.
    .OUTPUTS
        PSCustomObject. A structured object containing the system snapshot data.
    #>
    [CmdletBinding()]
    param(
        [string]$ComputerName,
        [pscredential]$Credential,
        [object]$Snapshot
    )

    # --- Load config ---
    $cfg = Get-TechToolboxConfig
    $snapshotCfg = $cfg["settings"]["systemSnapshot"]
    $exportPath = $snapshotCfg["exportPath"]

    if ([string]::IsNullOrWhiteSpace($exportPath)) {
        $exportPath = Join-Path $script:ModuleRoot "Exports"
    }

    # Ensure export directory exists
    if (-not (Test-Path $exportPath)) {
        try {
            New-Item -ItemType Directory -Path $exportPath -Force | Out-Null
        }
        catch {
            Write-Log -Level Error -Message ("Failed to create export directory '{0}': {1}" -f $exportPath, $_.Exception.Message)
            throw
        }
    }

    # --- Determine local vs remote ---
    $isRemote = -not [string]::IsNullOrWhiteSpace($ComputerName)

    if ($isRemote) {
        Write-Log -Level Info -Message ("Collecting system snapshot from remote system '{0}'..." -f $ComputerName)
    }
    else {
        Write-Log -Level Info -Message "Collecting system snapshot from local system..."
        $ComputerName = $env:COMPUTERNAME
    }

    # --- Build session if remote ---
    $session = $null
    if ($isRemote) {
        try {
            $session = New-PSSession -ComputerName $ComputerName `
                -Credential $Credential `
                -Authentication Default `
                -ErrorAction Stop

            Write-Log -Level Ok -Message ("Remote session established to {0}" -f $ComputerName)
        }
        catch {
            Write-Log -Level Error -Message ("Failed to create remote session: {0}" -f $_.Exception.Message)
            return
        }
    }

    # --- Collect datasets via private helpers ---
    try {
        $osInfo = Get-SnapshotOS      -Session $session
        $cpuInfo = Get-SnapshotCPU     -Session $session
        $memoryInfo = Get-SnapshotMemory  -Session $session
        $diskInfo = Get-SnapshotDisks   -Session $session
        $netInfo = Get-SnapshotNetwork -Session $session
        $identity = Get-SnapshotIdentity -Session $session
        $services = Get-SnapshotServices -Session $session
    }
    catch {
        Write-Log -Level Error -Message ("Snapshot collection failed: {0}" -f $_.Exception.Message)
        if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
        throw
    }

    # --- Close session if remote ---
    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        Write-Log -Level Info -Message "Remote session closed."
    }

    # --- Build final snapshot object ---
    $snapshot = [pscustomobject]@{
        ComputerName = $ComputerName
        Timestamp    = (Get-Date)
        OS           = $osInfo
        CPU          = $cpuInfo
        Memory       = $memoryInfo
        Disks        = $diskInfo
        Network      = $netInfo
        Identity     = $identity
        Services     = $services
    }

    # --- Export CSV ---
    $fileName = "SystemSnapshot_{0}_{1:yyyyMMdd_HHmmss}.csv" -f $ComputerName, (Get-Date)
    $csvPath = Join-Path $exportPath $fileName

    try {
        $flat = Convert-SnapshotToFlatObject -Snapshot $snapshot
        $rows = Convert-FlatSnapshotToRows -FlatObject $flat
        $rows | Export-Csv -Path $csvPath -NoTypeInformation -Force
        Write-Log -Level Ok -Message ("Snapshot exported to {0}" -f $csvPath)
    }
    catch {
        Write-Log -Level Warn -Message ("Failed to export snapshot CSV: {0}" -f $_.Exception.Message)
    }

    # --- Output snapshot object ---
    return $snapshot
}
[SIGNATURE BLOCK REMOVED]

```
