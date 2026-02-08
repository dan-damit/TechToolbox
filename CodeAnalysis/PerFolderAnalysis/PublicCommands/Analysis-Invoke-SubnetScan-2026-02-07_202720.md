# Code Analysis Report
Generated: 2/7/2026 8:27:20 PM

## Summary
 The provided PowerShell script is a function named `Invoke-SubnetScan` that scans a subnet for hosts and exports the results to CSV if specified. Here are some suggestions to enhance its functionality, readability, and performance:

1. **Modularize**: Break the function into smaller, reusable functions or classes for better organization and code maintainability. This can help reduce duplication and make it easier to manage and test individual components.

2. **Error handling**: Add more detailed error messages for each possible error case, making it easier to debug issues that may arise during execution.

3. **Comments**: Provide comments throughout the code to explain its purpose, variables, and logic. This will make it easier for others (or future you) to understand the code.

4. **Constants**: Create a constant class to store configuration options like default ports, export directories, etc., making it easier to modify them without having to update the script everywhere they are used.

5. **Input validation**: Implement input validation for parameters to ensure that only valid values are passed and to handle edge cases better. This will help prevent runtime errors.

6. **Performance tuning**: Consider using asynchronous methods where appropriate, such as PowerShell's `Start-Job` for scanning multiple hosts concurrently. Also, consider optimizing the scan process itself if it becomes a bottleneck.

7. **Logging**: Expand the logging functionality to provide more granular information about what is happening during execution, making it easier to diagnose issues and improve the overall user experience.

8. **Code formatting**: Apply consistent PowerShell coding standards, such as those provided by PSScriptAnalyzer, to ensure the code is easy to read and maintain.

## Source Code
```powershell

function Invoke-SubnetScan {
    <#
.SYNOPSIS
    Scans a subnet (locally or remotely) and can export results to CSV.
.DESCRIPTION
    Orchestrates a subnet scan by calling Invoke-SubnetScanLocal. Applies
    defaults from config.settings.subnetScan and exports locally to
    config.settings.subnetScan.exportDir when -ExportCsv is requested. Can also
    execute the scan on a remote host if -ComputerName is specified.
.PARAMETER ComputerName
    Specifies the remote computer on which to execute the subnet scan. If
    not specified, the scan will be executed locally.
.PARAMETER Port
    Specifies the TCP port to test on each host. Defaults to the value in
    config.settings.subnetScan.defaultPort or 80 if not specified.
.PARAMETER ResolveNames
    Switch to enable name resolution (PTR → NetBIOS → mDNS) for each host.
    Defaults to the value in config.settings.subnetScan.resolveNames or
    $false if not specified.
.PARAMETER HttpBanner
    Switch to enable HTTP banner retrieval for each host. Defaults to the
    value in config.settings.subnetScan.httpBanner or $false if not specified.
.PARAMETER ExportCsv
    Switch to enable exporting scan results to CSV. Defaults to the value in
    config.settings.subnetScan.exportCsv or $false if not specified.
.PARAMETER LocalOnly
    Switch to force the scan to execute locally, even if -ComputerName is
    specified.
.INPUTS
    None
.OUTPUTS
    System.Collections.Generic.List[PSCustomObject]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        # Remote options
        [string]$ComputerName,
        [ValidateSet('WSMan', 'SSH')]
        [string]$Transport = 'WSMan',
        [pscredential]$Credential,       # WSMan (domain/local); SSH (username only if not using key)
        [string]$UserName,               # SSH user if not using -Credential
        [string]$KeyFilePath,            # SSH key (optional)
        [switch]$LocalOnly,

        # Scan behavior (nullable by omission; we default from config)
        [int]$Port,
        [switch]$ResolveNames,
        [switch]$HttpBanner,

        # Export control
        [switch]$ExportCsv,
        [ValidateSet('Local', 'Remote')]
        [string]$ExportTarget = 'Local'
    )

    Set-StrictMode -Version Latest
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'

    try {
        # --- CONFIG & DEFAULTS ---
        $cfg = Get-TechToolboxConfig -Verbose
        if (-not $cfg) { throw "TechToolbox config is null/empty. Ensure Config\config.json exists and is valid JSON." }

        # Keep ?. tight (no whitespace between ? and . /  )
        $scanCfg = $cfg['settings']?['subnetScan']
        if (-not $scanCfg) { throw "Config missing 'settings.subnetScan'." }

        # Defaults only if user didn’t supply
        if (-not $PSBoundParameters.ContainsKey('Port')) { $Port = $scanCfg['defaultPort'] ?? 80 }
        if (-not $PSBoundParameters.ContainsKey('ResolveNames')) { $ResolveNames = [bool]($scanCfg['resolveNames'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('HttpBanner')) { $HttpBanner = [bool]($scanCfg['httpBanner'] ?? $false) }
        if (-not $PSBoundParameters.ContainsKey('ExportCsv')) { $ExportCsv = [bool]($scanCfg['exportCsv'] ?? $false) }

        # Local export dir resolved now (used when ExportTarget=Local)
        $localExportDir = $scanCfg['exportDir']
        if ($ExportCsv -and $ExportTarget -eq 'Local') {
            if (-not $localExportDir) { throw "Config 'settings.subnetScan.exportDir' is missing." }
            if (-not (Test-Path -LiteralPath $localExportDir)) {
                New-Item -ItemType Directory -Path $localExportDir -Force | Out-Null
            }
        }

        Write-Log -Level Info -Message ("SubnetScan: CIDR={0} Port={1} ResolveNames={2} HttpBanner={3} ExportCsv={4} Target={5}" -f `
                $CIDR, $Port, $ResolveNames, $HttpBanner, $ExportCsv, $ExportTarget)

        # --- EXECUTION LOCATION ---
        $runLocal = $LocalOnly -or (-not $ComputerName)
        $results = $null

        if ($runLocal) {
            Write-Log -Level Info -Message "Executing subnet scan locally."
            # Worker should not export in local mode if ExportTarget=Local (we export here)
            $doRemoteExport = $false
            $results = Invoke-SubnetScanLocal -CIDR $CIDR -Port $Port -ResolveNames:$ResolveNames -HttpBanner:$HttpBanner -ExportCsv:$doRemoteExport
        }
        else {
            Write-Log -Level Info -Message "Executing subnet scan on remote host: $ComputerName via $Transport"

            # Build session
            $session = $null
            try {
                if ($Transport -eq 'WSMan') {
                    $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
                }
                else {
                    # SSH remoting (PowerShell 7+)
                    if (-not $UserName -and $Credential) { $UserName = $Credential.UserName }
                    if (-not $UserName) { throw "For SSH transport, specify -UserName or -Credential." }

                    $sshParams = @{ HostName = $ComputerName; UserName = $UserName; ErrorAction = 'Stop' }
                    if ($KeyFilePath) { $sshParams['KeyFilePath'] = $KeyFilePath }
                    elseif ($Credential) { $sshParams['Password'] = $Credential.GetNetworkCredential().Password }

                    $session = New-PSSession @sshParams
                }
                Write-Log -Level Ok -Message "Connected to $ComputerName."
            }
            catch {
                Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
                return
            }

            try {
                # Ensure TechToolbox module is present & importable on remote
                $moduleRoot = 'C:\TechToolbox'
                $moduleManifest = Join-Path $moduleRoot 'TechToolbox.psd1'

                $remoteHasModule = Invoke-Command -Session $session -ScriptBlock {
                    param($moduleManifestPath)
                    Test-Path -LiteralPath $moduleManifestPath
                } -ArgumentList $moduleManifest

                if (-not $remoteHasModule) {
                    Write-Log -Level Info -Message "TechToolbox not found on remote; copying module..."
                    # Copy the whole folder (adjust if your layout differs)
                    Copy-Item -ToSession $session -Path 'C:\TechToolbox' -Destination 'C:\' -Recurse -Force
                }

                # Import module and run worker
                $doRemoteExport = $ExportCsv -and ($ExportTarget -eq 'Remote')

                $results = Invoke-Command -Session $session -ScriptBlock {
                    param($CIDR, $Port, $ResolveNames, $HttpBanner, $DoExport)

                    # Import module
                    Import-Module 'C:\TechToolbox\TechToolbox.psd1' -Force -ErrorAction Stop

                    Invoke-SubnetScanLocal -CIDR $CIDR -Port $Port -ResolveNames:$ResolveNames -HttpBanner:$HttpBanner -ExportCsv:$DoExport
                } -ArgumentList $CIDR, $Port, $ResolveNames, $HttpBanner, $doRemoteExport
            }
            catch {
                Write-Log -Level Error -Message "Remote scan failed: $($_.Exception.Message)"
                return
            }
            finally {
                if ($session) { Remove-PSSession $session }
            }
        }

        # Export locally (only if requested & results present)
        if ($ExportCsv -and $ExportTarget -eq 'Local' -and $results) {
            try {
                $cidrSafe = $CIDR -replace '[^\w\-\.]', '_'
                $csvPath = Join-Path $localExportDir ("subnet-scan-{0}-{1}.csv" -f $cidrSafe, (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
                Write-Log -Level Ok -Message "Results exported to $csvPath"
            }
            catch {
                Write-Log -Level Error -Message "Failed to export CSV: $($_.Exception.Message)"
            }
        }

        # Console summary (responders only)
        if ($results) {
            Write-Host "Discovered hosts:" -ForegroundColor DarkYellow
            $results |
            Select-Object IP, RTTms, MacAddress, NetBIOS, PTR, Mdns, PortOpen, ServerHdr |
            Format-Table -AutoSize
        }

        return $results
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}
[SIGNATURE BLOCK REMOVED]

```
