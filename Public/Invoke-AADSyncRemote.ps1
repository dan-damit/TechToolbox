
function Invoke-AADSyncRemote {
    <#
    .SYNOPSIS
        Remotely triggers Azure AD Connect (ADSync) sync cycle (Delta/Initial)
        on a target server via PSRemoting.
    .DESCRIPTION
        Creates a remote PSSession (Kerberos or credential-based) to the AAD
        Connect host, validates ADSync module/service, and triggers
        Start-ADSyncSyncCycle. Uses TechToolbox config for defaults and
        Write-Log for unified logging.
    .PARAMETER ComputerName
        FQDN/hostname of AAD Connect server.
    .PARAMETER PolicyType
        Sync policy type: Delta or Initial. Default pulled from config
        (AADSync.DefaultPolicyType).
    .PARAMETER UseKerberos
        Use Kerberos authentication instead of prompting for credentials.
        Default pulled from config (AADSync.AllowKerberos).
    .PARAMETER EnableTranscript
        Start a transcript in the Logs directory (TechToolbox
        Paths.LogDirectory) with timestamped name.
    .PARAMETER Port
        WinRM port: 5985 (HTTP) or 5986 (HTTPS). Default pulled from config
        (AADSync.DefaultPort).
    .EXAMPLE
        Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Delta
    .EXAMPLE
        Invoke-AADSyncRemote -ComputerName aadconnect01 -PolicyType Initial -UseKerberos -WhatIf
    #>
    
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()] [string]$ComputerName,
        [Parameter()] [ValidateSet('Delta', 'Initial')] [string]$PolicyType,
        [Parameter()] [switch]$UseKerberos,
        [Parameter()] [switch]$EnableTranscript,
        [Parameter()] [ValidateSet(5985, 5986)] [int]$Port
    )

    # --- Config & defaults (normalized camelCase) ---
    $cfg = Get-TechToolboxConfig
    $aadSync = $cfg["settings"]["aadSync"]
    $defaults = $cfg["settings"]["defaults"]

    # PolicyType (prefer parameter, otherwise config, otherwise safe default)
    if (-not $PSBoundParameters.ContainsKey('PolicyType') -or [string]::IsNullOrWhiteSpace($PolicyType)) {
        $PolicyType = $aadSync["defaultPolicyType"]
        if ([string]::IsNullOrWhiteSpace($PolicyType)) { $PolicyType = 'Delta' }
    }

    # Port (prefer parameter, otherwise config, otherwise safe default 5985)
    if (-not $PSBoundParameters.ContainsKey('Port') -or $Port -eq 0) {
        $Port = [int]$aadSync["defaultPort"]
        if ($Port -eq 0) { $Port = 5985 }
    }

    # Kerberos flag (prefer parameter; if omitted and allowed by config, enable)
    if (-not $PSBoundParameters.ContainsKey('UseKerberos')) {
        if ($aadSync["allowKerberos"]) { $UseKerberos = [switch]::Present }
    }

    # Prompt if missing, controlled by config defaults
    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        $shouldPromptHost = $defaults["promptForHostname"]
        if ($null -eq $shouldPromptHost) { $shouldPromptHost = $true }
        if ($shouldPromptHost) {
            $ComputerName = Read-Host -Prompt 'Enter the FQDN or hostname of the AAD Connect server'
        }
        else {
            throw "ComputerName is required and prompting is disabled by config."
        }
    }
    $ComputerName = $ComputerName.Trim()

    # --- Transcript (optional) ---
    $transcriptPath = $null
    if ($EnableTranscript) {
        $logDir = $cfg["paths"]["logs"]
        if ([string]::IsNullOrWhiteSpace($logDir)) { $logDir = (Get-Location).Path }
        $transcriptPath = Join-Path -Path $logDir -ChildPath ("AADSync_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

        try {
            if ($PSCmdlet.ShouldProcess($transcriptPath, 'Start transcript')) {
                Start-Transcript -Path $transcriptPath -ErrorAction Stop | Out-Null
                Write-Log -Level Info -Message ("Transcript started: {0}" -f $transcriptPath)
            }
        }
        catch {
            Write-Log -Level Warn -Message ("Could not start transcript: {0}" -f $_.Exception.Message)
        }
    }

    # --- DNS pre-check (non-blocking) ---
    Write-Log -Level Info -Message "Performing local pre-checks..."
    try {
        $resolved = Resolve-DnsName -Name $ComputerName -ErrorAction Stop
        $resolvedName = if ($resolved.NameHost) { $resolved.NameHost } else { $resolved.Name }
        Write-Log -Level Ok -Message ("DNS resolution succeeded: {0}" -f $resolvedName)
    }
    catch {
        Write-Log -Level Warn -Message ("DNS resolution failed for '{0}': {1} — proceeding anyway." -f $ComputerName, $_.Exception.Message)
    }

    # --- Connect session ---
    $session = $null
    try {
        Write-Log -Level Info -Message ("Creating remote session to {0} on port {1} ..." -f $ComputerName, $Port)
        $session = Connect-AADSyncRemoteSession -ComputerName $ComputerName -Port $Port -UseKerberos:$UseKerberos.IsPresent -WhatIf:$WhatIfPreference -Confirm:$false
        Write-Log -Level Ok -Message ( $UseKerberos ? "Session established using Kerberos." : "Session established using supplied credentials." )
    }
    catch {
        Write-Log -Level Error -Message ("Failed to create remote session: {0}" -f $_.Exception.Message)
        if ($EnableTranscript) { try { Stop-Transcript | Out-Null } catch {} }
        return
    }

    # --- Remote check + sync trigger ---
    try {
        Write-Log -Level Info -Message ("Checking ADSync module and service state on {0} ..." -f $ComputerName)
        $precheck = Test-AADSyncRemote -Session $session
        if ($precheck.Status -eq 'PreCheckFailed') {
            Write-Log -Level Error -Message ("Remote pre-checks failed: {0}" -f $precheck.Errors)
            return
        }

        $result = Invoke-RemoteADSyncCycle -Session $session -PolicyType $PolicyType -WhatIf:$WhatIfPreference -Confirm:$false
        Write-Log -Level Ok -Message ("Sync ({0}) triggered successfully on {1}." -f $PolicyType, $ComputerName)

        # Pretty table to Information stream (no Write-Host)
        $table = $result | Format-Table ComputerName, PolicyType, Status, Errors -AutoSize | Out-String
        Write-Information $table
    }
    catch {
        Write-Log -Level Error -Message ("Unhandled error: {0}" -f $_.Exception.Message)
        throw
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            Write-Log -Level Info -Message "Remote session closed."
        }
        if ($EnableTranscript -and $transcriptPath) {
            try { Stop-Transcript | Out-Null } catch {}
            Write-Log -Level Info -Message ("Transcript saved: {0}" -f $transcriptPath)
        }
    }
}
