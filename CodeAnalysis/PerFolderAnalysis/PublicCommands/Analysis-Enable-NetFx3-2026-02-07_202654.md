# Code Analysis Report
Generated: 2/7/2026 8:26:54 PM

## Summary
 The code provided is a PowerShell script named `Enable-NetFx3` that enables the .NET Framework 3.5 on local or remote machines. Here are some suggestions for improving its functionality, readability, and performance:

1. **Modularization**: Break down the script into smaller functions to make it more manageable and reusable. For example, you could create separate functions for local and remote execution, or for handling different parts of the logic (e.g., enabling the feature, validating, etc.). This will also help reduce clutter and improve readability.

2. **Error Handling**: Use try/catch blocks to handle errors more gracefully throughout the script. Currently, there are several places where errors could occur but are not handled consistently. For example, in the remote mode, if an error occurs while starting the process, the script does not exit with a non-zero status code.

3. **Code Organization**: Use consistent indentation and spacing to make the code easier to read. Currently, there is a mix of spaces and tabs, which can be confusing. Also, consider using PowerShell's native formatting for multi-line strings instead of concatenating multiple lines with `+`.

4. **Comments**: While the comments are generally well-written and descriptive, consider adding more inline comments to clarify complex parts of the code. This will help other developers understand what is happening at a glance.

5. **Variable Naming**: Some variable names could be more descriptive. For example, `sb` in the remote mode script block could be renamed to something like `$remoteScriptBlock`.

6. **Parameters Validation**: Validate parameters before using them to ensure they are set correctly. This can help catch errors early and make the script more robust.

7. **Logging**: Consider creating a custom logging function or using an existing logging module to centralize logging throughout the script. This will make it easier to manage and troubleshoot issues that may arise.

8. **Help Documentation**: Add help documentation (`<#...#>`) to the script to provide information about its usage, parameters, and examples. This will make it easier for other developers to use your script.

9. **Code Formatting**: Consider formatting the code according to a style guide like PowerShell Core Coding Guidelines or the Microsoft PowerShell Style Guide to ensure consistency across the script.

10. **Test Cases**: Write test cases to verify the functionality of the script under different scenarios and edge cases. This will help catch any unintended behavior and ensure that the script works as intended.

## Source Code
```powershell

function Enable-NetFx3 {
    <#
    .SYNOPSIS
        Enables .NET Framework 3.5 (NetFx3) locally or on remote computers.

    .DESCRIPTION
        Local mode (default): runs on the current machine; enforces optional
        timeout via DISM path; returns exit 0 on success (including
        3010/reboot-required), 1 on failure (PDQ-friendly). Remote mode: when
        -ComputerName is provided, runs via WinRM using -Credential (or falls
        back to $script:domainAdminCred if not supplied). Returns per-target
        result objects (no hard exit).

    .PARAMETER ComputerName
        One or more remote computers to run against. If omitted, runs locally.

    .PARAMETER Credential
        PSCredential to use for remoting. If omitted and $script:domainAdminCred
        exists, it will be used. Otherwise remoting requires your current
        credentials to have access.

    .PARAMETER Source
        Optional SxS source for offline/WSUS-only environments. Prefer a UNC
        path for remoting (e.g., \\server\share\Win11\sources\sxs).

    .PARAMETER Quiet
        Reduce chatter (maps to NoRestart for cmdlet path; DISM already uses
        /Quiet).

    .PARAMETER NoRestart
        Do not restart automatically.

    .PARAMETER TimeoutMinutes
        For DISM path, maximum time to wait. Default 45 minutes. (Local:
        controls DISM path selection; Remote: enforced on target.)

    .PARAMETER Validate
        AAfter enablement, query feature state to confirm it is Enabled (best
        effort).

    .OUTPUTS
        Local: process exit code (0 or 1) via 'exit'. Remote: [pscustomobject]
        per target with fields ComputerName, ExitCode, Success, RebootRequired,
        State, Message.

    .EXAMPLE
        # Local machine, online
        Enable-NetFx3 -Validate

    .EXAMPLE
        # Local machine, offline ISO mounted as D:
        Enable-NetFx3 -Source "D:\sources\sxs" -Validate

    .EXAMPLE
        # Remote machine(s) with stored domain admin credential
        $cred = Get-DomainAdminCredential Enable-NetFx3 -ComputerName "PC01","PC02"
        -Credential $cred -Source "\\files\Win11\sources\sxs" -TimeoutMinutes 45
        -Validate
        # Returns per-target objects instead of a hard exit.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [string]$Source,
        [switch]$Quiet,
        [switch]$NoRestart,
        [int]$TimeoutMinutes = 45,
        [switch]$Validate
    )

    # If ComputerName provided → Remote mode
    if ($ComputerName -and $ComputerName.Count -gt 0) {
        # Resolve credential: explicit > module default > none
        if (-not $Credential -and $script:domainAdminCred) {
            $Credential = $script:domainAdminCred
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] Using module domainAdminCred for remoting."
        }

        # Warn if Source looks like a local drive path (prefer UNC for remote)
        if ($Source -and -not ($Source.StartsWith('\\'))) {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] -Source '$Source' is not a UNC path. Ensure it exists on EACH target."
        }

        Write-Log -Level 'Info' -Message "[Enable-NetFx3] Remote mode → targets: $($ComputerName -join ', ')"

        # Build the remote scriptblock (self-contained; no dependency on local functions)
        $sb = {
            param($src, $timeoutMinutes, $validate, $noRestart, $quiet)

            $ErrorActionPreference = 'Stop'
            $overallSuccess = $false
            $exit = 1
            $state = $null
            $msg = $null

            try {
                # Prefer DISM to enforce timeout and consistent exit code
                $argsList = @(
                    '/online',
                    '/enable-feature',
                    '/featurename:NetFx3',
                    '/All',
                    '/Quiet',
                    '/NoRestart'
                )
                if ($src) { $argsList += "/Source:`"$src`""; $argsList += '/LimitAccess' }

                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'dism.exe'
                $psi.Arguments = ($argsList -join ' ')
                $psi.UseShellExecute = $false
                $psi.RedirectStandardOutput = $true
                $psi.RedirectStandardError = $true

                $proc = New-Object System.Diagnostics.Process
                $proc.StartInfo = $psi

                if (-not $proc.Start()) {
                    $msg = "Failed to start DISM."
                    throw $msg
                }

                $proc.BeginOutputReadLine()
                $proc.BeginErrorReadLine()

                $timeoutMs = [int][TimeSpan]::FromMinutes([Math]::Max(1, $timeoutMinutes)).TotalMilliseconds
                if (-not $proc.WaitForExit($timeoutMs)) {
                    try { $proc.Kill() } catch {}
                    $msg = "Timeout after $timeoutMinutes minutes."
                    $exit = 1
                }
                else {
                    $exit = $proc.ExitCode
                    if ($exit -in 0, 3010) {
                        $overallSuccess = $true
                    }
                    else {
                        $msg = "DISM failed with exit code $exit."
                    }
                }

                if ($overallSuccess -and $validate) {
                    try {
                        $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
                        if ($state -notin 'Enabled', 'EnablePending', 'EnabledPending') {
                            $overallSuccess = $false
                            if (-not $msg) { $msg = "Feature state after enablement: $state" }
                            if ($exit -in 0, 3010) { $exit = 1 } # normalize to failure if state isn't right
                        }
                    }
                    catch {
                        if (-not $msg) { $msg = "Validation failed: $($_.Exception.Message)" }
                    }
                }
            }
            catch {
                $msg = $_.Exception.Message
            }

            [pscustomobject]@{
                ComputerName   = $env:COMPUTERNAME
                ExitCode       = $exit
                Success        = [bool]$overallSuccess
                RebootRequired = ($exit -eq 3010)
                State          = $state
                Message        = $msg
            }
        }

        $icmParams = @{
            ComputerName = $ComputerName
            ScriptBlock  = $sb
            ArgumentList = @($Source, $TimeoutMinutes, [bool]$Validate, [bool]$NoRestart, [bool]$Quiet)
        }
        if ($Credential) { $icmParams.Credential = $Credential }

        $results = Invoke-Command @icmParams

        # Log summary and return objects (no hard exit in remote mode)
        foreach ($r in $results) {
            if ($r.Success) {
                if ($r.RebootRequired) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3][$($r.ComputerName)] Success (reboot required)."
                }
                else {
                    Write-Log -Level 'Ok' -Message "[Enable-NetFx3][$($r.ComputerName)] Success."
                }
            }
            else {
                $tail = if ($r.Message) { " - $($r.Message)" } else { "" }
                Write-Log -Level 'Error' -Message "[Enable-NetFx3][$($r.ComputerName)] Failed (Exit $($r.ExitCode))$tail"
            }
        }

        return $results
    }

    # ----------------------------
    # Local mode (original logic)
    # ----------------------------
    Write-Log -Level 'Info' -Message "[Enable-NetFx3] Starting enablement (local)."

    $params = @{
        Online      = $true
        FeatureName = 'NetFx3'
        All         = $true
    }
    if ($PSBoundParameters.ContainsKey('Source') -and $Source) {
        $params.Source = $Source
        $params.LimitAccess = $true  # Avoid WU/WSUS when explicit source is provided
    }
    if ($Quiet) { $params.NoRestart = $true }
    if ($NoRestart) { $params.NoRestart = $true }

    $useDirectDism = ($TimeoutMinutes -gt 0)
    Write-Log -Level 'Info'  -Message "[Enable-NetFx3] Enabling .NET Framework 3.5 (NetFx3)..."
    Write-Log -Level 'Debug' -Message ("[Enable-NetFx3] Using {0} path." -f ($(if ($useDirectDism) { 'DISM (timeout)' } else { 'Enable-WindowsOptionalFeature' })))

    $overallSuccess = $false
    $dismExit = $null

    try {
        if (-not $useDirectDism) {
            $result = Enable-WindowsOptionalFeature @params -ErrorAction Stop
            Write-Log -Level 'Ok' -Message "[Enable-NetFx3] State: $($result.State)"
            $overallSuccess = $true
        }
        else {
            $argsList = @(
                '/online', '/enable-feature', '/featurename:NetFx3', '/All', '/Quiet', '/NoRestart'
            )
            if ($params.ContainsKey('Source')) {
                $argsList += "/Source:`"$($params.Source)`""
                $argsList += '/LimitAccess'
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'dism.exe'
            $psi.Arguments = ($argsList -join ' ')
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo = $psi

            if (-not $proc.Start()) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed to start DISM."
                exit 1
            }

            $proc.add_OutputDataReceived({ param($s, $e) if ($e.Data) { Write-Log -Level 'Info' -Message $e.Data } })
            $proc.add_ErrorDataReceived( { param($s, $e) if ($e.Data) { Write-Log -Level 'Warn' -Message $e.Data } })
            $proc.BeginOutputReadLine()
            $proc.BeginErrorReadLine()

            $timeoutMs = [int][TimeSpan]::FromMinutes($TimeoutMinutes).TotalMilliseconds
            if (-not $proc.WaitForExit($timeoutMs)) {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] Timeout after $TimeoutMinutes minutes. Attempting to terminate DISM..."
                try { $proc.Kill() } catch {}
                exit 1
            }

            $dismExit = $proc.ExitCode
            Write-Log -Level 'Debug' -Message "[Enable-NetFx3] DISM exit code: $dismExit"

            if ($dismExit -in 0, 3010) {
                $overallSuccess = $true
                if ($dismExit -eq 3010) {
                    Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Reboot required to complete NetFx3 enablement."
                }
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] DISM reported failure."
            }
        }
    }
    catch {
        Write-Log -Level 'Error' -Message "[Enable-NetFx3] Failed: $($_.Exception.Message)"
        $overallSuccess = $false
    }

    if ($overallSuccess -and $Validate) {
        try {
            $state = (Get-WindowsOptionalFeature -Online -FeatureName NetFx3).State
            Write-Log -Level 'Info' -Message "[Enable-NetFx3] Feature state: $state"
            if ($state -in 'Enabled', 'EnablePending', 'EnabledPending') {
                Write-Log -Level 'Ok' -Message "[Enable-NetFx3] NetFx3 enablement validated."
            }
            else {
                Write-Log -Level 'Error' -Message "[Enable-NetFx3] NetFx3 state not enabled after operation."
                $overallSuccess = $false
            }
        }
        catch {
            Write-Log -Level 'Warn' -Message "[Enable-NetFx3] Validation skipped: $($_.Exception.Message)"
        }
    }

    if ($overallSuccess) { exit 0 } else { exit 1 }
}

[SIGNATURE BLOCK REMOVED]

```
