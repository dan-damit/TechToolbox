function Set-OneTimeReboot {
    <#
        .SYNOPSIS
        Schedules or removes a one-time reboot task locally or on remote
        computers.

        .DESCRIPTION
        Creates, updates, or removes a Windows Scheduled Task that runs
        shutdown.exe /r one time at a target local date/time.

        The function supports:
        - Local scheduling when -ComputerName is not provided.
        - Remote scheduling over PowerShell remoting when -ComputerName is
          provided.
        - WSMan (default) or SSH remoting via Start-NewPSRemoteSession.
        - Optional wake-to-run, force-close apps, and task self-deletion
          settings.

        TIME RESOLUTION
        - If -DateTime is supplied, that exact local timestamp is used.
        - If -DateTime is omitted, -At (HH:mm) is used for the next occurrence.
            If today's time has passed, scheduling rolls to tomorrow.

        IDEMPOTENT TASK UPDATE If a task with the same -TaskName already exists,
        it is removed and recreated with the new settings.

        REMOVE MODE Pass -Remove to unregister the task instead of creating it.

        CONFIG DEFAULTS Unbound parameters can be populated from
        settings.oneTimeReboot in config, including At, SelfDelete,
        defaultComment, taskNamePrefix, and optional
        deleteExpiredTaskAfterMinutes.

        SUPPORTS -WhatIf / -Confirm Local and remote operations honor
        ShouldProcess for safe preview.

        .PARAMETER ComputerName
        Target computer name(s) for remote scheduling/removal. Accepts values
        from pipeline and property name input. Aliases: CN, Host, Name.

        .PARAMETER Credential
        Credential used to establish remote sessions. Not required for local
        mode.

        .PARAMETER At
        Time of day in 24-hour HH:mm format for computed scheduling when
        -DateTime is not provided.

        .PARAMETER DateTime
        Exact local date/time to use for scheduling. Overrides -At when
        supplied.

        .PARAMETER TaskName
        Scheduled task name to create, update, or remove.

        .PARAMETER SelfDelete
        Enables or disables post-expiration task cleanup.

        .PARAMETER Force
        When true, adds /f to shutdown.exe to force-close running applications.

        .PARAMETER Wake
        When true, sets WakeToRun in scheduled task settings.

        .PARAMETER Remove
        Removes the scheduled task identified by -TaskName on each target and
        exits without creating a new reboot task.

        .PARAMETER UseSsh
        Uses SSH-based PowerShell remoting for remote targets.

        .PARAMETER UseCredSSP
        Uses CredSSP authentication for WSMan remoting when applicable.

        .PARAMETER Port
        Remote SSH port used when -UseSsh is specified. Default is 22.

        .INPUTS
        System.String[]. You can pipe computer names to this function.

        .OUTPUTS
        System.Management.Automation.PSCustomObject. Returns one object per
        processed target with properties: ComputerName, Transport, TaskName,
        ScheduledFor, Status, Detail.

        .EXAMPLE
        Set-OneTimeReboot

        Schedules a one-time local reboot using effective defaults from config.

        .EXAMPLE
        Set-OneTimeReboot -At '03:15' -Force:$true

        Schedules a local reboot at the next 03:15 and forces app closure.

        .EXAMPLE
        'PC01','PC02' | Set-OneTimeReboot -At '01:00' -TaskName 'TT_OneTimeReboot'

        Schedules the reboot task on two remote computers via default WSMan
        remoting.

        .EXAMPLE
        Set-OneTimeReboot -ComputerName 'srv-01' -UseSsh -Port 2222 -Credential (Get-Credential) -DateTime (Get-Date).AddHours(2)

        Schedules a reboot on srv-01 over SSH remoting using a custom port.

        .EXAMPLE
        Set-OneTimeReboot -ComputerName 'PC01' -TaskName 'TT_OneTimeReboot' -Remove

        Removes the reboot task from a remote target.

        .EXAMPLE
        Set-OneTimeReboot -ComputerName 'PC01' -At '01:00' -WhatIf

        Previews the remote operation without making changes.

        .NOTES
        - Administrative permissions are required on target systems.
        - Requires remoting connectivity and endpoint configuration for remote
          use.
        - Uses ScheduledTasks cmdlets when available; otherwise falls back to
            schtasks.exe on the target.

        .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Set-OneTimeReboot

        .LINK
        Start-NewPSRemoteSession

        .LINK
        Register-ScheduledTask

        .LINK
        Unregister-ScheduledTask
        #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        # If specified, schedules on remote machine(s). If omitted, schedules locally.
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('CN', 'Host', 'Name')]
        [string[]]$ComputerName,

        # Exact local date/time to use for scheduling.
        # Declared before Credential so positional calls like:
        # Set-OneTimeReboot -ComputerName PC01 '4/21/2026 1:00:00 AM'
        # bind the second argument to DateTime instead of Credential.
        [Nullable[datetime]]$DateTime,

        # Credential for remote session creation (WSMan/SSH).
        # Also supports username-only for SSH key auth via PSRemoting helper.
        [pscredential]$Credential,

        # --- scheduling params ---
        [ValidatePattern('^(?:[01]\d|2[0-3]):[0-5]\d$')]
        [string]$At,

        [string]$TaskName,
        [string]$Description,

        [Nullable[bool]]$SelfDelete,
        [Nullable[bool]]$Force,
        [Nullable[bool]]$Wake,

        [switch]$Remove,

        # --- transport passthrough (minimal, but useful) ---
        [switch]$UseSsh,
        [switch]$UseCredSSP,
        [int]$Port = 22
    )

    begin {
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        # Init runtime (loads config, helper functions, etc.)
        Initialize-TechToolboxRuntime

        # Map config defaults
        $cfg = $script:cfg.settings.oneTimeReboot

        # Logging shim (uses Write-Log if available, else Write-Host)
        function _Log {
            param([ValidateSet('Ok', 'E-Info', 'Info', 'Warn', 'Error')][string]$Level, [string]$Message)
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level $Level -Message $Message
            }
            else {
                $color = switch ($Level) {
                    'Ok' { 'Green' }
                    'E-Info' { 'Cyan' }
                    'Info' { 'Gray' }
                    'Warn' { 'Yellow' }
                    'Error' { 'Red' }
                    default { 'Gray' }
                }
                Write-Host "[Set-OneTimeReboot][$Level] $Message" -ForegroundColor $color
            }
        }

        # Apply config defaults only when param is not explicitly bound
        if (-not $PSBoundParameters.ContainsKey('At')) { $At = $cfg.at }
        if (-not $PSBoundParameters.ContainsKey('SelfDelete')) { $SelfDelete = [bool]$cfg.selfDelete }

        # Can be defaulted later
        if (-not $PSBoundParameters.ContainsKey('Force')) { $Force = $false }
        if (-not $PSBoundParameters.ContainsKey('Wake')) { $Wake = $false }

        if (-not $PSBoundParameters.ContainsKey('TaskName')) {
            # Default to prefix if no explicit TaskName
            $TaskName = $cfg.taskNamePrefix
        }
        if (-not $PSBoundParameters.ContainsKey('Description')) {
            $Description = $cfg.defaultDescription
        }

        $deleteAfterMin = 10
        if ($cfg.deleteExpiredTaskAfterMinutes -as [int]) {
            $deleteAfterMin = [int]$cfg.deleteExpiredTaskAfterMinutes
        }

        function _ComputeTargetDateTime {
            param([string]$At, [Nullable[datetime]]$DateTime)

            if ($null -ne $DateTime) { return [datetime]$DateTime }

            $parts = $At.Split(':')
            $candidate = (Get-Date).Date.AddHours([int]$parts[0]).AddMinutes([int]$parts[1])
            if ($candidate -le (Get-Date)) { $candidate = $candidate.AddDays(1) }
            return $candidate
        }

        function _SetOneTimeRebootLocal {
            [CmdletBinding(DefaultParameterSetName = 'Schedule')]
            param(
                [Parameter(ParameterSetName = 'Schedule', Mandatory = $true)]
                [datetime]$Target,

                [Parameter(ParameterSetName = 'Schedule', Mandatory = $true)]
                [string]$TaskName,

                [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
                [switch]$Remove,

                [string]$Description,
                [switch]$Force,
                [switch]$Wake,
                [switch]$SelfDelete
            )

            # --- Removal mode ---
            if ($Remove) {
                if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
                    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
                    return [pscustomobject]@{
                        Status       = 'Removed'
                        ScheduledFor = $null
                        TaskName     = $TaskName
                        Engine       = 'ScheduledTasks'
                    }
                }

                & schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
                return [pscustomobject]@{
                    Status       = 'Removed'
                    ScheduledFor = $null
                    TaskName     = $TaskName
                    Engine       = 'schtasks.exe'
                }
            }

            # --- Scheduling mode ---
            $hasST = [bool](Get-Command New-ScheduledTaskAction -ErrorAction SilentlyContinue)
            $useSchTasks = (-not $hasST) -or $SelfDelete

            # schtasks.exe does not support automatic task deletion, so we use a
            # short-term trigger as a workaround when SelfDelete is enabled.
            # Otherwise, we prefer ScheduledTasks cmdlets for better settings
            # control and reliability.
            if (-not $useSchTasks) {
                $RBargs = '/r', '/t', '0'
                if ($Force) { $RBargs += '/f' }

                $action = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument ($RBargs -join ' ')
                $trigger = New-ScheduledTaskTrigger -Once -At $Target
                $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

                if ($Wake) { $settings.WakeToRun = $true }

                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

                Register-ScheduledTask -TaskName $TaskName `
                    -Action $action `
                    -Trigger $trigger `
                    -Settings $settings `
                    -User 'SYSTEM' `
                    -Description $Description `
                    -Force | Out-Null

                return @{
                    Status       = 'Scheduled'
                    ScheduledFor = $Target
                    TaskName     = $TaskName
                    Engine       = 'ScheduledTasks'
                    Fallback     = $null
                }
            }

            # --- schtasks.exe path ---
            $trArgs = 'shutdown.exe /r /t 0'
            if ($Force) { $trArgs += ' /f' }

            $st = $Target.ToString('HH:mm')
            $sd = $Target.ToString('MM/dd/yyyy', [cultureinfo]::InvariantCulture)

            & schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null

            $createArgs = @(
                '/Create',
                '/SC', 'ONCE',
                '/TN', $TaskName,
                '/TR', $trArgs,
                '/ST', $st,
                '/SD', $sd,
                '/RU', 'SYSTEM',
                '/F'
            )

            & schtasks.exe @createArgs | Out-Null

            return [pscustomobject]@{
                Status       = 'Scheduled'
                ScheduledFor = $Target
                TaskName     = $TaskName
                Engine       = 'schtasks.exe'
                Fallback     = 'Used schtasks.exe (ScheduledTasks cmdlets unavailable or SelfDelete enabled)'
            }
        }

        $targetDT = _ComputeTargetDateTime -At $At -DateTime $DateTime
        $targetText = $targetDT.ToString('yyyy-MM-dd HH:mm:ss')
        _Log E-Info "`nEffective: At=$At | DateTime=$targetText | TaskName=$TaskName | SelfDelete=$SelfDelete | Force=$Force | Wake=$Wake | Remove=$Remove"
    }

    process {
        # Local mode when ComputerName is null/empty
        if (-not $ComputerName -or $ComputerName.Count -eq 0) {

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, ($Remove ? "Remove task $TaskName" : "Schedule reboot at $($targetDT)"))) {

                $r = _SetOneTimeRebootLocal `
                    -Target $targetDT `
                    -TaskName $TaskName `
                    -Description $Description `
                    -Remove:$Remove `
                    -Force:$Force `
                    -Wake:$Wake `
                    -SelfDelete:$SelfDelete

                [pscustomobject]@{
                    ComputerName = $env:COMPUTERNAME
                    Transport    = 'Local'
                    TaskName     = $r.TaskName
                    Description  = $Description
                    ScheduledFor = $r.ScheduledFor
                    Status       = $r.Status
                    Detail       = $r.Fallback
                }
            }
            return
        }

        foreach ($cn in $ComputerName) {

            if (-not $PSCmdlet.ShouldProcess($cn, ($Remove ? "Remove task $TaskName" : "Schedule reboot at $($targetDT)"))) {
                continue
            }

            try {
                $sess = Start-NewPSRemoteSession -ComputerName $cn -Credential $Credential -UseSsh:$UseSsh -UseCredSSP:$UseCredSSP -Port $Port

                try {
                    # ArgumentList order MUST match the helper param order.
                    # [1](https://stackoverflow.com/questions/13092352/how-important-is-parameter-order-when-calling-powershell-cmdlets)
                    # [2](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/09-functions?view=powershell-7.6)
                    # Capture the local helper scriptblock once (outside Invoke-Command)
                    $helperText = ${function:_SetOneTimeRebootLocal}.ToString()

                    $remoteResult = Invoke-Command -Session $sess -ScriptBlock {
                        param(
                            [string]$HelperText,
                            [datetime]$Target,
                            [string]$TaskName,
                            [string]$Description,
                            [bool]$Remove,
                            [bool]$Force,
                            [bool]$Wake,
                            [bool]$SelfDelete
                        )

                        # Rehydrate the scriptblock on the remote side
                        $Helper = [scriptblock]::Create($HelperText)

                        if ($Remove) {
                            & $Helper `
                                -TaskName     $TaskName `
                                -Description  $Description `
                                -Remove `
                                -Force:       $Force `
                                -Wake:        $Wake `
                                -SelfDelete:  $SelfDelete
                        }
                        else {
                            & $Helper `
                                -Target       $Target `
                                -TaskName     $TaskName `
                                -Description  $Description `
                                -Force:       $Force `
                                -Wake:        $Wake `
                                -SelfDelete:  $SelfDelete
                        }

                    } -ArgumentList @(
                        $helperText,
                        $targetDT,
                        $TaskName,
                        $Description,
                        [bool]$Remove,
                        [bool]$Force,
                        [bool]$Wake,
                        [bool]$SelfDelete
                    )

                    [pscustomobject]@{
                        ComputerName = $cn
                        Transport    = ($UseSsh ? "SSH:$Port" : "WSMan")
                        TaskName     = $remoteResult.TaskName
                        Description  = $Description
                        ScheduledFor = $remoteResult.ScheduledFor
                        Status       = $remoteResult.Status
                        Detail       = $remoteResult.Fallback
                    }
                }
                finally {
                    if ($sess) { Remove-PSSession -Session $sess -ErrorAction SilentlyContinue }
                }
            }
            catch {
                _Log Error "[$cn] $($_.Exception.Message)"
                [pscustomobject]@{
                    ComputerName = $cn
                    Transport    = ($UseSsh ? "SSH:$Port" : "WSMan")
                    TaskName     = $TaskName
                    Description  = $Description
                    ScheduledFor = $targetDT
                    Status       = 'Error'
                    Detail       = $_.Exception.Message
                }
            }
        }
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAoeRIJIn3TBut7
# kyJ7QGslL/UuhHoHNSc+wUB8SHnMxqCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBV
# Hpno9F/8ZCzH6Tum/BrtMj9ihNkY71l4QUsKLszwaDANBgkqhkiG9w0BAQEFAASC
# AYCYuw3tI9nE+u2Wc3U+qnndeMe5ba6dqx6XtPn5XocLoiCxSGNyOUALSAAEWAMI
# RLZWkwKYA4IbCJYBoldJ9CLPWRw5ofgBnDmZ9SMAbQghlR+N/ul0/qED5rJOztKw
# 9y5lFt9WAHe9PS/qanOCnlz3yjpL6FoqRB5Oz/NaTgoxCv5B0ItrFrE/erwAKOy+
# TS8Kqv/8q3VUWVKvjUK9B4hdSJwPFRcmzttbDfxtcuk+AT3vrfLAqtauOwnZFlCh
# P5e9d0JyKlndPpt+TIM1iiHf+T+rt+wPElTo4ca+47LPtwLkFQCs6RqPZIoMA1t8
# 7fcQ6KmzJm5HGY0BlP+DGyVJI/cxWGJjlm3HrJ8xtpYu4pKoFoV01zkX3M1fStpI
# M6QMyXWeJEj7bqSJ9/eYxLjkMvrjf69LAWDUMcrsBpU2McyqhgjANa6SpiItZezE
# 8znVMqUWCv668hUyTNfGwXDanoLBtQNSUIhR6AREUE0/Jv3l+awUzZXMAaSbS38V
# 0mmhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDU2WjAvBgkqhkiG
# 9w0BCQQxIgQgBocsSt3/4Pj/Am+z4LT+Vf6kRfJTuOWsjAsHeOi+Fg4wDQYJKoZI
# hvcNAQEBBQAEggIAGdwTimWG0VvJbwaJug4+3ghpkkTK81fpFpPC/uF+9SqsRKz/
# qOYtlGzhOq4VtrCskIy4E7gEMijTX1nPdlcrCzK7JZB0gSQqk6SzK5ZM0Q3I/8/T
# Z65J0T8jxHI+Jg/BNahi8xDpJn+Zz1S5DfQGnZzzshRDrT/MGjrtnQ+XJlZb8HW7
# 8Y9AyEoCz/cy1/53o9RJ8oMuOjjc7HTqJ+NFbTA4l/dVNkPHMfkoOvh3q5/YqdzQ
# nvtYhVMDcR6S0FjkKsm7BtX6KhefHUOq2CyxzyUyMOTj+/6ibrhK0DqpSEHFy25i
# W/vOR30CCiPuJvYZe3KrAd2ndjQjm7OvL3F824xc43vErykB7CbIcxFFy52za/tg
# 9uHTV47tpmVdl7f9axl1jj0UGgUytDgnSFWB/KDywMS8ORyv+W+g0CTd9edN4pu5
# VSozQTCbVBry7+hLMQP9kPZcixynxpLg4gzWnEqgkWMETKneqXP+gjSkxUhWA5vg
# 63MoK5tqmotNelrwzyWBotxWujcj2m0BXqvjOftoHcEubYH/Yea2S2EVmylKB7D+
# XPZuWVuNfVDbPLeR27BATDRvowyHWHeTM866W6Ft2mOmEEp+oNfbCvxD0ptQ6Uim
# LXT/9dMbUzUPV1pEt9bzfQvWppNXyWFeXIjuXJJZgFbW15Jzak7I4JhCajc=
# SIG # End signature block
