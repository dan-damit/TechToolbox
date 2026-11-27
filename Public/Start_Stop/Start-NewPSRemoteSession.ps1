function Start-NewPSRemoteSession {
    <#
    .SYNOPSIS
        Create a remote PSSession, preferring PowerShell 7 endpoint (WSMan) with
        fallback to Windows PowerShell. Also supports SSH transport.

    .DESCRIPTION
        - For WSMan: tries -ConfigurationName PowerShell.7 first, then falls
          back to Microsoft.PowerShell.
        - For SSH: uses New-PSSession -HostName (PowerShell 7+ locally).
          Supports password or key.
        - Applies sensible timeouts; returns a live PSSession or throws.

    .PARAMETER ComputerName
        Target computer (DNS name or IP).

    .PARAMETER Credential
        PSCredential for WSMan or SSH (username/password). For SSH+Key, Username
        can come from the credential or -UserName.

    .PARAMETER UseSsh
        Use SSH transport instead of WSMan.

    .PARAMETER UseCredSSP
        Enables CredSSP for WSMan remoting and bootstraps the remote host's
        WSMan CredSSP server setting before opening the delegated session.

    .PARAMETER Port
        SSH port (default 22).

    .PARAMETER Ps7ConfigName
        WSMan endpoint name for PS7 (default 'PowerShell.7').

    .PARAMETER WinPsConfigName
        WSMan endpoint name for Windows PowerShell (default
        'Microsoft.PowerShell').

    .PARAMETER UserName
        SSH username when not using PSCredential.

    .PARAMETER KeyFilePath
        SSH private key path (if using key-based auth).

    .PARAMETER ConnectTimeoutSec
        Open/operation timeout (seconds) used in session options.

    .PARAMETER IdleTimeoutSec
        Idle timeout (milliseconds) for the session.

    .PARAMETER AsList
        When set, returns a list-style summary object for display instead of the
        raw PSSession object.

    .OUTPUTS
        System.Management.Automation.Runspaces.PSSession

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Start-NewPSRemoteSession

    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [pscredential]$Credential,
        [string]$SessionName,

        [switch]$UseSsh,
        [switch]$UseCredSSP,

        [int]$Port = 22,

        [string]$Ps7ConfigName = 'PowerShell.7',
        [string]$WinPsConfigName = 'Microsoft.PowerShell',

        [string]$UserName,
        [string]$KeyFilePath,

        [int]$ConnectTimeoutSec = 20,
        [int]$IdleTimeoutSec = 1800000,  # 30 minutes

        [switch]$AsList
    )

    Set-StrictMode -Version Latest
    $oldEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        $sessOpts = New-PSSessionOption -OpenTimeout ($ConnectTimeoutSec * 1000) `
            -OperationTimeout ($ConnectTimeoutSec * 1000) `
            -IdleTimeout $IdleTimeoutSec

        function Test-LocalAdministrator {
            $id = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]$id
            return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        }

        function Get-SessionOutputObject {
            param(
                [Parameter(Mandatory)]
                [System.Management.Automation.Runspaces.PSSession]$Session,
                [switch]$AsList
            )

            if (-not $AsList) {
                return $Session
            }

            [pscustomobject]@{
                Id                = $Session.Id
                Name              = $Session.Name
                Transport         = $Session.Transport
                ComputerName      = $Session.ComputerName
                ComputerType      = $Session.ComputerType
                State             = $Session.State
                ConfigurationName = $Session.ConfigurationName
                Availability      = $Session.Availability
                RunspaceId        = $Session.Runspace.InstanceId
                PSSession         = $Session
            }
        }

        function Test-CredSSPClientDelegationConfigured {
            param([Parameter(Mandatory)][string]$TargetComputer)

            # First check the local WSMan CredSSP client auth toggle. This read is
            # available in normal sessions and avoids false negatives when
            # Get-WSManCredSSP itself requires elevation.
            try {
                $authEnabled = (Get-Item -Path WSMan:\localhost\Client\Auth\CredSSP -ErrorAction Stop).Value
            }
            catch {
                return $false
            }

            if ([string]$authEnabled -ne 'true') {
                return $false
            }

            try {
                $status = Get-WSManCredSSP
            }
            catch {
                # In non-elevated sessions this cmdlet can throw AccessDenied.
                # If CredSSP client auth is on, treat configuration as present.
                return $true
            }

            if (-not $status) {
                return $true
            }

            $patterns = @()
            foreach ($line in @($status -split "`r?`n")) {
                $trimmed = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

                $matches = [regex]::Matches($trimmed, '(?i)wsman/[^\s,;]+')
                foreach ($match in $matches) {
                    if ($match.Success) {
                        $patterns += $match.Value.ToLowerInvariant()
                    }
                }
            }

            $patterns = @($patterns | Select-Object -Unique)

            if ($patterns.Count -eq 0) {
                return $false
            }

            $shortComputer = ($TargetComputer -split '\.')[0]
            $targetsToMatch = @(
                ("wsman/{0}" -f $TargetComputer),
                ("wsman/{0}" -f $shortComputer),
                $TargetComputer,
                $shortComputer
            )

            foreach ($pattern in $patterns) {
                foreach ($candidate in $targetsToMatch) {
                    if ($candidate -like $pattern) {
                        return $true
                    }
                }
            }

            return $false
        }

        function Get-CredSSPDelegateTargets {
            param([Parameter(Mandatory)][string]$TargetComputer)

            $configuredTargets = @()
            $remoting = $null

            if ($script:cfg -and $script:cfg.settings) {
                $remoting = $script:cfg.settings.remoting
            }

            if ($remoting -and $remoting.ContainsKey('credSSPDelegateComputers')) {
                $rawTargets = $remoting['credSSPDelegateComputers']

                if ($rawTargets -is [string]) {
                    $configuredTargets = @($rawTargets)
                }
                elseif ($rawTargets -is [System.Collections.IEnumerable]) {
                    $configuredTargets = @($rawTargets)
                }
            }

            $normalizedTargets = @(
                $configuredTargets |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                ForEach-Object {
                    $value = [string]$_
                    if ($value -like 'wsman/*') {
                        $value.Substring(6)
                    }
                    else {
                        $value
                    }
                } |
                Select-Object -Unique
            )

            if ($normalizedTargets.Count -gt 0) {
                return $normalizedTargets
            }

            return @($TargetComputer)
        }

        function Enable-RemoteCredSSPServer {
            param(
                [Parameter(Mandatory)][string]$TargetComputer,
                [pscredential]$TargetCredential,
                [Parameter(Mandatory)][System.Management.Automation.Remoting.PSSessionOption]$SessionOptions,
                [Parameter(Mandatory)][string]$PrimaryConfig,
                [Parameter(Mandatory)][string]$FallbackConfig,
                [Parameter(Mandatory)][string]$TargetSessionName
            )

            Write-Log -Level Info -Message "Ensuring CredSSP is enabled on $TargetComputer for WSMan remoting."

            $delegateTargets = Get-CredSSPDelegateTargets -TargetComputer $TargetComputer
            $clientConfigured = Test-CredSSPClientDelegationConfigured -TargetComputer $TargetComputer
            if (-not $clientConfigured) {
                if (-not (Test-LocalAdministrator)) {
                    $delegateArg = ($delegateTargets | ForEach-Object { "'{0}'" -f $_ }) -join ', '
                    throw "CredSSP client delegation is not configured locally for $TargetComputer and enabling it requires an elevated PowerShell session. Run once as administrator: Enable-WSManCredSSP -Role Client -DelegateComputer $delegateArg -Force"
                }

                Enable-WSManCredSSP -Role Client -DelegateComputer $delegateTargets -Force | Out-Null
            }

            $bootstrap = $null
            try {
                $bootstrapParams = @{
                    ComputerName      = $TargetComputer
                    Credential        = $TargetCredential
                    Authentication    = 'Default'
                    ConfigurationName = $PrimaryConfig
                    ErrorAction       = 'Stop'
                    SessionOption     = $SessionOptions
                    Name              = "$TargetSessionName:bootstrap"
                }

                try {
                    $bootstrap = New-PSSession @bootstrapParams
                }
                catch {
                    $bootstrapParams.ConfigurationName = $FallbackConfig
                    $bootstrap = New-PSSession @bootstrapParams
                }

                $serverEnabled = Invoke-Command -Session $bootstrap -ScriptBlock {
                    $value = (Get-Item -Path WSMan:\localhost\Service\Auth\CredSSP -ErrorAction Stop).Value
                    return [string]$value -eq 'true'
                } -ErrorAction Stop

                if (-not $serverEnabled) {
                    Invoke-Command -Session $bootstrap -ScriptBlock {
                        Enable-WSManCredSSP -Role Server -Force | Out-Null
                    } -ErrorAction Stop | Out-Null
                }
            }
            finally {
                if ($bootstrap) {
                    Remove-PSSession -Session $bootstrap -ErrorAction SilentlyContinue
                }
            }
        }

        if (-not $SessionName) {
            $SessionName = "TT:Remote:{0}:{1:yyyyMMdd-HHmmss}" -f $ComputerName, (Get-Date)
        }

        if ($UseSsh) {

            # --- Preflight: must be PowerShell 7+ (or 6+) locally for SSH remoting parameter set ---
            if ($PSVersionTable.PSVersion.Major -lt 7) {
                throw "SSH transport requires PowerShell 7+ locally."
            } # PowerShell remoting over SSH is supported in PowerShell 6+ / 7+. [1](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.6)[3](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-7.5)

            # --- Preflight: ensure OpenSSH client is present (ssh.exe) ---
            if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
                throw "SSH transport requires OpenSSH client (ssh.exe) available on PATH."
            } # SSH transport depends on SSH being installed. [1](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.6)

            # --- Resolve username ---
            $resolvedUser = $null
            if ($UserName) {
                $resolvedUser = $UserName
            }
            elseif ($Credential) {
                $resolvedUser = $Credential.UserName
            }

            # --- Guardrail: by default, require KeyFilePath to avoid interactive prompts (worker-safe) ---
            # If you *want* to allow prompting, do it only when truly interactive.
            $isInteractive = $Host.Name -match 'ConsoleHost|Visual Studio Code Host' -and
            [Environment]::UserInteractive -and
            -not [Console]::IsInputRedirected

            if (-not $KeyFilePath) {
                if (-not $isInteractive) {
                    throw "SSH requires -KeyFilePath in non-interactive contexts to prevent password prompts/hangs."
                }

                # Interactive session without key: require username so prompt can occur
                if (-not $resolvedUser) {
                    throw "For interactive SSH without -KeyFilePath, specify -UserName or -Credential (username only)."
                }
            }
            else {
                # Key auth requires username (PowerShell uses -UserName + -KeyFilePath). [1](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.6)[2](https://bing.com/search?q=PowerShell+remoting+over+SSH+New-PSSession+-HostName+-UserName+-SSHTransport+key+authentication+requirements)
                if (-not $resolvedUser) {
                    throw "For SSH key auth, specify -UserName or -Credential (username only)."
                }

                if (-not (Test-Path -LiteralPath $KeyFilePath)) {
                    throw "SSH key file not found: $KeyFilePath"
                }
            }

            # --- Build SSH session params (only params valid/meaningful for SSH parameter set) ---
            $sshParams = @{
                HostName    = $ComputerName
                ErrorAction = 'Stop'
                Name        = $SessionName
            }

            # Only add Port if user supplied it (avoid passing null/0)
            if ($PSBoundParameters.ContainsKey('Port') -and $Port) {
                $sshParams.Port = $Port
            }

            if ($resolvedUser) {
                $sshParams.UserName = $resolvedUser
            }

            if ($KeyFilePath) {
                $sshParams.KeyFilePath = $KeyFilePath
            }

            # Optional: session options are fine to pass
            if ($sessOpts) {
                $sshParams.SessionOption = $sessOpts
            }

            # NOTE: No ConfigurationName here - SSH remoting doesn't use WinRM-style endpoint configuration/JEA. [1](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell?view=powershell-7.6)
            $s = New-PSSession @sshParams

            $portInfo = if ($sshParams.Port) { " (port $($sshParams.Port))" } else { "" }
            Write-Log -Level Ok -Message "Connected to $ComputerName via SSH$portInfo."
            return (Get-SessionOutputObject -Session $s -AsList:$AsList)
        }
        else {
            if ($UseCredSSP) {
                Enable-RemoteCredSSPServer `
                    -TargetComputer $ComputerName `
                    -TargetCredential $Credential `
                    -SessionOptions $sessOpts `
                    -PrimaryConfig $Ps7ConfigName `
                    -FallbackConfig $WinPsConfigName `
                    -TargetSessionName $SessionName
            }

            $auth = if ($UseCredSSP) { 'CredSSP' } else { 'Default' }

            # WSMan: PS7 endpoint first
            try {
                $wsmanParams = @{
                    ComputerName      = $ComputerName
                    Credential        = $Credential
                    Authentication    = $auth
                    ConfigurationName = $Ps7ConfigName
                    ErrorAction       = 'Stop'
                    SessionOption     = $sessOpts
                    Name              = $SessionName
                }
                $s = New-PSSession @wsmanParams
                Write-Log -Level Ok -Message "Connected to $ComputerName via WSMan ($Ps7ConfigName)."
                return (Get-SessionOutputObject -Session $s -AsList:$AsList)
            }
            catch {
                # Fallback to Windows PowerShell endpoint
                $wsmanParams = @{
                    ComputerName      = $ComputerName
                    Credential        = $Credential
                    Authentication    = $auth
                    ConfigurationName = $WinPsConfigName
                    ErrorAction       = 'Stop'
                    SessionOption     = $sessOpts
                    Name              = $SessionName
                }
                $s = New-PSSession @wsmanParams
                Write-Log -Level Ok -Message "Connected to $ComputerName via WSMan ($WinPsConfigName)."
                return (Get-SessionOutputObject -Session $s -AsList:$AsList)
            }
        }
    }
    catch {
        $msg = $_.Exception.Message
        Write-Log -Level Error -Message "Failed to create PSSession to ${ComputerName}: $msg"
        throw
    }
    finally {
        $ErrorActionPreference = $oldEAP
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChTA/Y6kqvyEPs
# JwuS9uXAF3CDb23mdeI4MMW2olxxm6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBl
# lXiGXtjzVg0xOsjn+wZKnqww7cWEOSU2Aro6aafoEzANBgkqhkiG9w0BAQEFAASC
# AYB680TMmcYXoDgXmi0o12Zhnys1vsn4zC35qr2QaFqbrbxyRpWLpR6aOX8dex8l
# sE0UOWl+RdE/b2VAo6+SpXQKMMOhssjlgiiSpoNNTEOiomd8EtKu91PxY4UfjxHh
# QAWOv//BqWT6D7VrOvKL1mU0yjTxapyGrmtbI6KGmEkqQo3LGkOb53Is4J7+O81x
# zfvhpin2uZt5kgw/vC3abnTM3L79QYubZHAdkGPeEU13ToV7NTNMV+qJkt/H4h3X
# BsLa/uBOL8BE3UiY3wztVUWhzmldo94/EcBAvzj2tW8JQOjOH/qGAizc6eSfATp+
# Fy4KL10OuveQiTCUqFHpcdHWJtTK8x7lBDNO/Sp09z6UMf4G19Mi5/M1i4PzD0+V
# MynK/gTArymp1yPAmQfiA/h9kNl9768fNyEbOcHE3mo9ShxLMMz0N5hEa4WHEp+g
# NSwLNcO2Z2IeUtcHb7g5vESKc9CbA6v0s340eaorO4qneV4JsXCB3ckXI9BZWIJ6
# voihggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNTA0WjAvBgkqhkiG
# 9w0BCQQxIgQgRl0QrU81jmTJeH5I1OMWY6KodoEx03VuZr34r/2x+sAwDQYJKoZI
# hvcNAQEBBQAEggIAL4ywWSp5fefqALJphsUuDq+UY9PrSIt28UaABcXQNSrfCRGb
# Nx7FZ3s0qNnoispOAuBXOnvBUxX63JEgTBTw7f/3giVcmcEvNra1/v4/Nw/LnBy9
# SCl8mNzDj13Sw4jjuv907xsPBgcO/vKPekB5P0/d4QQAeIb3uywMDZVvugqVsinJ
# E/g5KmS33S1NEmm9LfFwwkKTZB2d8Pv5LOgACRPJnh9w8jsh4Dkmm1mRgonE8JBM
# 2U3ScqZDaiqq1p/2D7v9fTOsbSnh0V4pYyD7Enf7mlMXlFS8PU0XlIwnHwXbDtwN
# mtYBkYoHaak2bps42i3qEKpPfmmIcv/lDsRcjT9iocmip3TIMHKOtlvGcuTaIWDB
# Nsdb5FLUTeuMhAviGLCzCatcx7VdaXcYGIjQwR+l3yaIzR5MRmqYaOANQivW+rAR
# K1ibg0yaLvevVOd8WqZG5ZU9opItCIuMAQYYcK5NsyS4yjkMUzvYxGkn9TYsggAs
# mCl6Lw/Ir1z21+JZ6xv3VSM8lHqvuaoe8rAbqDJnSYyF2EEN5pqJgAuS6JfAJJGq
# ZubpzKJG9oOafA4pO1KEwDaA69fdtzAuQULJJD8cV1xkoxVvH6UmB1AlNitPTKvg
# 9TSY2ltorTF8mCGJbvw27HRLDfa5whPcm/Ed9Gy9Z4b26PFLSCXCGTtnPXo=
# SIG # End signature block
