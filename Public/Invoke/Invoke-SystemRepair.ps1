function Invoke-SystemRepair {
    <#
    .SYNOPSIS
    Invokes system repair operations on a local or remote computer.

    .DESCRIPTION
    Performs various system repair operations including DISM RestoreHealth,
    StartComponentCleanup, ResetBase, SFC /scannow, and Windows Update component
    reset.

    .PARAMETER RestoreHealth
    Run DISM RestoreHealth operation.

    .PARAMETER StartComponentCleanup
    Run DISM StartComponentCleanup operation.

    .PARAMETER ResetBase
    Run DISM ResetBase operation.

    .PARAMETER SfcScannow
    Run SFC /scannow operation.

    .PARAMETER ResetUpdateComponents
    Reset Windows Update components.

    .PARAMETER ComputerName
    Target computer name for remote execution.

    .PARAMETER Local
    Run operations locally instead of remotely.

    .PARAMETER Credential
    Credentials for remote session.

    .PARAMETER UseCredSSP
    Uses CredSSP authentication for WSMan remoting so remote DISM can access
    delegated network resources such as UNC repair sources.

    .PARAMETER OperationTimeoutMinutes
    Maximum minutes to wait for each DISM/SFC operation.

    .PARAMETER WaitPollSeconds
    Poll interval used by Wait-TerminalState during local execution.

    .PARAMETER WaitHeartbeatSeconds
    Heartbeat interval used by Wait-TerminalState during local execution.

    .PARAMETER RepairSource
    Optional DISM repair source path (for example, WIM/ESD or SxS folder).

    .PARAMETER RepairSourceIndex
    Optional image index used when RepairSource points to a WIM/ESD file and an
    explicit index is not already provided in the source string.

    .PARAMETER LimitAccess
    When set, DISM does not contact Windows Update and uses only local source
    content.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Invoke-SystemRepair
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [switch]$RestoreHealth,
        [switch]$StartComponentCleanup,
        [switch]$ResetBase,
        [switch]$SfcScannow,
        [switch]$ResetUpdateComponents,
        [string]$ComputerName,
        [switch]$Local,
        [pscredential]$Credential,
        [switch]$UseCredSSP,
        [string]$RepairSource,
        [ValidateRange(1, 999)]
        [int]$RepairSourceIndex = 1,
        [switch]$LimitAccess,
        [ValidateRange(1, 480)]
        [int]$OperationTimeoutMinutes = 60,
        [ValidateRange(1, 300)]
        [int]$WaitPollSeconds = 5,
        [ValidateRange(0, 3600)]
        [int]$WaitHeartbeatSeconds = 300
    )

    if (-not ($RestoreHealth -or $StartComponentCleanup -or $ResetBase -or $SfcScannow -or $ResetUpdateComponents)) {
        Write-Log -Level Warn -Message "No operations specified. Choose at least one operation to run."
        return
    }

    Initialize-TechToolboxRuntime

    function Get-VersionTokenFromText {
        param([string]$Text)

        if ([string]::IsNullOrWhiteSpace($Text)) {
            return $null
        }

        $m = [regex]::Match($Text, '(?i)\b(1\d|2\d)H[12]\b')
        if (-not $m.Success) {
            return $null
        }

        return $m.Value.ToUpperInvariant()
    }

    function Get-RemoteWindowsVersionInfo {
        [CmdletBinding()]
        param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session)

        Invoke-Command -Session $Session -ScriptBlock {
            $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop

            $displayVersion = [string]$cv.DisplayVersion
            $releaseId = [string]$cv.ReleaseId
            $productName = [string]$cv.ProductName

            $text = @($displayVersion, $releaseId, $productName) -join ' '
            $tokenMatch = [regex]::Match($text, '(?i)\b(1\d|2\d)H[12]\b')

            [pscustomobject]@{
                DisplayVersion = $displayVersion
                ReleaseId      = $releaseId
                ProductName    = $productName
                VersionToken   = if ($tokenMatch.Success) { $tokenMatch.Value.ToUpperInvariant() } else { $null }
            }
        }
    }

    $repair = $script:cfg.settings.systemRepair
    $runRemoteDefault = $repair.runRemote ?? $true
    $retryRestoreHealthWithoutSource = $false
    $usingDefaultRepairSource = $false

    if (-not $PSBoundParameters.ContainsKey('UseCredSSP') -and $repair.ContainsKey('useCredSSPByDefault')) {
        $UseCredSSP = [bool]$repair['useCredSSPByDefault']
    }

    if (-not $PSBoundParameters.ContainsKey('LimitAccess') -and $repair.ContainsKey('limitAccessByDefault')) {
        $LimitAccess = [bool]$repair['limitAccessByDefault']
    }

    if ($repair.ContainsKey('retryWithoutSourceOnNotFound')) {
        $retryRestoreHealthWithoutSource = [bool]$repair['retryWithoutSourceOnNotFound']
    }

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

    if ($runRemoteEffective -and -not $PSBoundParameters.ContainsKey('RepairSource') -and $repair.ContainsKey('defaultRepairSource')) {
        $RepairSource = [string]$repair['defaultRepairSource']
        $usingDefaultRepairSource = -not [string]::IsNullOrWhiteSpace($RepairSource)
    }

    if (-not $PSBoundParameters.ContainsKey('RepairSourceIndex') -and $repair.ContainsKey('defaultRepairSourceIndex')) {
        $RepairSourceIndex = [int]$repair['defaultRepairSourceIndex']
    }

    $targetLabel = if ($runRemoteEffective) { "remote host $targetComputer" } else { "local machine" }

    Write-Log -Level Info -Message ("Preparing system repair operations on {0}." -f $targetLabel)

    $ops = @()
    if ($RestoreHealth) { $ops += "DISM RestoreHealth" }
    if ($StartComponentCleanup) { $ops += "DISM StartComponentCleanup" }
    if ($ResetBase) { $ops += "DISM ResetBase" }
    if ($SfcScannow) { $ops += "SFC /scannow" }
    if ($ResetUpdateComponents) { $ops += "Reset Windows Update Components" }

    $operationDesc = $ops -join ", "

    if (-not $PSCmdlet.ShouldProcess($targetLabel, "Run: $operationDesc")) { return }

    if ($runRemoteEffective) {
        Write-Log -Level Info -Message ("Executing repair operations remotely on [{0}]." -f $targetComputer)

        $moduleRoot = Get-ModuleRoot
        $workerLocal = Join-Path $moduleRoot 'Workers\Invoke-SystemRepair.Worker.ps1'
        $workerRemote = Join-Path $moduleRoot 'Workers\Invoke-SystemRepair.Worker.ps1'

        # build helper list
        $helperLibs = @(
            Join-Path $moduleRoot 'Private\Logging\Write-Log.ps1'
            Join-Path $moduleRoot 'Private\System\Utilities\ReusableHelpers\WaitingHeartbeatScripts\Wait-TerminalState.ps1'
            Join-Path $moduleRoot 'Private\System\Utilities\ReusableHelpers\WaitingHeartbeatScripts\Get-DotPulse.ps1'
        )

        $workerFiles = @(
            Join-Path $moduleRoot 'Workers\Invoke-SystemRepair.Worker.ps1'
            Join-Path $moduleRoot 'Workers\Reset-WindowsUpdateComponents.Worker.ps1'
        )

        $pkg = New-HelpersPackage -HelperLibs $helperLibs -WorkerFiles $workerFiles

        $session = $null
        try {
            $session = Start-NewPSRemoteSession -ComputerName $targetComputer -Credential $Credential -UseCredSSP:$UseCredSSP

            if ($usingDefaultRepairSource -and -not [string]::IsNullOrWhiteSpace($RepairSource)) {
                $sourceVersionToken = Get-VersionTokenFromText -Text $RepairSource

                if (-not [string]::IsNullOrWhiteSpace($sourceVersionToken)) {
                    $remoteVersionInfo = Get-RemoteWindowsVersionInfo -Session $session
                    $remoteVersionToken = [string]$remoteVersionInfo.VersionToken

                    if (-not [string]::IsNullOrWhiteSpace($remoteVersionToken) -and $sourceVersionToken -ne $remoteVersionToken) {
                        Write-Log -Level Warn -Message (
                            "Skipping defaultRepairSource because source version [{0}] does not match remote host version [{1}] on [{2}]." -f
                            $sourceVersionToken,
                            $remoteVersionToken,
                            $targetComputer
                        )
                        $RepairSource = $null
                    }
                    else {
                        Write-Log -Level Info -Message (
                            "defaultRepairSource version check passed on [{0}] (source={1}, host={2})." -f
                            $targetComputer,
                            $sourceVersionToken,
                            ($(if ([string]::IsNullOrWhiteSpace($remoteVersionToken)) { 'unknown' } else { $remoteVersionToken }))
                        )
                    }
                }
            }

            $result = Invoke-RemoteWorker `
                -Session $session `
                -HelpersZip $pkg.ZipPath `
                -HelpersZipHash $pkg.ZipHash `
                -WorkerRemotePath $workerRemote `
                -WorkerLocalPath $workerLocal `
                -EntryPoint 'Invoke-SystemRepairCore' `
                -InformationAction Continue `
                -EntryParameters @{
                RestoreHealth                = $RestoreHealth
                StartComponentCleanup        = $StartComponentCleanup
                ResetBase                    = $ResetBase
                SfcScannow                   = $SfcScannow
                ResetUpdateComponents        = $ResetUpdateComponents
                RepairSource                 = $RepairSource
                RepairSourceIndex            = $RepairSourceIndex
                RetryWithoutSourceOnNotFound = $retryRestoreHealthWithoutSource
                LimitAccess                  = $LimitAccess
                OperationTimeoutMinutes      = $OperationTimeoutMinutes
                WaitPollSeconds              = $WaitPollSeconds
                WaitHeartbeatSeconds         = $WaitHeartbeatSeconds
            }
        }
        catch {
            $err = $_
            $msg = $err.Exception.Message
            $details = $err.ScriptStackTrace
            if ($details) {
                Write-Log -Level Error -Message ("Invoke-SystemRepair remote failed on {0}: {1}`n{2}" -f $targetComputer, $msg, $details)
            }
            else {
                Write-Log -Level Error -Message ("Invoke-SystemRepair remote failed on {0}: {1}" -f $targetComputer, $msg)
            }
            return
        }
        finally {
            if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
        }

        $failedOps = @()
        foreach ($name in @('RestoreHealthResult', 'StartComponentCleanup', 'ResetBaseResult', 'SfcResult', 'ResetWUResult')) {
            $op = $result.$name
            if ($null -ne $op -and ($op.PSObject.Properties.Name -contains 'Success') -and -not [bool]$op.Success) {
                $failedOps += $name
            }
        }

        if ($failedOps.Count -gt 0) {
            Write-Log -Level Warn -Message ("System repair finished on {0} with failures: {1}." -f $targetLabel, ($failedOps -join ', '))
        }
        else {
            Write-Log -Level Ok -Message ("System repair operations completed on {0}." -f $targetLabel)
        }
        return $result
    }
    else {
        $localParams = @{}
        if ($RestoreHealth) { $localParams.RestoreHealth = $true }
        if ($StartComponentCleanup) { $localParams.StartComponentCleanup = $true }
        if ($ResetBase) { $localParams.ResetBase = $true }
        if ($SfcScannow) { $localParams.SfcScannow = $true }
        if ($ResetUpdateComponents) { $localParams.ResetUpdateComponents = $true }
        if (-not [string]::IsNullOrWhiteSpace($RepairSource)) { $localParams.RepairSource = $RepairSource }
        $localParams.RepairSourceIndex = $RepairSourceIndex
        $localParams.RetryWithoutSourceOnNotFound = $retryRestoreHealthWithoutSource
        if ($LimitAccess) { $localParams.LimitAccess = $true }
        $localParams.OperationTimeoutMinutes = $OperationTimeoutMinutes
        $localParams.WaitPollSeconds = $WaitPollSeconds
        $localParams.WaitHeartbeatSeconds = $WaitHeartbeatSeconds

        $result = Invoke-SystemRepairLocal @localParams

        $failedOps = @()
        foreach ($name in @('RestoreHealthResult', 'StartComponentCleanup', 'ResetBaseResult', 'SfcResult', 'ResetWUResult')) {
            $op = $result.$name
            if ($null -ne $op -and ($op.PSObject.Properties.Name -contains 'Success') -and -not [bool]$op.Success) {
                $failedOps += $name
            }
        }

        if ($failedOps.Count -gt 0) {
            Write-Log -Level Warn -Message ("System repair finished on {0} with failures: {1}." -f $targetLabel, ($failedOps -join ', '))
        }
        else {
            Write-Log -Level Ok -Message ("System repair operations completed on {0}." -f $targetLabel)
        }
        return $result
    }
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCv9hZ7Kxakv51l
# K+NbN25rp1rGZ+xAacN/4ab8URcmC6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDw
# 9wM+fcS8072ZmbKWrB0job38zigwTZVHG39mMQAq4zANBgkqhkiG9w0BAQEFAASC
# AYCzOR9EUvzNLrft8Ml7ewUfpiWIP9rFp+4G2kqRWTLQ9JeeWcXYsqSzCQSwhbLR
# le2MUG0sm1NKHEiA1FjJmq9zrIzg+jBZNwquV0OeRFk+URU50vRnikpnXKpvoSDP
# va/t+o0WzzX49ncf0EzfgBiiYqZtBh28k7NFduOMNJkO/9IikUm2cuPZxbXINM4+
# lTVILzkVs1CvRcAQVaCyv/5DhQ9Ck1Q5vGEPsgfFIaFULD4kPPRVGNuv/l4mtnwo
# rC4XMUaXrYlufyXmyklHnmpqCw4fhK2wiH4ufa+ZGzRbQfirU1eo1rhxqKsrCLSt
# sy17C69ga90bfus2btdmLh4pRbzVHYMAOCW6fBkbk4kc2ESr0gsOqJSvHUrwcXZP
# 3nZAM6kEjAKv2I/8dlzrmOCxmiG34hbFcXxSwtfY/xmCG4zSR1dnAwr39s99Evkz
# FwnbbSg3FfZSyT8PdU5COWff45r9rASq/JDFJjjdO281wgFpaT3U7QAheZaSmiFl
# hQehggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDUzWjAvBgkqhkiG
# 9w0BCQQxIgQgDO22qbg/HxF9IBym3A5CXTkFLJGqPU5BdCa1IjdOaCgwDQYJKoZI
# hvcNAQEBBQAEggIAcbzrT9oBHW07Wl9WORcWj2fRb49P+32de/Fcgzos36CWKvbe
# v/hVR/i4sxsAjj6pmNYcA0Rbx7tM9A66Ezwg4xzvIkFQbELI8isbCj17saSPEgI+
# p7OHlB95hndY8WC8HkdZOB7Ls3iz/jRWaExvlWt1J8p+yibGQh6JQ/tbWbsUvO8+
# zKNdqWLtZpQuBidqF03h/XLWOf0QaLGgQLVxk3sdHklsNs60k64c6yCsSxidHTat
# FQwaZnVF1gmYyE1+g1REHDbhNmEjfMddMec5kGVWNcu9rip6/TOBSYxj0e0gOObP
# 33GegbGnivbaHrj0rynBpjLwuFu7neFLTZhhisc0Kjg3AQIkylF5LQ33BeEnmLvl
# KSxNwZTobrxoAWyCAqWF/BJ28CdqjpYsKzUnD0Ck1Y5igcix1IJxpxMawmqBY7Bh
# BsdZh6/WLugBXIKG9F7ifX7ZSFhBK1sQOjJNBGgSWV7kywCpj7JC8rTPDm+2g/uo
# rZD6w8POr+TI5tZWVw8VVFBhQ7fvrXmXtLPeLO7aurqy3JLFc2VDGr3iCO2p0AfJ
# eteFEN0P65A2Sx1l16tWw6kwNi/5VX00fGXW8wRr2TkiLEbOyi5iptAOo44bqS1/
# loQWmfxwDJliJ5bE5EarcE6yffP58a2xkfE7QgkIMNtOgrAxyjDSVO3naTw=
# SIG # End signature block
