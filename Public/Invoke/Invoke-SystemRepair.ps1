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
    When set, DISM does not contact Windows Update and uses only local source content.
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
                ReleaseId = $releaseId
                ProductName = $productName
                VersionToken = if ($tokenMatch.Success) { $tokenMatch.Value.ToUpperInvariant() } else { $null }
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
                RestoreHealth           = $RestoreHealth
                StartComponentCleanup   = $StartComponentCleanup
                ResetBase               = $ResetBase
                SfcScannow              = $SfcScannow
                ResetUpdateComponents   = $ResetUpdateComponents
                RepairSource            = $RepairSource
                RepairSourceIndex       = $RepairSourceIndex
                RetryWithoutSourceOnNotFound = $retryRestoreHealthWithoutSource
                LimitAccess             = $LimitAccess
                OperationTimeoutMinutes = $OperationTimeoutMinutes
                WaitPollSeconds         = $WaitPollSeconds
                WaitHeartbeatSeconds    = $WaitHeartbeatSeconds
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
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCS+8fr9OwTW7cm
# bPFDMAlN6WfFlrxLbTXLpuYDJ9/SDaCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDyvaH3/ap+
# mYuGhBcxAiZawumXq4cp5KlwelLoResS/TANBgkqhkiG9w0BAQEFAASCAgA3+WAj
# Z/nDvtwgwPycUfNhF3Ym+z7t64wJuzSJB2/Ll813cpBT+KT0vjWbluo/sUUj8rJ+
# AWjUOI6a+ILuG1ukRAIt11/EwYXxqOC0ZD/oToCfMJBttmX5Jr4oi+zXnlMZNRzA
# VFXnN3uopYeQajEjeG/dHrxwa+TJSxpz4t9AkQyH4dqP76EukOTzL3HUvF++Vgjh
# IF2AeZj/Fj5ynZoiS3FTNRo2XrIPl3HOes7pjTDx/HYIm39qGRcxXgeZtdB66uwF
# 2W/bB+hZV/+FJx4M4a+1Qxkn9DLIG+Gjwh2W1SUfgpHAkalRrQU7/WnolvxNyvRl
# UsivR4hC+8yc3ReTxXg61FZZgcYb5YZnL83+JjS+xn6aCS5zSEGHEUC7GKGsLtm+
# msS6xI4BKuRKkoJzjPs+0iIumiHsYJEUiACCcn4N13Vfe7O8ESgBP08Tt3utkt2n
# +UUvn/xp3eiDZpMEL002+bAgdaWA4H7erUIVfJvWoFhEzzU6GVcOj6ikhdIhoR+Y
# NQo+BiHxGrmadx/e1sT5QgAnXZ+tp/vWQtZZeyqQpB8tWMezQ7mjVHSZu8IPc+ph
# aukdFEo7YFFyQxWmbgJCUIPl+bGzfEYSsYpAJJmQcPvbUE9QPo/LgDckda30pCA5
# XPX5aGfPiw2g/Ne5oxXGirER19cqilWvAGk996GCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA2MDExMzQxMThaMC8GCSqGSIb3DQEJBDEiBCB33Bw5d8Av0Yo0tbbR
# VwzeSQt8jZTPXAogqNEEUB9ZVDANBgkqhkiG9w0BAQEFAASCAgCh3rDiTrxWrw1I
# saT58oFxp5OKRKRhi6A0VYpMliUTC2BrxdEbRBsBMlN3h88/Nr4CBGpoImZ2EmDS
# 6XLAYIKpOXb2VOTMY3UqdshGgYwRDBK7uPMsnYpLZxK7lj8whNP/GaGgituypPqV
# dJniMplqBqLKOlCyBN0RwwBPc3v9e1SPoIFDlYuh9MOqG17cBf7AXoN90n41X3/r
# CRMIpTHI82Db6vUScqquuvtqBAhCWQBZV2RqqPYgDc448kMlicyGTdyNfDKmPE/X
# eQeQk17RyquFOvWr/c3u0c+NN1zwgs0yflbzKzeGmj4xZi2ww+dEcgsuRfwwB5Tt
# E9B1UiISH+98aPPDXWBBEyxDR1UobkoygOrUZCoZmdLBSKdFkqnZYJoy0v/pVz9Q
# rl1VcncS/6TfbXLmiATnmA5Yp7QhD1FMCUdcgiEUuWc2RkGXlICa6isVrcts7n0p
# Fp799WwhsAp6Bk26vfhKoaEfiGfY3s4w3kQqhB8v11KgjyehQT7nKyXbIeN6SH3s
# qXZsw2ghHzb1IobnsHmxoDbep9hGTvMAHc/qwxGHkvOedjKZxw3lkX8F3N2dMhgG
# nPDmbtEr4oTGXXr7Mj1GqdwWmEnr8er2TLzx9x9TRsl/jXVH7DL89dCrwhrGuPTg
# 06FWEqC4R2VYCV+s0MwGfXr45Uv4dA==
# SIG # End signature block
