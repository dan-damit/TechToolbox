function Get-ErrorEvents {
    <#
	.SYNOPSIS
	    Retrieves Critical and Error events from a local or remote event log.

	.DESCRIPTION
	    Queries a Windows event log for Level 1 (Critical) and Level 2 (Error)
	    records. Local targets run directly; remote targets use the toolbox
	    remoting helper through Start-NewPSRemoteSession.

	.PARAMETER LogName
	    The event log name to query, such as System, Application, or Security.

	.PARAMETER ComputerName
	    One or more computer names. Defaults to the local computer.

	.PARAMETER MaxEvents
	    Maximum number of events to return per target. Defaults to 100.

	.PARAMETER StartTime
	    Optional lower time bound for returned events.

    .PARAMETER EventId
        Optional event ID filter. When specified, only matching Critical and
        Error events are returned.

    .PARAMETER ExportPath
        Optional CSV export path. If a directory or path without an extension is
        provided, a timestamped CSV file is created in that location.

	.PARAMETER Credential
	    Credential used for remote session creation.

	.PARAMETER UseSsh
	    Use SSH transport instead of WSMan for remote execution.

	.PARAMETER UseCredSSP
	    Use CredSSP authentication for WSMan remoting.

	.PARAMETER Port
	    SSH port when -UseSsh is specified.

	.PARAMETER Ps7ConfigName
	    WSMan PowerShell 7 endpoint name.

	.PARAMETER WinPsConfigName
	    WSMan Windows PowerShell endpoint name.

	.PARAMETER UserName
	    SSH username when not using PSCredential.

	.PARAMETER KeyFilePath
	    SSH private key path when using key-based auth.

	.EXAMPLE
	    Get-ErrorEvents -LogName System

	    Returns the most recent 100 Critical and Error events from the local
	    System log.

	.EXAMPLE
	    Get-ErrorEvents -LogName Application -ComputerName SRV-01 -Credential $cred -MaxEvents 25

	    Returns the most recent 25 Critical and Error events from the
	    Application log on SRV-01.

    .EXAMPLE
        Get-ErrorEvents -LogName System -StartTime '2026-05-28T08:00:00' -MaxEvents 200
        Get-ErrorEvents -LogName System -StartTime (Get-Date).AddDays(-1) -MaxEvents 200

        Returns up to 200 Critical and Error events from the System log
        that were created on or after 2026-05-28 08:00:00.

    .EXAMPLE
        Get-ErrorEvents -LogName System -ComputerName SRV-01,SRV-02 -Export C:\Temp

        Returns matching events and exports the combined results to a
        timestamped CSV file under C:\Temp.

	.EXAMPLE
	    Get-ErrorEvents -LogName System -EventId 41, 6008 -MaxEvents 50

	    Returns up to 50 Critical and Error events from the System log where
	    the event ID is 41 or 6008.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-ErrorEvents
	#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrWhiteSpace()]
        [string]$LogName,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Name', 'CN')]
        [string[]]$ComputerName = $env:COMPUTERNAME,

        [ValidateRange(1, 5000)]
        [int]$MaxEvents = 100,

        [datetime]$StartTime,

        [Alias('Id')]
        [int[]]$EventId,

        [Alias('Export')]
        [string]$ExportPath,

        [pscredential]$Credential,

        [switch]$UseSsh,
        [switch]$UseCredSSP,

        [int]$Port = 22,

        [string]$Ps7ConfigName = 'PowerShell.7',
        [string]$WinPsConfigName = 'Microsoft.PowerShell',

        [string]$UserName,
        [string]$KeyFilePath
    )

    begin {
        Set-StrictMode -Version Latest
        Initialize-TechToolboxRuntime
        $allResults = New-Object System.Collections.Generic.List[object]
        $cfg = $script:cfg.settings.errorEvents

        function Test-IsLocalTarget {
            param([string]$Name)

            if ([string]::IsNullOrWhiteSpace($Name)) { return $true }

            $normalized = $Name.Trim().ToLowerInvariant()
            if ($normalized -in @('.', 'localhost', '127.0.0.1', '::1')) { return $true }

            $localName = $env:COMPUTERNAME.ToLowerInvariant()
            if ($normalized -eq $localName) { return $true }
            if ($normalized.StartsWith("$localName.")) { return $true }

            return $false
        }

        if (-not $PSBoundParameters.ContainsKey('ExportPath') -and
            $cfg -and
            -not [string]::IsNullOrWhiteSpace($cfg.exportPath)) {
            $ExportPath = [string]$cfg.exportPath
        }

        $hasStartTime = $PSBoundParameters.ContainsKey('StartTime')
        $hasEventId = $PSBoundParameters.ContainsKey('EventId') -and $null -ne $EventId -and $EventId.Count -gt 0
        $shouldExport = $PSBoundParameters.ContainsKey('ExportPath') -and -not [string]::IsNullOrWhiteSpace($ExportPath)

        if (-not $shouldExport -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {
            $shouldExport = $true
        }

        $resolvedExportPath = $null

        function Resolve-ErrorEventsExportPath {
            param(
                [Parameter(Mandatory)]
                [string]$Path,

                [Parameter(Mandatory)]
                [string]$TargetLogName
            )

            $expandedPath = [Environment]::ExpandEnvironmentVariables($Path)
            $isDirectory = $false

            if (Test-Path -LiteralPath $expandedPath -PathType Container) {
                $isDirectory = $true
            }
            elseif ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($expandedPath))) {
                $isDirectory = $true
            }

            if ($isDirectory) {
                $directoryPath = $expandedPath

                if ([System.IO.Path]::GetFileName($directoryPath) -ne 'ErrorEvents') {
                    $directoryPath = Join-Path -Path $directoryPath -ChildPath 'ErrorEvents'
                }

                $hostFolderName = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '_')
                if ([string]::IsNullOrWhiteSpace($hostFolderName)) {
                    $hostFolderName = 'UnknownHost'
                }

                $directoryPath = Join-Path -Path $directoryPath -ChildPath $hostFolderName

                if (-not (Test-Path -LiteralPath $directoryPath)) {
                    New-Item -Path $directoryPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }

                $safeLogName = ($TargetLogName -replace '[^A-Za-z0-9._-]', '_')
                $fileName = 'ErrorEvents_{0}_{1}.csv' -f $safeLogName, (Get-Date -Format 'yyyyMMdd-HHmmss')
                return Join-Path $directoryPath $fileName
            }

            $parent = Split-Path -Path $expandedPath -Parent
            if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
                New-Item -Path $parent -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            return $expandedPath
        }

        if ($shouldExport) {
            $resolvedExportPath = Resolve-ErrorEventsExportPath -Path $ExportPath -TargetLogName $LogName
        }

        $queryScript = {
            param(
                [string]$TargetLogName,
                [int]$TargetMaxEvents,
                [object]$TargetStartTime,
                [bool]$HasStartTime,
                [int[]]$TargetEventId,
                [bool]$HasEventId
            )

            $filter = @{
                LogName = $TargetLogName
                Level   = @(1, 2)
            }

            if ($HasStartTime) {
                $filter.StartTime = $TargetStartTime
            }

            if ($HasEventId) {
                $filter.Id = $TargetEventId
            }

            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $TargetMaxEvents -ErrorAction Stop

            foreach ($eventRecord in $events) {
                [pscustomobject]@{
                    ComputerName    = $env:COMPUTERNAME
                    LogName         = $eventRecord.LogName
                    TimeCreated     = $eventRecord.TimeCreated
                    Id              = $eventRecord.Id
                    Level           = $eventRecord.Level
                    LevelDisplay    = $eventRecord.LevelDisplayName
                    ProviderName    = $eventRecord.ProviderName
                    MachineName     = $eventRecord.MachineName
                    RecordId        = $eventRecord.RecordId
                    TaskDisplay     = $eventRecord.TaskDisplayName
                    OpcodeDisplay   = $eventRecord.OpcodeDisplayName
                    KeywordsDisplay = (($eventRecord.KeywordsDisplayNames | Where-Object { $_ }) -join '; ')
                    Message         = $eventRecord.Message
                }
            }
        }

        $queryScriptSource = $queryScript.ToString()
    }

    process {
        foreach ($targetComputer in $ComputerName) {
            if (Test-IsLocalTarget -Name $targetComputer) {
                Write-Log -Level Info -Message ("Querying {0} log on the local computer." -f $LogName)

                try {
                    $targetResults = & $queryScript -TargetLogName $LogName -TargetMaxEvents $MaxEvents -TargetStartTime $StartTime -HasStartTime $hasStartTime -TargetEventId $EventId -HasEventId $hasEventId
                    if ($targetResults) {
                        [void]$allResults.AddRange([object[]]$targetResults)
                        $targetResults
                    }
                }
                catch {
                    $message = "Get-ErrorEvents: local query failed for log '{0}': {1}" -f $LogName, $_.Exception.Message
                    Write-Error -Message $message
                }

                continue
            }

            Write-Log -Level Info -Message ("[{0}] Querying {1} log via PowerShell remoting." -f $targetComputer, $LogName)

            $session = $null
            try {
                $sessionParams = @{
                    ComputerName    = $targetComputer
                    Credential      = $Credential
                    UseSsh          = $UseSsh
                    UseCredSSP      = $UseCredSSP
                    Port            = $Port
                    Ps7ConfigName   = $Ps7ConfigName
                    WinPsConfigName = $WinPsConfigName
                }

                if ($PSBoundParameters.ContainsKey('UserName')) {
                    $sessionParams.UserName = $UserName
                }

                if ($PSBoundParameters.ContainsKey('KeyFilePath')) {
                    $sessionParams.KeyFilePath = $KeyFilePath
                }

                $session = Start-NewPSRemoteSession @sessionParams

                $targetResults = Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $LogName, $MaxEvents, $StartTime, $hasStartTime, $EventId, $hasEventId, $queryScriptSource -ScriptBlock {
                    param(
                        [string]$TargetLogName,
                        [int]$TargetMaxEvents,
                        [object]$TargetStartTime,
                        [bool]$HasStartTime,
                        [int[]]$TargetEventId,
                        [bool]$HasEventId,
                        [string]$RemoteQueryScriptSource
                    )

                    $remoteQueryScript = [ScriptBlock]::Create($RemoteQueryScriptSource)

                    & $RemoteQueryScript -TargetLogName $TargetLogName -TargetMaxEvents $TargetMaxEvents -TargetStartTime $TargetStartTime -HasStartTime $HasStartTime -TargetEventId $TargetEventId -HasEventId $HasEventId
                }

                if ($targetResults) {
                    [void]$allResults.AddRange([object[]]$targetResults)
                    $targetResults
                }
            }
            catch {
                $message = "Get-ErrorEvents: remote query failed on {0} for log '{1}': {2}" -f $targetComputer, $LogName, $_.Exception.Message
                Write-Error -Message $message
            }
            finally {
                if ($session) {
                    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
                }
            }
        }
    }

    end {
        if (-not $shouldExport) {
            return
        }

        if ($allResults.Count -eq 0) {
            Write-Log -Level Warn -Message 'Get-ErrorEvents: no results were returned, skipping CSV export.'
            return
        }

        try {
            $allResults | Export-Csv -Path $resolvedExportPath -NoTypeInformation -Encoding UTF8 -Force
            Write-Log -Level Ok -Message ("Exported {0} event(s) to {1}" -f $allResults.Count, $resolvedExportPath)
        }
        catch {
            Write-Error -Message ("Get-ErrorEvents: failed to export results to '{0}': {1}" -f $resolvedExportPath, $_.Exception.Message)
        }
    }
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBuwVeAi4RS7xHk
# IkuYVQd9NPvWCmB1nrqS+RDYhVjzYKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB+SCC3kEY7
# 6U9jomfFkIVbxJor6BxmrzHWGGNqayXymDANBgkqhkiG9w0BAQEFAASCAgALHgJf
# bxjbJDJQegtkDPGAjHC2lpkWr5SMEbr/8LusYQQ7JBZcwTKc50mYOzQBD7wZQois
# Bq/L1+mMO9NfTjReeciKu+rcjI20eGc7wSkCKP3dxdTj8o5LGbk1Mh4OyB7gXNCl
# fCnQoeQPjjSIdrRosYhi/7+ZQ9M9F5dySayNwNJ6x9ycJsqvim8RRpPrKwFTY4i7
# 8NiMWhlG3b237RCR8vM1C7xkQaZlAmhirgC+vPgDoF3u9ASGXb4DMXSQMrXxCiGf
# LFkLZIKUijXvliAyXlMC79YyjBPxziQGoXzTphrsKYr37rRuF/W5J1sBRSZCEa5Q
# 2ca8DHoKsYaejs6zpL2iQ6KMgevMQ/1/PyPnw0CClNc/C+mEHfLoULHZ0tGhmA0f
# 1wYGv61/jKjWvWb5WCI1X+ududC3tosGDPFxyED70of8S7r/5ezIjhi5/1Tn9dTb
# BhA2lgY2RG+kItSfbHuYvaxzH2d/vah/KGpbffTN2XQHSTpCb8NQw8PdU45wTUTL
# 3UswA7AjJW5X2BsHwprVzwb7KNB9HxIrOfNSzQV0xkMcalZfrxkLPhDqfXFe/CvX
# XVxg2INUYf6M2q6ZrKG5259mUJ+6v5sKJEUtU+k6Pr/I4ko2ypHL6B093paI7NMp
# RbTrSbXzTTlPnYrfP4+6/XCW1kAVUMLJfScVqaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MDEwMzEzNTdaMC8GCSqGSIb3DQEJBDEiBCAtZAP7mFqmcjmxxZs4
# zZ344vFc6u+lXsH/MXzpYiX/pjANBgkqhkiG9w0BAQEFAASCAgBU3uEqTPv1lT1w
# 9i9NI3JE+RRsEZqVDRq/7egl4AowBlwVbkJX8u7T4GCC4yfZuPl8mafvtc1uOXQb
# JS6UNROoKhDJE4fqBvnkhrGZ1qeus6mW+FZKuzex4WGvYyN2ooIJGckBhGsdhwLG
# VdiK/mT2W+s8JHv650ilSeZ8C7dKmlhdVwvIqnkIOKUTJlXKXLiAnipofUr7wPm5
# U9hNQVI/oNtz7gOWLVkuk0+FIeexTGen/ufFrO5DfthG+OREX7r4jh/CKkbYAlje
# VhQPHcIDHtZHfWD3bj6QVMHpmyOAM7UEkyWm4Alee5AVOcM2VFlsRpktRwvC+khM
# ovW+Y4V8Eczgu25xo30DCTgvGbZflpP5y1XDdnxRACJCUHIzxvQuyICH5tUm9DLq
# DJGO8PUAp7XpCC13DJVOJ84nSc3yq5JvZPfrxGmy9CaN6N8HWwkGEbWT/rPGCNy1
# BYkNoLcFFMGZK1G+mIWxu+mqAhDlna7/Ss5abEU+QUi0O4hI+Kbw/yDmX59r1c98
# ycZQ6+awR1zhUpBIQAQ9Qbbdkh/+AIRxD7AcYPzD86DEOKtURJf2pwpeIs6u0wFL
# +WdrjFUvmGi72m2zQlzvKhKetdA+dDrozwITGIgahQmnN1NwiYOTMvwzaLXfbgAS
# 9uMTDDUDaW3GxYBXGnnh3Dprf10fnA==
# SIG # End signature block
