function Invoke-SystemRepairCore {
    [CmdletBinding()]
    param(
        [switch]$RestoreHealth,
        [switch]$StartComponentCleanup,
        [switch]$ResetBase,
        [switch]$SfcScannow,
        [switch]$ResetUpdateComponents,
        [string]$RepairSource,
        [ValidateRange(1, 999)]
        [int]$RepairSourceIndex = 1,
        [bool]$RetryWithoutSourceOnNotFound = $false,
        [switch]$LimitAccess,
        [ValidateRange(1, 480)]
        [int]$OperationTimeoutMinutes = 60,
        [ValidateRange(1, 300)]
        [int]$WaitPollSeconds = 5,
        [ValidateRange(0, 3600)]
        [int]$WaitHeartbeatSeconds = 300
    )

    function Test-IsAdmin {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = [Security.Principal.WindowsPrincipal]$id
        $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = Test-IsAdmin
    $isSystem = $currentIdentity.Name -eq 'NT AUTHORITY\SYSTEM'
    $effectiveRepairSource = $null

    $system32 = Join-Path $env:SystemRoot 'System32'

    $results = [ordered]@{
        ComputerName          = $env:COMPUTERNAME
        RunContext            = [pscustomobject]@{
            UserName = $currentIdentity.Name
            IsAdmin  = $isAdmin
            IsSystem = $isSystem
        }
        RepairSource          = $RepairSource
        RepairSourceIndex     = $RepairSourceIndex
        EffectiveRepairSource = $null
        RestoreHealthSourceResult = $null
        RestoreHealthFallbackResult = $null
        RestoreHealthFallbackUsed = $false
        LimitAccess           = [bool]$LimitAccess
        RestoreHealthResult   = $null
        StartComponentCleanup = $null
        ResetBaseResult       = $null
        SfcResult             = $null
        ResetWUResult         = $null
    }

    function New-AdminRequiredResult {
        param([Parameter(Mandatory)][string]$Operation)

        [pscustomobject]@{
            Success  = $false
            ExitCode = 740
            Message  = "{0} requires an elevated token on the remote host. Current identity: {1} (IsAdmin={2}, IsSystem={3})." -f $Operation, $currentIdentity.Name, $isAdmin, $isSystem
        }
    }

    function Start-TTExe {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$FilePath,
            [string[]]$Arguments = @()
        )

        if (-not (Test-Path -LiteralPath $FilePath)) {
            throw "Start-TTExe: File not found: $FilePath"
        }

        $argLine = ($Arguments -join ' ')

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        $psi.Arguments = $argLine
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $false
        $psi.RedirectStandardError = $false

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $null = $proc.Start()

        [pscustomobject]@{
            Process   = $proc
            FilePath  = $FilePath
            Arguments = $Arguments
            StartedAt = Get-Date
        }
    }

    function Invoke-RepairWithWait {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)][string]$Label,
            [Parameter(Mandatory)][scriptblock]$StartScript,
            [int]$TimeoutMinutes = 60
        )

        $opStartedAt = Get-Date
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        Write-Log -Level Info -Message "$Label started..."

        $job = & $StartScript
        if (-not $job -or -not $job.Process) {
            throw "$Label failed to start process."
        }

        $proc = $job.Process
        $deadline = $opStartedAt.AddMinutes($TimeoutMinutes)
        $state = [pscustomobject]@{
            TimedOut       = $false
            LastHeartbeatAt = $opStartedAt
        }

        Write-Information ("[{0}] started..." -f $Label) -InformationAction Continue

        $poll = {
            if (-not $proc.HasExited) {
                if ((Get-Date) -ge $deadline) {
                    $state.TimedOut = $true
                    try { $proc.Kill() } catch {}
                    return @{ Status = 'Timeout' }
                }

                $now = Get-Date
                if ($WaitHeartbeatSeconds -gt 0 -and $now -ge $state.LastHeartbeatAt.AddSeconds($WaitHeartbeatSeconds)) {
                    Write-Information ("[{0}] still running..." -f $Label) -InformationAction Continue
                    $state.LastHeartbeatAt = $now
                }

                return @{ Status = 'Running' }
            }

            return @{ Status = 'Done'; Code = $proc.ExitCode }
        }

        $getStatus = {
            param($obj)
            switch ($obj.Status) {
                'Timeout' { return 'Timeout' }
                'Done' {
                    if ($obj.Code -eq 0) { return 'Success' }
                    return 'Error'
                }
                default { return 'Running' }
            }
        }

        function Get-DismLogTail {
            param([int]$Lines = 60)

            $dismLog = Join-Path $env:WINDIR 'Logs\DISM\dism.log'
            if (-not (Test-Path -LiteralPath $dismLog)) {
                return $null
            }

            try {
                return (Get-Content -LiteralPath $dismLog -Tail $Lines -ErrorAction Stop) -join [Environment]::NewLine
            }
            catch {
                return "Failed to read DISM log tail from ${dismLog}: $($_.Exception.Message)"
            }
        }

        $terminal = @{
            'Success' = @{ Level = 'Ok'; Message = "$Label completed successfully."; Return = $true }
            'Error'   = @{ Level = 'Warn'; Message = { param($obj, $status) "{0} failed (exit code {1})." -f $Label, $obj.Code }; Return = $true }
            'Timeout' = @{ Level = 'Warn'; Message = "$Label timed out."; Return = $true }
        }

        $final = Wait-TerminalState `
            -Target $Label `
            -PollScript $poll `
            -GetStatus $getStatus `
            -TerminalStates $terminal `
            -TimeoutSeconds ($TimeoutMinutes * 60) `
            -PollSeconds $WaitPollSeconds `
            -HeartbeatSeconds $WaitHeartbeatSeconds `
            -OnStatusChange {
                param($obj, $status, $lastStatus)

                if ($status -ne $lastStatus) {
                    Write-Information ("[{0}] status: {1}" -f $Label, $status) -InformationAction Continue
                }
            }

        $sw.Stop()
        $opCompletedAt = Get-Date

        $exitCode = if ($state.TimedOut) { -1 } else { [int]$final.Code }
        $status = if ($state.TimedOut) { 'Timeout' } elseif ($exitCode -eq 0) { 'Success' } else { 'Error' }

        $message = switch ($status) {
            'Success' { "$Label completed successfully." }
            'Timeout' { "$Label timed out after $TimeoutMinutes minutes." }
            default { "$Label failed with exit code $exitCode." }
        }

        $diagnosticTail = $null
        if ($status -eq 'Error' -and $Label -like 'DISM*') {
            $diagnosticTail = Get-DismLogTail
        }

        [pscustomobject]@{
            Label           = $Label
            StartedAt       = $opStartedAt
            CompletedAt     = $opCompletedAt
            DurationSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            Status          = $status
            ExitCode        = $exitCode
            TimedOut        = $state.TimedOut
            Success         = (-not $state.TimedOut -and $exitCode -eq 0)
            Message         = $message
            DiagnosticTail  = $diagnosticTail
        }
    }

    function Invoke-Dism {
        param([string[]]$DismArgs)
        Start-TTExe -FilePath (Join-Path $system32 'dism.exe') -Arguments $DismArgs
    }

    function Get-DismRestoreHealthArgs {
        $args = @('/online', '/cleanup-image', '/restorehealth')

        function Get-EditionHintTokens {
            $tokens = New-Object System.Collections.Generic.List[string]

            try {
                $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            }
            catch {
                return @()
            }

            $editionId = [string]$cv.EditionID
            $productName = [string]$cv.ProductName

            if (-not [string]::IsNullOrWhiteSpace($editionId)) {
                $editionLower = $editionId.ToLowerInvariant()
                $tokens.Add($editionLower) | Out-Null

                switch ($editionLower) {
                    'professional' {
                        $tokens.Add('pro') | Out-Null
                        $tokens.Add('professional') | Out-Null
                    }
                    'core' {
                        $tokens.Add('core') | Out-Null
                        $tokens.Add('home') | Out-Null
                    }
                    'coresinglelanguage' {
                        $tokens.Add('single language') | Out-Null
                        $tokens.Add('core single language') | Out-Null
                    }
                    'enterprise' { $tokens.Add('enterprise') | Out-Null }
                    'education' { $tokens.Add('education') | Out-Null }
                    'serverstandard' { $tokens.Add('standard') | Out-Null }
                    'serverdatacenter' { $tokens.Add('datacenter') | Out-Null }
                }
            }

            if (-not [string]::IsNullOrWhiteSpace($productName)) {
                $ignore = @('microsoft', 'windows', 'server', 'home', 'edition', 'operating', 'system', '11', '10')
                foreach ($word in ($productName.ToLowerInvariant() -split '[^a-z0-9]+')) {
                    if ([string]::IsNullOrWhiteSpace($word)) { continue }
                    if ($ignore -contains $word) { continue }
                    if ($word.Length -lt 3) { continue }
                    $tokens.Add($word) | Out-Null
                }
            }

            return @($tokens | Select-Object -Unique)
        }

        function Get-BestImageIndexForCurrentOS {
            param([Parameter(Mandatory)][string]$ImagePath)

            $dismExe = Join-Path $system32 'dism.exe'
            if (-not (Test-Path -LiteralPath $dismExe)) {
                return $null
            }

            $output = & $dismExe '/English' '/Get-WimInfo' "/WimFile:$ImagePath" 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) {
                return $null
            }

            $images = @()
            $current = $null

            foreach ($line in @($output -split "`r?`n")) {
                if ($line -match '^\s*Index\s*:\s*(\d+)\s*$') {
                    if ($current) {
                        $images += [pscustomobject]$current
                    }

                    $current = [ordered]@{
                        Index       = [int]$Matches[1]
                        Name        = ''
                        Description = ''
                    }
                    continue
                }

                if (-not $current) { continue }

                if ($line -match '^\s*Name\s*:\s*(.+?)\s*$') {
                    $current.Name = $Matches[1]
                    continue
                }

                if ($line -match '^\s*Description\s*:\s*(.+?)\s*$') {
                    $current.Description = $Matches[1]
                    continue
                }
            }

            if ($current) {
                $images += [pscustomobject]$current
            }

            if (-not $images -or $images.Count -eq 0) {
                return $null
            }

            $tokens = Get-EditionHintTokens
            if (-not $tokens -or $tokens.Count -eq 0) {
                return $null
            }

            $ranked = foreach ($img in $images) {
                $text = ("{0} {1}" -f $img.Name, $img.Description).ToLowerInvariant()
                $score = 0

                foreach ($token in $tokens) {
                    $escaped = [regex]::Escape($token)
                    if ($text -match "(^|[^a-z0-9])${escaped}([^a-z0-9]|$)") {
                        $score += 2
                    }
                    elseif ($text.Contains($token)) {
                        $score += 1
                    }
                }

                [pscustomobject]@{
                    Index = [int]$img.Index
                    Score = [int]$score
                }
            }

            $best = $ranked | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'Index'; Descending = $false } | Select-Object -First 1
            if (-not $best -or $best.Score -le 0) {
                return $null
            }

            return [int]$best.Index
        }

        function Resolve-DismSourceValue {
            param(
                [Parameter(Mandatory)][string]$Source,
                [int]$DefaultIndex = 1
            )

            $trimmed = $Source.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { return $trimmed }

            if ($trimmed -match '^(?i)(wim|esd):') {
                return $trimmed
            }

            if ($trimmed -match '(?i)\.(wim|esd)(:\d+)?$') {
                $kind = $Matches[1].ToLowerInvariant()

                if ($trimmed -match '(?i):\d+$') {
                    return "${kind}:$trimmed"
                }

                $detectedIndex = Get-BestImageIndexForCurrentOS -ImagePath $trimmed
                if ($detectedIndex) {
                    return "${kind}:${trimmed}:$detectedIndex"
                }

                return "${kind}:${trimmed}:$DefaultIndex"
            }

            return $trimmed
        }

        if (-not [string]::IsNullOrWhiteSpace($RepairSource)) {
            $sourceValue = Resolve-DismSourceValue -Source $RepairSource -DefaultIndex $RepairSourceIndex
            $effectiveRepairSource = $sourceValue
            $args += "/Source:$sourceValue"
            if ($LimitAccess) {
                $args += '/LimitAccess'
            }
        }
        elseif ($LimitAccess) {
            Write-Log -Level Warn -Message 'LimitAccess was requested without RepairSource. DISM may fail if local payload is unavailable.'
            $args += '/LimitAccess'
        }

        return $args
    }

    function Test-ShouldRetryRestoreHealthWithoutSource {
        param([Parameter(Mandatory)][object]$Result)

        if (-not $RetryWithoutSourceOnNotFound) {
            return $false
        }

        if ([string]::IsNullOrWhiteSpace($RepairSource)) {
            return $false
        }

        if ($LimitAccess) {
            return $false
        }

        if ($null -eq $Result) {
            return $false
        }

        return ((-not [bool]$Result.Success) -and ([int]$Result.ExitCode -eq -2146498283))
    }

    function Invoke-Sfc {
        Start-TTExe -FilePath (Join-Path $system32 'sfc.exe') -Arguments @('/scannow')
    }

    if ($RestoreHealth) {
        if (-not $isAdmin) {
            $results.RestoreHealthResult = New-AdminRequiredResult -Operation 'DISM /RestoreHealth'
        }
        else {
            try {
                $dismArgs = Get-DismRestoreHealthArgs
                $sourceAttempt = Invoke-RepairWithWait `
                    -Label "DISM /RestoreHealth" `
                    -StartScript { Invoke-Dism $dismArgs } `
                    -TimeoutMinutes $OperationTimeoutMinutes

                $results.RestoreHealthResult = $sourceAttempt
                if (-not [string]::IsNullOrWhiteSpace($RepairSource)) {
                    $results.RestoreHealthSourceResult = $sourceAttempt
                }

                if (Test-ShouldRetryRestoreHealthWithoutSource -Result $sourceAttempt) {
                    Write-Log -Level Warn -Message ("DISM /RestoreHealth source attempt failed with exit code {0}; retrying without /Source so CBS can use default repair sources." -f $sourceAttempt.ExitCode)

                    $fallbackAttempt = Invoke-RepairWithWait `
                        -Label "DISM /RestoreHealth (fallback without source)" `
                        -StartScript { Invoke-Dism @('/online', '/cleanup-image', '/restorehealth') } `
                        -TimeoutMinutes $OperationTimeoutMinutes

                    $results.RestoreHealthFallbackUsed = $true
                    $results.RestoreHealthFallbackResult = $fallbackAttempt
                    $results.RestoreHealthResult = $fallbackAttempt
                    $initialEffectiveRepairSource = if (-not [string]::IsNullOrWhiteSpace($effectiveRepairSource)) { $effectiveRepairSource } else { $RepairSource }
                    $effectiveRepairSource = $null

                    $results.RestoreHealthResult | Add-Member -Force NoteProperty FallbackAttempted $true
                    $results.RestoreHealthResult | Add-Member -Force NoteProperty InitialSourceExitCode $sourceAttempt.ExitCode
                    $results.RestoreHealthResult | Add-Member -Force NoteProperty InitialEffectiveRepairSource $initialEffectiveRepairSource

                    if ($fallbackAttempt.Success) {
                        $results.RestoreHealthResult.Message = "DISM /RestoreHealth succeeded on retry without /Source after source-based attempt failed."
                    }
                    else {
                        $results.RestoreHealthResult.Message = "DISM /RestoreHealth retry without /Source also failed after source-based attempt failed."
                    }
                }
            }
            catch {
                $results.RestoreHealthResult = [pscustomobject]@{ Success = $false; ExitCode = 1; Message = $_.Exception.Message }
            }
        }
    }

    if ($StartComponentCleanup) {
        if (-not $isAdmin) {
            $results.StartComponentCleanup = New-AdminRequiredResult -Operation 'DISM /StartComponentCleanup'
        }
        else {
            try {
                $results.StartComponentCleanup = Invoke-RepairWithWait `
                    -Label "DISM /StartComponentCleanup" `
                    -StartScript { Invoke-Dism @("/online", "/cleanup-image", "/startcomponentcleanup") } `
                    -TimeoutMinutes $OperationTimeoutMinutes
            }
            catch {
                $results.StartComponentCleanup = [pscustomobject]@{ Success = $false; ExitCode = 1; Message = $_.Exception.Message }
            }
        }
    }

    if ($ResetBase) {
        if (-not $isAdmin) {
            $results.ResetBaseResult = New-AdminRequiredResult -Operation 'DISM /ResetBase'
        }
        else {
            try {
                $results.ResetBaseResult = Invoke-RepairWithWait `
                    -Label "DISM /ResetBase" `
                    -StartScript { Invoke-Dism @("/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase") } `
                    -TimeoutMinutes $OperationTimeoutMinutes
            }
            catch {
                $results.ResetBaseResult = [pscustomobject]@{ Success = $false; ExitCode = 1; Message = $_.Exception.Message }
            }
        }
    }

    if ($SfcScannow) {
        if (-not $isAdmin) {
            $results.SfcResult = New-AdminRequiredResult -Operation 'SFC /scannow'
        }
        else {
            try {
                $results.SfcResult = Invoke-RepairWithWait `
                    -Label "SFC /scannow" `
                    -StartScript { Invoke-Sfc } `
                    -TimeoutMinutes $OperationTimeoutMinutes
            }
            catch {
                $results.SfcResult = [pscustomobject]@{ Success = $false; ExitCode = 1; Message = $_.Exception.Message }
            }
        }
    }

    if ($ResetUpdateComponents) {
        if (-not $isAdmin) {
            $results.ResetWUResult = New-AdminRequiredResult -Operation 'Reset Windows Update Components'
        }
        else {
            try {
                if (Get-Command Reset-WindowsUpdateComponents -ErrorAction SilentlyContinue) {
                    $results.ResetWUResult = Reset-WindowsUpdateComponents -ShowProgress
                }
                else {
                    $results.ResetWUResult = [pscustomobject]@{
                        Success = $false
                        Message = "Reset-WindowsUpdateComponents not available on remote host."
                    }
                }
            }
            catch {
                $results.ResetWUResult = [pscustomobject]@{
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        }
    }

    if ($results.RestoreHealthFallbackUsed) {
        $results.EffectiveRepairSource = '[default online repair sources]'
    }
    else {
        $results.EffectiveRepairSource = if (-not [string]::IsNullOrWhiteSpace($effectiveRepairSource)) { $effectiveRepairSource } else { $RepairSource }
    }

    [pscustomobject]$results
}

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALLIUw4s+maUK5
# ENQIrgJwt+TwconZ/vQmADMZhhFiWKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDzNF/JqneG
# OQxXksIT4uO01k9CcnKrXCLsQE21pq2xZTANBgkqhkiG9w0BAQEFAASCAgAcTvQ6
# 3hXeCTQLvByebrt6ngNxtenCOPIall24wI+o9bhfP1nd61IV1z3pZccbQQw5MNli
# yg9XV9RJHeyfnKtIdvjkkGX1F2FxQaLxp8Xun0SejO7tZND/IoQjD6xjGXiqOZzf
# gNi+TwU3APUkPo9CLTuvXZaBVv6A800yOX127Q1p7+GJzpAx/vDF9nr5mFfpmm9m
# CWnfiG8t6nztfxcQbw9eWluPQU0+zqD4WaX7a+Jd2kJ8VZqv64y64MT4RnvkZMmE
# SSx+8OX2iY9cqdtugOVWBs/7vpXhhTtvjHlniT501Cmo2fCQlPUUYfbtdvPmapzD
# kM2QS0aPnvR+w9XPqLQeoysHFBBUmgjVrgGLyKe8ZTr+nfu+vu21QYbZJURy8EJA
# h0CeYqtUEOQOgVLNDc2K1aeFsiVHZKMZPX1rWCr3U7sdr0EMfhaCl7D8+CbDjOD5
# h2guV2e2Xv3mSqSt0ZZBoa6qsMtBlXjb4aeE8vrCZWVluQODpp7JodA/jgl6vFa+
# atJF2OfQMBWlA0g9zaj5n/qsZELEHoRKEf9K2jEA/Ls2PV/XC4xEx+uazpnFXQ7v
# OcfXkXo8EMyw+pvm8P45Z6Pykcsqhr9yzi9Xg9FArDEg6E0UUINbt1K959d2k3Mk
# Xe8I9a1egAE0KInXZQnzFQoEOvHXp/GI65Yc1qGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MjIxOTQ3MTBaMC8GCSqGSIb3DQEJBDEiBCADvnta7DC1Bl7LLBHl
# jJLIZVGQZR0BbLlDMzY5SKq+fTANBgkqhkiG9w0BAQEFAASCAgCRAVjmyzfDTe+F
# AzfjyxvelWO4RGdnMGtLdKc5Mbdmt4bp9ufN9shoz7fY7ZyPT5/dBjTZMEo8+nxI
# 99VgXfijn9ltHjL7Ebp8/e/kcdu4YPuy6C3xmkd+IbAUSj7Fx/Z2ma/FaNgwqOzB
# 132rePAj+TltiEx36wb8qvT0aKQ1N2RWBNSUybRqRV2uxE6NuswDXUCdoxKkSUPm
# Q1TNJyd1YSqoPZu0afSN63HAPrPMCAXXRTQldlXSOhqc7VkaLP1vx+Aiv81GAzVb
# yT7L03swKjx66Gg+puaVqyNFr6BkVnwI41HPqWunmdP4QxpIR2f68S96dK+8Pgfv
# TZSGeT6t4AXtunLXQyiijhFUIv9UruN/hdwQnbgs79PriWtzMGgkgHB77AQAT7Br
# U31hieVxozoqM9fm7gRYtRMcYogpSrqUJbtNl0arRQmNOBW/7rsgCHP3aQ/A/IOS
# 7DOMmYfZ8N3kq3FUKtiMPdGNQFdcmimAdjythjTkM8FqH3vyDsSpnXflh3kr/lTv
# ZgOdoZHvsvSvMhP9k5sGj60mK7ymBOI0M4M95MKAuoDKzLVWWQsyIBMp8+dIfgM+
# W4pLgy29qcZLj00JZPLflu+bOZkRKMrE2DDgKx4N5FdaHfZY6yIiPxrEp5154vnc
# LEeqvbHI7BD/gyhTeTS8laJlCATZ9A==
# SIG # End signature block
