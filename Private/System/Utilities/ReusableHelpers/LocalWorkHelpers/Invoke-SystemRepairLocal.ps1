function Invoke-SystemRepairLocal {
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
        [int]$WaitHeartbeatSeconds = 300,

        # --- Internal/sentinel: prevents infinite RunAs recursion ---
        [switch]$NoSelfElevate,

        # --- Internal: used only during self-elevation round-trip ---
        [string]$ElevatedResultPath,
        [string]$ElevatedErrorPath,

        # Optional: keep temp artifacts for debugging (result.json/error.txt)
        [switch]$KeepElevatedArtifacts
    )

    # Ensure runtime/config exists even in elevated re-launches
    Initialize-TechToolboxRuntime
    $effectiveRepairSource = $null

    $needsAdmin = ($RestoreHealth -or $StartComponentCleanup -or $ResetBase -or $SfcScannow -or $ResetUpdateComponents)

    # ----------------------------
    # Self-elevate (local only) + WAIT + return results
    # ----------------------------
    if ($needsAdmin -and -not $NoSelfElevate -and -not (Test-TTIsAdmin)) {

        Write-Log -Level Info -Message "Invoke-SystemRepairLocal: Elevation required. Relaunching as Administrator and waiting for completion..."

        # IPC folder (result + error)
        $tmpRoot = Join-Path $env:TEMP ("TT_SystemRepair_{0}" -f ([guid]::NewGuid().ToString('N')))
        $null = New-Item -Path $tmpRoot -ItemType Directory -Force

        $resultPath = Join-Path $tmpRoot 'result.json'
        $errorPath = Join-Path $tmpRoot 'error.txt'

        # Prefer pwsh, fallback to Windows PowerShell
        $psExe = (Get-Command pwsh -ErrorAction SilentlyContinue)?.Source
        if (-not $psExe) { $psExe = (Get-Command powershell -ErrorAction Stop).Source }

        # ✅ Use your helper to locate the manifest
        $moduleRoot = Get-ModuleRoot
        $manifest = Join-Path $moduleRoot 'TechToolbox.psd1'

        # Escape strings embedded into -Command
        $manifestEsc = $manifest.Replace('"', '`"')
        $resultEsc = $resultPath.Replace('"', '`"')
        $errorEsc = $errorPath.Replace('"', '`"')

        # Build explicit invoke parameters and serialize them for robust cross-process passing.
        # This avoids fragile tokenized command text that can break on paths/special characters.
        $elevatedParams = @{
            Local                   = $true
            Confirm                 = $false
            RepairSourceIndex       = $RepairSourceIndex
            OperationTimeoutMinutes = $OperationTimeoutMinutes
            WaitPollSeconds         = $WaitPollSeconds
            WaitHeartbeatSeconds    = $WaitHeartbeatSeconds
        }

        if ($RestoreHealth) { $elevatedParams.RestoreHealth = $true }
        if ($StartComponentCleanup) { $elevatedParams.StartComponentCleanup = $true }
        if ($ResetBase) { $elevatedParams.ResetBase = $true }
        if ($SfcScannow) { $elevatedParams.SfcScannow = $true }
        if ($ResetUpdateComponents) { $elevatedParams.ResetUpdateComponents = $true }
        if (-not [string]::IsNullOrWhiteSpace($RepairSource)) { $elevatedParams.RepairSource = $RepairSource }
        if ($LimitAccess) { $elevatedParams.LimitAccess = $true }

        $elevatedParamsJson = ($elevatedParams | ConvertTo-Json -Depth 5 -Compress).Replace("'", "''")

        # Elevated session script:
        # - Import module from manifest
        # - Init runtime
        # - Invoke this function with -NoSelfElevate
        # - Write JSON result (or error)
        $cmd = @"
& {
  try {
    if (-not (Test-Path -LiteralPath "$manifestEsc")) {
      throw "TechToolbox manifest not found: $manifestEsc"
    }

    Import-Module "$manifestEsc" -Force

    # Call the EXPORTED wrapper so module-internal init works
    `$invokeParamsObject = ConvertFrom-Json -InputObject '$elevatedParamsJson'
    `$invokeParams = @{}
    foreach (`$prop in `$invokeParamsObject.PSObject.Properties) {
      `$invokeParams[`$prop.Name] = `$prop.Value
    }
    `$r = Invoke-SystemRepair @invokeParams

    (`$r | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath "$resultEsc" -Encoding UTF8 -Force
    exit 0
  }
  catch {
    (`$_.Exception.Message + [Environment]::NewLine + `$_.ScriptStackTrace) |
      Set-Content -LiteralPath "$errorEsc" -Encoding UTF8 -Force
    exit 1
  }
}
"@

        # Use EncodedCommand to avoid command-line tokenization issues with
        # embedded JSON/paths (for example values containing " - ").
        $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cmd))

        $p = Start-Process -FilePath $psExe -Verb RunAs -ArgumentList @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', $encodedCmd
        ) -PassThru

        if (-not $p) { throw "Invoke-SystemRepairLocal: Failed to start elevated process." }

        # WAIT for completion
        $p.WaitForExit()

        # Rehydrate / throw
        try {
            if (Test-Path -LiteralPath $resultPath) {
                $raw = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($raw)) {
                    throw "Elevated process completed but result file was empty: $resultPath"
                }

                $obj = $raw | ConvertFrom-Json

                if (-not $KeepElevatedArtifacts) {
                    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Log -Level Info -Message "Keeping elevation artifacts for debugging: $tmpRoot"
                }

                return $obj
            }

            $detail = $null
            if (Test-Path -LiteralPath $errorPath) {
                $detail = Get-Content -LiteralPath $errorPath -Raw -ErrorAction SilentlyContinue
            }

            if (-not $detail) {
                $detail = "Elevated process exited with code $($p.ExitCode), but no result/error file was produced. Temp: $tmpRoot"
            }

            throw $detail
        }
        finally {
            if (-not $KeepElevatedArtifacts) {
                Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # ----------------------------
    # If already elevated (or self-elevate disabled), enforce admin
    # ----------------------------
    if ($needsAdmin -and -not (Test-TTIsAdmin)) {
        throw "Invoke-SystemRepairLocal: This operation requires an elevated PowerShell session. Run PowerShell as Administrator."
    }

    $system32 = Join-Path $env:SystemRoot 'System32'

    function Invoke-Dism {
        param([string[]]$DISM_Args)
        Invoke-TTExe -FilePath (Join-Path $system32 'dism.exe') -Arguments $DISM_Args -TimeoutMinutes $OperationTimeoutMinutes
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

    function Invoke-Sfc {
        Invoke-TTExe -FilePath (Join-Path $system32 'sfc.exe') -Arguments @('/scannow') -TimeoutMinutes $OperationTimeoutMinutes
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

    function Invoke-RepairWithWait {
        param(
            [Parameter(Mandatory)][string]$Label,
            [Parameter(Mandatory)][scriptblock]$StartScript,
            [int]$TimeoutMinutes = 60
        )

        $opStartedAt = Get-Date
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        Write-Log -Level Info -Message "$Label started..."

        $procResult = & $StartScript

        $poll = {
            if ($procResult.TimedOut) { return @{ Status = 'Timeout' } }
            if ($procResult.ExitCode -ne $null) { return @{ Status = 'Done'; Code = $procResult.ExitCode } }
            return $null
        }

        $getStatus = {
            param($obj)
            if ($obj.Status -eq 'Timeout') { return 'Timeout' }
            if ($obj.Status -eq 'Done') {
                if ($obj.Code -eq 0) { return 'Success' }
                return 'Error'
            }
            return '<notfound>'
        }

        $terminal = @{
            'Success' = @{ Level = 'Ok'; Message = "$Label completed successfully."; Return = $true }
            'Error'   = @{ Level = 'Error'; Message = "$Label failed."; Return = $true }
            'Timeout' = @{ Level = 'Error'; Message = "$Label timed out."; Return = $true }
        }

        $null = Wait-TerminalState `
            -Target $Label `
            -PollScript $poll `
            -GetStatus $getStatus `
            -TerminalStates $terminal `
            -TimeoutSeconds ($TimeoutMinutes * 60) `
            -PollSeconds $WaitPollSeconds `
            -HeartbeatSeconds $WaitHeartbeatSeconds

        $sw.Stop()
        $opCompletedAt = Get-Date

        [pscustomobject]@{
            Label           = $Label
            StartedAt       = $opStartedAt
            CompletedAt     = $opCompletedAt
            DurationSeconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            ExitCode        = $procResult.ExitCode
            TimedOut        = $procResult.TimedOut
            Success         = ($procResult.ExitCode -eq 0 -and -not $procResult.TimedOut)
        }
    }

    # --- Overall timing ---
    $overallStartedAt = Get-Date
    $overallSw = [System.Diagnostics.Stopwatch]::StartNew()

    $results = [ordered]@{
        ComputerName                = $env:COMPUTERNAME
        StartedAt                   = $overallStartedAt
        EffectiveRepairSource       = $null
        RestoreHealthSourceResult   = $null
        RestoreHealthFallbackResult = $null
        RestoreHealthFallbackUsed   = $false
        RestoreHealthResult         = $null
        StartComponentCleanup       = $null
        ResetBaseResult             = $null
        SfcResult                   = $null
        ResetWUResult               = $null
        CompletedAt                 = $null
        DurationSeconds             = $null
    }

    if ($RestoreHealth) {
        $restoreHealthArgs = Get-DismRestoreHealthArgs
        $sourceAttempt = Invoke-RepairWithWait `
            -Label "DISM /RestoreHealth" `
            -StartScript { Invoke-Dism -DISM_Args $restoreHealthArgs } `
            -TimeoutMinutes $OperationTimeoutMinutes

        $results.RestoreHealthResult = $sourceAttempt
        if (-not [string]::IsNullOrWhiteSpace($RepairSource)) {
            $results.RestoreHealthSourceResult = $sourceAttempt
        }

        if (Test-ShouldRetryRestoreHealthWithoutSource -Result $sourceAttempt) {
            Write-Log -Level Warn -Message ("DISM /RestoreHealth source attempt failed with exit code {0}; retrying without /Source so CBS can use default repair sources." -f $sourceAttempt.ExitCode)

            $fallbackAttempt = Invoke-RepairWithWait `
                -Label "DISM /RestoreHealth (fallback without source)" `
                -StartScript { Invoke-Dism -DISM_Args @('/online', '/cleanup-image', '/restorehealth') } `
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

    if ($StartComponentCleanup) {
        $results.StartComponentCleanup = Invoke-RepairWithWait `
            -Label "DISM /StartComponentCleanup" `
            -StartScript { Invoke-Dism -DISM_Args @("/online", "/cleanup-image", "/startcomponentcleanup") } `
            -TimeoutMinutes $OperationTimeoutMinutes
    }

    if ($ResetBase) {
        $results.ResetBaseResult = Invoke-RepairWithWait `
            -Label "DISM /ResetBase" `
            -StartScript { Invoke-Dism -DISM_Args @("/online", "/cleanup-image", "/startcomponentcleanup", "/resetbase") } `
            -TimeoutMinutes $OperationTimeoutMinutes
    }

    if ($SfcScannow) {
        $results.SfcResult = Invoke-RepairWithWait `
            -Label "SFC /scannow" `
            -StartScript { Invoke-Sfc } `
            -TimeoutMinutes $OperationTimeoutMinutes
    }

    if ($ResetUpdateComponents) {
        Write-Log -Level Info -Message "Resetting Windows Update components locally..."

        $wuStartedAt = Get-Date
        $wuSw = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            $wu = Reset-WindowsUpdateComponents -ShowProgress
            $wuSw.Stop()
            $wuCompletedAt = Get-Date

            if ($wu -isnot [psobject]) { $wu = [pscustomobject]@{ Result = $wu } }

            $wu | Add-Member -Force NoteProperty Label           'Reset Windows Update Components'
            $wu | Add-Member -Force NoteProperty StartedAt       $wuStartedAt
            $wu | Add-Member -Force NoteProperty CompletedAt     $wuCompletedAt
            $wu | Add-Member -Force NoteProperty DurationSeconds ([math]::Round($wuSw.Elapsed.TotalSeconds, 2))

            $results.ResetWUResult = $wu
        }
        catch {
            $wuSw.Stop()
            $wuCompletedAt = Get-Date

            $results.ResetWUResult = [pscustomobject]@{
                Label           = 'Reset Windows Update Components'
                StartedAt       = $wuStartedAt
                CompletedAt     = $wuCompletedAt
                DurationSeconds = [math]::Round($wuSw.Elapsed.TotalSeconds, 2)
                Success         = $false
                Message         = "WU reset failed: $($_.Exception.Message)"
            }
        }
    }

    $overallSw.Stop()
    $results.CompletedAt = Get-Date
    $results.DurationSeconds = [math]::Round($overallSw.Elapsed.TotalSeconds, 2)
    if ($results.RestoreHealthFallbackUsed) {
        $results.EffectiveRepairSource = '[default online repair sources]'
    }
    else {
        $results.EffectiveRepairSource = if (-not [string]::IsNullOrWhiteSpace($effectiveRepairSource)) { $effectiveRepairSource } else { $RepairSource }
    }

    # Extra safety for elevation round-trip (not required, but harmless)
    if ($ElevatedResultPath) {
        try { ($results | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $ElevatedResultPath -Encoding UTF8 -Force } catch {}
    }
    if ($ElevatedErrorPath) {
        try { if (Test-Path $ElevatedErrorPath) { Remove-Item -LiteralPath $ElevatedErrorPath -Force -ErrorAction SilentlyContinue } } catch {}
    }

    return [pscustomobject]$results
}

# SIG # Begin signature block
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDb8A8a9FW2pEP1
# AE2AJVbv9xN+oqlDZoUGkM89rI+uWKCCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBQ
# zzUJgbe2uO2Jo3XBMVL2EoJlRqKa76/5CU5feJQ+bTANBgkqhkiG9w0BAQEFAASC
# AYBsv0zeF0uUbWCewV6f1CgPYo/XL4SMCsDfjpXaiOGwcEi79mFTcNGlTlCxufCN
# GJv/JLWXlClLHvVmO1dqvIZmkzKuTDh5Or54LtM10RwyIFBXpfTXabx6/eNPfhp1
# LqeevypAS6+i97mOxoNCRhDYV9dzLzemPFZpdLjRC3V5MQxthgGoMu7pAVSEsbNQ
# 3OFJhgkxtxLpK3CHpFL/+5Y442mAvTP1WUCMRWxlfLiF71JLeXLpSZqcH5avtQUT
# bYwz5EYCsDnnvCqh59LBzQLp9HOLFWzdi9gt6M0dGwV0YoFPt/4MKlDI6jz4AQEW
# ZFFzoqHkPwViBPTZCf5DB8ZJuH8CyXWtodbIfS8roZjupgD8GIvQz1Aq2sA15x3I
# cv4GDhNUPhYGs4D3XPpDjX0q7vNVudhITXV3Eno1fUORqVlYwOE9yLc/rBroVa3Z
# 09ArUeUcOqsnOlutMejVh1T4ZJcM/Ey/Z89KXqSNfYYjcN9qeZb8MLgxB12sspCa
# uFihggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTAyMTgxMzEwWjAvBgkqhkiG
# 9w0BCQQxIgQgmmnUB9VpoJYpCokiNfMJ6GUvSxQkFB1pseeiCtV99hswDQYJKoZI
# hvcNAQEBBQAEggIABcOfuOG87gV74TjxsOY2TpvGvA8GN1XSmVH92ErTC2Ng8geS
# SD+Hz9mz3Y4x6SMw0tvI9HPHEgYc/sCYcPz2zFyb4f1sXMamMSYEDy5rWQQuh4j3
# BV0dsEYmQjSY0w2XBcue/F4Ribz8LsLm6jo6pUdUZPaIl+o/zDHZ4bOQe7Cz58is
# cJyp7YoxGdZIWHL64ZegEta81wK98F5FqDKyYHo2Ppk6A4Fr4jCdjCKDfsUCpC2j
# 7ETdszrK7z597HcqSiU7cQ01mLy7X6zGmwKs8VPRKLszzu4m+KHeCaMh8mrH+a9H
# HVpstT75LZvFxt0OPMNsHQUQW/fkBRLGbr0Pqmqo+OlJ3bOiLFr7MHKTZk8K1fP1
# MR523pQqfiGLUBIKYZxVdLvK9anDYGO0v0RvU1lcFW3GZB8UMm3kA95R7AqWpAcG
# An2Pt9wZY4azYFFyMPwr/qSK42YkjbLJouQtAkLGUdxPvJZusn/bsXnWmdvTrNdW
# mV3QRHiLAKvDwg4Oc6ysVosBR0WDiKWN1wTWApbglEXYkDa/c4/YM89m/UBHrjdB
# /sHsV4WdXCbjy/sPU3bDRfIkTeSrXGNwTd/iNR/6+8Wd3ucuJ6+XlBrW57gRqfM1
# 1xPGidXnscBPF80IY51stbMWIZ2x7A+kwV7ROgi2uGHR0dw4USkUWFQxJCA=
# SIG # End signature block
