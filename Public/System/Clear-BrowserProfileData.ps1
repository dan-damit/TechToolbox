function Clear-BrowserProfileData {
    <#
    .SYNOPSIS
        Clears Chromium browser profile data for Chrome and/or Edge.

    .DESCRIPTION
        Performs a browser profile cleanup workflow for Google Chrome, Microsoft
        Edge, or both:

          1. Loads runtime configuration from settings.browserCleanup.
          2. Applies config-driven defaults only for parameters not explicitly
             supplied by the caller.
          3. Resolves one or both target browsers (Chrome, Edge, or All).
          4. Optionally stops browser processes before deletion to avoid file
             locks on cache and cookie databases.
          5. Discovers Chromium profile folders beneath each browser's User Data
             path.
          6. Optionally filters the discovered set to named profiles such as
             Default or Profile 1.
          7. Clears cookies, cache, and optionally local storage by delegating
             to the internal profile-cleanup helpers.
          8. Logs each stage of the run via Write-Log.

        CONFIG-DRIVEN DEFAULTS When a parameter is omitted, the function
        attempts to read its default value from settings.browserCleanup in
        config.json. This includes:

          - includeCache
          - includeCookies
          - skipLocalStorage
          - killProcesses
          - sleepAfterKillMs
          - defaultBrowser
          - defaultProfiles

        Caller-supplied parameter values always take precedence over config.

        SHOULDPROCESS / SAFETY This function supports -WhatIf and -Confirm.
        Process termination and any downstream deletion work are guarded by
        ShouldProcess-aware flow so you can preview the intended browser/profile
        targets before making changes.

        SCOPE This workflow is designed for Chromium-based profile layouts used
        by Chrome and Edge. It does not target Firefox, Internet Explorer, or
        non-Chromium storage paths.

    .PARAMETER Browser
        Specifies which browser to process. Valid values are:

          - Chrome
          - Edge
          - All

        Defaults to All unless overridden by
        settings.browserCleanup.defaultBrowser.

    .PARAMETER Profiles
        One or more Chromium profile folder names to target, for example:

          - Default
          - Profile 1
          - Profile 2

        When omitted, all discovered profiles for the selected browser(s) are
        processed unless settings.browserCleanup.defaultProfiles defines a
        default filter.

    .PARAMETER IncludeCookies
        When $true, clears cookie databases for each targeted profile by calling
        Clear-CookiesForProfile. Defaults to $true, unless overridden by
        settings.browserCleanup.includeCookies.

    .PARAMETER IncludeCache
        When $true, clears browser cache folders for each targeted profile by
        calling Clear-CacheForProfile. Defaults to $true, unless overridden by
        settings.browserCleanup.includeCache.

    .PARAMETER SkipLocalStorage
        When $true, local storage content is preserved even when cookies are
        being cleared. When $false, local storage cleanup is delegated to
        Clear-CookiesForProfile as part of that workflow. Defaults to $false,
        unless overridden by settings.browserCleanup.skipLocalStorage.

    .PARAMETER KillProcesses
        When $true, attempts to stop the relevant browser processes before any
        cleanup begins. This helps prevent file locks on cookies and cache
        files. Defaults to $true, unless overridden by
        settings.browserCleanup.killProcesses.

    .PARAMETER SleepAfterKillMs
        Number of milliseconds to wait after stopping browser processes before
        profile cleanup continues. This delay gives the browser time to fully
        release locks on profile files. Defaults to 1500, unless overridden by
        settings.browserCleanup.sleepAfterKillMs.

    .INPUTS
        None. This function does not accept pipeline input.

    .OUTPUTS
        None.

        This function does not emit structured result objects to the pipeline.
        Progress and outcomes are written through Write-Log and, during -WhatIf
        runs, additional dry-run detail is written via Write-Information.

    .EXAMPLE
        Clear-BrowserProfileData -Browser Chrome -Profiles 'Default','Profile 2' -WhatIf

        Previews cleanup of the Default and Profile 2 Chrome profiles without
        stopping processes or deleting any browser data.

    .EXAMPLE
        Clear-BrowserProfileData -Browser All -IncludeCache:$true -IncludeCookies:$false -Confirm

        Processes both Chrome and Edge, clearing cache only, and prompts before
        destructive actions are taken.

    .EXAMPLE
        Clear-BrowserProfileData -Browser Edge -Profiles 'Default' -KillProcesses:$false

        Clears the Edge Default profile without attempting to stop Edge first.
        Useful when process management is handled externally.

    .EXAMPLE
        Clear-BrowserProfileData -Browser Chrome -SkipLocalStorage:$true

        Clears Chrome cookies and cache while preserving local storage.

    .EXAMPLE
        Clear-BrowserProfileData -Browser All -IncludeCache:$false -IncludeCookies:$true

        Clears cookies for all discovered Chrome and Edge profiles, and skips
        cache deletion.

    .NOTES
        - Requires the internal helper functions Get-BrowserUserDataPath,
          Get-BrowserProfileFolders, Clear-CookiesForProfile, and
          Clear-CacheForProfile.
        - This function assumes Chromium-style profile folders such as Default
          and Profile 1.
        - If no profiles are discovered for a browser, that browser is skipped
          and a warning is logged.
        - If profile filtering removes all discovered profiles, that browser is
          skipped and a warning is logged.
        - The function currently returns no PSCustomObject results despite older
          help text implying otherwise.

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Clear-BrowserProfileData

    .LINK
        Get-BrowserUserDataPath

    .LINK
        Get-BrowserProfileFolders

    .LINK
        Clear-CookiesForProfile

    .LINK
        Clear-CacheForProfile
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [ValidateSet('Chrome', 'Edge', 'All')]
        [string]$Browser = 'All',

        [string[]]$Profiles,

        [bool]$IncludeCookies = $true,
        [bool]$IncludeCache = $true,
        [bool]$SkipLocalStorage = $false,

        [bool]$KillProcesses = $true,
        [int]  $SleepAfterKillMs = 1500,

        [string[]]$ComputerName,
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
        # --- Config & Defaults ---
        Initialize-TechToolboxRuntime
        $cfg = $script:cfg

        # Resolve settings.browserCleanup safely (works for hashtables or PSCustomObjects)
        $bc = @{}
        if ($cfg) {
            $settings = $cfg.settings
            if ($null -eq $settings) { $settings = $cfg.settings }
            if ($settings) {
                $bc = $settings.browserCleanup
                if ($null -eq $bc) { $bc = $settings.browserCleanup }
            }
            if ($null -eq $bc) { $bc = @{} }
        }

        # Apply config-driven defaults only when the parameter wasn't provided
        if (-not $PSBoundParameters.ContainsKey('IncludeCache') -and $bc.ContainsKey('includeCache')) { $IncludeCache = [bool]$bc.includeCache }
        if (-not $PSBoundParameters.ContainsKey('IncludeCookies') -and $bc.ContainsKey('includeCookies')) { $IncludeCookies = [bool]$bc.includeCookies }
        if (-not $PSBoundParameters.ContainsKey('SkipLocalStorage') -and $bc.ContainsKey('skipLocalStorage')) { $SkipLocalStorage = [bool]$bc.skipLocalStorage }
        if (-not $PSBoundParameters.ContainsKey('KillProcesses') -and $bc.ContainsKey('killProcesses')) { $KillProcesses = [bool]$bc.killProcesses }
        if (-not $PSBoundParameters.ContainsKey('SleepAfterKillMs') -and $bc.ContainsKey('sleepAfterKillMs')) { $SleepAfterKillMs = [int] $bc.sleepAfterKillMs }

        # Browser (string default)
        if (-not $PSBoundParameters.ContainsKey('Browser') -and [string]::IsNullOrWhiteSpace($Browser)) {
            if ($bc.ContainsKey('defaultBrowser') -and $bc.defaultBrowser) {
                $Browser = [string]$bc.defaultBrowser
            }
        }

        # Profiles (array or string)
        if (-not $PSBoundParameters.ContainsKey('Profiles') -and $bc.ContainsKey('defaultProfiles') -and $null -ne $bc.defaultProfiles) {
            $dp = $bc.defaultProfiles
            $Profiles = @(
                if ($dp -is [System.Collections.IEnumerable] -and -not ($dp -is [string])) { $dp }
                else { "$dp" }
            )
        }

        # Metadata per browser
        $BrowserMeta = @{
            Chrome = @{ ProcessName = 'chrome'; DisplayName = 'Google Chrome' }
            Edge   = @{ ProcessName = 'msedge'; DisplayName = 'Microsoft Edge' }
        }

        $moduleRoot = Get-ModuleRoot
        $workerPath = Join-Path $moduleRoot 'Workers\Clear-BrowserProfileData.Worker.ps1'
        $workerPackage = New-HelpersPackage -HelperLibs @() -WorkerFiles @($workerPath)

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
    }

    process {
        if ($PSBoundParameters.ContainsKey('ComputerName') -and @($ComputerName).Count -gt 0) {
            if (-not (Get-Command -Name Start-NewPSRemoteSession -ErrorAction SilentlyContinue)) {
                throw "Start-NewPSRemoteSession is required for remote execution but was not found in the current session."
            }

            $runLocal = $false
            foreach ($targetComputer in @($ComputerName | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)) {
                if (Test-IsLocalTarget -Name $targetComputer) {
                    $runLocal = $true
                    continue
                }

                Write-Log -Level Info -Message ("[{0}] Running browser cleanup via Invoke-RemoteWorker." -f $targetComputer)
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

                    $remoteResult = Invoke-RemoteWorker `
                        -Session $session `
                        -HelpersZip $workerPackage.ZipPath `
                        -HelpersZipHash $workerPackage.ZipHash `
                        -WorkerRemotePath 'IGNORED' `
                        -WorkerLocalPath $workerPath `
                        -EntryPoint 'Clear-BrowserProfileDataWorkerCore' `
                        -EntryParameters @{
                        Browser          = $Browser
                        Profiles         = [string[]]@($Profiles)
                        IncludeCookies   = $IncludeCookies
                        IncludeCache     = $IncludeCache
                        SkipLocalStorage = $SkipLocalStorage
                        KillProcesses    = $KillProcesses
                        SleepAfterKillMs = $SleepAfterKillMs
                    }

                    foreach ($line in @($remoteResult.LogLines)) {
                        Write-Log -Level Info -Message "[$targetComputer] $line"
                    }

                    if ($remoteResult.Success) {
                        Write-Log -Level Ok -Message "[$targetComputer] Browser profile cleanup completed for active user '$($remoteResult.ActiveUser)'."
                    }
                    else {
                        Write-Log -Level Error -Message "[$targetComputer] Browser profile cleanup reported failure: $($remoteResult.ErrorMessage)"
                    }

                    Write-Output $remoteResult
                }
                catch {
                    Write-Log -Level Error -Message "[$targetComputer] Remote browser cleanup failed: $($_.Exception.Message)"
                    if ($_.ScriptStackTrace) {
                        Write-Log -Level Error -Message "[$targetComputer] Stack: $($_.ScriptStackTrace)"
                    }
                }
                finally {
                    if ($session) {
                        Stop-PSRemoteSession -Session $session -ErrorAction SilentlyContinue
                    }
                }
            }

            if (-not $runLocal) {
                return
            }
        }

        $targetBrowsers = switch ($Browser) {
            'Chrome' { @('Chrome') }
            'Edge' { @('Edge') }
            'All' { @('Chrome', 'Edge') }
        }

        if ($WhatIfPreference) {
            Write-Information "=== DRY RUN SUMMARY ==="
            Write-Information ("Browsers: {0}" -f ($targetBrowsers -join ', '))
            Write-Information "Include Cache: $IncludeCache"
            Write-Information "Include Cookies: $IncludeCookies"
            Write-Information "Skip Local Storage: $SkipLocalStorage"
            Write-Information "Kill Processes: $KillProcesses"
            Write-Information ("Profiles filter: {0}" -f (($Profiles ?? @()) -join ', '))
            Write-Information "======================="
        }

        if ($KillProcesses) {
            foreach ($browserToStop in $targetBrowsers) {
                $stopBrowserName = $BrowserMeta[$browserToStop].DisplayName
                $stopProcessName = $BrowserMeta[$browserToStop].ProcessName

                if ($PSCmdlet.ShouldProcess("$stopBrowserName ($stopProcessName)", "Stop process tree before browser data cleanup")) {
                    for ($attempt = 1; $attempt -le 4; $attempt++) {
                        Stop-Process -Name $stopProcessName -Force -ErrorAction SilentlyContinue
                        & taskkill.exe /IM "$stopProcessName.exe" /T /F 2>$null | Out-Null

                        $remaining = @(Get-Process -Name $stopProcessName -ErrorAction SilentlyContinue)
                        if ($remaining.Count -eq 0) {
                            break
                        }

                        Start-Sleep -Milliseconds 350
                    }

                    $remaining = @(Get-Process -Name $stopProcessName -ErrorAction SilentlyContinue)
                    if ($remaining.Count -gt 0) {
                        Write-Log -Level Warn -Message "$stopBrowserName still has $($remaining.Count) running process(es) after kill retries."
                    }
                }
            }

            Start-Sleep -Milliseconds $SleepAfterKillMs
        }

        foreach ($b in $targetBrowsers) {
            Write-Log -Level Info -Message "=== Processing $b ==="

            $browserName = $BrowserMeta[$b].DisplayName
            $processName = $BrowserMeta[$b].ProcessName

            $userData = Get-BrowserUserDataPath -Browser $b
            $profileDirs = @(Get-BrowserProfileFolders -UserDataPath $userData)  # ensure array

            if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                Write-Log -Level Warn -Message "No profiles found for $b at '$userData'."
                continue
            }

            Write-Log -Level Info -Message ("Discovered profiles: {0}" -f ($profileDirs.Name -join ', '))

            # Optional filter by provided profile names
            if ($Profiles) {
                $profileDirs = @($profileDirs | Where-Object { $Profiles -contains $_.Name })
                Write-Log -Level Info -Message ("Filtered profiles: {0}" -f ($profileDirs.Name -join ', '))
                if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                    Write-Log -Level Warn -Message "No profiles remain after filtering. Skipping $b."
                    continue
                }
            }

            foreach ($prof in $profileDirs) {
                # Support DirectoryInfo or string
                $profileName = try { $prof.Name } catch { Split-Path -Path $prof -Leaf }
                $profilePath = try { $prof.FullName } catch { [string]$prof }

                Write-Log -Level Info -Message "Profile: '$profileName' ($profilePath)"

                # Cookies & Local Storage
                if ($IncludeCookies) {
                    $cookieStatus = Clear-CookiesForProfile -ProfilePath $profilePath -SkipLocalStorage:$SkipLocalStorage
                    # (No output—driver consumes status silently; use $cookieStatus for debug if needed)
                }
                else {
                    Write-Log -Level Info -Message "Cookies deletion skipped by configuration."
                }

                # Cache
                if ($IncludeCache) {
                    # If your cache helper returns status, capture silently to avoid tables
                    $cacheStatus = Clear-CacheForProfile -ProfilePath $profilePath
                    # Or: $null = Clear-CacheForProfile -ProfilePath $profilePath
                }
                else {
                    Write-Log -Level Info -Message "Cache deletion skipped by configuration."
                }

                Write-Log -Level Ok -Message "Finished: $profileName"
            }

            Write-Log -Level Ok -Message "=== Completed $b ==="
        }

        # No PSCustomObject results returned
        return
    }

    end {
        if ($workerPackage -and $workerPackage.ZipPath -and (Test-Path -LiteralPath $workerPackage.ZipPath)) {
            Remove-Item -LiteralPath $workerPackage.ZipPath -Force -ErrorAction SilentlyContinue
        }

        Write-Log -Level Ok -Message "All requested browser profile cleanup completed."
    }
}
# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCytb+3VaDaU5lJ
# GByENNhtm3DjpcPH0U3fiG/9wwE5HKCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAr44Im5eGb
# DGe2TiKMLgEQyWn1b4KFRrmoOQWVmyTEpzANBgkqhkiG9w0BAQEFAASCAgB7F4a+
# eBk6VLMztKSzfKdf/eMEGvs6PZoTUJvOxwuCSlTqYGNEAweq+0mNmWma0oOCPlNQ
# wxq13hELhUUaWfuYVER34RLgYzQpIqeOSenA++Iyuhjwq+Ka4wgRS0NOe6jn1rxU
# MIVPm01mm8Tc9Jlx0iwXP/sYexD9TTYzsmaEqqniMQbDDONdEgMKYkEmQ1jD9t/w
# 6oFDa7h9Er6X8yv+nzvZWBevHmS+vgPjBlnuPZj/ZPhCY8BVhXn8tx4uYmgkfWbV
# 5D3VnlMScSKcnRZOalKKBKhV5xTxxA11rsXj2yOWFKEnK7auV5cV6ny4vEIy92Un
# nlhYpKoACBaadTIaWNBBsKTlvZDQfTbDuzbfF9LDlPtN4Db+XT6EfTV+LX2vZMnx
# iOLJ5F7mQ2bGDh2rs15wwJLgFcQxl6rn7zpE5+0SOPgfwbuNad4KLw2Jzmf/biK0
# B8ndCKQLHP3cpEV5MzjlJH8FTgqz/MEMZgIeIA1M+GxwYsKNYcvuQCt83hWAJjqz
# OkRX7jGqXazJaDhtkpNS1U1aEJJaj2nGhe4Sd4NamDWZcSTr/5rYs2IX5tP2lBYW
# Yi9jnhFd1VGoByzMo8WaAI28mbuUS+yUTlNg+U4Xn+XCVjIzdTSP3kYzI3X7QyFq
# 2Lp7KCxO9BDkD1u9e5uOcBdvNNXOH0tcIYkThKGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA3MTQyMjM0NThaMC8GCSqGSIb3DQEJBDEiBCBbsfeWOPO9V7r7QKfT
# uz+KsdW97rSWOMP24/UAAI+AcjANBgkqhkiG9w0BAQEFAASCAgDM5zPiBKiH+TIx
# /93Zi+xjLytdxY+DbheNwgKLQZMfbyWKr5hhxKEDfrjyqtu5WPRUaYvUPs7uQQhW
# sI3upXLe2mmTlXS5oxasRO9CfhUdgLkR0FR2AuLJ4i07oywlasc4LNes8DuVfq7i
# Q9MSC2n7Js4rcjZ41Bf3ngk5AiD8dw8KJnEk3H9/wOhMioR4/vSVLGMdp3dzGHIg
# QrlvJj9fFxqgQpT6DwHOwk2TBzlgl5jVPPQN5uiCUcSaqCXdTUB6A7utWHzSDrKb
# cJwtbYKdNwYKIwmMY9y+pW/km6OH9HKq7irP2zwYzfl1XWcvO7pKPxOvsIxTumAp
# 3J4uQmAYin4UWk0TucEFeyPPKJV4AlooC3ERuT6sGdi7Y9ZHdlJ42sgtwYUrjBbh
# gJP+9F9yZLkjbbHUbLJnETwecosSXdM5WfDyrn14uXOSOOB+xeEjUVcyoJFSKydX
# P4NOlp+HkmjOo/N2foqp1Hphc9LR5kdnE7nLbP1L/17VZ9hfFZpppkREBnvIcjcc
# eXGIaSIR9VlYLZq7izs+STBzpEwveJlHzoGCfWf0MV5qNOiSq57Kfnfw+ChEy5gB
# 7wXED2AHDHJFa+z8V3BDVlM3bc7mFIZDZnZT8iyROdlvCFzV1DygBNhITs0Las7T
# 6RcvNDaxqYuy3rQc1XALYotKxFSmRA==
# SIG # End signature block
