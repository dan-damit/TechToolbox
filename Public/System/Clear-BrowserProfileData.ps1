function Clear-BrowserProfileData {
    <#
    .SYNOPSIS
        Clears cache, cookies, and optional local storage for Chrome/Edge profiles.
    .DESCRIPTION
        Stops browser processes (optional), discovers Chromium profile folders, and clears
        cache/cookies/local storage per switches. Logging is centralized via Write-Log.
    .PARAMETER Browser
        Chrome, Edge, or All. Default: All.
    .PARAMETER Profiles
        One or more profile names to target (e.g., 'Default','Profile 1'). If omitted, all known profiles.
    .PARAMETER IncludeCookies
        Clears cookie databases. Default: $true
    .PARAMETER IncludeCache
        Clears browser cache folders. Default: $true
    .PARAMETER SkipLocalStorage
        Skips clearing 'Local Storage' content when $true. Default: $false
    .PARAMETER KillProcesses
        Attempts to stop browser processes before deletion. Default: $true
    .PARAMETER SleepAfterKillMs
        Milliseconds to wait after killing processes. Default: 1500
    .EXAMPLE
        Clear-BrowserProfileData -Browser Chrome -Profiles 'Default','Profile 2' -WhatIf
    .EXAMPLE
        Clear-BrowserProfileData -Browser All -IncludeCache:$true -IncludeCookies:$false -Confirm
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
        [int] $SleepAfterKillMs = 1500
    )

    begin {
        # --- Config & Defaults ---
        $cfg = Get-TechToolboxConfig
        $bc = $cfg["settings"]["browserCleanup"]

        # Apply config-driven defaults only when the parameter wasn't provided
        $IncludeCache = $PSBoundParameters.ContainsKey('IncludeCache')      ? $IncludeCache      : ([bool]($bc["includeCache"] ?? $IncludeCache))
        $IncludeCookies = $PSBoundParameters.ContainsKey('IncludeCookies')    ? $IncludeCookies    : ([bool]($bc["includeCookies"] ?? $IncludeCookies))
        $SkipLocalStorage = $PSBoundParameters.ContainsKey('SkipLocalStorage')  ? $SkipLocalStorage  : ([bool]($bc["skipLocalStorage"] ?? $SkipLocalStorage))
        $KillProcesses = $PSBoundParameters.ContainsKey('KillProcesses')     ? $KillProcesses     : ([bool]($bc["killProcesses"] ?? $KillProcesses))
        $SleepAfterKillMs = $PSBoundParameters.ContainsKey('SleepAfterKillMs')  ? $SleepAfterKillMs  : ([int] ($bc["sleepAfterKillMs"] ?? $SleepAfterKillMs))

        # Browser (string default)
        if (-not $PSBoundParameters.ContainsKey('Browser') -and [string]::IsNullOrWhiteSpace($Browser)) {
            $Browser = [string]($bc["defaultBrowser"] ?? $Browser)
        }

        # Profiles (array or string)
        if (-not $PSBoundParameters.ContainsKey('Profiles') -and $null -ne $bc["defaultProfiles"]) {
            $Profiles = @(
                if ($bc["defaultProfiles"] -is [System.Collections.IEnumerable] -and -not ($bc["defaultProfiles"] -is [string])) {
                    $bc["defaultProfiles"]
                }
                else {
                    "$($bc["defaultProfiles"])"
                }
            )
        }
    }

    process {
        $results = New-Object System.Collections.Generic.List[object]

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
            Write-Information ("Profiles filter: {0}" -f ($Profiles -join ', '))
            Write-Information "======================="
        }

        foreach ($b in $targetBrowsers) {
            Write-Log -Level Info -Message "=== Processing $b ==="

            if ($KillProcesses) {
                if ($PSCmdlet.ShouldProcess("Browser processes: $browserName", "Stop processes")) {
                    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds $SleepAfterKillMs
                }
            }

            $userData = Get-BrowserUserDataPath -Browser $b
            $profileDirs = Get-BrowserProfileFolders -UserDataPath $userData

            if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                Write-Log -Level Warn -Message "No profiles found for $b at '$userData'."
                continue
            }

            Write-Log -Level Info -Message ("Discovered profiles: {0}" -f ($profileDirs.Name -join ', '))

            if ($Profiles) {
                $profileDirs = $profileDirs | Where-Object { $Profiles -contains $_.Name }
                Write-Log -Level Info -Message ("Filtered profiles: {0}" -f ($profileDirs.Name -join ', '))
                if (-not $profileDirs -or $profileDirs.Count -eq 0) {
                    Write-Log -Level Warn -Message "No profiles remain after filtering. Skipping $b."
                    continue
                }
            }

            foreach ($prof in $profileDirs) {
                $profileName = $prof.Name
                $profilePath = $prof.FullName

                Write-Log -Level Info -Message "Profile: '$profileName' ($profilePath)"

                if (Test-Path $cookiePath) {
                    if ($PSCmdlet.ShouldProcess($cookiePath, "Delete cookies")) {
                        Remove-Item -Path $cookiePath -Force -ErrorAction Continue
                    }
                }

                if (Test-Path $cachePath) {
                    if ($PSCmdlet.ShouldProcess($cachePath, "Delete cache folder")) {
                        Remove-Item -Path $cachePath -Recurse -Force -ErrorAction Continue
                    }
                }
                Write-Log -Level Ok -Message "Finished: $profileName"

                $results.Add([PSCustomObject]@{
                        Browser             = $b
                        Profile             = $profileName
                        CacheCleared        = $IncludeCache
                        CookiesCleared      = $IncludeCookies
                        LocalStorageCleared = (-not $SkipLocalStorage)
                        Timestamp           = (Get-Date)
                    })
            }

            Write-Log -Level Ok -Message "=== Completed $b ==="
        }

        return $results
    }

    end {
        Write-Log -Level Ok -Message "All requested browser profile cleanup completed."
    }
}
