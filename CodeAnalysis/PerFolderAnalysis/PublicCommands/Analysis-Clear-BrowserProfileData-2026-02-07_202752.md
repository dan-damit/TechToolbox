# Code Analysis Report
Generated: 2/7/2026 8:27:52 PM

## Summary
 The provided PowerShell script, `Clear-BrowserProfileData`, is a well-structured function that clears cache, cookies, and local storage for Chrome/Edge profiles. Here are some suggestions to enhance its functionality, readability, and performance:

1. **Input validation**: Add input validation for the parameters to ensure they meet certain requirements (e.g., `[ValidateSet]` attribute for `Browser`, or `[String[]]` for `Profiles`). This will help avoid runtime errors caused by invalid input.

2. **Comments and documentation**: The script is well-documented, but you could consider adding more comments to explain the purpose of certain sections of the code (e.g., the `begin`, `process`, and `end` blocks) and provide context for any new features or improvements you plan to add in the future.

3. **Error handling**: Add error handling to catch and report exceptions that may occur during the execution of the script, such as when trying to stop browser processes or accessing profile folders. This will make it easier for users to understand and troubleshoot issues that might arise.

4. **Modularization**: Break down the function into smaller, reusable functions (e.g., separate the process of discovering profiles from clearing cache, cookies, and local storage). This will make the code more manageable and easier to maintain in the long run.

5. **Code formatting**: Use PowerShell Core's automatic formatting features or an external tool like PSScriptAnalyzer to ensure consistent indentation and line breaks across the entire script. This makes it easier for others to read and understand your code.

6. **Documentation**: Document the function (`Clear-BrowserProfileData`) using the `New-HelpData` cmdlet, so users can easily access information about its syntax, parameters, examples, and links to related resources.

## Source Code
```powershell
function Clear-BrowserProfileData {
    <#
    .SYNOPSIS
        Clears cache, cookies, and optional local storage for Chrome/Edge
        profiles.
    .DESCRIPTION
        Stops browser processes (optional), discovers Chromium profile folders,
        and clears cache/cookies/local storage per switches. Logging is
        centralized via Write-Log.
    .PARAMETER Browser
        Chrome, Edge, or All. Default: All.
    .PARAMETER Profiles
        One or more profile names to target (e.g., 'Default','Profile 1'). If
        omitted, all known profiles.
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
    .INPUTS
        None. You cannot pipe objects to Clear-BrowserProfileData.
    .OUTPUTS
        [PSCustomObject] with properties:
            Browser             - The browser processed (Chrome/Edge)
            Profile             - The profile name processed
            CacheCleared        - $true if cache was cleared
            CookiesCleared      - $true if cookies were cleared
            LocalStorageCleared - $true if local storage was cleared
            Timestamp           - DateTime of operation
    .EXAMPLE
        Clear-BrowserProfileData -Browser Chrome -Profiles 'Default','Profile 2' -WhatIf
    .EXAMPLE
        Clear-BrowserProfileData -Browser All -IncludeCache:$true -IncludeCookies:$false -Confirm
    .LINK
        [TechToolbox](https://github.com/dan-damit/TechToolbox)
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
        [int]  $SleepAfterKillMs = 1500
    )

    begin {
        # --- Config & Defaults ---
        $cfg = Get-TechToolboxConfig

        # Resolve settings.browserCleanup safely (works for hashtables or PSCustomObjects)
        $bc = @{}
        if ($cfg) {
            $settings = $cfg['settings']
            if ($null -eq $settings) { $settings = $cfg.settings }
            if ($settings) {
                $bc = $settings['browserCleanup']
                if ($null -eq $bc) { $bc = $settings.browserCleanup }
            }
            if ($null -eq $bc) { $bc = @{} }
        }

        # Apply config-driven defaults only when the parameter wasn't provided
        if (-not $PSBoundParameters.ContainsKey('IncludeCache') -and $bc.ContainsKey('includeCache')) { $IncludeCache = [bool]$bc['includeCache'] }
        if (-not $PSBoundParameters.ContainsKey('IncludeCookies') -and $bc.ContainsKey('includeCookies')) { $IncludeCookies = [bool]$bc['includeCookies'] }
        if (-not $PSBoundParameters.ContainsKey('SkipLocalStorage') -and $bc.ContainsKey('skipLocalStorage')) { $SkipLocalStorage = [bool]$bc['skipLocalStorage'] }
        if (-not $PSBoundParameters.ContainsKey('KillProcesses') -and $bc.ContainsKey('killProcesses')) { $KillProcesses = [bool]$bc['killProcesses'] }
        if (-not $PSBoundParameters.ContainsKey('SleepAfterKillMs') -and $bc.ContainsKey('sleepAfterKillMs')) { $SleepAfterKillMs = [int] $bc['sleepAfterKillMs'] }

        # Browser (string default)
        if (-not $PSBoundParameters.ContainsKey('Browser') -and [string]::IsNullOrWhiteSpace($Browser)) {
            if ($bc.ContainsKey('defaultBrowser') -and $bc['defaultBrowser']) {
                $Browser = [string]$bc['defaultBrowser']
            }
        }

        # Profiles (array or string)
        if (-not $PSBoundParameters.ContainsKey('Profiles') -and $bc.ContainsKey('defaultProfiles') -and $null -ne $bc['defaultProfiles']) {
            $dp = $bc['defaultProfiles']
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
    }

    process {
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

        foreach ($b in $targetBrowsers) {
            Write-Log -Level Info -Message "=== Processing $b ==="

            $browserName = $BrowserMeta[$b].DisplayName
            $processName = $BrowserMeta[$b].ProcessName

            # Optional: stop processes
            if ($KillProcesses) {
                if ($PSCmdlet.ShouldProcess("$browserName ($processName)", "Stop processes")) {
                    Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds $SleepAfterKillMs
                }
            }

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
        Write-Log -Level Ok -Message "All requested browser profile cleanup completed."
    }
}
[SIGNATURE BLOCK REMOVED]

```
