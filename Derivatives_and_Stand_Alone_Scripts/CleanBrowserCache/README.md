# DumpBrowserCache.ps1
### Author: Dan.Damit ( https://github.com/dan-damit)

---

A PowerShell utility for safely and predictably clearing cache, cookies, and optional Local Storage for Chrome and Edge browser profiles. This script is designed with technician‑friendly transparency, deterministic behavior, and guardrails — including dry‑run summaries, structured output, and full ShouldProcess support.

---

## Features
  - Supports Chrome, Edge, or All
  - Clears: 
    - Cache directories (Cache, Code Cache, GPUCache, Service Worker, Network\Cache, etc.)
    - Cookies (modern and legacy SQLite DBs)
    - Optional Local Storage cleanup
  - Dry‑run mode (-WhatIf) with a full pre‑execution summary
  - Profile discovery summary (Default, Profile N)
  - Structured return objects for automation pipelines
  - Safe process handling (optional browser process termination)
  - Verbose logging and optional log file output
  - Fully supports PowerShell’s -WhatIf and -Confirm safety mechanisms

---

## Requirements
  - Windows 10 or Windows 11
  - PowerShell 5.1+ or PowerShell 7+
  - Run under the user account whose browser profiles you want to clean

---

## Parameters
| Parameter           | Description                                      |
|----------------------|--------------------------------------------------|
| `-Browser`          | Chrome, Edge, or All                            |
| `-Profiles`         | Specific profiles (e.g., 'Default','Profile 1') |
| `-IncludeCookies`   | Include cookie cleanup (default: true)          |
| `-IncludeCache`     | Include cache cleanup (default: true)           |
| `-KillProcesses`    | Stop browser processes before cleanup (default: true) |
| `-SleepAfterKillMs` | Wait time after killing processes (default: 1500 ms) |
| `-LogPath`          | Optional log file path                          |
| `-WhatIf`           | Dry-run mode                                    |
| `-Verbose`          | Detailed output                                 |
| `-SkipLocalStorage` | Skip clearing Local Storage (default: false)    |

---

## Dry‑Run Summary Example
When using -WhatIf, the script prints a technician‑friendly summary before any action:

```
=== DRY RUN SUMMARY ===
Browsers: Chrome, Edge
Include Cache: True
Include Cookies: True
Skip Local Storage: False
Kill Processes: True
Profiles filter: Default, Profile 1
=======================
```

This ensures full transparency before any destructive action.

---
## Supported Cache & Cookie Paths

### Cache directories cleared:

- Cache
- Code Cache
- GPUCache
- Service Worker
- Application Cache (legacy)
- Network\Cache

### Cookie DBs removed:

- Network\Cookies
- Network\Cookies-journal
- Cookies (legacy)
- Cookies-journal

### Optional:

- Local Storage\* (unless -SkipLocalStorage is used)

---

## Return Object
Each processed profile returns a structured object:
```powershell
[PSCustomObject]@{
    Browser             = 'Chrome'
    Profile             = 'Default'
    CacheCleared        = $true
    CookiesCleared      = $true
    LocalStorageCleared = $false
    Timestamp           = '2025-12-22T18:58:00'
}
```
This makes the script ideal for:
- Logging pipelines
- Scheduled tasks
- Enterprise automation
- Monitoring dashboards

---

## Example Usage
| Example |  Usage  |
|---------|---------|
| Clean Chrome (all profiles) | .\DumpBrowserCache.ps1 -Browser Chrome -Verbose
| Dry run (no changes), both browsers | .\DumpBrowserCache.ps1 -Browser All -WhatIf -Verbose
| Clean only specific profiles | .\DumpBrowserCache.ps1 -Browser Chrome -Profiles 'Default','Profile 2'
| Clean everything except Local Storage | .\DumpBrowserCache.ps1 -SkipLocalStorage
| Log all actions | .\DumpBrowserCache.ps1 -LogPath "C:\Logs\browser-cleanup.log"

---

## Notes & Limitations
- Must be run under the user whose browser data is being cleaned
- Does not clear extension‑specific caches
- Does not modify browser settings or registry entries
- Does not elevate privileges (not required for user‑level cleanup)

---

## Summary
This script is built for real‑world technician workflows: predictable, transparent, and safe. With v2.0’s enhancements — dry‑run summaries, profile discovery, structured output, and optional Local Storage control — it’s now a fully‑featured browser maintenance tool suitable for enterprise environments.
