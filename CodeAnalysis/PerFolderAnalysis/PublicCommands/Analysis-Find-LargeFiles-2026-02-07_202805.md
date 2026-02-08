# Code Analysis Report
Generated: 2/7/2026 8:28:05 PM

## Summary
 The PowerShell script you provided is a function called `Find-LargeFiles` that searches for large files recursively in one or more directories and (optionally) exports the results to a CSV file. Here are some suggestions for improving the code's functionality, readability, and performance:

1. **Code organization**: The script could be better organized by breaking it down into smaller functions to make it easier to understand and maintain. For example, the code that deals with getting the configuration could be extracted into a separate function.

2. **Parameter validation**: Some parameters are validated using the `ValidateNotNullOrEmpty()` and `ValidateRange()` attributes. However, these attributes are not defined in the script. It is recommended to use PowerShell's built-in validation attributes or write custom ones if necessary.

3. **Error handling**: The error handling in the script could be improved by using try/catch blocks more consistently. For example, when getting the configuration, the script only uses `try` and `Write-Verbose` for errors instead of throwing an exception that can be caught and handled elsewhere.

4. **Performance**: To improve performance, consider using PowerShell's optimized collection types like `[System.Collections.ObjectModel.ReadOnlyCollection[PSCustomObject]]` instead of `System.Collections.Generic.List[object]`. Also, since the script sorts the results twice (once during processing and once at the end), it could be optimized by sorting the results only once.

5. **Code comments**: The code is well-documented with comments that explain what each parameter does, the function's purpose, examples of usage, and notes. However, some variable names could be more descriptive to make the code easier to read.

6. **PowerShell Core compatibility**: The script uses PowerShell 7's `-Depth` parameter for `Get-ChildItem`, which may not work in older versions of PowerShell. To ensure compatibility, you can provide a fallback using `-Recurse` and manually setting the maximum depth.

Here is an example of how some of these suggestions could be implemented:

```powershell
function Get-TechToolboxConfig {
    $cmd = Get-Command -Name 'Get-TechToolboxConfig' -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            return $cmd Invoke()
        } catch { Write-Verbose "Get-TechToolboxConfig failed: $($_.Exception.Message)" }
    }
    $defaultPath = 'C:\TechToolbox\Config\config.json'
    if (Test-Path -LiteralPath $defaultPath) {
        try {
            return Get-Content -LiteralPath $defaultPath -Raw | ConvertFrom-Json -ErrorAction Stop
        } catch { Write-Verbose "Failed to parse config.json at ${defaultPath}: $($_.Exception.Message)" }
    }
    throw "Failed to find configuration file."
}

function Find-LargeFiles {
    [CmdletBinding()]
    param (
        # Other parameters as before...

        [Parameter(Mandatory = $false)]
        [ValidateSet('-Recurse', '-Depth')]
        [string[]]$DepthOptions,

        [Parameter(Mandatory = $false)]
        [int]$MaxDepth = 100
    )

    # Helper: Try to use module's Get-TechToolboxConfig; if not found, fallback to local file.
    function _Get-Config { Get-TechToolboxConfig }

    # ... rest of the script with improved error handling and code organization
}
```

## Source Code
```powershell

function Find-LargeFiles {
    <#
    .SYNOPSIS
    Finds large files recursively and (optionally) exports results to CSV.

    .DESCRIPTION
    Searches under one or more directories for files larger than a minimum size.
    Paths can be provided by parameter, config
    (settings.largeFileSearch.defaultSearchDirectory), or prompt. If -Export is
    specified, results are saved to CSV in the configured export directory
    (settings.largeFileSearch.exportDirectory) or a path you provide.

    .PARAMETER SearchDirectory
    One or more root directories to search. If omitted, will use config or
    prompt.

    .PARAMETER MinSizeMB
    Minimum size threshold in MB. If omitted, will use config
    (settings.largeFileSearch.defaultMinSizeMB) or default of 256.

    .PARAMETER Depth
    Optional maximum recursion depth (PowerShell 7+ only).

    .PARAMETER Export
    When present, exports results to CSV.

    .PARAMETER ExportDirectory
    Override the export directory (otherwise uses
    settings.largeFileSearch.exportDirectory).

    .PARAMETER CsvDelimiter
    Optional CSV delimiter (default ',').

    .EXAMPLE
    Find-LargeFiles -SearchDirectory 'C:\','D:\Shares' -MinSizeMB 512 -Export -Verbose

    .EXAMPLE
    Find-LargeFiles -Export  # uses config search dirs (or prompts) and exports to config exportDirectory

    .NOTES
    Outputs PSCustomObject with FullName and SizeMB. Also writes CSV when
    -Export is used.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] $SearchDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $MinSizeMB,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int] $Depth,

        [Parameter(Mandatory = $false)]
        [switch] $Export,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $ExportDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] $CsvDelimiter = ','
    )

    begin {
        # Helper: Try to use module's Get-TechToolboxConfig; if not found, fallback to local file.
        function _Get-Config {
            $cmd = Get-Command -Name 'Get-TechToolboxConfig' -ErrorAction SilentlyContinue
            if ($cmd) {
                try { return Get-TechToolboxConfig } catch { Write-Verbose "Get-TechToolboxConfig failed: $($_.Exception.Message)" }
            }
            $defaultPath = 'C:\TechToolbox\Config\config.json'
            if (Test-Path -LiteralPath $defaultPath) {
                try {
                    return Get-Content -LiteralPath $defaultPath -Raw | ConvertFrom-Json -ErrorAction Stop
                }
                catch { Write-Verbose "Failed to parse config.json at ${defaultPath}: $($_.Exception.Message)" }
            }
            return $null
        }

        $cfg = _Get-Config

        # Resolve MinSizeMB: param > config > default (256)
        if (-not $PSBoundParameters.ContainsKey('MinSizeMB')) {
            $MinSizeMB = if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['defaultMinSizeMB']) {
                [int]$cfg['settings']['largeFileSearch']['defaultMinSizeMB']
            }
            else {
                256
            }
        }

        # Resolve SearchDirectory: param > config > prompt
        if (-not $SearchDirectory -or $SearchDirectory.Count -eq 0) {
            $fromCfg = @()
            if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['defaultSearchDirectory']) {
                if ($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] -is [string]) {
                    $fromCfg = @($cfg['settings']['largeFileSearch']['defaultSearchDirectory'])
                }
                elseif ($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] -is [System.Collections.IEnumerable]) {
                    $fromCfg = @($cfg['settings']['largeFileSearch']['defaultSearchDirectory'] | ForEach-Object { $_ })
                }
            }
            if ($fromCfg.Count -gt 0) {
                $SearchDirectory = $fromCfg
                Write-Verbose "Using search directories from config: $($SearchDirectory -join '; ')"
            }
            else {
                $inputPath = Read-Host "Enter directories to search (use ';' to separate multiple)"
                $SearchDirectory = $inputPath -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
        }

        # Normalize and validate directories
        $SearchDirectory = $SearchDirectory |
        ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) } |
        ForEach-Object {
            if (-not (Test-Path -LiteralPath $_)) {
                Write-Warning "Path not found: $_ (skipping)"
                $null
            }
            else { $_ }
        } | Where-Object { $_ }

        if (-not $SearchDirectory -or $SearchDirectory.Count -eq 0) {
            throw "No valid search directories were provided."
        }

        $minBytes = [int64]$MinSizeMB * 1MB

        # Resolve ExportDirectory if -Export is used and no override is provided.
        if ($Export -and -not $PSBoundParameters.ContainsKey('ExportDirectory')) {
            if ($cfg -and $cfg['settings'] -and $cfg['settings']['largeFileSearch'] -and $cfg['settings']['largeFileSearch']['exportDirectory']) {
                $ExportDirectory = [string]$cfg['settings']['largeFileSearch']['exportDirectory']
                Write-Verbose "Using export directory from config: $ExportDirectory"
            }
            else {
                throw "Export requested, but 'settings.largeFileSearch.exportDirectory' was not found in config and no -ExportDirectory was provided."
            }
        }

        # Ensure export directory exists if we will export
        if ($Export) {
            try {
                $null = New-Item -ItemType Directory -Path $ExportDirectory -Force -ErrorAction Stop
            }
            catch {
                throw "Failed to ensure export directory '$ExportDirectory': $($_.Exception.Message)"
            }
        }

        # Build output list
        $results = New-Object System.Collections.Generic.List[object]
    }

    process {
        $totalRoots = $SearchDirectory.Count
        $rootIndex = 0

        foreach ($root in $SearchDirectory) {
            $rootIndex++
            Write-Verbose "Scanning $root ($rootIndex of $totalRoots) …"

            try {
                $gciParams = @{
                    Path        = $root
                    File        = $true
                    Recurse     = $true
                    ErrorAction = 'SilentlyContinue'
                    Force       = $true
                }
                if ($PSBoundParameters.ContainsKey('Depth')) {
                    # PowerShell 7+ supports -Depth on Get-ChildItem
                    $gciParams['Depth'] = $Depth
                }

                $count = 0
                Get-ChildItem @gciParams |
                Where-Object { $_.Length -ge $minBytes } |
                Sort-Object Length -Descending |
                ForEach-Object {
                    $count++
                    if ($PSBoundParameters.Verbose) {
                        # Lightweight progress when -Verbose is on
                        Write-Progress -Activity "Scanning $root" -Status "Found $count large files…" -PercentComplete -1
                    }

                    [PSCustomObject]@{
                        FullName = $_.FullName
                        SizeMB   = [math]::Round(($_.Length / 1MB), 2)
                    }
                } | ForEach-Object { [void]$results.Add($_) }

                if ($PSBoundParameters.Verbose) {
                    Write-Progress -Activity "Scanning $root" -Completed
                }
            }
            catch {
                Write-Warning "Error scanning '$root': $($_.Exception.Message)"
            }
        }
    }

    end {
        # Emit combined, globally sorted output to pipeline
        $sorted = $results | Sort-Object SizeMB -Descending
        $sorted

        if ($Export) {
            # Determine filename
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $defaultName = "LargeFiles_${timestamp}.csv"

            $fileName = $defaultName
            if ($cfg -and $cfg.settings -and $cfg.settings.largeFileSearch -and $cfg.settings.largeFileSearch.exportFileNamePattern) {
                $pattern = [string]$cfg.settings.largeFileSearch.exportFileNamePattern
                # Simple token replacement for {yyyyMMdd_HHmmss}
                $fileName = $pattern -replace '\{yyyyMMdd_HHmmss\}', $timestamp
                if ([string]::IsNullOrWhiteSpace($fileName)) { $fileName = $defaultName }
            }

            $exportPath = Join-Path -Path $ExportDirectory -ChildPath $fileName

            try {
                $sorted | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8 -Delimiter $CsvDelimiter -Force
                Write-Host "Exported $($sorted.Count) items to: $exportPath" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to export CSV to '$exportPath': $($_.Exception.Message)"
            }
        }
    }
}

[SIGNATURE BLOCK REMOVED]

```
