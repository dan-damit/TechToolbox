# Code Analysis Report
Generated: 2/7/2026 8:06:15 PM

## Summary
 The provided PowerShell script, `Get-BatteryReportHtml`, parses battery report HTML and returns battery objects. Here are some suggestions to enhance its functionality, readability, and performance:

1. Use constants for pattern matching: Instead of defining the patterns directly in the script, consider creating constant variables at the beginning of the script for better organization and easier maintenance.

2. Add error handling: Incorporate try-catch blocks to handle exceptions that might occur during the parsing process. This can make the code more robust by preventing it from crashing when encountering unexpected HTML structures or invalid input.

3. Use functions: Break down large, complex functions into smaller, reusable ones for better readability and modularity. For example, separate the pattern matching logic into a separate function.

4. Improve variable naming: Follow a consistent naming convention for variables to make the script more readable. Avoid abbreviations or short names and choose descriptive names instead.

5. Consider using Select-Xml: If possible, consider using the built-in PowerShell `Select-Xml` cmdlet instead of regular expressions (regex) for parsing XML content, as it may provide better performance and ease of use for working with structured data like HTML tables.

6. Use comments effectively: Add comments to explain complex logic or the purpose of each section in the script, making it easier for others to understand your code.

7. Avoid using `Format-Text` inside loops: Using `Format-Text` inside a loop can slow down the performance significantly due to the creation and disposal of strings. Instead, consider concatenating strings or building an array of string fragments first before converting it into a single string at the end.

8. Add validation for input HTML: Check if the input HTML is valid XML or well-formed HTML before processing it. This can help avoid errors that might occur when parsing malformed HTML.

9. Use PowerShell 7+ features: If possible, use PowerShell 7+ features like multi-line strings (```) for better readability and easier code management.

10. Avoid using `ConvertTo-mWh` function inside the loop: Move the conversion of capacity values to mWh outside of the loop to avoid repeated computations and improve performance.

Here is an example of how the improved script might look like:

```powershell
constant BATTERY_PATTERN = '(?is)<h[1-6][^>]*>.*?Installed\W+Batter(?:y|ies).*?</h[1-6]>.*?<table\b[^>]*>(.*?)</table>'
constant TABLE_PATTERN = '(?is)<table\b[^>]*>(.*?)</table>'
constant START_KEYS = @('manufacturer', 'serialNumber', 'name', 'batteryName')

function Get-BatteryReportHtml {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Html
    )

    # ... (The rest of the script, with modifications as suggested above)
}
```

## Source Code
```powershell

function Get-BatteryReportHtml {
    <#
    .SYNOPSIS
        Parses the battery report HTML and returns battery objects + optional
        debug text.
    .OUTPUTS
        [object[]], [string]  # batteries array, debug text (headings) when
        table detection fails
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Html
    )

    $htmlNorm = $Html -replace "`r`n", "`n" -replace "\t", " "
    $installedPattern = '(?is)<h[1-6][^>]*>.*?Installed\W+Batter(?:y|ies).*?</h[1-6]>.*?<table\b[^>]*>(.*?)</table>'
    $sectionMatch = [regex]::Match($htmlNorm, $installedPattern)

    # Fallback: detect table by typical labels if heading not found
    if (-not $sectionMatch.Success) {
        $tableMatches = [regex]::Matches($htmlNorm, '(?is)<table\b[^>]*>(.*?)</table>')
        foreach ($tm in $tableMatches) {
            if ($tm.Value -match '(?is)(Design\s+Capacity|Full\s+Charge\s+Capacity|Chemistry|Serial|Manufacturer)') {
                $sectionMatch = $tm
                break
            }
        }
    }

    if (-not $sectionMatch.Success) {
        # Gather headings for debug
        $headings = [regex]::Matches($htmlNorm, '(?is)<h[1-6][^>]*>(.*?)</h[1-6]>') | ForEach-Object {
            Format-Text $_.Groups[1].Value
        }
        return @(), ($headings -join [Environment]::NewLine)
    }

    $tableHtml = $sectionMatch.Value
    $tbodyMatch = [regex]::Match($tableHtml, '(?is)<tbody\b[^>]*>(.*?)</tbody>')
    $rowsHtml = if ($tbodyMatch.Success) { $tbodyMatch.Groups[1].Value } else { $tableHtml }
    $rowMatches = [regex]::Matches($rowsHtml, '(?is)<tr\b[^>]*>(.*?)</tr>')
    if ($rowMatches.Count -eq 0) { return @(), $null }

    $batteries = New-Object System.Collections.Generic.List[object]
    $current = [ordered]@{}
    $startKeys = @('manufacturer', 'serialNumber', 'name', 'batteryName')

    foreach ($rm in $rowMatches) {
        $rowInner = $rm.Groups[1].Value
        $cellMatches = [regex]::Matches($rowInner, '(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>')
        if ($cellMatches.Count -eq 0) { continue }

        if ($cellMatches.Count -eq 2) {
            # Key-value row
            $label = Format-Text $cellMatches[0].Groups[1].Value
            $value = Format-Text $cellMatches[1].Groups[1].Value         
            if (-not [string]::IsNullOrWhiteSpace($label)) {
                $key = Move-ToCamelKey -Label $label
            }

            # Detect start of a new battery when a "start key" repeats
            if ($startKeys -contains $key -and $current.Contains($key)) {
                # finalize previous battery with parsed capacities
                $dc = if ($current.Contains('designCapacity')) { ConvertTo-mWh $current['designCapacity'] } else { $null }
                $fc = if ($current.Contains('fullChargeCapacity')) { ConvertTo-mWh $current['fullChargeCapacity'] } else { $null }
                if ($dc -and $fc -and $dc -gt 0) {
                    $current['designCapacity_mWh'] = $dc
                    $current['fullChargeCapacity_mWh'] = $fc
                    $current['healthRatio'] = [math]::Round($fc / $dc, 4)
                    $current['healthPercent'] = [math]::Round(($fc * 100.0) / $dc, 2)
                }
                $batteries.Add([PSCustomObject]$current)
                $current = [ordered]@{}
            }
            $current[$key] = $value
        }
        else {
            # Multi-column row: capture as raw values
            $vals = @()
            foreach ($cm in $cellMatches) { $vals += (Format-Text $cm.Groups[1].Value) }
            if ($vals.Count -gt 0) {
                if (-not $current.Contains('rows')) {
                    $current['rows'] = New-Object System.Collections.Generic.List[object]
                }
                $current['rows'].Add($vals)
            }
        }
    }

    # finalize last battery
    if ($current.Count -gt 0) {
        $dc = if ($current.Contains('designCapacity')) { ConvertTo-mWh $current['designCapacity'] } else { $null }
        $fc = if ($current.Contains('fullChargeCapacity')) { ConvertTo-mWh $current['fullChargeCapacity'] } else { $null }
        if ($dc -and $fc -and $dc -gt 0) {
            $current['designCapacity_mWh'] = $dc
            $current['fullChargeCapacity_mWh'] = $fc
            $current['healthRatio'] = [math]::Round($fc / $dc, 4)
            $current['healthPercent'] = [math]::Round(($fc * 100.0) / $dc, 2)
        }
        $batteries.Add([PSCustomObject]$current)
    }

    return , $batteries, $null
}

[SIGNATURE BLOCK REMOVED]

```
