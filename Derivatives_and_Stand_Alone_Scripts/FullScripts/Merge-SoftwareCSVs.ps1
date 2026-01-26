
<#
.SYNOPSIS
  Robust merge of per-PC software inventory CSVs (PS7), with delimiter detection and flexible header mapping.

.DESCRIPTION
  - Scans *.csv in -InputDir
  - Auto-detects delimiter (comma, semicolon, tab)
  - Skips leading metadata lines if needed
  - Maps many header variants to normalized fields
  - Dedupes by DeviceName + DisplayName + DisplayVersion + Publisher
  - Emits per-file diagnostics
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$InputDir,
  [Parameter(Mandatory=$true)]
  [string]$OutputDir
)

function New-Folder { param([string]$Path) if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null } }

function Coalesce {
  param([Parameter(ValueFromRemainingArguments=$true)]$Values)
  foreach ($v in $Values) {
    if ($null -ne $v) {
      if ($v -is [string]) { if (-not [string]::IsNullOrWhiteSpace($v)) { return $v } }
      else { return $v }
    }
  }
  return $null
}

function TrimIfString([object]$v) { if ($v -is [string]) { $v.Trim() } else { $v } }

function Find-Delimiter {
  param([string[]]$Lines)
  # Look at the first few non-empty lines to decide
  $candidates = @(',', ';', "`t")
  $scores = @{}
  foreach ($d in $candidates) { $scores[$d] = 0 }
  foreach ($ln in $Lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 5) {
    foreach ($d in $candidates) {
      $scores[$d] += ($ln -split [regex]::Escape($d)).Count
    }
  }
  # Pick delimiter with the highest split count
  $best = $candidates | Sort-Object { -$scores[$_] } | Select-Object -First 1
  if (-not $best) { $best = ',' }
  return $best
}

function Import-AnyCsv {
  param(
    [Parameter(Mandatory=$true)][string]$Path
  )
  # Read raw file (handle different encodings). PS7 usually auto-detects BOM.
  $raw = Get-Content -LiteralPath $Path -Raw
  if ([string]::IsNullOrWhiteSpace($raw)) { return ,@() }

  # Split into lines and attempt to find header line (skip metadata if present)
  $lines = $raw -split "(`r`n|`n|`r)"
  # Find first plausible header: it should contain some of these tokens (case-insensitive)
  $headerHints = @('name','display','product','software','application','version','publisher','company','vendor')
  $startIdx = 0
  for ($i=0; $i -lt [math]::Min($lines.Count, 10); $i++) {
    $ln = $lines[$i]
    if ($headerHints | Where-Object { $ln -match $_ }) { $startIdx = $i; break }
  }
  $usable = $lines[$startIdx..($lines.Count-1)]

  # Detect delimiter on the header + next lines
  $delim = Find-Delimiter -Lines ($usable | Select-Object -First 5)

  # Try import with detected delimiter
  $data = $null
  try {
    $data = ($usable -join "`n") | ConvertFrom-Csv -Delimiter $delim
  } catch {
    $data = $null
  }

  # If single-column results, try other delimiters as fallback
  if ($null -eq $data -or ($data.Count -gt 0 -and ($data[0].PSObject.Properties.Name).Count -le 1)) {
    foreach ($alt in @(',', ';', "`t") | Where-Object { $_ -ne $delim }) {
      try {
        $tryData = ($usable -join "`n") | ConvertFrom-Csv -Delimiter $alt
        if ($tryData.Count -gt 0 -and ($tryData[0].PSObject.Properties.Name).Count -gt 1) {
          $data = $tryData; break
        }
      } catch {}
    }
  }
  if ($null -eq $data) { return ,@() }
  return ,$data
}

function Get-Prop {
  param(
    [Parameter(Mandatory=$true)][psobject]$Row,
    [Parameter(Mandatory=$true)][string[]]$Names
  )
  foreach ($n in $Names) {
    # Support property names with spaces or odd characters
    if ($Row.PSObject.Properties.Match($n).Count -gt 0) {
      $val = $Row.PSObject.Properties[$n].Value
      if ($null -ne $val -and (-not ($val -is [string]) -or -not [string]::IsNullOrWhiteSpace($val))) {
        return $val
      }
    }
  }
  return $null
}

New-Folder -Path $OutputDir
$files = Get-ChildItem -Path $InputDir -Filter *.csv -File -ErrorAction Stop
if (-not $files) { Write-Error "No CSV files found in $InputDir"; exit 1 }

$normalized = @()
$diag = New-Object System.Collections.Generic.List[object]
$total = $files.Count
$idx = 0

# Define header aliases (case-sensitive in property accessor, but we match with exact names likely produced by ConvertFrom-Csv)
$aliases = @{
  DeviceName      = @('DeviceName','PSComputerName','ComputerName','Hostname','Host','Machine','Device','Node')
  DisplayName     = @('DisplayName','Display Name','ProductName','Product Name','Name','Software','Software Name','Application','Application Name','Title')
  DisplayVersion  = @('DisplayVersion','Display Version','Version','Version Number','Product Version')
  Publisher       = @('Publisher','Company','CompanyName','Company Name','Vendor','Vendor Name','Manufacturer')
  InstallDate     = @('InstallDate','Install Date','InstalledOn','Installed On','DateInstalled','Date Installed')
  InstallLocation = @('InstallLocation','Install Location','InstallPath','Install Path','Path','Location')
  UninstallString = @('UninstallString','Uninstall String','UninstallCmd','Uninstall Cmd','Uninstall Command')
  RegistryKey     = @('RegistryKey','PSPath','Registry Path')
  EstimatedSizeKB = @('EstimatedSize','Estimated Size','EstimatedSizeKB','SizeKB','Size KB')
  Architecture    = @('Architecture','Arch','Platform')
  OS              = @('OS','OperatingSystem','Operating System')
}

foreach ($f in $files) {
  $idx++
  $pct = [int](($idx / $total) * 100)
  Write-Progress -Activity "Merging software CSVs" -Status $f.Name -PercentComplete $pct

  # Infer Device from filename (PC14-SoftwareInventory.csv → PC14)
  $deviceFromName = $null
  $base = $f.BaseName
  if ($base -match '^(?<dev>.+?)-_$') { $deviceFromName = $Matches['dev'] }
  if (-not $deviceFromName) { $deviceFromName = $base }

  $rows = @()
  try {
    $rows = Import-AnyCsv -Path $f.FullName
  } catch {
    $rows = @()
  }

  $imported = 0
  $skippedNoName = 0
  $rowErrors = 0

  if ($rows.Count -eq 0) {
    $diag.Add([pscustomobject]@{ File=$f.Name; Rows=0; Imported=0; SkippedNoName=0; RowErrors=0; Note='No rows parsed (delimiter/encoding/metadata?)' })
    continue
  }

  foreach ($row in $rows) {
    try {
      $DeviceName      = Coalesce (Get-Prop $row $aliases.DeviceName) $deviceFromName
      $DisplayName     = Get-Prop $row $aliases.DisplayName
      $DisplayVersion  = Get-Prop $row $aliases.DisplayVersion
      $Publisher       = Get-Prop $row $aliases.Publisher
      $InstallDate     = Get-Prop $row $aliases.InstallDate
      $InstallLocation = Get-Prop $row $aliases.InstallLocation
      $UninstallString = Get-Prop $row $aliases.UninstallString
      $RegistryKey     = Get-Prop $row $aliases.RegistryKey
      $EstimatedSizeKB = Get-Prop $row $aliases.EstimatedSizeKB
      $Architecture    = Get-Prop $row $aliases.Architecture
      $OS              = Get-Prop $row $aliases.OS

      if ([string]::IsNullOrWhiteSpace([string]$DisplayName)) { $skippedNoName++; continue }

      $out = [pscustomobject]@{
        DeviceName      = TrimIfString $DeviceName
        DisplayName     = TrimIfString $DisplayName
        DisplayVersion  = TrimIfString $DisplayVersion
        Publisher       = TrimIfString $Publisher
        InstallDate     = TrimIfString $InstallDate
        InstallLocation = TrimIfString $InstallLocation
        UninstallString = TrimIfString $UninstallString
        RegistryKey     = TrimIfString $RegistryKey
        EstimatedSizeKB = TrimIfString $EstimatedSizeKB
        Architecture    = TrimIfString $Architecture
        OS              = TrimIfString $OS
        SourceFile      = $f.Name
      }
      $normalized += $out
      $imported++
    } catch {
      $rowErrors++
    }
  }

  $diag.Add([pscustomobject]@{
    File          = $f.Name
    Rows          = $rows.Count
    Imported      = $imported
    SkippedNoName = $skippedNoName
    RowErrors     = $rowErrors
    Note          = if ($imported -eq 0) { 'Check delimiter/headers' } else { '' }
  })
}

# Deduplicate
$deduped = $normalized | Group-Object DeviceName, DisplayName, DisplayVersion, Publisher | ForEach-Object {
  $_.Group | Select-Object -First 1
}

# Output
New-Folder -Path $OutputDir
$masterPath = Join-Path $OutputDir "Master_SoftwareInventory.csv"
$countsPath = Join-Path $OutputDir "Master_SoftwareCounts_ByDevice.csv"
$diagPath   = Join-Path $OutputDir "Merge_Diagnostics.csv"

$deduped | Sort-Object DeviceName, DisplayName, DisplayVersion | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $masterPath
($deduped | Group-Object DeviceName | Sort-Object Name | ForEach-Object {
  [pscustomobject]@{ DeviceName = $_.Name; SoftwareCount = $_.Count }
}) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $countsPath

$diag | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $diagPath

Write-Progress -Activity "Merging software CSVs" -Completed
Write-Host "[*] Wrote:" -ForegroundColor Green
Write-Host "    $masterPath"
Write-Host "    $countsPath"
Write-Host "    $diagPath"
