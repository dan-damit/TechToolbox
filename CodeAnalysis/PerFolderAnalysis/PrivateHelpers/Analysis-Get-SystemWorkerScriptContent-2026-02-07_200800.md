# Code Analysis Report
Generated: 2/7/2026 8:08:00 PM

## Summary
 The provided PowerShell script, named `Get-SystemWorkerScriptContent`, is designed to collect system information and logs related to PDQ Deploy and PDQ Inventory. Here are some suggestions for enhancing its functionality, readability, and performance:

1. Modularize the script: Break down the script into smaller functions for better organization and reusability. For example, separate the functions that collect service information, registry data, and system metadata into their own functions.

2. Error handling: Implement a more structured error handling mechanism using try-catch blocks throughout the script to handle exceptions more gracefully. This will make it easier to identify and debug issues when they occur.

3. Variable naming: Use more descriptive variable names that clearly indicate their purpose, which will improve readability and maintainability. For example, `$cfgRaw` could be renamed to something like `$systemConfigRawData`.

4. Documentation: Add comments throughout the script explaining what each section does, as well as any assumptions or requirements for using the function. This will help other developers understand the code more easily.

5. Code formatting: Apply consistent formatting across the entire script to make it easier to read and maintain. This includes indenting code blocks consistently, adding blank lines between sections, and using descriptive variable names.

6. Logging: Implement a logging mechanism that provides detailed information about the actions performed by the script. This will help in debugging and auditing purposes.

7. Parameter validation: Validate input parameters for the function to ensure they are valid before processing them. This can help prevent issues caused by invalid or unexpected data.

8. Performance optimization: Use PowerShell optimizations like pipelining, parallel processing, and caching where appropriate to improve performance. For example, instead of using `if ($cfgRaw)`, you could use the `-and` operator for a more readable and performant alternative: `if ($cfgRaw -and $cfgRaw.Length -gt 0)`.

9. Testing: Write unit tests for the functions to ensure they behave as expected under various conditions. This will help catch issues early in the development process and make it easier to maintain the code over time.

10. Input validation: Validate the input file format (JSON) and structure when reading the configuration file, to avoid potential errors or unexpected behavior due to incorrect input.

By implementing these suggestions, you can significantly improve the functionality, readability, and performance of your PowerShell script.

## Source Code
```powershell
function Get-SystemWorkerScriptContent {
    @'
param(
  [string]$ArgsPath
)

$ErrorActionPreference = 'Stop'

# Read args
$cfgRaw = if ($ArgsPath -and (Test-Path -LiteralPath $ArgsPath -ErrorAction SilentlyContinue)) {
  Get-Content -LiteralPath $ArgsPath -Raw -Encoding UTF8
} else { $null }

$cfg = if ($cfgRaw) { $cfgRaw | ConvertFrom-Json } else { $null }

# Extract settings
$timestamp       = if ($cfg.Timestamp) { [string]$cfg.Timestamp } else { (Get-Date -Format 'yyyyMMdd-HHmmss') }
$connectPath     = if ($cfg.ConnectDataPath) { [string]$cfg.ConnectDataPath } else { (Join-Path $env:ProgramData 'PDQ\PDQConnectAgent') }
$extra           = @()
if ($cfg.ExtraPaths) {
  # Ensure array type after deserialization
  if ($cfg.ExtraPaths -is [string]) { $extra = @($cfg.ExtraPaths) }
  elseif ($cfg.ExtraPaths -is [System.Collections.IEnumerable]) { $extra = @($cfg.ExtraPaths) }
}

# Paths
$tempRoot = Join-Path $env:windir 'Temp'
$staging  = Join-Path $tempRoot ("PDQDiag_{0}_{1}" -f $env:COMPUTERNAME,$timestamp)
$zipPath  = Join-Path $tempRoot ("PDQDiag_{0}_{1}.zip" -f $env:COMPUTERNAME,$timestamp)
$doneFlg  = Join-Path $staging 'system_done.flag'

# Clean & create staging
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

# Build PDQ paths
$pdqPaths = @(
  'C:\ProgramData\Admin Arsenal\PDQ Deploy\Logs'
  'C:\ProgramData\Admin Arsenal\PDQ Inventory\Logs'
  'C:\Windows\Temp\PDQDeployRunner'
  'C:\Windows\Temp\PDQInventory'
  (Join-Path $env:SystemRoot 'System32\Winevt\Logs\PDQ.com.evtx')  # fallback; we'll export via wevtutil too
)
if ($connectPath) {
  $pdqPaths += (Join-Path $connectPath 'PDQConnectAgent.db')
  $pdqPaths += (Join-Path $connectPath 'Updates\install.log')
}

# Normalize extras (PS 5.1-safe)
$extras = if ($null -eq $extra -or -not $extra) { @() } else { $extra }

# Resilient copy helper (Copy-Item → robocopy /B)
function Copy-PathResilient {
  param([string]$SourcePath,[string]$StagingRoot)

  if (-not (Test-Path -LiteralPath $SourcePath -ErrorAction SilentlyContinue)) { return $false }

  $leaf = Split-Path -Leaf $SourcePath
  $dest = Join-Path $StagingRoot $leaf

  try {
    $it = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if ($it -is [IO.DirectoryInfo]) {
      New-Item -ItemType Directory -Path $dest -Force | Out-Null
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Recurse -Force -ErrorAction Stop
    } else {
      Copy-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
    }
    return $true
  } catch {
    $primary = $_.Exception.Message
    try {
      $rc = Get-Command robocopy.exe -ErrorAction SilentlyContinue
      if (-not $rc) { throw "robocopy.exe not found" }
      $it2 = Get-Item -LiteralPath $SourcePath -ErrorAction SilentlyContinue
      if ($it2 -is [IO.DirectoryInfo]) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        $null = & $rc.Source $SourcePath $dest /E /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      } else {
        $srcDir = Split-Path -Parent $SourcePath
        $file   = Split-Path -Leaf   $SourcePath
        New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null
        $null = & $rc.Source $srcDir $StagingRoot $file /R:0 /W:0 /NFL /NDL /NJH /NJS /NS /NP /COPY:DAT /B
      }
      if ($LASTEXITCODE -lt 8) { return $true }
      Add-Content -Path $copyErr -Value ("{0} | robocopy exit {1} | {2}" -f (Get-Date), $LASTEXITCODE, $SourcePath) -Encoding UTF8
      return $false
    } catch {
      Add-Content -Path $copyErr -Value ("{0} | Copy failed: {1} | {2}" -f (Get-Date), $primary, $SourcePath) -Encoding UTF8
      return $false
    }
  }
}

# Merge non-empty paths (no pre-Test-Path to avoid "Access denied" noise)
$all = @($pdqPaths; $extras) | Where-Object { $_ } | Select-Object -Unique
foreach ($p in $all) { try { Copy-PathResilient -SourcePath $p -StagingRoot $staging } catch {} }

# Export event log by name (avoids in-use copy issues)
try {
  $destEvtx = Join-Path $staging 'PDQ.com.evtx'
  if (-not (Test-Path -LiteralPath $destEvtx -ErrorAction SilentlyContinue)) {
    $logName = 'PDQ.com'
    $wevt = Join-Path $env:windir 'System32\wevtutil.exe'
    if ($env:PROCESSOR_ARCHITEW6432 -or $env:ProgramW6432) {
      $sysnative = Join-Path $env:windir 'Sysnative\wevtutil.exe'
      if (Test-Path -LiteralPath $sysnative) { $wevt = $sysnative }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $wevt
    $psi.Arguments = "epl `"$logName`" `"$destEvtx`""
    $psi.CreateNoWindow = $true
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [Diagnostics.Process]::Start($psi); $p.WaitForExit()
    if ($p.ExitCode -ne 0) {
      $err = $p.StandardError.ReadToEnd()
      Add-Content -Path $copyErr -Value ("{0} | wevtutil failed ({1}): {2}" -f (Get-Date), $p.ExitCode, $err) -Encoding UTF8
    }
  }
} catch {
  Add-Content -Path $copyErr -Value ("{0} | wevtutil exception: {1}" -f (Get-Date), $_.Exception.Message) -Encoding UTF8
}

# Useful metadata
try {
  Get-CimInstance Win32_Service |
    Where-Object { $_.Name -like 'PDQ*' -or $_.DisplayName -like '*PDQ*' } |
    Select-Object Name,DisplayName,State,StartMode |
    Export-Csv -Path (Join-Path $staging 'services.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' |
    Where-Object { $_.DisplayName -match 'PDQ' -or $_.Publisher -match 'Admin Arsenal' } |
    Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
    Export-Csv -Path (Join-Path $staging 'installed.csv') -NoTypeInformation -Encoding UTF8
} catch {}
try {
  $sys = Get-ComputerInfo -ErrorAction SilentlyContinue
  if ($sys) { $sys | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $staging 'computerinfo.json') -Encoding UTF8 }
  $PSVersionTable | Out-String | Set-Content -Path (Join-Path $staging 'psversion.txt') -Encoding UTF8
} catch {}

# Zip
if (Test-Path $zipPath) { Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $zipPath -Force

# Done flag
"ZipPath=$zipPath" | Set-Content -Path $doneFlg -Encoding UTF8
'@
}

[SIGNATURE BLOCK REMOVED]

```
