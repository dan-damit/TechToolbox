# Set defaults if not provided
if (-not $OldServer) { $OldServer = "E10-REPORT-1" }
if (-not $NewServer) { $NewServer = "PRINTSRV-1" }

$oldPrefix = "\\$OldServer\"
$diagnosticFile = "$env:TEMP\PrinterMigration_Debug.txt"

# Capture current default printer connection
$defaultConn = $null
$defaultWmi = Get-CimInstance -ClassName Win32_Printer -Filter "Default = TRUE" -ErrorAction SilentlyContinue
if ($defaultWmi -and $defaultWmi.Name) {
    if ($defaultWmi.Name -like "\\*\*") {
        $defaultConn = $defaultWmi.Name
    }
}

# Get printers connected from old server
$allPrinters = Get-CimInstance -ClassName Win32_Printer -ErrorAction SilentlyContinue
$allConnectionNames = @($allPrinters | Where-Object { $_.Name -like "\\*\*" } | Select-Object -ExpandProperty Name)
$oldPrinters = @($allPrinters | Where-Object { $_.Name -like "$oldPrefix*" })
$matchingConnectionNames = @($oldPrinters | Select-Object -ExpandProperty Name)

# Diagnostic output
"User: $env:USERDOMAIN\$env:USERNAME" | Out-File $diagnosticFile
"Computer: $env:COMPUTERNAME" | Out-File $diagnosticFile -Append
"All Printers: $($allConnectionNames -join '; ')" | Out-File $diagnosticFile -Append
"Old Server Prefix: $oldPrefix" | Out-File $diagnosticFile -Append
"Matching Printers: $($matchingConnectionNames -join '; ')" | Out-File $diagnosticFile -Append

if (-not $oldPrinters) {
    return
}

# Determine if we need to restore default printer after migration
$setDefaultTo = $null
if ($defaultConn -like "$oldPrefix*") {
    $defaultShare = $defaultConn -replace "^\\\\$OldServer\\", ""
    $setDefaultTo = "\\$NewServer\$defaultShare"
}

# Migrate each printer
foreach ($p in $oldPrinters) {
    $oldConn = $p.Name
    $share = $oldConn -replace "^\\\\$OldServer\\", ""
    $newConn = "\\$NewServer\$share"

    rundll32 printui.dll,PrintUIEntry /q /dn /n "$oldConn" | Out-Null
    Add-Printer -ConnectionName "$newConn" | Out-Null
}

# Restore default printer if it was migrated
if ($setDefaultTo) {
    rundll32 printui.dll,PrintUIEntry /q /y /n "$setDefaultTo" | Out-Null
}

