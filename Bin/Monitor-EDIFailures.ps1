# Monitor-EDIFailures.ps1
# Monitors an Outlook inbox subfolder for EDI failure reports, extracts key info
# from attached PDFs, and logs to CSV.
#
# Author: (https://github.com/dan-damit)

[CmdletBinding()]
param(
    [string]$OutCsv,
    [string]$InboxSubFolder = "EDI Failures",
    [string]$ProcessedSubFolder = "Processed"
)

if (-not $PSBoundParameters.ContainsKey('OutCsv') -or [string]::IsNullOrWhiteSpace($OutCsv)) {
    $logsRoot = if ($env:TT_LogsRoot) { $env:TT_LogsRoot } else { 'C:\TechToolbox_LogsAndExports\Logs' }
    $OutCsv = Join-Path $logsRoot 'EDI_Failures\EDI_Failures.csv'
}

function Get-RegexGroup {
    param(
        [string]$Text,
        [string]$Pattern,
        [int]$Group = 1
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $m = [regex]::Match($Text, $Pattern, 'IgnoreCase')
    if ($m.Success -and $m.Groups.Count -gt $Group) { return $m.Groups[$Group].Value.Trim() }
    return $null
}

function Get-PdfText {
    param([Parameter(Mandatory)][string]$PdfPath)

    $scriptPath = Join-Path $env:TEMP "extract_pdf_text_pypdf2.py"

    # Create the python helper once (or overwrite; it's tiny)
    @'
import sys
from PyPDF2 import PdfReader

path = sys.argv[1]
reader = PdfReader(path)
out = []
for p in reader.pages:
    try:
        out.append(p.extract_text() or "")
    except Exception:
        out.append("")
print("\n".join(out))
'@ | Set-Content -Path $scriptPath -Encoding UTF8

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "python"
    $psi.Arguments = "`"$scriptPath`" `"$PdfPath`""
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($p.ExitCode -ne 0) {
        throw "PDF text extraction failed for '$PdfPath': $stderr"
    }

    return $stdout
}

# Ensure output folder exists
$null = New-Item -ItemType Directory -Path (Split-Path $OutCsv) -Force -ErrorAction SilentlyContinue

# Outlook COM (Classic Outlook required)
$outlook = New-Object -ComObject Outlook.Application
$ns = $outlook.GetNamespace("MAPI")

$inbox = $ns.GetDefaultFolder(6) # olFolderInbox
$ediFolder = $inbox.Folders.Item($InboxSubFolder)

# Create/ensure Processed subfolder
$processedFolder = $null
try { $processedFolder = $ediFolder.Folders.Item($ProcessedSubFolder) } catch {}
if (-not $processedFolder) { $processedFolder = $ediFolder.Folders.Add($ProcessedSubFolder) }

# Pull newest first
$items = $ediFolder.Items
$items.Sort("[ReceivedTime]", $true)

# Process unread items (or you can remove this filter and instead use folder move as idempotency)
foreach ($item in @($items)) {

    try {
        if ($item.Class -ne 43) { continue } # MailItem
        if ($item.UnRead -ne $true) { continue }
        if ($item.Subject -notlike "*EDI Data with Error Notes*") { continue }

        $rows = @()

        foreach ($att in @($item.Attachments)) {
            # Only process PDFs
            if ($att.FileName -notmatch "\.pdf$") { continue }

            $tempPath = Join-Path $env:TEMP $att.FileName
            $att.SaveAsFile($tempPath)

            $pdfText = $null
            try {
                $pdfText = Get-PdfText -PdfPath $tempPath
            }
            finally {
                Remove-Item $tempPath -ErrorAction SilentlyContinue
            }

            # Parse fields (these patterns match report format)
            $partner = Get-RegexGroup $pdfText "Trading Partner:\s*([^\r\n]+)"
            $tset = Get-RegexGroup $pdfText "T-Set:\s*(\d+)"
            $ship = Get-RegexGroup $pdfText "Shipment ID:\s*(\d+)"

            $mapError = Get-RegexGroup $pdfText "Mapping Error:\s*'([^']+)'"   # quoted
            if (-not $mapError) {
                $mapError = Get-RegexGroup $pdfText "Mapping Error:\s*([^\r\n]+)"
            }

            if (-not $mapError -and $pdfText -match "Transaction will not be sent") {
                $mapError = "Transaction will not be sent (reason not captured)"
            }

            if (-not $mapError) {
                # Required-field / missing data cases
                $mapError = Get-RegexGroup $pdfText "(mandatory.*missing[^\r\n]*)"
            }

            if (-not $mapError) {
                # Abort-style failures
                $mapError = Get-RegexGroup $pdfText "(triggered Abort[^\r\n]*)"
            }

            if (-not $mapError) {
                # Specific LIN03 missing
                $mapError = Get-RegexGroup $pdfText "(Data element\s+'LIN03'.*?mandatory.*?missing[^\r\n]*)"
            }

            if (-not $mapError) {
                # General LIN segment error
                $mapError = Get-RegexGroup $pdfText "(The\s+'LIN'\s+segment.*?element\s+errors[^\r\n]*)"
            }

            # Final fallback
            if (-not $mapError) {
                $mapError = "Unknown"
            }

            $failureType = switch -Regex ($mapError) {
                "LIN03" { "MissingLIN03"; break }
                "mandatory.*missing" { "MissingRequiredField"; break }
                "Smart Condition" { "SmartConditionAbort"; break }
                "triggered Abort" { "AbortCondition"; break }
                "Transaction will not be sent" { "SuppressedTransaction"; break }
                default { "Other" }
            }

            $rows += [pscustomobject]@{
                Time        = $item.ReceivedTime
                Partner     = $partner
                TSet        = $tset
                Shipment    = $ship
                FailureType = $failureType
                Subject     = $item.Subject
            }
        }

        # Write results if any attachments are parsed
        if ($rows.Count -gt 0) {
            $rows | Export-Csv -Path $OutCsv -Append -NoTypeInformation
        }

        # Mark processed and move
        $item.UnRead = $false
        $null = $item.Move($processedFolder)
    }
    catch {
        # Don’t fail the whole run — tag the message so it can be reviewed later
        try { $item.Categories = "EDI-ParseFailed" } catch {}
        try { $item.UnRead = $false } catch {}
        # write a minimal line to CSV so you know it errored
        [pscustomobject]@{
            Time        = $item.ReceivedTime
            Partner     = ""
            TSet        = ""
            Shipment    = ""
            FailureType = "ParseFailed"
            Subject     = $item.Subject
        } | Export-Csv -Path $OutCsv -Append -NoTypeInformation
    }
}
