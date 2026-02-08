# Code Analysis Report
Generated: 2/7/2026 5:39:41 PM

## Summary
 The PowerShell script you've provided signs all .ps1 and .psm1 scripts in a user-provided directory using a specific code signing certificate. Here are some suggestions to improve the code's functionality, readability, and performance:

1. **Error handling**: Currently, there is no centralized error handling mechanism. I recommend creating a custom `Write-Error` function or modifying existing functions to output detailed error messages with stack traces for better debugging.

2. **Function organization**: Break the script into smaller functions for easier maintenance and readability. For example, separate the configuration, error handling, input validation, and file processing logic into distinct functions.

3. **Use parameters more consistently**: Use `[Parameter()]` attribute on all function parameters for better parameter discovery and intellisense support.

4. **Input validation**: Perform more stringent input validation for the thumbprint and directory path to prevent potential security issues and improve user experience.

5. **Help messages**: Add detailed help messages for each parameter, using the `.SYNOPSIS`, `.DESCRIPTION`, `.EXAMPLE`, and other help tags to make it easier for users to understand how to use your script.

6. **Parameter Prompts**: Instead of manually prompting the user for input, consider using a param block with prompts defined for each parameter (using the `[string]$ScriptDirectory` example). This makes the code more modular and self-explanatory.

7. **Code Comments**: Improve code comments throughout the script to make it easier for others to understand your implementation. Consider adding explanations for non-obvious sections of the code and including a summary of what each function does at the beginning.

8. **Use Constants for Certificate Paths**: If the certificate path is hardcoded, consider moving it into a constant or config file for easier management and deployment.

9. **Consider using PowerShell modules**: Organize your script into a PowerShell module with custom cmdlets to improve reusability and integration with other scripts.

10. **Optimization**: Optimize the performance of the script by caching the certificate object or skipping files that have already been signed if the `$SkipValidSigs` parameter is set to false.

Overall, these suggestions should help improve the functionality, readability, and maintainability of your PowerShell script while also making it easier for other users to understand and utilize your code.

## Source Code
```powershell

<#
.SYNOPSIS
    Signs all .ps1 scripts in a user-provided directory using a fixed code
    signing certificate from Cert:\CurrentUser\My, identified by thumbprint.

.DESCRIPTION
    - Prompts for the target script directory.
    - Optionally recurses through subfolders.
    - Signs with SHA256. Optional timestamp server.
    - Skips already validly signed files (optional).
    - Outputs per-file status and a final summary.
.PARAMETER Thumb
    The thumbprint of the code signing certificate to use.
.PARAMETER TimestampServer
    Optional URL of a timestamp server to use when signing.
.PARAMETER ScriptDirectory
    The directory containing .ps1/.psm1 scripts to sign. If not provided,
    prompts the user.
.PARAMETER Recurse
    If specified, recurses into subfolders to find scripts.
.PARAMETER SkipValidSigs
    If specified, skips scripts that are already validly signed.
.EXAMPLE
    Update-SignScriptsByThumbprint -Thumb '7168509FC1A2AE7AFC4C40342D6A8FED7413029C' -ScriptDirectory 'C:\TechToolbox\Scripts' -Recurse

    Signs all .ps1 and .psm1 scripts in C:\TechToolbox\Scripts and its subfolders,
    using the specified certificate thumbprint, skipping already validly signed files.
.INPUTS
    None. You cannot pipe objects to this function.
.OUTPUTS
    None. Output is written to the console.
.NOTES
    Author: Dan.Damit (https://github.com/dan-damit) Requires: PowerShell 5.1+
    (Set-AuthenticodeSignature), cert with private key in CurrentUser\My.
.LINK
[Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature)
#>
param(
    [string]$ScriptDirectory,
    [switch]$Recurse,
    [switch]$SkipValidSigs
)

# --- Configuration: fixed thumbprint for VADTEK Code Signing cert ---
$Thumbprint = '7168509FC1A2AE7AFC4C40342D6A8FED7413029C'

function Get-CodeSigningCertByThumbprint {
    param(
        [Parameter(Mandatory = $true)][string]$Thumb
    )

    # Look in CurrentUser\My
    $cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $Thumb }

    # Fallback to LocalMachine\My
    if (-not $cert) {
        $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumb }
    }

    if (-not $cert) {
        Write-Error "Signing certificate with thumbprint $Thumb was not found."
        return $null
    }

    if (-not $cert.HasPrivateKey) {
        Write-Error "Found certificate but it has NO private key. Re-import the PFX."
        return $null
    }

    Write-Host ("Using certificate: {0} | Thumbprint: {1} | Expires: {2}" -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter) -ForegroundColor Cyan
    return $cert
}

function Update-SignScriptsByThumbprint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumb,

        [string]$TimestampServer = 'http://timestamp.digicert.com',

        [string]$ScriptDirectory,
        [switch]$Recurse,
        [switch]$SkipValidSigs
    )

    # --- Resolve Script Directory ---
    if (-not $ScriptDirectory) {
        do {
            $dirInput = Read-Host "Enter the directory containing .ps1 scripts"
            if ([string]::IsNullOrWhiteSpace($dirInput)) {
                Write-Host "Directory cannot be empty." -ForegroundColor Yellow
                continue
            }

            $resolved = Resolve-Path -LiteralPath $dirInput -ErrorAction SilentlyContinue
            if ($resolved) {
                $ScriptDirectory = $resolved.Path
            }
            else {
                Write-Host "Path not found. Please enter a valid directory." -ForegroundColor Yellow
                $ScriptDirectory = $null
            }
        } while (-not $ScriptDirectory)
    }
    else {
        $resolved = Resolve-Path -LiteralPath $ScriptDirectory -ErrorAction SilentlyContinue
        if ($resolved) {
            $ScriptDirectory = $resolved.Path
        }
        else {
            throw "ScriptDirectory '$ScriptDirectory' does not exist."
        }
    }

    # --- Recurse Prompt ---
    if (-not $PSBoundParameters.ContainsKey('Recurse')) {
        $recurseInput = Read-Host "Recurse into subfolders? (Y/N) [Default: N]"
        if ($recurseInput -match '^(?i)y(es)?$') { $Recurse = $true }
    }

    # --- Skip Valid Signatures Prompt ---
    if (-not $PSBoundParameters.ContainsKey('SkipValidSigs')) {
        $skipInput = Read-Host "Skip scripts already validly signed? (Y/N) [Default: Y]"
        if ($skipInput -match '^(?i)n(o)?$') {
            $SkipValidSigs = $false
        }
        else {
            $SkipValidSigs = $true
        }
    }

    # --- Find Scripts ---
    $searchParams = @{
        Path    = "$ScriptDirectory\*"
        Include = '*.ps1', '*.psm1'
        File    = $true
    }
    if ($Recurse) { $searchParams['Recurse'] = $true }

    $scripts = Get-ChildItem @searchParams

    if (-not $scripts -or $scripts.Count -eq 0) {
        Write-Host "No .ps1 or .psm1 files found in the selected path." -ForegroundColor Yellow
        return
    }

    Write-Host ("Found {0} script(s) to sign." -f $scripts.Count) -ForegroundColor Cyan

    # --- Get Certificate ---
    $cert = Get-CodeSigningCertByThumbprint -Thumb $Thumb
    if (-not $cert) { return }

    $success = 0
    $skipped = 0
    $failed = 0

    foreach ($file in $scripts) {
        try {
            if ($SkipValidSigs) {
                $sig = Get-AuthenticodeSignature -FilePath $file.FullName
                if ($sig.Status -eq 'Valid') {
                    Write-Host ("[SKIP] {0} -> already validly signed." -f $file.FullName) -ForegroundColor DarkYellow
                    $skipped++
                    continue
                }
            }

            $params = @{
                FilePath      = $file.FullName
                Certificate   = $cert
                HashAlgorithm = 'SHA256'
            }
            if ($TimestampServer) { $params['TimestampServer'] = $TimestampServer }

            $result = Set-AuthenticodeSignature @params

            if ($result.Status -eq 'Valid') {
                Write-Host ("[OK] {0}" -f $file.FullName) -ForegroundColor Green
                $success++
            }
            else {
                Write-Host ("[WARN] {0} -> Status: {1} | {2}" -f $file.FullName, $result.Status, $result.StatusMessage) -ForegroundColor Yellow
                if ($result.SignerCertificate -and $result.SignerCertificate.NotAfter -lt (Get-Date)) {
                    Write-Host "   ❗ Certificate appears expired." -ForegroundColor Red
                }
                $failed++
            }
        }
        catch {
            Write-Host ("[ERROR] {0} -> {1}" -f $file.FullName, $_.Exception.Message) -ForegroundColor Red
            $failed++
        }
    }

    Write-Host "----------------------------------------"
    Write-Host ("Signing complete. Success: {0} | Skipped: {1} | Failed/Warnings: {2}" -f $success, $skipped, $failed) -ForegroundColor Cyan

    $ep = Get-ExecutionPolicy
    Write-Host ("`nCurrent execution policy: {0}. Ensure it allows running signed scripts (e.g., RemoteSigned or AllSigned)." -f $ep) -ForegroundColor DarkCyan
}

# --- Run ---
Update-SignScriptsByThumbprint -Thumb $Thumbprint -ScriptDirectory $ScriptDirectory -Recurse:$Recurse -SkipValidSigs:$SkipValidSigs
[SIGNATURE BLOCK REMOVED]

```
