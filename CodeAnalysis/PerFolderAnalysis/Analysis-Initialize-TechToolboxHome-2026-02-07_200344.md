# Code Analysis Report
Generated: 2/7/2026 8:03:44 PM

## Summary
 The PowerShell script provided initializes a TechToolbox home directory by copying the contents of a source folder, potentially overwriting existing files. Here are some observations and suggestions for improvements:

1. **Variable Naming**: Some variable names could be more descriptive to make the code easier to understand. For example, `$src` and `$home` are used as shorthand for "source" and "home", respectively. Using `$sourcePath` and `$targetPath` would improve readability.

2. **Error Handling**: While the script does handle some errors, it could benefit from more robust error handling. For example, if a file is missing during the copy process, the script only checks for robocopy's exit code. It might be better to capture specific exceptions and log them for debugging purposes.

3. **Input Validation**: The script currently does not validate the input parameters (`$HomePath`, `$SourcePath`, `$Force`, and `$Quiet`) beyond checking if they are strings. Adding additional validation checks such as ensuring that paths exist, are valid directories, or are accessible by the current user could help prevent issues during execution.

4. **Code Formatting**: The code formatting could be improved to follow PowerShell best practices, such as using consistent spacing and indentation, and adding comments to explain complex logic or parts of the script that may not be immediately obvious. This would make the script easier for others to understand and modify in the future.

5. **Documentation**: Adding comments throughout the script to explain what each section does would greatly improve readability for other developers who might need to work with or maintain the code.

6. **Function Organization**: Consider breaking the function down into smaller, more manageable functions to improve modularity and testability. For example, a separate function for determining the source path, another for checking if the installation is already present, and so on. This would make the script easier to modify and extend in the future.

7. **Logging**: Implementing proper logging would help with debugging and tracking changes during development and production use. This could include logging user input, status updates, and errors to a file or console.

8. **Help Documentation**: Adding help documentation (using PowerShell's built-in comment-based help system) would make it easier for users to understand how to use the script. This should include detailed explanations of each parameter, as well as any optional parameters and switches.

## Source Code
```powershell
function Initialize-TechToolboxHome {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()][string]$HomePath = 'C:\TechToolbox',
        [Parameter()][string]$SourcePath,       # <-- optional override
        [switch]$Force,
        [switch]$Quiet
    )

    $ErrorActionPreference = 'Stop'

    # Resolve Source (module files location)
    if (-not $SourcePath -or [string]::IsNullOrWhiteSpace($SourcePath)) {
        if ($script:ModuleRoot) {
            $SourcePath = $script:ModuleRoot
        }
        elseif ($MyInvocation.PSScriptRoot) {
            $SourcePath = $MyInvocation.PSScriptRoot
        }
        elseif ($ExecutionContext.SessionState.Module.ModuleBase) {
            $SourcePath = $ExecutionContext.SessionState.Module.ModuleBase
        }
    }

    if (-not $SourcePath) {
        Write-Error "Initialize-TechToolboxHome: Unable to determine source path (ModuleRoot/PSScriptRoot not set)."
        return
    }

    $src = [System.IO.Path]::GetFullPath($SourcePath)
    $home = [System.IO.Path]::GetFullPath($HomePath)

    Write-Verbose ("[Init] Source: {0}" -f $src)
    Write-Verbose ("[Init] Home:   {0}" -f $home)

    if (-not (Test-Path -LiteralPath $src)) {
        Write-Error "Initialize-TechToolboxHome: Source path not found: $src"
        return
    }

    # Short-circuit if already running from home
    if ($src.TrimEnd('\') -ieq $home.TrimEnd('\')) {
        Write-Verbose "Already running from $home — skipping copy."
        return
    }

    # Read module version (optional)
    $manifest = Join-Path $src 'TechToolbox.psd1'
    $version = '0.0.0-dev'
    if (Test-Path $manifest) {
        try {
            $data = Import-PowerShellDataFile -Path $manifest
            if ($data.ModuleVersion) { $version = $data.ModuleVersion }
        }
        catch { Write-Warning "Unable to read module version from psd1." }
    }

    # Check install stamp
    $stampDir = Join-Path $home '.ttb'
    $stampFile = Join-Path $stampDir 'install.json'
    if (-not $Force -and (Test-Path $stampFile)) {
        try {
            $stamp = Get-Content $stampFile -Raw | ConvertFrom-Json
            if ($stamp.version -eq $version) {
                Write-Information "TechToolbox v$version already installed at $home." -InformationAction Continue
                return
            }
        }
        catch { Write-Warning "Unable to parse existing install.json." }
    }

    # Ensure destination exists
    if (-not (Test-Path $home)) {
        if ($PSCmdlet.ShouldProcess($home, "Create destination folder")) {
            New-Item -ItemType Directory -Path $home -Force | Out-Null
            Write-Verbose "Created: $home"
        }
    }

    # Manual confirmation unless -Quiet
    if (-not $Quiet) {
        $resp = Read-Host "Copy TechToolbox $version to $home? (Y/N)"
        if ($resp -notmatch '^(?i)y(es)?$') {
            Write-Information "Copy aborted." -InformationAction Continue
            return
        }
    }

    # Perform copy via robocopy
    $robocopy = "$env:SystemRoot\System32\robocopy.exe"
    if (-not (Test-Path $robocopy)) { throw "robocopy.exe not found." }

    Write-Information "Copying TechToolbox to $home..." -InformationAction Continue

    # Exclude common dev/volatile dirs if you want; otherwise keep it simple
    $args = @("`"$src`"", "`"$home`"", '/MIR', '/COPY:DAT', '/R:2', '/W:1', '/NFL', '/NDL', '/NP', '/NJH', '/NJS')

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $robocopy
    $psi.Arguments = $args -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    $output = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()

    if ($p.ExitCode -gt 7) {
        Write-Verbose $output
        throw "Robocopy failed with exit code $($p.ExitCode)."
    }

    # Write install stamp
    if (-not (Test-Path $stampDir)) { New-Item -ItemType Directory -Path $stampDir -Force | Out-Null }
    $stampJson = @{
        version      = "$version"
        source       = "$src"
        installedUtc = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Depth 3
    Set-Content -Path $stampFile -Value $stampJson -Encoding UTF8

    Write-Information "TechToolbox v$version installed to $home." -InformationAction Continue
}

[SIGNATURE BLOCK REMOVED]

```
