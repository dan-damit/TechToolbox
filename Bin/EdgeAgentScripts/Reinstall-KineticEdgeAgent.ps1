# This PowerShell script will uninstall existing Epicor Edge Agent on port 6071 (if found),
# then install the specified version silently using local mode.
# TO BE USED FOR NON IT PERSONNEL

# Define constants
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$kineticEdgeAgentVersionsUrl = "https://epicorsaascdn.blob.core.windows.net/edgeagent/kinetic_edge_versions.json"
$kineticWindows64InstallerName = "edgeagent-local-kinetic-windows-x64-installer.exe"
$installedEdgeAgentDisplayNamePattern = "*Epicor*Edge Agent*"

# Define variables
$kineticVersion = "5.1.100.0"
$edgeAgentVersion = "1.2.616.0"
$edgeAgentPort = "6071"
$edgeAgentLabel = ""
$appServerUrl = "https://REDACTED-live.epicorsaas.com/server"
$appServerUrl2 = "https://REDACTED-pilot.epicorsaas.com/server"
$appServerUrl3 = ""
$appServerUrl4 = ""
$sysconfigPath = "C:\Kinetic\27610-LIVE\Client\config\lv27610.sysconfig"
$sysconfigPath2 = "C:\Kinetic\27610-PILOT\Client\config\plt27610.sysconfig"
$sysconfigPath3 = ""
$sysconfigPath4 = ""
$epicorExeFullPath = "C:\Kinetic\27610-LIVE\Client\Epicor.exe"
$epicorExeFullPath2 = "C:\Kinetic\27610-PILOT\Client\Epicor.exe"
$epicorExeFullPath3 = ""
$epicorExeFullPath4 = ""

# Define the path for the log file
$tempDir = [System.IO.Path]::GetTempPath()
$utcDate = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$logFilename = "$utcDate`_EdgeAgentSilentInstallerLog.txt"
$logFilepath = Join-Path $tempDir $logFilename

function Write-LogMessage {
    param (
        [string]$Message,
        [string]$MessageType
    )
    Add-Content -Path $logFilepath -Value "$(Get-Date -Format o) - [$MessageType] - $Message"
}

function Write-Message {
    param (
        [string]$Message
    )
    Write-Host $Message
    Write-LogMessage -Message $Message -MessageType "Information"
}

function Write-WarningMessage {
    param (
        [string]$Message
    )
    Write-Warning $Message
    Write-LogMessage -Message $Message -MessageType "Warning"
}

function Write-ErrorMessage {
    param (
        [string]$Message
    )
    Write-Error $Message
    Write-LogMessage -Message $Message -MessageType "Error"
}

function ValidateData {
    if ([string]::IsNullOrWhiteSpace($appServerUrl)) {
        throw "The field '$appServerUrl' cannot be empty."
    }

    if ([string]::IsNullOrWhiteSpace($epicorExeFullPath)) {
        throw "The field '$epicorExeFullPath' cannot be empty."
    }
}

function Get-InstalledEdgeAgents {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $entries = foreach ($path in $paths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -like $installedEdgeAgentDisplayNamePattern -and
            -not [string]::IsNullOrWhiteSpace($_.UninstallString)
        }
    }

    return $entries | Sort-Object DisplayName, PSPath -Unique
}

function Stop-EdgeAgentProcessesAndServices {
    Write-Message "Attempting to stop related Edge Agent services/processes if running"

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*Edge Agent*" -or $_.Name -like "*edge*agent*"
    }

    foreach ($svc in $services) {
        try {
            if ($svc.Status -ne 'Stopped') {
                Write-Message "Stopping service: $($svc.Name)"
                Stop-Service -Name $svc.Name -Force -ErrorAction Stop
            }
        }
        catch {
            Write-WarningMessage "Failed to stop service $($svc.Name): $($_.Exception.Message)"
        }
    }

    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $_.ProcessName -like "*edgeagent*"
    }

    foreach ($proc in $processes) {
        try {
            Write-Message "Stopping process: $($proc.ProcessName) (PID $($proc.Id))"
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        }
        catch {
            Write-WarningMessage "Failed to stop process $($proc.ProcessName): $($_.Exception.Message)"
        }
    }
}

function ConvertTo-ExecutableAndArguments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$CommandLine
    )

    $trimmed = $CommandLine.Trim()

    if ($trimmed.StartsWith('"')) {
        $secondQuote = $trimmed.IndexOf('"', 1)
        if ($secondQuote -lt 0) {
            throw "Unable to parse command line: $CommandLine"
        }

        $exe = $trimmed.Substring(1, $secondQuote - 1)
        $args = $trimmed.Substring($secondQuote + 1).Trim()
    }
    else {
        $parts = $trimmed -split '\s+', 2
        $exe = $parts[0]
        $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
    }

    [PSCustomObject]@{
        FilePath  = $exe
        Arguments = $args
    }
}

function Uninstall-ExistingEdgeAgent {
    $installedApps = Get-InstalledEdgeAgents

    if (-not $installedApps) {
        Write-Message "No existing Edge Agent installation was detected."
        return
    }

    Stop-EdgeAgentProcessesAndServices

    foreach ($installedApp in $installedApps) {
        Write-Message "Existing Edge Agent detected: $($installedApp.DisplayName) $($installedApp.DisplayVersion)"

        if ([string]::IsNullOrWhiteSpace($installedApp.UninstallString)) {
            throw "Installed Edge Agent was found, but UninstallString is empty."
        }

        $cmd = ConvertTo-ExecutableAndArguments -CommandLine $installedApp.UninstallString

        if (-not (Test-Path $cmd.FilePath)) {
            throw "Uninstaller not found: $($cmd.FilePath)"
        }

        # Add silent uninstall arguments based on the installer style used by Epicor
        $uninstallArgs = ($cmd.Arguments + " --mode unattended --unattendedmodeui none").Trim()

        Write-Message "Executing uninstall command: `"$($cmd.FilePath)`" $uninstallArgs"
        $process = Start-Process -FilePath $cmd.FilePath -ArgumentList $uninstallArgs -Wait -PassThru

        if ($process.ExitCode -ne 0) {
            throw "Uninstall failed with exit code $($process.ExitCode)"
        }
    }

    Start-Sleep -Seconds 3

    $remaining = Get-InstalledEdgeAgents
    if ($remaining) {
        $remainingDisplayNames = ($remaining | Select-Object -ExpandProperty DisplayName) -join ', '
        throw "Edge Agent still appears installed after uninstall attempt: $remainingDisplayNames"
    }

    Write-Message "Confirmed existing Edge Agent install has been removed."
}

function Get-EdgeAgentDownloadLink {
    param (
        [string]$version
    )

    Write-Message "Generating download link for edge agent version $version"
    $parts = $kineticEdgeAgentVersionsUrl.Split('/')
    $parentDirectory = $parts[0..($parts.Length - 2)] -join '/'

    return "$parentDirectory/$version/$kineticWindows64InstallerName"
}

function Get-EdgeAgent {
    param (
        [string]$edgeAgentVersion
    )

    Write-Message "Downloading Edge Agent version $edgeAgentVersion..."
    $edgeAgentDownloadLink = Get-EdgeAgentDownloadLink -version $edgeAgentVersion
    Write-Message "Downloading Edge Agent from $edgeAgentDownloadLink"

    $tempFolder = $env:Temp
    $installerPath = Join-Path $tempFolder $kineticWindows64InstallerName

    Invoke-WebRequest -Uri $edgeAgentDownloadLink -OutFile $installerPath

    return $installerPath
}

function Invoke-EdgeAgentInstaller {
    param (
        [string]$installerPath
    )

    $parameters = (
        "--mode unattended --unattendedmodeui none --port $edgeAgentPort --edgeAgentLabel `"$edgeAgentLabel`" --allowedURL `"$appServerUrl`"" +
        " --allowedURL2 `"$appServerUrl2`" --allowedURL3 `"$appServerUrl3`" --allowedURL4 `"$appServerUrl4`"" +
        " --sysconfigPath `"$sysconfigPath`" --sysconfigPath2 `"$sysconfigPath2`" --sysconfigPath3 `"$sysconfigPath3`" --sysconfigPath4 `"$sysconfigPath4`"" +
        " --clientExePath `"$epicorExeFullPath`" --clientExePath2 `"$epicorExeFullPath2`" --clientExePath3 `"$epicorExeFullPath3`" --clientExePath4 `"$epicorExeFullPath4`""
    )

    Write-Message "Executing $installerPath with next parameters:"
    Write-Message $parameters

    $process = Start-Process -FilePath $installerPath -ArgumentList $parameters -PassThru
    $process.WaitForExit()

    if ($process.ExitCode -eq 0) {
        Write-Message "Edge Agent installation completed successfully."
    }
    elseif ($process.ExitCode -eq 77) {
        throw "Installer requires administrator privileges for first-time installation on port $edgeAgentPort. Exit code: 77"
    }
    else {
        throw "Installer exited with code $($process.ExitCode)."
    }

    $UserProfilePath = $env:USERPROFILE
    Write-Message "Installer log is located at: $UserProfilePath/edgeagent_install.log"
}

function Install-EdgeAgent {
    $scriptSucceeded = $false

    try {
        Write-Message "Preparing to remove any existing edge agent and install a fresh copy"

        ValidateData
        Uninstall-ExistingEdgeAgent

        Write-Message "Edge agent version $edgeAgentVersion will be installed for Kinetic ERP $kineticVersion"
        $edgeAgentInstallerPath = Get-EdgeAgent -EdgeAgentVersion $edgeAgentVersion

        Write-Message "Executing Edge Agent installer silently"
        [void](Invoke-EdgeAgentInstaller -InstallerPath $edgeAgentInstallerPath)

        $scriptSucceeded = $true
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $StackTrace = $_.Exception.StackTrace
        Write-ErrorMessage "$ErrorMessage`n$StackTrace"
    }
    finally {
        Write-Host "Edge Agent Silent Installer Log file created at: $logFilepath"
    }

    return [bool]$scriptSucceeded
}

function Complete-ScriptExecution {
    param (
        [Parameter(Mandatory = $true)]
        [bool]$Succeeded
    )

    # Defensive cleanup for hosted runners that may keep background state alive.
    Get-Job -ErrorAction SilentlyContinue | Remove-Job -Force -ErrorAction SilentlyContinue
    Get-EventSubscriber -ErrorAction SilentlyContinue | Unregister-Event -Force -ErrorAction SilentlyContinue

    if ($Succeeded) {
        [System.Environment]::Exit(0)
    }

    [System.Environment]::Exit(1)
}

$installSucceeded = Install-EdgeAgent
Complete-ScriptExecution -Succeeded $installSucceeded