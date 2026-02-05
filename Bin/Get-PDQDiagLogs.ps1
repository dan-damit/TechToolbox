try {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) { Write-Host "Please start the script as an Administrator" -ForegroundColor DarkYellow; throw }
    # Default info
    $DiagnosticDirectory = "C:\ConnectDiagnostics"
    $ConnectDataPath = "C:\ProgramData\PDQ\PDQConnectAgent"

    # Set paths to files
    $Files = @(
        "$ConnectDataPath\PDQConnectAgent.db"
        "$ConnectDataPath\Updates\install.log"
        "$env:SystemRoot\System32\Winevt\Logs\PDQ.com.evtx"
    )

    # Create directory if it does not exist
    if ( -not (Test-Path $DiagnosticDirectory) ) {
        New-Item -Path $DiagnosticDirectory -ItemType Directory -Force | Out-Null
    }

    # Find Connect version
    $UninstallKeys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $Version = (Get-ItemProperty -Path "$UninstallKeys\*" | Where-Object -FilterScript { $_.DisplayName -eq "PDQConnectAgent" } | Select-Object DisplayName, DisplayVersion)
    if (!$Version) {
        $Version = "No Connect Agent found on device"
    }
    $Version | Out-File "$DiagnosticDirectory\ConnectVersion.txt"

    # Copy files to directory
    $Files | ForEach-Object {
        if (Test-Path $_) {
            Copy-Item -Path $_ -Destination $DiagnosticDirectory
        }
    }

    # Compress files into zip
    Compress-Archive -Path $DiagnosticDirectory -DestinationPath "$DiagnosticDirectory.zip" -Force

    # Remove main directory
    Remove-Item -Path $DiagnosticDirectory -Recurse -Force

    Write-Host "Please attach the zip file to your support ticket. " -ForegroundColor Green -NoNewline
    Write-Host "File is located here: " -ForegroundColor Green -NoNewline
    Write-Host "$DiagnosticDirectory.zip"
}
catch {
    Write-Error "Please start the script as an Administrator"
}
