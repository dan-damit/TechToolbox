# Kill Teams processes
Get-Process Teams -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "Removing Teams Machine-Wide Installer..."

# Remove Machine-Wide Installer via registry (faster/cleaner than Win32_Product)
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($key in $uninstallKeys) {
    Get-ChildItem $key | Get-ItemProperty | Where-Object {
        $_.DisplayName -like "*Teams Machine-Wide Installer*"
    } | ForEach-Object {
        Start-Process "msiexec.exe" -ArgumentList "/x $($_.PSChildName) /qn" -Wait
    }
}

# Remove installer folder
Remove-Item "C:\Program Files (x86)\Teams Installer" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removing per-user Teams installs..."

# Loop through all user profiles
$profiles = Get-ChildItem "C:\Users" -Directory | Where-Object { $_.Name -notin @("Public","Default","Default User","All Users") }

foreach ($profile in $profiles) {

    $local = "$($profile.FullName)\AppData\Local\Microsoft\Teams"
    $roaming = "$($profile.FullName)\AppData\Roaming\Microsoft\Teams"

    # Uninstall via Update.exe if present
    if (Test-Path "$local\Update.exe") {
        Start-Process "$local\Update.exe" -ArgumentList "--uninstall -s" -Wait
    }

    # Remove folders
    Remove-Item $local -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $roaming -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Cleaning Run keys..."

# Remove machine-wide autorun
$runPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($path in $runPaths) {
    Remove-ItemProperty -Path $path -Name "TeamsMachineInstaller" -ErrorAction SilentlyContinue
}

Write-Host "Removing new Teams (if present)..."

Get-AppxPackage *MSTeams* -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

Write-Host "Teams cleanup complete."