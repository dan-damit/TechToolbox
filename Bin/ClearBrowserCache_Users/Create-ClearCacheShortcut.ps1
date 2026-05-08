# Author: (https://github.com/dan-damit)
$DestDir = "C:\ProgramData\VAC\Scripts"
$ScriptPath = Join-Path $DestDir "Clear-EdgeChromeCacheOnly.ps1"
$ShortcutPath = "C:\Users\Public\Desktop\Fix Epicor (Reset Browser Cache).lnk"

New-Item -ItemType Directory -Path $DestDir -Force | Out-Null

# (Assumes Clear-EdgeChromeCacheOnly.ps1 already copied the script to
# $ScriptPath via PDQ step or file copy)

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""
$Shortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,167"
$Shortcut.WorkingDirectory = $DestDir
$Shortcut.Save()
