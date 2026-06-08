# Author: (https://github.com/dan-damit)
$VbsPath = "C:\ProgramData\VAC\Scripts\BrowserCleanup\RunHidden.vbs"
$ShortcutPath = "C:\Users\Public\Desktop\Fix Epicor (Browser Reset).lnk"
$IconLocation = "$env:WINDIR\System32\shell32.dll,238"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "$env:WINDIR\System32\wscript.exe"
$Shortcut.Arguments = "`"$VbsPath`""
$Shortcut.WorkingDirectory = Split-Path $VbsPath
$Shortcut.IconLocation = $IconLocation
$Shortcut.Save()
