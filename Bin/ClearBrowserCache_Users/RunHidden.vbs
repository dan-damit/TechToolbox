' RunHidden.vbs - runs PowerShell invisibly
Dim objShell, psCmd
Set objShell = CreateObject("Wscript.Shell")

psCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""C:\ProgramData\VAC\Scripts\BrowserCleanup\Clear-EdgeChromeCacheOnly.ps1"""
objShell.Run psCmd, 0, False
