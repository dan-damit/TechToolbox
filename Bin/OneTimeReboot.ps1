$TaskName = 'OneTimeReboot_1AM'
$RebootTime = (Get-Date).Date.AddDays(1).AddHours(1)  # tomorrow at 1:00 AM

$Action = New-ScheduledTaskAction `
    -Execute 'shutdown.exe' `
    -Argument '/r /f /t 0 /c "Scheduled maintenance reboot"'

$Trigger = New-ScheduledTaskTrigger -Once -At $RebootTime

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 10)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -User 'SYSTEM' `
    -Force
