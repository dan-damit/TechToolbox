Start-NewPSRemoteSession -ComputerName '<domain controller>' -Credential (Get-Credential)

$session = Get-PSSession | Select-Object -First 1

Invoke-Command -Session $session -ScriptBlock {
    $user = "<username>"
    Write-Host "Monitoring AD bad password attempts for $user (Ctrl+C to stop)..." -ForegroundColor Cyan

    $lastBad = $null
    $lastCount = $null
    $lastBeat = Get-Date

    while ($true) {
        $u = Get-ADUser $user -Properties LockedOut, BadPwdCount, LastBadPasswordAttempt

        if ($lastBad -ne $u.LastBadPasswordAttempt -or $lastCount -ne $u.BadPwdCount) {
            $ts = Get-Date -Format "HH:mm:ss"
            Write-Host "[$ts] LockedOut=$($u.LockedOut)  BadPwdCount=$($u.BadPwdCount)  LastBad=$($u.LastBadPasswordAttempt)" -ForegroundColor Yellow
            $lastBad = $u.LastBadPasswordAttempt
            $lastCount = $u.BadPwdCount
        }
        elseif ((Get-Date) - $lastBeat -gt [TimeSpan]::FromSeconds(10)) {
            $ts = Get-Date -Format "HH:mm:ss"
            Write-Host "[$ts] No changes. Still stable. BadPwdCount=$($u.BadPwdCount) LastBad=$($u.LastBadPasswordAttempt)" -ForegroundColor DarkGray
            $lastBeat = Get-Date
        }

        Start-Sleep -Seconds 2
    }
}
