
function Set-PageFileSize {
    <#
    .SYNOPSIS
        Sets the pagefile size on a remote computer via CIM/WMI.
    .EXAMPLE
        Set-PageFileSize -ComputerName "Server01.domain.local"
    .EXAMPLE
        Set-PageFileSize -ComputerName "Server01.domain.local" -InitialSize 4096 -MaximumSize 8192 -Path "C:\pagefile.sys"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter()][int]$InitialSize,
        [Parameter()][int]$MaximumSize,
        [Parameter()][string]$Path
    )

    # Load config
    $cfg = Get-TechToolboxConfig
    $pfCfg = $cfg.settings.pagefile

    # Defaults from config
    if (-not $Path) { $Path = $pfCfg.defaultPath }
    $minSize = $pfCfg.minSizeMB
    $maxSize = $pfCfg.maxSizeMB

    # Prompt for sizes locally before remoting
    if (-not $InitialSize) {
        $InitialSize = Read-Int -Prompt "Enter initial pagefile size (MB)" -Min $minSize -Max $maxSize
    }

    if (-not $MaximumSize) {
        $MaximumSize = Read-Int -Prompt "Enter maximum pagefile size (MB)" -Min $InitialSize -Max $maxSize
    }

    # Credential prompting based on config
    $creds = $null
    if ($cfg.settings.defaults.promptForCredentials) {
        $creds = Get-Credential -Message "Enter credentials for $ComputerName"
    }

    Write-Log -Level Info -Message "Connecting to $ComputerName..."

    # Kerberos/Negotiate only
    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $creds
        Write-Log -Level Ok -Message "Connected to $ComputerName."
    }
    catch {
        Write-Log -Level Error -Message "Failed to create PSSession: $($_.Exception.Message)"
        return
    }

    Write-Log -Level Info -Message "Applying pagefile settings on $ComputerName..."

    # Remote scriptblock — runs entirely on the target machine
    $result = Invoke-Command -Session $session -ScriptBlock {
        param($Path, $InitialSize, $MaximumSize)

        try {
            $computersys = Get-CimInstance Win32_ComputerSystem
            if ($computersys.AutomaticManagedPagefile) {
                $computersys | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false } | Out-Null
            }

            $pagefile = Get-CimInstance Win32_PageFileSetting -Filter "Name='$Path'"

            if (-not $pagefile) {
                New-CimInstance Win32_PageFileSetting -Property @{
                    Name        = $Path
                    InitialSize = $InitialSize
                    MaximumSize = $MaximumSize
                } | Out-Null
            }
            else {
                $pagefile | Set-CimInstance -Property @{
                    InitialSize = $InitialSize
                    MaximumSize = $MaximumSize
                } | Out-Null
            }

            return @{
                Success = $true
                Message = "Pagefile updated: $Path (Initial=$InitialSize MB, Max=$MaximumSize MB)"
            }
        }
        catch {
            return @{
                Success = $false
                Message = $_.Exception.Message
            }
        }

    } -ArgumentList $Path, $InitialSize, $MaximumSize

    Remove-PSSession $session

    # Handle result
    if ($result.Success) {
        Write-Log -Level Ok -Message $result.Message
    }
    else {
        Write-Log -Level Error -Message "Remote failure: $($result.Message)"
        return
    }

    # Reboot prompt
    $resp = Read-Host "Reboot $ComputerName now? (y/n)"
    if ($resp -match '^(y|yes)$') {
        Write-Log -Level Info -Message "Rebooting $ComputerName..."
        Restart-Computer -ComputerName $ComputerName -Force -Credential $creds
    }
    else {
        Write-Log -Level Warn -Message "Reboot later to apply changes."
    }
}