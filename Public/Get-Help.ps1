
function Get-Help {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$List
    )

    # List all public functions
    if ($List) {
        Write-Host ""
        Write-Host "TechToolbox Public Commands" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        Get-Command -Module TechToolbox |
        Where-Object { $_.CommandType -eq 'Function' } |
        Select-Object -ExpandProperty Name |
        Sort-Object |
        ForEach-Object { Write-Host "  $_" }
        Write-Host ""
        return
    }

    # If a specific function was requested
    if ($Name) {
        try {
            Write-Host ""
            Write-Host "Help for: $Name" -ForegroundColor Cyan
            Write-Host "----------------------------------------"
            Get-Help $Name -Full
            Write-Host ""
        }
        catch {
            Write-Host "No help found for '$Name'." -ForegroundColor Yellow
        }
        return
    }

    # Default: show module overview
    Write-Host ""
    Write-Host "TechToolbox Help" -ForegroundColor Cyan
    Write-Host "----------------------------------------"
    Write-Host "A technician-grade PowerShell toolkit for diagnostics,"
    Write-Host "automation, and environment-agnostic workflows."
    Write-Host ""
    Write-Host "Common Commands:"
    Write-Host "  Get-Help -List"
    Write-Host "  Get-Help Invoke-SubnetScan"
    Write-Host "  Invoke-SubnetScan -CIDR 192.168.1.0/24"
    Write-Host ""
    Write-Host "For full help on any command:"
    Write-Host "  Get-Help <CommandName>"
    Write-Host ""
}