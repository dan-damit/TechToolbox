# Code Analysis Report
Generated: 2/19/2026 7:27:36 PM

## Mode
Static

## Summary
Here are the findings from the static code analysis of the provided script:

### Unused Variables
- `$configLoaded`: This variable is used to track whether the configuration is loaded, but it is only set and checked. It does not affect the flow or output of the function.

### Unreachable Code
- The `if ($Name -eq 'New-OnPremUserFromTemplate')` block appears twice in the script, making the second occurrence unreachable.

### Missing or Weak Error Handling
- The `try-catch` blocks are used appropriately to handle errors during runtime initialization and direct config loading. However, more detailed error handling could be added for other operations, especially when dealing with file paths and external commands.

### Missing Parameter Validation
- There is no parameter validation for the `$Name` parameter. If an invalid command name is passed, it will not be handled gracefully.
- The script does not validate that the `-AsJson` switch is used only when `$ShowEffectiveConfig` is true.

### Pipeline Misuse
- The script uses `Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object { Write-Host "  $_" }` to list commands. This could be simplified by using `ForEach-Object` directly with `Sort-Object`.

### Quoting and Path Handling Issues
- Paths are constructed using `Join-Path`, which is good practice.
- The script uses `-LiteralPath` in the `Test-Path` cmdlet, which is appropriate for paths that may contain special characters.

### Missing CmdletBinding / SupportsShouldProcess
- The `[CmdletBinding()]` attribute is present, which is good. However, the function does not use `SupportsShouldProcess`, which could be beneficial for actions that modify state.

### Missing or Weak Comment-Based Help
- The comment-based help is present but lacks detailed descriptions for each parameter and usage examples. Additionally, there are some sections with placeholders like `<CODE>` in the help description that should be removed or filled with actual information.

### Other Observations
- The script includes a placeholder for a signature block at the end, which should be reviewed and properly implemented if required.
- The script uses `Write-Host` extensively for output. While this is acceptable for user-friendly messages, it might be better to use `Write-Output` or `Write-Information` for more structured output.

### Recommendations
1. Remove the duplicate `if ($Name -eq 'New-OnPremUserFromTemplate')` block.
2. Add parameter validation for the `$Name` parameter to ensure it is a valid command name.
3. Ensure that the `-AsJson` switch is used correctly in conjunction with `$ShowEffectiveConfig`.
4. Simplify the command listing by directly using `ForEach-Object` with `Sort-Object`.
5. Consider adding `SupportsShouldProcess` to handle actions that modify state.
6. Enhance the comment-based help with detailed descriptions and usage examples.
7. Review and properly implement the signature block if required.

By addressing these issues, the script can become more robust and user-friendly.

## Source Code
```powershell
function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.
    .DESCRIPTION
        Displays overview, lists commands, shows full help for a given command,
        or prints the effective configuration.
    #>
    [CmdletBinding()]
    param(
        [string]$Name,
        [switch]$List,
        [switch]$ShowEffectiveConfig,
        [switch]$AsJson
    )

    # Ensure runtime (config/logging/etc.) is initialized
    try {
        Initialize-TechToolboxRuntime
    }
    catch {
        # If runtime can't init (e.g., config missing), we still want the help text to show.
        Write-Verbose ("Get-ToolboxHelp: runtime init failed: {0}" -f $_.Exception.Message)
    }

    # Safe access to config (strict-mode friendly)
    $configLoaded = $false
    $Config = $null
    if (Get-Variable -Name cfg -Scope Script -ErrorAction SilentlyContinue) {
        $Config = $script:cfg
        $configLoaded = [bool]$Config
    }

    # If user explicitly asked for effective config but it's not loaded, try to load it directly
    if ($ShowEffectiveConfig -and -not $configLoaded) {
        try {
            # Resolve default config path the same way Initialize-Config does
            if (-not $script:ModuleRoot) { $script:ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase }
            $configDir = Join-Path $script:ModuleRoot 'Config'
            $cfgPath = Join-Path $configDir 'config.json'
            if (Test-Path -LiteralPath $cfgPath) {
                $Config = Get-TechToolboxConfig -Path $cfgPath
                $configLoaded = [bool]$Config
            }
        }
        catch {
            Write-Verbose ("Get-ToolboxHelp: direct config load failed: {0}" -f $_.Exception.Message)
        }
    }

    # ---------- Presentation ----------
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host "        TechToolbox Help Center         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "A technician-grade PowerShell toolkit for:" -ForegroundColor Gray
    Write-Host "  • Diagnostics" -ForegroundColor Gray
    Write-Host "  • Automation" -ForegroundColor Gray
    Write-Host "  • Environment-agnostic workflows" -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " Common Commands:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp -List" -ForegroundColor Yellow
    Write-Host "    Displays all available commands." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp Invoke-SubnetScan" -ForegroundColor Yellow
    Write-Host "    Shows detailed help for Invoke-SubnetScan." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Invoke-PurviewPurge -CaseName 'XYZ123'" -ForegroundColor Yellow
    Write-Host "    Creates a Case search and purges the search results." -ForegroundColor Gray
    Write-Host ""
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host " For full help on any command:" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Get-ToolboxHelp <CommandName>" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "========================================" -ForegroundColor DarkCyan

    # ----- Effective configuration requested -----
    if ($ShowEffectiveConfig) {
        Write-Host ""
        Write-Host "TechToolbox Effective Configuration" -ForegroundColor Cyan
        Write-Host "----------------------------------------"

        if (-not $configLoaded) {
            Write-Host "(configuration not loaded)" -ForegroundColor Yellow
            return
        }

        if ($AsJson) {
            $Config | ConvertTo-Json -Depth 10
        }
        else {
            $Config | Format-List
        }

        Write-Host ""
        return
    }

    # ----- List commands -----
    if ($List) {
        Write-Host ""
        Write-Host "TechToolbox Commands" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        # Use the current module name to be resilient if someone renames it
        $modName = $PSCmdlet.MyInvocation.MyCommand.ModuleName
        if (-not $modName) { $modName = 'TechToolbox' }

        Get-Command -Module $modName -CommandType Function |
        Select-Object -ExpandProperty Name |
        Sort-Object |
        ForEach-Object { Write-Host "  $_" }
        Write-Host ""
        return
    }

    # ----- Specific command help -----
    if ($Name) {
        try {
            Write-Host ""
            Write-Host "Help for: $Name" -ForegroundColor Cyan
            Write-Host "----------------------------------------"
            # -Full can be noisy; keep it if that’s your preference
            Get-Help -Name $Name -Full
            Write-Host ""
        }
        catch {
            Write-Host "No help found for '$Name'." -ForegroundColor Yellow
        }
        return
    }

    # Clear-BrowserProfileData
    if ($Name -eq 'Clear-BrowserProfileData') {
        Write-Host ""
        Write-Host "Clear-BrowserProfileData" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SubnetScan
    if ($Name -eq 'Invoke-SubnetScan') {
        Write-Host ""
        Write-Host "Invoke-SubnetScan" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-RemoteInstalledSoftware
    if ($Name -eq 'Get-RemoteInstalledSoftware') {
        Write-Host ""
        Write-Host "Get-RemoteInstalledSoftware" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-BatteryHealth
    if ($Name -eq 'Get-BatteryHealth') {
        Write-Host ""
        Write-Host "Get-BatteryHealth" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-MessageTrace
    if ($Name -eq 'Get-MessageTrace') {
        Write-Host ""
        Write-Host "Get-MessageTrace" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-TechToolboxConfig
    if ($Name -eq 'Get-TechToolboxConfig') {
        Write-Host ""
        Write-Host "Get-TechToolboxConfig" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-ToolboxHelp
    if ($Name -eq 'Get-ToolboxHelp') {
        Write-Host ""
        Write-Host "Get-ToolboxHelp" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-WindowsProductKey
    if ($Name -eq 'Get-WindowsProductKey') {
        Write-Host ""
        Write-Host "Get-WindowsProductKey" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-AADSyncRemote
    if ($Name -eq 'Invoke-AADSyncRemote') {
        Write-Host ""
        Write-Host "Invoke-AADSyncRemote" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-DownloadsCleanup
    if ($Name -eq 'Invoke-DownloadsCleanup') {
        Write-Host ""
        Write-Host "Invoke-DownloadsCleanup" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-PurviewPurge
    if ($Name -eq 'Invoke-PurviewPurge') {
        Write-Host ""
        Write-Host "Invoke-PurviewPurge" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-SystemRepair
    if ($Name -eq 'Invoke-SystemRepair') {
        Write-Host ""
        Write-Host "Invoke-SystemRepair" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-PageFileSize
    if ($Name -eq 'Set-PageFileSize') {
        Write-Host ""
        Write-Host "Set-PageFileSize" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-ProxyAddress
    if ($Name -eq 'Set-ProxyAddress') {
        Write-Host ""
        Write-Host "Set-ProxyAddress" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-DnsQueryLogger
    if ($Name -eq 'Start-DnsQueryLogger') {
        Write-Host ""
        Write-Host "Start-DnsQueryLogger" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Copy-Directory
    if ($Name -eq 'Copy-Directory') {
        Write-Host ""
        Write-Host "Copy-Directory" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Reset-WindowsUpdateComponents
    if ($Name -eq 'Reset-WindowsUpdateComponents') {
        Write-Host ""
        Write-Host "Reset-WindowsUpdateComponents" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Test-PathAs
    if ($Name -eq 'Test-PathAs') {
        Write-Host ""
        Write-Host "Test-PathAs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # New-OnPremUserFromTemplate
    if ($Name -eq 'New-OnPremUserFromTemplate') {
        Write-Host ""
        Write-Host "New-OnPremUserFromTemplate" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemSnapshot
    if ($Name -eq 'Get-SystemSnapshot') {
        Write-Host ""
        Write-Host "Get-SystemSnapshot" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Search-User
    if ($Name -eq 'Search-User') {
        Write-Host ""
        Write-Host "Search-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Disable-User
    if ($Name -eq 'Disable-User') {
        Write-Host ""
        Write-Host "Disable-User" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    #Remove-Printers
    if ($Name -eq 'Remove-Printers') {
        Write-Host ""
        Write-Host "Remove-Printers" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-DomainAdminCred
    if ($Name -eq 'Initialize-DomainAdminCred') {
        Write-Host ""
        Write-Host "Initialize-DomainAdminCred" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-DomainAdminCredential
    if ($Name -eq 'Get-DomainAdminCredential') {
        Write-Host ""
        Write-Host "Get-DomainAdminCredential" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Enable-NetFx3
    if ($Name -eq 'Enable-NetFx3') {
        Write-Host ""
        Write-Host "Enable-NetFx3" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Initialize-TTWordList
    if ($Name -eq 'Initialize-TTWordList') {
        Write-Host ""
        Write-Host "Initialize-TTWordList" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-SystemUptime
    if ($Name -eq 'Get-SystemUptime') {
        Write-Host ""
        Write-Host "Get-SystemUptime" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-AutodiscoverXmlInteractive
    if ($Name -eq 'Get-AutodiscoverXmlInteractive') {
        Write-Host ""
        Write-Host "Get-AutodiscoverXmlInteractive" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Start-PDQDiagLocalElevated
    if ($Name -eq 'Start-PDQDiagLocalElevated') {
        Write-Host ""
        Write-Host "Start-PDQDiagLocalElevated" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-PDQDiagLogs
    if ($Name -eq 'Get-PDQDiagLogs') {
        Write-Host ""
        Write-Host "Get-PDQDiagLogs" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-LocalLLM
    if ($Name -eq 'Invoke-LocalLLM') {
        Write-Host ""
        Write-Host "Invoke-LocalLLM" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }
    
    # Invoke-CodeAssistant
    if ($Name -eq 'Invoke-CodeAssistant') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistant" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-CodeAssistantWrapper
    if ($Name -eq 'Invoke-CodeAssistantWrapper') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistantWrapper" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Invoke-CodeAssistantFolder
    if ($Name -eq 'Invoke-CodeAssistantFolder') {
        Write-Host ""
        Write-Host "Invoke-CodeAssistantFolder" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Watch-ISPConnection
    if ($Name -eq 'Watch-ISPConnection') {
        Write-Host ""
        Write-Host "Watch-ISPConnection" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Test-MailHeaderAuth
    if ($Name -eq 'Test-MailHeaderAuth') {
        Write-Host ""
        Write-Host "Test-MailHeaderAuth" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Get-AutoDiscoverXmlInteractive
    if ($Name -eq 'Get-AutoDiscoverXmlInteractive') {
        Write-Host ""
        Write-Host "Get-AutoDiscoverXmlInteractive" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }

    # Set-EmailAlias
    if ($Name -eq 'Set-EmailAlias') {
        Write-Host ""
        Write-Host "Set-EmailAlias" -ForegroundColor Cyan
        Write-Host "----------------------------------------"
        return
    }
}
[SIGNATURE BLOCK REMOVED]

```
