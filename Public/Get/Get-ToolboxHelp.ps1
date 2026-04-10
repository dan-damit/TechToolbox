function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.

    .DESCRIPTION
        Get-ToolboxHelp displays help information for TechToolbox commands and
        configuration in an interactive, formatted manner. The function supports
        multiple display modes:

        - Overview: Displays general information and usage suggestions
        - List: Displays all public exported commands grouped by verb
        - Command Help: Shows detailed help for a specific command with fuzzy
          matching
        - Configuration: Displays the effective configuration currently loaded

        When running in an interactive console, output is formatted with colors
        and tables. In non-interactive environments, output is redirected to the
        Information stream for better logging compatibility.

    .PARAMETER Name
        The name or partial name of a command to display help for. Supports
        fuzzy pattern matching using wildcards. If multiple matches are found,
        suggestions are displayed.

    .PARAMETER List
        Switch to list all public exported TechToolbox commands. Commands are
        grouped by verb and sorted alphabetically. Each command displays its
        associated synopsis when available.

        Can be combined with -AsJson for structured output.

    .PARAMETER ShowEffectiveConfig
        Switch to display the effective configuration currently loaded in the
        TechToolbox runtime. If no configuration is loaded, attempts to load
        config.json directly from the module Config directory.

        Can be combined with -AsJson for structured output.

    .PARAMETER AsJson
        When used with -List or -ShowEffectiveConfig, outputs the result as JSON
        instead of human-readable format. Useful for scripting and pipeline
        integration.

    .PARAMETER Examples
        When used with -Name, displays only the Examples section of the help
        instead of the full help content. Ignored when -Name is not specified.

    .INPUTS
        None. Get-ToolboxHelp does not accept pipeline input.

    .OUTPUTS
        System.String Formatted help text (interactive mode) or error messages

        System.Object When -AsJson is specified, outputs a JSON-serialized
        object

    .EXAMPLE
        PS> Get-ToolboxHelp

        Displays the main help overview with common usage commands and links.

    .EXAMPLE
        PS> Get-ToolboxHelp -List

        Lists all public TechToolbox commands grouped by verb with synopses.

    .EXAMPLE
        PS> Get-ToolboxHelp -List -AsJson | ConvertFrom-Json

        Lists all public commands in JSON format for structured processing.

    .EXAMPLE
        PS> Get-ToolboxHelp Invoke-Subnet

        Shows detailed help for the first command matching "Invoke-Subnet".
        If exact match not found, displays suggestions.

    .EXAMPLE
        PS> Get-ToolboxHelp Get-SystemSnapshot -Examples

        Displays only the Examples section for Get-SystemSnapshot.

    .EXAMPLE
        PS> Get-ToolboxHelp -ShowEffectiveConfig

        Displays the current effective configuration loaded by TechToolbox.

    .EXAMPLE
        PS> Get-ToolboxHelp -ShowEffectiveConfig -AsJson | Out-File config-export.json

        Exports the effective configuration as JSON to a file.

    .NOTES
        Author: TechToolbox Team Version: 1.0.0

        ENVIRONMENT COMPATIBILITY: The function automatically adapts output
        format based on the host environment. In interactive console hosts,
        colored text and formatted tables are used. In non-interactive hosts
        (like ISE ServerHost or scheduled tasks), output is sent to the
        Information stream.

        COMMAND DISCOVERY: Only PUBLIC/EXPORTED functions are searched. Private
        functions are not included in the catalog.

        CONFIGURATION LOADING: Uses a two-stage approach:
        1. First checks if configuration is already loaded in script scope
        2. Attempts to load config.json from module Config directory if needed

        This ensures compatibility with both module-initialized and standalone
        script execution contexts.

    .RELATED LINKS
        Get-Help Get-Command Get-Module
    #>
    [CmdletBinding(DefaultParameterSetName = 'Overview')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Command', ValueFromPipelineByPropertyName = $false)]
        [Alias('CommandName')]
        [AllowEmptyString()]
        [ValidateNotNull()]
        [string]$Name,

        [Parameter(ParameterSetName = 'List')]
        [switch]$List,

        [Parameter(ParameterSetName = 'Config')]
        [switch]$ShowEffectiveConfig,

        [switch]$AsJson,

        [Parameter(ParameterSetName = 'Command')]
        [switch]$Examples
    )

    begin {
        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'

        # Detect interactive mode
        $hostEnvironment = Get-HostEnvironmentInfo
        
        # Initialize configuration state
        $configState = @{
            Loaded     = $false
            Data       = $null
            ModuleRoot = $script:ModuleRoot
        }
    }

    process {
        try {
            # Attempt runtime initialization
            Initialize-RuntimeEnvironment

            # Determine display mode and execute
            switch ($PSCmdlet.ParameterSetName) {
                'List' {
                    Show-CommandList -AsJson $AsJson -HostEnv $hostEnvironment
                }
                'Config' {
                    Show-Configuration -AsJson $AsJson -ConfigState $configState -HostEnv $hostEnvironment
                }
                'Command' {
                    Show-CommandHelp -Name $Name -Examples $Examples -HostEnv $hostEnvironment
                }
                'Overview' {
                    Show-HelpOverview -HostEnv $hostEnvironment
                }
                default {
                    Show-HelpOverview -HostEnv $hostEnvironment
                }
            }
        }
        catch {
            $ErrorMessage = "Get-ToolboxHelp: $_"
            if ($hostEnvironment.IsInteractive) {
                Write-Host $ErrorMessage -ForegroundColor Red
            }
            else {
                Write-Information $ErrorMessage
            }
            throw
        }
    }

    end {
        # Cleanup if needed
        $null = Remove-Variable -Name 'hostEnvironment', 'configState' -ErrorAction SilentlyContinue
    }
}

#region Helper Functions

function Get-HostEnvironmentInfo {
    <#
    .SYNOPSIS
        Determines the current host environment capabilities.
    #>
    param()

    $isServerHost = $Host.Name -like '*ServerHost*'
    $supportsUI = $null -ne $Host.UI -and $null -ne $Host.UI.RawUI

    return @{
        Name          = $Host.Name
        IsInteractive = -not $isServerHost -and $supportsUI
        SupportsUI    = $supportsUI
        IsServerHost  = $isServerHost
        BufferWidth   = if ($supportsUI) { $Host.UI.RawUI.BufferSize.Width } else { 120 }
    }
}

function Initialize-RuntimeEnvironment {
    <#
    .SYNOPSIS
        Initializes the TechToolbox runtime (best effort).
    #>
    param()

    if (Get-Command -Name 'Initialize-TechToolboxRuntime' -ErrorAction SilentlyContinue) {
        try {
            Initialize-TechToolboxRuntime -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Verbose ("Get-ToolboxHelp: Runtime initialization failed: {0}" -f $_.Exception.Message)
        }
    }
}

function Get-ModuleInfo {
    <#
    .SYNOPSIS
        Retrieves the current module reference.
    #>
    param()

    $modName = $PSCmdlet.MyInvocation.MyCommand.ModuleName
    if (-not $modName) {
        $modName = $ExecutionContext.SessionState.Module.Name
    }
    if (-not $modName) {
        $modName = 'TechToolbox'
    }

    $mod = Get-Module -Name $modName -ErrorAction SilentlyContinue
    if (-not $mod) {
        $mod = $ExecutionContext.SessionState.Module
    }

    return @{
        Name   = $modName
        Module = $mod
    }
}

function Write-FormattedText {
    <#
    .SYNOPSIS
        Writes formatted text with appropriate output method.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Text,

        [ConsoleColor]$ForegroundColor = [ConsoleColor]::Gray,

        [switch]$NoNewline,

        [bool]$IsInteractive = $true
    )

    if ($IsInteractive) {
        $writeHostParams = @{
            ForegroundColor = $ForegroundColor
            NoNewline       = $NoNewline
        }
        Write-Host $Text @writeHostParams
    }
    else {
        Write-Information $Text
    }
}

function Split-TextToColumns {
    <#
    .SYNOPSIS
        Wraps text to fit within specified column width with hanging indent.
    #>
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory)]
        [ValidateRange(20, 200)]
        [int]$MaxWidth,

        [Parameter(Mandatory)]
        [string]$HangingIndent
    )

    # Normalize whitespace
    $normalized = ($Text -replace '\s+', ' ').Trim()

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @('')
    }

    # Split into lines based on width
    [System.Collections.Generic.List[string]]$lines = @()
    [string]$currentLine = ''

    foreach ($word in $normalized -split ' ') {
        if ($currentLine.Length -eq 0) {
            $currentLine = $word
        }
        elseif (($currentLine.Length + 1 + $word.Length) -le $MaxWidth) {
            $currentLine += " $word"
        }
        else {
            [void]$lines.Add($currentLine)
            $currentLine = $word
        }
    }

    if ($currentLine) {
        [void]$lines.Add($currentLine)
    }

    # Apply hanging indent
    [System.Collections.Generic.List[string]]$output = @()
    [void]$output.Add($lines[0])

    for ($i = 1; $i -lt $lines.Count; $i++) {
        [void]$output.Add($HangingIndent + $lines[$i])
    }

    return $output.ToArray()
}

function Show-HelpOverview {
    <#
    .SYNOPSIS
        Displays the help overview screen.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$HostEnv
    )

    if ($HostEnv.IsInteractive) {
        Write-Host ''
        Write-Host '========================================' -ForegroundColor DarkCyan
        Write-Host 'TechToolbox Help Center' -ForegroundColor Cyan
        Write-Host '========================================' -ForegroundColor DarkCyan
        Write-Host ''
    }

    Write-FormattedText -Text 'A technician-grade PowerShell toolkit for:' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '  • Diagnostics' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '  • Automation' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '  • Environment-agnostic workflows' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

    Write-FormattedText -Text '----------------------------------------' -ForegroundColor DarkGray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text ' Common Commands:' -ForegroundColor White -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '----------------------------------------' -ForegroundColor DarkGray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

    Write-FormattedText -Text '  Get-ToolboxHelp -List' -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '    Lists all available PUBLIC commands (grouped by verb).' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

    Write-FormattedText -Text '  Get-ToolboxHelp Invoke-SubnetScan' -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '    Shows detailed help for a specific command.' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

    Write-FormattedText -Text '  Get-ToolboxHelp -ShowEffectiveConfig' -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '    Displays the current configuration.' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

    Write-FormattedText -Text '========================================' -ForegroundColor DarkCyan -IsInteractive $HostEnv.IsInteractive
}

function Show-CommandList {
    <#
    .SYNOPSIS
        Displays all available commands grouped by verb.
    #>
    param(
        [bool]$AsJson = $false,
        [Parameter(Mandatory)]
        [hashtable]$HostEnv
    )

    $modInfo = Get-ModuleInfo

    # Retrieve exported functions
    [System.Collections.Generic.List[System.Management.Automation.FunctionInfo]]$commands = @()
    if ($modInfo.Module -and $modInfo.Module.ExportedFunctions.Count -gt 0) {
        $commands = $modInfo.Module.ExportedFunctions.Values | Sort-Object Name
    }
    else {
        $commands = Get-Command -Module $modInfo.Name -CommandType Function -ErrorAction SilentlyContinue | Sort-Object Name
    }

    if ($AsJson) {
        $commandList = @()
        foreach ($cmd in $commands) {
            $help = $null
            try {
                $help = Get-Help -Name $cmd.Name -ErrorAction SilentlyContinue
            }
            catch {
                # Suppress errors silently
            }

            $commandList += [PSCustomObject]@{
                Name     = $cmd.Name
                Verb     = $cmd.Verb
                Noun     = $cmd.Noun
                Synopsis = if ($help) { $help.Synopsis } else { '' }
            }
        }

        $commandList | ConvertTo-Json -Depth 4
        return
    }

    if ($HostEnv.IsInteractive) {
        Write-Host ''
        Write-Host 'Commands (PUBLIC / Exported) — grouped by verb' -ForegroundColor Cyan
        Write-Host '----------------------------------------' -ForegroundColor DarkGray
        Write-Host ''
    }

    [hashtable]$helpCache = @{}
    $columnWidth = $HostEnv.BufferWidth - 36
    $columnWidth = [Math]::Max(40, $columnWidth)

    $commands | Group-Object -Property Verb | Sort-Object Name | ForEach-Object {
        Write-FormattedText -Text "[$($_.Name)]" -ForegroundColor Cyan -IsInteractive $HostEnv.IsInteractive

        $_.Group | Sort-Object Name | ForEach-Object {
            $cmdName = $_.Name

            # Lazy-load help
            if (-not $helpCache.ContainsKey($cmdName)) {
                try {
                    $helpCache[$cmdName] = Get-Help -Name $cmdName -ErrorAction SilentlyContinue
                }
                catch {
                    $helpCache[$cmdName] = $null
                }
            }

            $synopsis = $null
            if ($helpCache[$cmdName]) {
                $synopsis = $helpCache[$cmdName].Synopsis
            }

            if ([string]::IsNullOrWhiteSpace($synopsis)) {
                Write-FormattedText -Text ("  {0}" -f $cmdName) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            }
            else {
                $leftColWidth = 34
                $leftPrefix = "  {0,-$leftColWidth}" -f $cmdName
                $hangingIndent = ' ' * ($leftColWidth + 2)

                $wrappedLines = Split-TextToColumns -Text $synopsis -MaxWidth $columnWidth -HangingIndent $hangingIndent

                Write-FormattedText -Text ($leftPrefix + $wrappedLines[0]) -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive

                for ($i = 1; $i -lt $wrappedLines.Count; $i++) {
                    Write-FormattedText -Text $wrappedLines[$i] -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
                }
            }
        }

        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    }
}

function Show-Configuration {
    <#
    .SYNOPSIS
        Displays the effective configuration.
    #>
    param(
        [bool]$AsJson = $false,
        [Parameter(Mandatory)]
        [hashtable]$ConfigState,
        [Parameter(Mandatory)]
        [hashtable]$HostEnv
    )

    $config = $null
    $loaded = $false

    # Stage 1: Check script scope
    if (Get-Variable -Name 'cfg' -Scope Script -ErrorAction SilentlyContinue) {
        $config = $script:cfg
        $loaded = [bool]$config
    }

    # Stage 2: Attempt direct load
    if (-not $loaded) {
        try {
            if (-not $ConfigState.ModuleRoot) {
                $ConfigState.ModuleRoot = $ExecutionContext.SessionState.Module.ModuleBase
            }

            $configPath = Join-Path $ConfigState.ModuleRoot 'Config' 'config.json'

            if (Test-Path -LiteralPath $configPath) {
                if (Get-Command -Name 'Get-TechToolboxConfig' -ErrorAction SilentlyContinue) {
                    $config = Get-TechToolboxConfig -Path $configPath
                }
                else {
                    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
                }
                $loaded = [bool]$config
            }
        }
        catch {
            Write-Verbose ("Get-ToolboxHelp: Configuration load failed: {0}" -f $_.Exception.Message)
        }
    }

    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text 'Effective Configuration' -ForegroundColor Cyan -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '----------------------------------------' -ForegroundColor DarkGray -IsInteractive $HostEnv.IsInteractive

    if (-not $loaded) {
        Write-FormattedText -Text '(no configuration loaded)' -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
        return
    }

    if ($AsJson) {
        $config | ConvertTo-Json -Depth 10
    }
    else {
        $config | Format-List
    }

    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
}

function Show-CommandHelp {
    <#
    .SYNOPSIS
        Displays help for a specific command with fuzzy matching.
    #>
    param(
        [string]$Name,
        [bool]$Examples = $false,
        [Parameter(Mandatory)]
        [hashtable]$HostEnv
    )

    $modInfo = Get-ModuleInfo

    # Attempt exact match first
    $command = Get-Command -Name $Name -ErrorAction SilentlyContinue

    if (-not $command) {
        # Fuzzy matching for exported functions only
        [System.Collections.Generic.List[System.Management.Automation.FunctionInfo]]$candidates = @()

        if ($modInfo.Module -and $modInfo.Module.ExportedFunctions.Count -gt 0) {
            $candidates = $modInfo.Module.ExportedFunctions.Values
        }
        else {
            $candidates = Get-Command -Module $modInfo.Name -CommandType Function -ErrorAction SilentlyContinue
        }

        $matches = $candidates |
        Where-Object { $_.Name -like "*$Name*" } |
        Select-Object -ExpandProperty Name -Unique |
        Sort-Object

        if ($matches.Count -eq 1) {
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text ("Resolved '{0}' → '{1}'" -f $Name, $matches[0]) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            $Name = $matches[0]
        }
        elseif ($matches.Count -gt 1) {
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text ("Multiple commands found for '{0}':" -f $Name) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            $matches | ForEach-Object { Write-FormattedText -Text ("  {0}" -f $_) -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive }
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            return
        }
        else {
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text ("No command found matching '{0}'" -f $Name) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text 'Try: Get-ToolboxHelp -List' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            return
        }
    }

    try {
        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
        Write-FormattedText -Text ("Help for: {0}" -f $Name) -ForegroundColor Cyan -IsInteractive $HostEnv.IsInteractive
        Write-FormattedText -Text '----------------------------------------' -ForegroundColor DarkGray -IsInteractive $HostEnv.IsInteractive

        if ($Examples) {
            Get-Help -Name $Name -Examples
        }
        else {
            Get-Help -Name $Name -Full
        }

        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    }
    catch {
        Write-FormattedText -Text ("Error retrieving help for '{0}': {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red -IsInteractive $HostEnv.IsInteractive
    }
}

#endregion Helper Functions

# SIG # Begin signature block
# MIIfAgYJKoZIhvcNAQcCoIIe8zCCHu8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZbgxxFxrngrKz
# H0iiYjLG8t4HzgsV7f4s1Xvh5dcIsqCCGEowggUMMIIC9KADAgECAhAR+U4xG7FH
# qkyqS9NIt7l5MA0GCSqGSIb3DQEBCwUAMB4xHDAaBgNVBAMME1ZBRFRFSyBDb2Rl
# IFNpZ25pbmcwHhcNMjUxMjE5MTk1NDIxWhcNMjYxMjE5MjAwNDIxWjAeMRwwGgYD
# VQQDDBNWQURURUsgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEA3pzzZIUEY92GDldMWuzvbLeivHOuMupgpwbezoG5v90KeuN03S5d
# nM/eom/PcIz08+fGZF04ueuCS6b48q1qFnylwg/C/TkcVRo0WFcKoFGT8yGxdfXi
# caHtapZfbSRh73r7qR7w0CioVveNBVgfMsTgE0WKcuwxemvIe/ptmkfzwAiw/IAC
# Ib0E0BjiX4PySbwWy/QKy/qMXYY19xpRItVTKNBtXzADUtzPzUcFqJU83vM2gZFs
# Or0MhPvM7xEVkOWZFBAWAubbMCJ3rmwyVv9keVDJChhCeLSz2XR11VGDOEA2OO90
# Y30WfY9aOI2sCfQcKMeJ9ypkHl0xORdhUwZ3Wz48d3yJDXGkduPm2vl05RvnA4T6
# 29HVZTmMdvP2475/8nLxCte9IB7TobAOGl6P1NuwplAMKM8qyZh62Br23vcx1fXZ
# TJlKCxBFx1nTa6VlIJk+UbM4ZPm954peB/fIqEacm8LkZ0cPwmLE5ckW7hfK4Trs
# o+RaudU1sKeA+FvpOWgsPccVRWcEYyGkwbyTB3xrIBXA+YckbANZ0XL7fv7x29hn
# gXbZipGu3DnTISiFB43V4MhNDKZYfbWdxze0SwLe8KzIaKnwlwRgvXDMwXgk99Mi
# EbYa3DvA/5ZWikLW9PxBFD7Vdr8ZiG/tRC9I2Y6fnb+PVoZKc/2xsW0CAwEAAaNG
# MEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQW
# BBRfYLVE8caSc990rnrIHUjoB7X/KjANBgkqhkiG9w0BAQsFAAOCAgEAiGB2Wmk3
# QBtd1LcynmxHzmu+X4Y5DIpMMNC2ahsqZtPUVcGqmb5IFbVuAdQphL6PSrDjaAR8
# 1S8uTfUnMa119LmIb7di7TlH2F5K3530h5x8JMj5EErl0xmZyJtSg7BTiBA/UrMz
# 6WCf8wWIG2/4NbV6aAyFwIojfAcKoO8ng44Dal/oLGzLO3FDE5AWhcda/FbqVjSJ
# 1zMfiW8odd4LgbmoyEI024KkwOkkPyJQ2Ugn6HMqlFLazAmBBpyS7wxdaAGrl18n
# 6bS7QuAwCd9hitdMMitG8YyWL6tKeRSbuTP5E+ASbu0Ga8/fxRO5ZSQhO6/5ro1j
# PGe1/Kr49Uyuf9VSCZdNIZAyjjeVAoxmV0IfxQLKz6VOG0kGDYkFGskvllIpQbQg
# WLuPLJxoskJsoJllk7MjZJwrpr08+3FQnLkRuisjDOc3l4VxFUsUe4fnJhMUONXT
# Sk7vdspgxirNbLmXU4yYWdsizz3nMUR0zebUW29A+HYme16hzrMPOeyoQjy4I5XX
# 3wXAFdworfPEr/ozDFrdXKgbLwZopymKbBwv6wtT7+1zVhJXr+jGVQ1TWr6R+8ea
# tIOFnY7HqGaxe5XB7HzOwJKdj+bpHAfXft1vUoiKr16VajLigcYCG8MdwC3sngO3
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95EwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYg
# MjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphB
# cr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6p
# vF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHe
# HYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEd
# gkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjU
# jsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bR
# VFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeS
# LsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIV
# NSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL
# 6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2Zd
# SoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFU
# eEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEw
# DQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/
# T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQ
# E7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9r
# EVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y
# 1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gx
# dEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3t
# y9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcy
# tL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEB
# YTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud
# /v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiS
# uEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZP
# ubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsF
# ADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hB
# MjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzEL
# MAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJE
# aWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUg
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMr
# V7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8
# dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7M
# rxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZ
# ZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFO
# nHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+n
# igNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeIt
# K/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1
# zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk
# 8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsW
# eupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAk
# prxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0G
# A1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQG
# fHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYB
# BQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEy
# NTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hB
# MjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWL
# pQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgj
# g8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3Q
# YIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5
# bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUG
# tMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNE
# suEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6U
# Arb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG
# 0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWV
# FjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5
# t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjs
# arfNZzGCBg4wggYKAgEBMDIwHjEcMBoGA1UEAwwTVkFEVEVLIENvZGUgU2lnbmlu
# ZwIQEflOMRuxR6pMqkvTSLe5eTANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCZt4v+DgbR
# ZMEHf565tIzYpDPBQv7IdsNAU/iYOVCN1DANBgkqhkiG9w0BAQEFAASCAgAyvcBF
# ttFb6+yDnu1yFKz+EtJYy5gKnoWw/F6MGQMTukBc6Np3ssh69pxTCURCcSFC56Vp
# GD7+orF5wexCWapF13g3EqtFqTqzr3xOtmqyYSZQ2qUL9c6mq7kSQOoy2stNxFPb
# NyN7NR52n+U15dmnGXujc5ahftTveMmSP9yAPYCngaqiFX9qij+ELPuKEBdjutqh
# BPE9RQfjR1ZsgQ//mhh00uNFwdGKEUB7uSeyUAIV5sXhKQIQxu+ad20u7WLwb6Qp
# AzGr46JLh52SXqSY3Oe1CTzinV69/Ld1cHQPAl2D1p1JVI8bI4LZdGO1NJe6Pj0v
# ufQ6Ailgr8nV8nGFPd01iF8RUjbWm6f+iRHEI+NR8/ugCgDqLOgUE7e06momqmPB
# U1zoaHkc0Mf8WdGbKJKS3tQOxWgTJ76WK5yqUaJAKUGRgih3hEjwyBNxJaN5UPsH
# Eu4B160puQsIM0wEdSSGtfQGgJ5kVVM4C8iXgzVcujLgtfWMTDrf8q2Ne15Tqj0b
# x3etlgp7Eb+IiiRU7ulkmcc+ZGNY5oI4JR+OHgz4CIpFgI7wSX1y/HTIrLEMEcn5
# +rzBfNosDf7FsEeqSRtZzmjvrSdtMYxP+xQFXtMd7vobw7CiPavInHP8E4qPEo2A
# MtN9xUjY9yuEvFvKZfD+ZkYTFG80w0CYZ8bgEaGCAyYwggMiBgkqhkiG9w0BCQYx
# ggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZI
# AWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0yNjA0MTAyMTQ2MjlaMC8GCSqGSIb3DQEJBDEiBCABmr+yooYnCdSqm3RX
# B7p/LsM6dovWzFbsHRrmEwK1wDANBgkqhkiG9w0BAQEFAASCAgBHfvYfbardakH2
# B8SYAY37uoOleDzVUiob87kSykV72FopZr5wOZWmYFCpsUTUR6VRDNys9Ztnkq0W
# l5S4uKjm0Xb8ESKAwukGmOnn8XDYSWWJf4jI9vDs0kELpfUI3nrBbHik6e2cP+qD
# 0jb58sub3CRrURZsrwXT+qAa0S75CJy1afnGY3vnZmdjpnrBJy5ZHXJDDY1MrnCr
# HEPXwTaV0CvIFc8nz9AdlSO+ZxXM//DNQyZ1Wyts2DtMvWlQvxPyoDIj7EnDI3RZ
# TP9K0lBSVVG88yAZhSJd7nvECuW2PhVWjzvx5ZJaaMSx7MdpQKy6bgDCAHtHKHz8
# +4STFs7NjaTn7EMVv+QzoRh/ltPzGV4BBnpq0mpdz1Lp0trTb/Mk2OskqIgPlJxx
# 7Hcs+PVu7rLV+kv58CpZZPa2z1xNsM1zaZ5UZQR2utjfgWgxFh+O+9VxZyJs3HE7
# AxAnAhfx9Vs54Ti5t65QEDDiPjPEPEwoq1pCtYa2nDG6PuLLW0d0Cv/TOmEvDNim
# SdKUuIwNHhQOigDV9dluOVUPSGg52xnuTkiPC5n/JiqKefkQ5D4jS8bl8AODFS07
# aiWLhGxG7ts/vhHu3fxylDVVczEkhwQtwHYaN5RcL/TF6QI/rycG4GQcDqDB253M
# KoGe/rif5hL+AxXrCLx525HXoKi4qg==
# SIG # End signature block
