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

        $Text = $null

        # Attempt runtime initialization
        Initialize-RuntimeEnvironment

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
# MIIIngYJKoZIhvcNAQcCoIIIjzCCCIsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBraQAf3uhMbagW
# 1sZ/7rcBuzwJSJL9cYKQZwb++BlFEaCCBRAwggUMMIIC9KADAgECAhAR+U4xG7FH
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
# JDyv2V+YMfsYBmItMGBwvizlQ6557NbK95ExggLkMIIC4AIBATAyMB4xHDAaBgNV
# BAMME1ZBRFRFSyBDb2RlIFNpZ25pbmcCEBH5TjEbsUeqTKpL00i3uXkwDQYJYIZI
# AWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgnjHmJM8mL3H27u8k9hyp60KQ2CRGJ4fwg14AVZa1yfEw
# DQYJKoZIhvcNAQEBBQAEggIAGJ3j7l1RL7U62aamGjopTq6l+flN/UGlKd0ypuVL
# CTX+ojcoAWRxVSCKSHrQS2Ojw9MDMGxmVH9Pa/d/o2MteyMaYwDNSq0JhNckXBRW
# 1P+A8CJOGosc1yn1RYqOXx5o3gIGlYKjFof9WuXgBiBv64YuRFsyrfww6/eDOKHg
# RnsVb8xTGS2yX+BelMM1St6JGiLV/e4nlkETZ9f8N5bMawlmvXProLItSaCq7k4d
# SL0RDW96pXYsp+MNM66A54SS+z8pGBuRANvpCU4Ki41cAUepIicwJu2bluG7NLT3
# XjnuX6NPcgLKRXSplzdsVjkjXIM1QIhPIzMdrCmCEM9InZEWhnVD3HQWBi0p1K0L
# DzO2KVecaZRjCW37H1c5Fx0mDoBSc79QFkSHxj4wgGu5AAucW+i98/fWhzX2kTo6
# MJlwndwZAvw3+rDd5FCNtdn9R1KW23h76VfPF1sZNYGRVrTmHlAtuPchwuusrfO4
# DVRIb0UyLs9z0s8dNikvSg1xxqz7GJbHi3VMyn6UVtsusI/byZMRzNrCoA7HBTXH
# wIysL6dDzYRSkj9wcP5xnHRblYoNFLHBfCiRCtSAvstjllz5lqLerzzN9/tlhUgt
# yz/kWy6ouIWUSFJ6gdi3vN5/2L0PeYcTrlNKDaEmqSYCfzbT9oIfsRyOEHR+Gims
# WuM=
# SIG # End signature block
