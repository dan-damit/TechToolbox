function Get-ToolboxHelp {
    <#
    .SYNOPSIS
        Provides help information for TechToolbox public commands.

    .DESCRIPTION
        Get-ToolboxHelp displays help information for TechToolbox commands and
        configuration in an interactive, formatted manner. The function supports
        multiple display modes:

        - Default (no parameters): Displays a brief note pointing users to
          PowerShell's native 'Get-Help' cmdlet for detailed command
          documentation.

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

        Displays a brief note pointing users to PowerShell's native 'Get-Help'
        cmdlet for detailed documentation. Use '-List' to see available commands
        or '-Name <Cmdlet>' for specific help.

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
        Author: Dan.Damit (https://github.com/dan-damit/)

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

    .LINK
        https://dan-damit.github.io/TechToolbox-Docs/Get-ToolboxHelp

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
        [switch]$Examples,

        [Parameter(ParameterSetName = 'Config')]
        [string]$Section,

        [Parameter(ParameterSetName = 'Config')]
        [string]$Search
    )

    begin {
        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'

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
                    Show-Configuration -AsJson $AsJson -ConfigState $configState -HostEnv $hostEnvironment -Section $Section -Search $Search
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
        [AllowEmptyString()]
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
        Displays a brief note pointing users to PowerShell's native Get-Help cmdlet.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$HostEnv
    )

    if ($HostEnv.IsInteractive) {
        Write-Host '' -ForegroundColor Gray
        Write-FormattedText -Text 'For detailed help on any TechToolbox command, use PowerShell native Get-Help:' -ForegroundColor Cyan -IsInteractive $true
        Write-FormattedText -Text '  Get-Help <CommandName>       Show detailed help for a specific command' -ForegroundColor Yellow -IsInteractive $true
        Write-FormattedText -Text '  Get-Help <CommandName> -Full Show complete documentation including examples' -ForegroundColor Yellow -IsInteractive $true
        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $true
        Write-FormattedText -Text 'To see all available public commands, run: Get-ToolboxHelp -List' -ForegroundColor Cyan -IsInteractive $true
        Write-Host '' -ForegroundColor Gray
    }
    else {
        Write-Information "For detailed help on any TechToolbox command, use PowerShell native Get-Help."
        Write-Information "  Get-Help <CommandName>       Show detailed help for a specific command"
        Write-Information "  Get-Help <CommandName> -Full Show complete documentation including examples"
        Write-Information ""
        Write-Information "To see all available public commands, run: Get-ToolboxHelp -List"
    }
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

                $wrappedLines = @(Split-TextToColumns -Text $synopsis -MaxWidth $columnWidth -HangingIndent $hangingIndent)

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
        Displays the effective configuration with optional JSON output,
        colorized sections, section filtering, and regex search.
    #>
    param(
        [bool]$AsJson = $false,

        [Parameter(Mandatory)]
        [hashtable]$ConfigState,

        [Parameter(Mandatory)]
        [hashtable]$HostEnv,

        [string]$Section,

        [string]$Search
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
            Write-Verbose ("Show-Configuration: Configuration load failed: {0}" -f $_.Exception.Message)
        }
    }

    Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text 'Effective Configuration' -ForegroundColor Cyan -IsInteractive $HostEnv.IsInteractive
    Write-FormattedText -Text '----------------------------------------' -ForegroundColor DarkGray -IsInteractive $HostEnv.IsInteractive

    if (-not $loaded) {
        Write-FormattedText -Text '(no configuration loaded)' -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
        return
    }

    # ---- Section filtering ----
    if ($Section) {
        if ($config.PSObject.Properties.Name -contains $Section) {
            $config = $config.$Section
            Write-FormattedText -Text ("[Section: {0}]" -f $Section) -ForegroundColor Green -IsInteractive $HostEnv.IsInteractive
        }
        else {
            Write-FormattedText -Text ("Section '{0}' not found." -f $Section) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            return
        }
    }

    # ---- JSON mode ----
    if ($AsJson) {
        $config | ConvertTo-Json -Depth 20
        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
        return
    }

    # ---- Regex search mode ----
    if ($Search) {
        Write-FormattedText -Text ("[Search: {0}]" -f $Search) -ForegroundColor Green -IsInteractive $HostEnv.IsInteractive

        function Search-Config {
            param(
                [object]$Obj,
                [string]$Path = ''
            )

            if ($Obj -is [System.Collections.IDictionary]) {
                foreach ($key in $Obj.Keys) {
                    $newPath = if ($Path) { "$Path.$key" } else { $key }
                    Search-Config -Obj $Obj[$key] -Path $newPath
                }
            }
            elseif ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
                $i = 0
                foreach ($item in $Obj) {
                    Search-Config -Obj $item -Path "$Path[$i]"
                    $i++
                }
            }
            else {
                $value = [string]$Obj
                if ($Path -match $Search -or $value -match $Search) {
                    Write-FormattedText -Text ("{0} = {1}" -f $Path, $value) -ForegroundColor DarkCyan -IsInteractive $HostEnv.IsInteractive
                }
            }
        }

        Search-Config -Obj $config
        Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
        return
    }

    # ---- Colorized pretty output ----
    function Show-ColorizedObject {
        param([object]$Obj, [int]$Indent = 0)

        $pad = ' ' * $Indent

        if ($Obj -is [System.Collections.IDictionary]) {
            foreach ($key in $Obj.Keys) {
                Write-FormattedText -Text ("{0}{1}:" -f $pad, $key) -ForegroundColor DarkCyan -IsInteractive $HostEnv.IsInteractive
                Show-ColorizedObject -Obj $Obj[$key] -Indent ($Indent + 4)
            }
        }
        elseif ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
            foreach ($item in $Obj) {
                Show-ColorizedObject -Obj $item -Indent ($Indent + 2)
            }
        }
        else {
            Write-FormattedText -Text ("{0}{1}" -f $pad, $Obj) -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
        }
    }

    Show-ColorizedObject -Obj $config

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

        $CMHMatches = $candidates |
        Where-Object { $_.Name -like "*$Name*" } |
        Select-Object -ExpandProperty Name -Unique |
        Sort-Object

        if ($CMHMatches.Count -eq 1) {
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text ("Resolved '{0}' => '{1}'" -f $Name, $CMHMatches[0]) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            $Name = $CMHMatches[0]
        }
        elseif ($CMHMatches.Count -gt 1) {
            Write-FormattedText -Text '' -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive
            Write-FormattedText -Text ("Multiple commands found for '{0}':" -f $Name) -ForegroundColor Yellow -IsInteractive $HostEnv.IsInteractive
            $CMHMatches | ForEach-Object { Write-FormattedText -Text ("  {0}" -f $_) -ForegroundColor Gray -IsInteractive $HostEnv.IsInteractive }
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
# MIImyAYJKoZIhvcNAQcCoIImuTCCJrUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCzsNG3sj3hIqXt
# Xnh1C02ocfrkP9HGeSd+ewHJuo7+D6CCIFgwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# twGpn1eqXijiuZQwggZdMIIERaADAgECAhBpTFLXctn5PbJa0As3IGxtMA0GCSqG
# SIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0YSBT
# eXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAyMSBD
# QTAeFw0yNjEwMDUxMzMxNDFaFw0yNzEwMDUxMzMxNDBaMIGCMQswCQYDVQQGEwJV
# UzESMBAGA1UECAwJV2lzY29uc2luMRIwEAYDVQQHDAlHcmVlbiBCYXkxHjAcBgNV
# BAoMFU9wZW4gU291cmNlIERldmVsb3BlcjErMCkGA1UEAwwiT3BlbiBTb3VyY2Ug
# RGV2ZWxvcGVyIERhbmllbCBEYW1pdDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCC
# AYoCggGBANilePw/amtPJjQeEn4JFolWXMyIqYt6qWyV8w8x1UxEay+xJ4AXUZOZ
# x1fqS+H/rHVwW2Qt1Z2yYmYxaq5HHCUXz3KfjsvCamr7VVgytzmkJYid9ciQsZNQ
# 5ki3cwp63NUm6TsuUUln/9AzTfRDFVFQYZJWj6gSyzg8VMzd8J67YgZsb9b/gjWW
# hnP6IdHhSEYvINMKDVd4R0KCsSKPspArt5g/c/MkmqbKNa73zHfhTbJWPG+azmIN
# oEfFt8aUOp98+jsi3o6nI/vH7kT4HMm6HZrTwGPpkkWF6Y8aazCcaYP6e3skwYF6
# NNv6lbNXGNpTZZrta1kqHPaXfyK+QgjYUK2VxXivV2LuhfaeLeyq1ex2dty2U4Si
# e6zeJqihKYxDEcwUIburAZ9ei8qKugbmT0Rp9Hhn8GUl+TeJfSebnB/CpGfwU6A4
# k7MsYRBGOcpnaHAxYPLsIO+TRPjAzLU6aPSjMmMq76Mc5/vP7qJOhYcMZy5KQA5E
# QmyC7e41JQIDAQABo4IBeDCCAXQwDAYDVR0TAQH/BAIwADA9BgNVHR8ENjA0MDKg
# MKAuhixodHRwOi8vY2NzY2EyMDIxLmNybC5jZXJ0dW0ucGwvY2NzY2EyMDIxLmNy
# bDBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9jY3NjYTIwMjEu
# b2NzcC1jZXJ0dW0uY29tMDUGCCsGAQUFBzAChilodHRwOi8vcmVwb3NpdG9yeS5j
# ZXJ0dW0ucGwvY2NzY2EyMDIxLmNlcjAfBgNVHSMEGDAWgBTddF1MANt7n6B0yrFu
# 9zzAMsBwzTAdBgNVHQ4EFgQUXEW08OGC/PMxgp4+sfHWDuO+VlAwSwYDVR0gBEQw
# QjAIBgZngQwBBAEwNgYLKoRoAYb2dwIFAQQwJzAlBggrBgEFBQcCARYZaHR0cHM6
# Ly93d3cuY2VydHVtLnBsL0NQUzATBgNVHSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBACmDxwDt3CyhNLBL/Hgcn9cnYkJa
# rOYB95K1G38KJGWxyH0ABL7+VhmG3dUsw0M3CldokOOsYglSXMBnXoDUwjbtafEH
# JJf5XkGyllKIVKVy3i2vvrdaW3GZW3aJ8h/iqPbcG3T4/ghQMxsQXvVc9JjQ0V+l
# IHIJnYDSZlcmCqVhUglgRCtV3X4Z5QaTXh+bDWz2UgP8Rh8X0vfr24e//AmoAMAm
# wsjBJh6f+VR+bcjoYZz8goqxbc14tEROzybiwcuxty46E35OaMDQbf0niBUhRsFI
# cgZ9Yc3EtENQpl539qE/G12uvVJdLN5+YGU5Eq2j3Pvi0ULEueWPHAl5BtsxL72l
# JW6ET4AWVs1GD3cS6lYXlQQfIgv3vpjry5VS3G7j2IsqjGpoz1ICFAyjpHxxdiXD
# XmIMQfPco7I5FJIZaJblehUY1Y5B7wJk7X3W822hVyi0/q3qWiJu/DENsivpC6ds
# pl/l544af0OEusv1HslZcJ7cL0hJojqaYbn21Rhp5C9pAuI7s36PbdSpXw/dIbNr
# 4QxOsA2EYBwcgYWF4wczdbsJg3KpnriFUs/dVGcYFbhqdhtPWSiXg/CyFQjdpnHS
# TsLMjqO137madchLsRR4NktGTjEiFiq4WYm9df9UImQKP1otePSdpMLjItHn/Ln/
# uzy3ZnU96zwlheYwMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkq
# hkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2
# IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqY
# QXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+
# qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB
# 3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIB
# HYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI
# 1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN2
# 0VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDn
# ki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmS
# FTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6To
# y+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1Btm
# XUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHR
# VHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB
# /wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1Ud
# IwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNV
# HSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0f
# BDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcB
# MA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBow
# f0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEI
# UBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/
# axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYf
# ctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4
# MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i69
# 7cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsX
# MrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7h
# AWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSab
# nf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rY
# krhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2
# T7m3XDCCBrkwggShoAMCAQICEQCZo4AKJlU7ZavcboSms+o5MA0GCSqGSIb3DQEB
# DAUAMIGAMQswCQYDVQQGEwJQTDEiMCAGA1UEChMZVW5pemV0byBUZWNobm9sb2dp
# ZXMgUy5BLjEnMCUGA1UECxMeQ2VydHVtIENlcnRpZmljYXRpb24gQXV0aG9yaXR5
# MSQwIgYDVQQDExtDZXJ0dW0gVHJ1c3RlZCBOZXR3b3JrIENBIDIwHhcNMjEwNTE5
# MDUzMjE4WhcNMzYwNTE4MDUzMjE4WjBWMQswCQYDVQQGEwJQTDEhMB8GA1UEChMY
# QXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMSQwIgYDVQQDExtDZXJ0dW0gQ29kZSBT
# aWduaW5nIDIwMjEgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCd
# I88EMCM7wUYs5zNzPmNdenW6vlxNur3rLfi+5OZ+U3iZIB+AspO+CC/bj+taJUbM
# bFP1gQBJUzDUCPx7BNLgid1TyztVLn52NKgxxu8gpyTr6EjWyGzKU/gnIu+bHAse
# 1LCitX3CaOE13rbuHbtrxF2tPU8f253QgX6eO8yTbGps1Mg+yda3DcTsOYOhSYNC
# JiL+5wnjZ9weoGRtvFgMHtJg6i671OPXIciiHO4Lwo2p9xh/tnj+JmCQEn5QU0Nx
# zrOiRna4kjFaA9ZcwSaG7WAxeC/xoZSxF1oK1UPZtKVt+yrsGKqWONoK6f5EmBOA
# VEK2y4ATDSkb34UD7JA32f+Rm0wsr5ajzftDhA5mBipVZDjHpwzv8bTKzCDUSUuU
# mPo1govD0RwFcTtMXcfJtm1i+P2UNXadPyYVKRxKQATHN3imsfBiNRdN5kiVVeqP
# 55piqgxOkyt+HkwIA4gbmSc3hD8ke66t9MjlcNg73rZZlrLHsAIV/nJ0mmgSjBI/
# TthoGJDydekOQ2tQD2Dup/+sKQptalDlui59SerVSJg8gAeV7N/ia4mrGoiez+Sq
# V3olVfxyLFt3o/OQOnBmjhKUANoKLYlKmUpKEFI0PfoT8Q1W/y6s9LTI6ekbi0ig
# EbFUIBE8KDUGfIwnisEkBw5KcBZ3XwnHmfznwlKo8QIDAQABo4IBVTCCAVEwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3XRdTADbe5+gdMqxbvc8wDLAcM0wHwYD
# VR0jBBgwFoAUtqFUOQLDoD+Oirz61PgcptE6Dv0wDgYDVR0PAQH/BAQDAgEGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9jcmwu
# Y2VydHVtLnBsL2N0bmNhMi5jcmwwbAYIKwYBBQUHAQEEYDBeMCgGCCsGAQUFBzAB
# hhxodHRwOi8vc3ViY2Eub2NzcC1jZXJ0dW0uY29tMDIGCCsGAQUFBzAChiZodHRw
# Oi8vcmVwb3NpdG9yeS5jZXJ0dW0ucGwvY3RuY2EyLmNlcjA5BgNVHSAEMjAwMC4G
# BFUdIAAwJjAkBggrBgEFBQcCARYYaHR0cDovL3d3dy5jZXJ0dW0ucGwvQ1BTMA0G
# CSqGSIb3DQEBDAUAA4ICAQB1iFgP5Y9QKJpTnxDsQ/z0O23JmoZifZdEOEmQvo/7
# 9PQg9nLF/GJe6ZiUBEyDBHMtFRK0mXj3Qv3gL0sYXe+PPMfwmreJHvgFGWQ7Xwnf
# Mh2YIpBrkvJnjwh8gIlNlUl4KENTK5DLqsYPEtRQCw7R6p4s2EtWyDDr/M58iY2U
# BEqfUU/ujR9NuPyKk0bEcEi62JGxauFYzZ/yld13fHaZskIoq2XazjaD0pQkcQiI
# ueL0HKiohS6XgZuUtCKA7S6CHttZEsObQJ1j2s0urIDdqF7xaXFVaTHKtAuMfwi0
# jXtF3JJphrJfc+FFILgCbX/uYBPBlbBIP4Ht4xxk2GmfzMn7oxPITpigQFJFWuzT
# MUUgdRHTxaTSKRJ/6Uh7ki/pFjf9sUASWgxT69QF9Ki4JF5nBIujxZ2sOU9e1HSC
# JwOfK07t5nnzbs1LbHuAIGJsRJiQ6HX/DW1XFOlXY1rc9HufFhWU+7Uk+hFkJsfz
# qBz3pRO+5aI6u5abI4Qws4YaeJH7H7M8X/YNoaArZbV4Ql+jarKsE0+8XvC4DJB+
# IVcvC9Ydqahi09mjQse4fxfef0L7E3hho2O3bLDM6v60rIRUCi2fJT2/IRU5ohgy
# Tch4GuYWefSBsp5NPJh4QRTP9DC3gc5QEKtbrTY0Ka87Web7/zScvLmvQBm8JDFp
# DjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAw
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04
# xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZ
# dw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4
# yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqM
# v9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d
# 3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ
# 27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pB
# NY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmV
# ZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71
# fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4t
# MZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X
# +eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNV
# HQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6
# yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2
# MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1
# NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAN
# BgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDa
# MiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+O
# ReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R7
# 9ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp
# 1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylch
# eWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ
# 3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6
# QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc
# 1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDD
# W15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbe
# vGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0
# /YMxggXGMIIFwgIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28g
# RGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcg
# MjAyMSBDQQIQaUxS13LZ+T2yWtALNyBsbTANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD+
# PGOAu24h91ANH4XXbJndJQveeYlMF3g+lSdXgD0O+zANBgkqhkiG9w0BAQEFAASC
# AYCXx5nZSFMsmunhjSRg6A8GpYojN0ci//DcFGUOVsCxJmePQMXtMwYJbP/p46Fu
# 0Q+oyigfEXgn0aV8rWVqLCgLvERandaOqkiUqWmE+qn2fk6XzJ54KgGtdoIyZqFG
# oakspwgw3nr6HbV8oqucIqQ0Mf0ott6n2vXFKIU8jpFTfkYTfpH0rrfXX7sgsA59
# Tp8EmVV7jeNoFPn+Hqt7c8Z+FpMTrF7SkQ2jAA8EWnA2ZbfGJfK3GvTFo4Ma7Rdp
# 3g8qr3BS/Rdc0DE4/eoysTbAGtODlX0P3eLsAMqh5WpUhccfPzLGdFEsvahb2VpV
# UMAGygj6Mc55rHxB0WvlE9nQ3LqQX9VuPrFmnek3exurSZaEUJVHUuGikvHQfy0Z
# aYLWO8LuvHkdVLLA5zzbFxIKa3vFnh1TLq4CqmznNXaLU0B9xpb5lqBwFT1TihfU
# 9HqEScSVzcKYi559OklKJ7XbeMR9cP4OG7DvwKJ81ARvglyYbWzUsTRW3kI2/ljr
# jhuhggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAI
# T9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkDMQsG
# CSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYxMTI3MjIxNDQ0WjAvBgkqhkiG
# 9w0BCQQxIgQg0XYFC3wf5wl1vRrEMn+Q9EYr1y3ZtFQ7P/25ekBiyu0wDQYJKoZI
# hvcNAQEBBQAEggIAbzVn4y+ORmSvnyLFHIe5GA4gsmF8PR/gWV7NjE09AJXYpjh8
# ABAskg6KhDgUgwngQBNc68b2/ZHZw3NXq8lvp4hhJQ+XGOxb48hXZCTH7M8CA4Y0
# jFHXzaVs4L3on6Cx8oDvZqouakvZqmhy/rG0NZ6iAEWE6HwRHzDOFJ8gbidcQn5D
# OGrjI3iQ8G90vTa0jctv9s2ORtLzo2v/zpnCaEQAcuIF/Yxui4xkVsLjNGse9UYP
# lpaJOms+gNnTTlEiNA/dkd1bnLREvZMy+T4Ap1MGN5Oa0m6Zn/NqjcD+qxDIxbva
# F5ihS8sesJHVNRDWlpHZE0OKfbr3GJUHmxFIBjY0I4CefyEUGBPOfSWJCnaF7Rds
# G39pn8cRStTZX4f/wH7UfyVvTyUNBKUCU+7eZ4wcRTfCxGHVoxk/eKqQvLfyI429
# UlSp8bav2/yfQfnQWPcJT6nrY55ckmNmC9mocQbYXS2tJGk5HpwYGV/pt7hNbH+a
# P+EULLYU+GCOutcA57PYvnTKLhoUV8cMvLN5zg//iw3xUXyb1ghI8dLteWp0gfoW
# rqVf+3/o7pWj5OO8hUTacbT5LTxkBciUWvIccPj/dIno1oIgNFlduJjrzpB2L5LO
# GUGjVVHRxjecD5+Prw7JtUA/5we1D5BNz0az3PwSwedEg/6wU0B7O/gcufI=
# SIG # End signature block
