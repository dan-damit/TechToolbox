# Code Analysis Report
Generated: 2/7/2026 8:03:06 PM

## Summary
 The provided PowerShell script is a function named `Invoke-DisconnectExchangeOnline` that checks if an Exchange Online session is active and prompts the user to disconnect it if necessary. Here's my analysis and suggestions for improvements:

1. **Code Structure**: The code is well-structured and easy to follow, with clear comments explaining what each section does.

2. **Variable Naming**: Variable names are descriptive and self-explanatory, making the code easier to understand.

3. **Parameter Validation**: The function accepts multiple ways of passing configuration data, which is a good practice for making the function flexible and user-friendly. However, it might be worth adding some additional parameter validation to ensure that the provided configurations are valid.

4. **Error Handling**: Error handling could be improved by wrapping more sections of the code in try/catch blocks, particularly during configuration resolution and disconnection. This would make the function more robust and able to handle unexpected issues gracefully.

5. **Code Duplication**: There's a bit of code duplication in the configuration resolution section (lines 13-36). You could potentially refactor this to reduce redundancy. For example, you could create a helper function for resolving the configuration object.

6. **Readability**: To improve readability, consider adding blank lines between sections of the code and using indentation consistently. This will make it easier for others to understand the flow of the script.

7. **Performance**: Performance might not be a significant concern in this case, but if the function takes a long time to run or consumes a lot of resources, you could consider optimizing it by reducing the number of API calls and minimizing unnecessary operations.

## Source Code
```powershell
function Invoke-DisconnectExchangeOnline {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        # Either pass the full config or omit and it will try $global:cfg
        [pscustomobject]$Config,

        # Or pass just the exchangeOnline section explicitly
        [pscustomobject]$ExchangeOnline,

        # Skip prompting and disconnect.
        [switch]$Force,

        # Suppress prompting (opposite of Force: don’t disconnect unless forced).
        [switch]$NoPrompt
    )

    # --- Resolve configuration ---
    $exoCfg = $null

    if ($PSBoundParameters.ContainsKey('ExchangeOnline') -and $ExchangeOnline) {
        $exoCfg = $ExchangeOnline
    }
    elseif ($PSBoundParameters.ContainsKey('Config') -and $Config) {
        # If full config was provided (has settings.exchangeOnline), use that
        if ($Config.PSObject.Properties.Name -contains 'settings' -and
            $Config.settings -and
            $Config.settings.PSObject.Properties.Name -contains 'exchangeOnline') {
            $exoCfg = $Config.settings.exchangeOnline
        }
        # Or if we were given the exchangeOnline section directly (has autoDisconnectPrompt), use it
        elseif ($Config.PSObject.Properties.Name -contains 'autoDisconnectPrompt') {
            $exoCfg = $Config
        }
    }
    elseif ($global:cfg) {
        $exoCfg = $global:cfg.settings.exchangeOnline
    }

    # Default: prompt unless config says otherwise
    $autoPrompt = $true
    if ($exoCfg -and $null -ne $exoCfg.autoDisconnectPrompt) {
        $autoPrompt = [bool]$exoCfg.autoDisconnectPrompt
    }

    $shouldPrompt = $autoPrompt -and -not $Force -and -not $NoPrompt

    # --- Connection check ---
    $isConnected = $false
    try {
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $conn = Get-ConnectionInformation -ErrorAction SilentlyContinue
            $isConnected = $conn -and $conn.State -eq 'Connected'
        }
        else {
            # Older module: we can't reliably check; assume connected and let disconnect handle it
            $isConnected = $true
        }
    }
    catch {
        # If uncertain, err on the side of attempting a disconnect
        $isConnected = $true
    }

    if (-not $isConnected) {
        Write-Log -Level Info -Message "No active Exchange Online session detected."
        return $true
    }

    # --- Decide whether to proceed ---
    $proceed = $false
    if ($Force) {
        $proceed = $true
    }
    elseif ($shouldPrompt) {
        $resp = Read-Host -Prompt "Disconnect from Exchange Online? (y/N)"
        $proceed = ($resp.Trim() -match '^(y|yes)$')
    }

    if (-not $proceed) {
        Write-Log -Level Info -Message "Keeping Exchange Online session connected."
        return $false
    }

    # --- Disconnect ---
    if ($PSCmdlet.ShouldProcess('Exchange Online session', 'Disconnect')) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false
            Write-Log -Level Info -Message "Disconnected from Exchange Online."
            return $true
        }
        catch {
            Write-Log -Level Warn -Message ("Failed to disconnect cleanly: {0}" -f $_.Exception.Message)
            Write-Log -Level Info -Message "Session may remain connected."
            return $false
        }
    }

    return $false
}

[SIGNATURE BLOCK REMOVED]

```
