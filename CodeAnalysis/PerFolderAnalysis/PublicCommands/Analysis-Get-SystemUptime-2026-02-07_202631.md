# Code Analysis Report
Generated: 2/7/2026 8:26:31 PM

## Summary
 This PowerShell script defines a function `Get-SystemUptime` that retrieves the system uptime for the local or remote computers. The function can be run either locally or via PowerShell Remoting, with the option to use different methods for calculating the uptime: 'LastBoot' (default) or 'TickCount'.

Here are some suggestions for improving the code's functionality, readability, and performance:

1. Add validation for `$Method` parameter: It is currently possible to pass invalid values to the `$Method` parameter. You could add an `[ValidateScript()]` attribute to validate that the input string matches either 'LastBoot' or 'TickCount'.

2. Use the `-ErrorAction PreferSilence` instead of `-ErrorAction Stop` in the function definition: By using `-ErrorAction PreferSilence`, any errors encountered during the execution of the script block will be suppressed, and the function will continue to run for other computers (or the local computer if it's being executed locally). If you want to handle these errors in a more graceful way, consider adding error handling code instead.

3. Consider using `foreach -parallel` for processing multiple remote computers: To improve performance when working with multiple remote computers, you could use the `foreach -parallel` cmdlet, which allows for parallel execution of script blocks on multiple computers.

4. Add comments to explain the purpose and behavior of functions: In the current code, the two functions (`Get-UptimeFromLastBoot` and `Get-UptimeFromTickCount`) lack comments explaining their purpose and behavior. This makes it harder for others to understand how they work. Adding comments would make the code more readable and maintainable.

5. Use PowerCLI for better handling of VMware environments: If you're working with VMware environments, consider using PowerCLI instead of WMI for more reliable and efficient management of virtual machines.

6. Consider using a try-catch block in the main script to handle errors: Instead of returning an error object when an error occurs during the execution of the script block on a remote computer, you could handle the error within the main script using a try-catch block. This would help to ensure that the entire function returns a consistent output and doesn't stop early due to an error on one computer.

Overall, the code is well-structured and easy to follow. With these suggested improvements, the code can be made more robust, efficient, and maintainable.

## Source Code
```powershell
function Get-SystemUptime {
    <#
        .SYNOPSIS
        Returns system uptime locally or via PowerShell Remoting.

        .DESCRIPTION
        Defaults to using Win32_OperatingSystem.LastBootUpTime on the target system
        for maximum reliability across endpoints. Optionally, you can force the
        TickCount method.

        .PARAMETER ComputerName
        One or more remote computer names. Omit for local system.

        .PARAMETER Credential
        Credential for remote sessions.

        .PARAMETER Method
        Uptime calculation method:
        - LastBoot (default): (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        - TickCount:         [Environment]::TickCount64 (fast, may be unreliable on some endpoints)

        .EXAMPLE
        Get-SystemUptime
        .EXAMPLE
        Get-SystemUptime -ComputerName 'SRV01','SRV02'
        .EXAMPLE
        Get-SystemUptime -ComputerName SRV01 -Credential (Get-Credential) -Method TickCount

        .OUTPUTS
        PSCustomObject with ComputerName, BootTime, Uptime (TimeSpan), Days/Hours/Minutes/Seconds,
        TotalSeconds, Method, and (if applicable) Error.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string[]]$ComputerName,

        [System.Management.Automation.PSCredential]$Credential,

        [ValidateSet('LastBoot', 'TickCount')]
        [string]$Method = 'LastBoot'
    )

    $sb = {
        param([string]$Method)

        function Get-UptimeFromLastBoot {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $boot = $os.LastBootUpTime
            $now = Get-Date
            $ts = $now - $boot

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                BootTime     = $boot
                Uptime       = $ts
                Days         = $ts.Days
                Hours        = $ts.Hours
                Minutes      = $ts.Minutes
                Seconds      = $ts.Seconds
                TotalSeconds = [math]::Round($ts.TotalSeconds, 0)
                Method       = 'LastBoot'
            }
        }

        function Get-UptimeFromTickCount {
            $ms = [System.Environment]::TickCount64
            # Fallback if the endpoint returns 0 or negative (shouldn't, but we guard it)
            if ($ms -le 0) {
                return Get-UptimeFromLastBoot
            }

            $ts = [TimeSpan]::FromMilliseconds($ms)

            # Approximate BootTime from TickCount (may differ from LastBoot because TickCount may pause in sleep)
            $bootApprox = (Get-Date).AddMilliseconds(-$ms)

            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                BootTime     = $bootApprox
                Uptime       = $ts
                Days         = $ts.Days
                Hours        = $ts.Hours
                Minutes      = $ts.Minutes
                Seconds      = $ts.Seconds
                TotalSeconds = [math]::Round($ts.TotalSeconds, 0)
                Method       = 'TickCount'
            }
        }

        try {
            switch ($Method) {
                'TickCount' { Get-UptimeFromTickCount }
                default { Get-UptimeFromLastBoot }
            }
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Error        = $_.Exception.Message
                Method       = $Method
            }
        }
    }

    if (-not $ComputerName) {
        return & $sb -ArgumentList $Method
    }

    $results = foreach ($cn in $ComputerName) {
        try {
            Invoke-Command -ComputerName $cn -ScriptBlock $sb -ArgumentList $Method -Credential $Credential -ErrorAction Stop
        }
        catch {
            [PSCustomObject]@{
                ComputerName = $cn
                Error        = $_.Exception.Message
                Method       = $Method
            }
        }
    }

    return $results
}

[SIGNATURE BLOCK REMOVED]

```
