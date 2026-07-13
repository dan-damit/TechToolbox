namespace TechToolbox.Agent.Execution;

/// <summary>
/// Default tool executor that delegates to the PowerShell bridge.
/// </summary>
public sealed class PowerShellToolExecutor : IToolExecutor
{
    public static PowerShellToolExecutor Instance { get; } = new();

    private PowerShellToolExecutor() { }

    public object? RunTool(string toolName, IDictionary<string, object?> args)
    {
        return PowerShellBridge.RunTool(toolName, args);
    }
}
