using System.Management.Automation;
using TechToolbox.Agent.Agent;

namespace TechToolbox.Agent.Execution;

public static class PowerShellBridge
{
    public static object? RunTool(string toolName, IDictionary<string, object?> args)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            throw new ArgumentException("Tool name must not be empty.", nameof(toolName));

        // Safety check for destructive tools
        Safety.RequireDestructiveConfirmation(toolName, args);

        using var ps = PowerShell.Create();

        // Import the TechToolbox module explicitly
        // (Assumes the module is discoverable via PSModulePath)
        ps.AddCommand("Import-Module")
          .AddParameter("Name", "TechToolbox")
          .AddParameter("ErrorAction", "Stop")
          .Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Failed to import TechToolbox module: {ps.Streams.Error[0]}");

        ps.Commands.Clear();

        // Add the tool command
        ps.AddCommand(toolName);

        // Add parameters
        foreach (var kv in args)
        {
            // Skip internal agent control keys
            if (kv.Key.StartsWith("__", StringComparison.Ordinal))
                continue;

            ps.AddParameter(kv.Key, kv.Value);
        }

        // Execute
        var results = ps.Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Tool '{toolName}' failed: {ps.Streams.Error[0]}");

        // Normalize output
        if (results is null || results.Count == 0)
            return null;

        if (results.Count == 1)
            return results[0].BaseObject;

        return results.Select(r => r.BaseObject).ToList();
    }
}
