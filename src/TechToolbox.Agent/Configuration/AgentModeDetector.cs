using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Configuration;

/// <summary>
/// Helper to infer AgentMode from a tool registry.
/// </summary>
public static class AgentModeDetector
{
    /// <summary>
    /// Detects the agent mode based on available tools.
    /// - If PowerShell tools are present: TechToolbox
    /// - If only file I/O tools: Assistant
    /// - Otherwise: Custom
    /// </summary>
    public static AgentMode DetectMode(IReadOnlyDictionary<string, ToolSpec> registry)
    {
        if (registry == null || registry.Count == 0)
            return AgentMode.Custom;

        // Check if TechToolbox PowerShell tools are available
        var toolNames = registry.Keys.Select(k => k.ToLowerInvariant()).ToHashSet();

        var hasPowerShellTools = toolNames.Any(name =>
            !name.Equals("read-file", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("write-file", StringComparison.OrdinalIgnoreCase)
            && !name.Equals("list-directory", StringComparison.OrdinalIgnoreCase)
        );

        if (hasPowerShellTools)
            return AgentMode.TechToolbox;

        // Only basic file tools available
        var hasFileTools = toolNames.Contains("read-file")
            || toolNames.Contains("write-file")
            || toolNames.Contains("list-directory");

        if (hasFileTools && !hasPowerShellTools)
            return AgentMode.Assistant;

        return AgentMode.Custom;
    }
}
