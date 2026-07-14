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
        var genericBuiltInTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "read-file",
            "write-file",
            "append-file",
            "finalize-file-write",
            "replace-in-file",
            "list-directory",
            "fetch-url",
        };

        var hasPowerShellTools = toolNames.Any(name =>
            !genericBuiltInTools.Contains(name)
        );

        if (hasPowerShellTools)
            return AgentMode.TechToolbox;

        // Only basic file tools available
        var hasFileTools = toolNames.Any(genericBuiltInTools.Contains);

        if (hasFileTools && !hasPowerShellTools)
            return AgentMode.Assistant;

        return AgentMode.Custom;
    }
}
