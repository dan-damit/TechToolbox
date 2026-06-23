namespace TechToolbox.Agent.Registry;

/// <summary>
/// Builds a tool registry from multiple tool providers and the manifest.
/// Supports flexible tool discovery and composition.
/// </summary>
public static class ToolRegistry
{
    /// <summary>
    /// Legacy method: builds registry with PowerShell and built-in tools.
    /// Maintained for backward compatibility.
    /// </summary>
    public static IReadOnlyDictionary<string, ToolSpec> BuildToolRegistry()
    {
        var providers = new List<IToolProvider>
        {
            new GenericToolProvider(),
            new PowerShellToolProvider()
        };

        return BuildToolRegistry(providers);
    }

    /// <summary>
    /// Builds a tool registry from the specified tool providers.
    /// </summary>
    public static IReadOnlyDictionary<string, ToolSpec> BuildToolRegistry(
        IEnumerable<IToolProvider> providers
    )
    {
        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase);
        var manifest = ManifestLoader.LoadManifest();

        // 1. Discover and add tools from all providers
        foreach (var provider in providers ?? Enumerable.Empty<IToolProvider>())
        {
            try
            {
                var discovered = provider.DiscoverTools();
                foreach (var tool in discovered ?? Enumerable.Empty<ToolSpec>())
                {
                    registry[tool.Name] = tool;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"Warning: Tool provider {provider.ProviderName} failed: {ex.Message}"
                );
            }
        }

        // 2. Apply manifest overrides
        foreach (var kv in manifest)
        {
            var name = kv.Key;
            var overrideSpec = kv.Value;

            if (!registry.TryGetValue(name, out var existing))
            {
                // Manifest-only tool
                registry[name] = overrideSpec;
                continue;
            }

            // Merge discovered + manifest
            var merged = existing with
            {
                Description = string.IsNullOrWhiteSpace(overrideSpec.Description)
                    ? existing.Description
                    : overrideSpec.Description,

                Parameters =
                    overrideSpec.Parameters?.Count > 0
                        ? overrideSpec.Parameters
                        : existing.Parameters,

                Module = string.IsNullOrWhiteSpace(overrideSpec.Module)
                    ? existing.Module
                    : overrideSpec.Module,

                Meta = overrideSpec.Meta?.Count > 0 ? overrideSpec.Meta : existing.Meta,
            };

            registry[name] = merged;
        }

        return registry;
    }

    private static IEnumerable<ToolSpec> GetBuiltInTools()
    {
        // Kept for reference; functionality moved to GenericToolProvider
        return Enumerable.Empty<ToolSpec>();
    }

    private static IEnumerable<ToolSpec> DiscoverTools()
    {
        // Kept for backward compatibility; use PowerShellToolProvider directly instead
        return Enumerable.Empty<ToolSpec>();
    }

    private static string? ResolveModuleManifestPath()
    {
        // Kept for reference; moved to PowerShellToolProvider
        return null;
    }
}

/// <summary>
/// Represents a tool specification with metadata.
/// </summary>
public record ToolSpec(
    string Name,
    string Description,
    Dictionary<string, ParameterSpec> Parameters,
    string Module,
    Dictionary<string, object?> Meta
);

/// <summary>
/// Represents a parameter specification for a tool.
/// </summary>
public record ParameterSpec(bool Mandatory, string? Type, string? Help);
