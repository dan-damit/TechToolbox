namespace TechToolbox.Agent.Registry;

/// <summary>
/// Interface for pluggable tool discovery and provisioning.
/// Implementations discover and provide tool specifications for different domains.
/// </summary>
public interface IToolProvider
{
    /// <summary>
    /// Discovers and returns tool specifications.
    /// </summary>
    /// <returns>An enumerable of ToolSpec objects.</returns>
    IEnumerable<ToolSpec> DiscoverTools();

    /// <summary>
    /// Optional: Gets the display name of this provider (for logging/debugging).
    /// </summary>
    string ProviderName => this.GetType().Name;
}
