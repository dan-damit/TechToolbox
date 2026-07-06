using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Configuration;

/// <summary>
/// Centralized configuration for agent behavior, tools, and prompting.
/// Allows flexible customization without modifying AgentOrchestrator.
/// </summary>
public class AgentConfiguration
{
    /// <summary>
    /// The operating mode of the agent.
    /// </summary>
    public AgentMode Mode { get; set; } = AgentMode.TechToolbox;

    /// <summary>
    /// LLM model identifier (e.g., "llama3", "gpt-4", etc.).
    /// </summary>
    public string Model { get; set; } = "llama3";

    /// <summary>
    /// Maximum number of iterations before the agent stops.
    /// </summary>
    public int MaxIterations { get; set; } = 15;

    /// <summary>
    /// Whether the agent should automatically retry with more iterations if it reaches the limit.
    /// </summary>
    public bool AutoRetryOnIterationLimit { get; set; } = false;

    /// <summary>
    /// Whether destructive operations have been explicitly confirmed by the user.
    /// Only relevant in TechToolbox mode.
    /// </summary>
    public bool DestructiveConfirmed { get; set; } = false;

    /// <summary>
    /// File signature policy for signed file operations.
    /// Options: "ignore", "warn", "require". Only relevant in TechToolbox mode.
    /// </summary>
    public string SignedFilePolicy { get; set; } = "ignore";

    /// <summary>
    /// Tool providers to use for discovering tools.
    /// If empty, defaults are chosen based on Mode.
    /// </summary>
    public List<IToolProvider> ToolProviders { get; set; } = new();

    /// <summary>
    /// Optional override for the system prompt.
    /// If provided, takes precedence over mode-based prompt generation.
    /// </summary>
    public string? SystemPromptOverride { get; set; }

    /// <summary>
    /// Optional path to a memory store file for persistent learning.
    /// </summary>
    public string? MemoryPath { get; set; }

    /// <summary>
    /// Number of recent run-history entries to inject into prompt memory context.
    /// Set to 0 to disable recent history injection.
    /// </summary>
    public int RecentHistoryItemsInPrompt { get; set; } = 2;

    /// <summary>
    /// Whether to return metadata about the agent run along with the output.
    /// </summary>
    public bool ReturnMetadata { get; set; } = false;

    /// <summary>
    /// Optional path for writing diagnostic trace information.
    /// </summary>
    public string? DiagnosticTracePath { get; set; }

    /// <summary>
    /// Optional expected output file path.
    /// If provided, the agent will enforce that WRITE-FILE is called at this location.
    /// </summary>
    public string? ExpectedOutputPath { get; set; }

    /// <summary>
    /// Optional host allowlist for built-in FETCH-URL tool requests.
    /// When empty, external fetch requests are blocked.
    /// </summary>
    public List<string> AllowedFetchHosts { get; set; } = new();

    /// <summary>
    /// Creates a default configuration for the specified mode.
    /// </summary>
    public static AgentConfiguration CreateForMode(AgentMode mode)
    {
        var config = new AgentConfiguration { Mode = mode };

        // Set defaults based on mode
        return mode switch
        {
            AgentMode.TechToolbox =>
                new AgentConfiguration
                {
                    Mode = AgentMode.TechToolbox,
                    Model = "llama3",
                    MaxIterations = 15,
                    AutoRetryOnIterationLimit = false,
                    DestructiveConfirmed = false,
                    SignedFilePolicy = "ignore",
                    ToolProviders = new()
                    {
                        new GenericToolProvider(),
                        new PowerShellToolProvider()
                    }
                },
            AgentMode.Assistant =>
                new AgentConfiguration
                {
                    Mode = AgentMode.Assistant,
                    Model = "llama3",
                    MaxIterations = 10,
                    AutoRetryOnIterationLimit = false,
                    DestructiveConfirmed = false,
                    SignedFilePolicy = "ignore",
                    ToolProviders = new() { new GenericToolProvider() }
                },
            AgentMode.CodingAgent =>
                new AgentConfiguration
                {
                    Mode = AgentMode.CodingAgent,
                    Model = "llama3",
                    MaxIterations = 20,
                    AutoRetryOnIterationLimit = true,
                    DestructiveConfirmed = false,
                    SignedFilePolicy = "ignore",
                    ToolProviders = new() { new GenericToolProvider() }
                },
            AgentMode.Custom =>
                new AgentConfiguration
                {
                    Mode = AgentMode.Custom,
                    Model = "llama3",
                    MaxIterations = 15,
                    ToolProviders = new() { new GenericToolProvider() }
                },
            _ => config
        };
    }
}
