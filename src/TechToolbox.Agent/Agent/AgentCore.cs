using TechToolbox.Agent.Configuration;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public static class AgentCore
{
    private static readonly HashSet<string> MetaToolNames = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        "Invoke-CodeAssistant",
        "Invoke-CodeAssistantFolder",
        "Invoke-CodeAssistantWrapper",
        "Invoke-TechAgent",
        "ITA",
    };

    /// <summary>
    /// Runs an agent with the specified configuration.
    /// </summary>
    public static string RunAgent(AgentConfiguration config, string prompt)
    {
        return RunAgentAsync(config, prompt).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Runs an agent asynchronously with the specified configuration.
    /// </summary>
    public static async Task<string> RunAgentAsync(AgentConfiguration config, string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return "Error: prompt must not be empty.";

        if (config == null)
            return "Error: configuration must not be null.";

        try
        {
            return await RunAgentInternalAsync(config, prompt).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }

    /// <summary>
    /// Legacy method: runs an agent with individual parameters.
    /// Maintained for backward compatibility. Use RunAgent(AgentConfiguration, string) for new code.
    /// </summary>
    public static string RunAgent(
        string prompt,
        string model = "llama3",
        bool verbose = true,
        int maxIterations = 15,
        bool destructiveConfirmed = false,
        string? memoryPath = null,
        bool autoRetryOnRecursion = false,
        bool returnMetadata = false,
        string signedFilePolicy = "ignore",
        string? diagnosticTracePath = null,
        string? expectedOutputPath = null,
        int recentHistoryItemsInPrompt = 2,
        IEnumerable<string>? allowedFetchHosts = null,
        bool allowMetaTools = false
    )
    {
        return RunAgentAsync(
                prompt,
                model,
                verbose,
                maxIterations,
                destructiveConfirmed,
                memoryPath,
                autoRetryOnRecursion,
                returnMetadata,
                signedFilePolicy,
                diagnosticTracePath,
                expectedOutputPath,
                recentHistoryItemsInPrompt,
                allowedFetchHosts,
                allowMetaTools
            )
            .GetAwaiter()
            .GetResult();
    }

    /// <summary>
    /// Legacy method: runs an agent asynchronously with individual parameters.
    /// Maintained for backward compatibility. Use RunAgentAsync(AgentConfiguration, string) for new code.
    /// </summary>
    public static async Task<string> RunAgentAsync(
        string prompt,
        string model = "llama3",
        bool verbose = true,
        int maxIterations = 15,
        bool destructiveConfirmed = false,
        string? memoryPath = null,
        bool autoRetryOnRecursion = false,
        bool returnMetadata = false,
        string signedFilePolicy = "ignore",
        string? diagnosticTracePath = null,
        string? expectedOutputPath = null,
        int recentHistoryItemsInPrompt = 2,
        IEnumerable<string>? allowedFetchHosts = null,
        bool allowMetaTools = false
    )
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return "Error: prompt must not be empty.";

        // Convert legacy parameters to configuration
        var config = new AgentConfiguration
        {
            Mode = AgentMode.TechToolbox,
            Model = model,
            MaxIterations = maxIterations,
            AutoRetryOnIterationLimit = autoRetryOnRecursion,
            DestructiveConfirmed = destructiveConfirmed,
            SignedFilePolicy = signedFilePolicy,
            MemoryPath = memoryPath,
            RecentHistoryItemsInPrompt = recentHistoryItemsInPrompt,
            ReturnMetadata = returnMetadata,
            DiagnosticTracePath = diagnosticTracePath,
            ExpectedOutputPath = expectedOutputPath,
            AllowMetaTools = allowMetaTools,
            AllowedFetchHosts = allowedFetchHosts?.Where(h => !string.IsNullOrWhiteSpace(h)).ToList()
                ?? new List<string>(),
            ToolProviders = new()
            {
                new GenericToolProvider(),
                new PowerShellToolProvider()
            }
        };

        var output = await RunAgentInternalAsync(config, prompt).ConfigureAwait(false);

        if (!returnMetadata)
            return output;

        // For backward compatibility with old API, return metadata if requested
        // (Note: metadata is already included if output is JSON)
        return output;
    }

    private static async Task<string> RunAgentInternalAsync(
        AgentConfiguration config,
        string prompt
    )
    {
        // 1. Build tool registry from configured tool providers
        var toolProviders = config.ToolProviders ?? Enumerable.Empty<IToolProvider>();
        var registry = ToolRegistry.BuildToolRegistry(toolProviders);
        if (!config.AllowMetaTools)
        {
            registry = registry
                .Where(kv => !MetaToolNames.Contains(kv.Key))
                .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        }

        if (registry.Count == 0)
            return "Error: No tools were discovered. Verify tool providers and manifest.";

        // 2. Build tool wrappers
        var tools = ToolWrapper.BuildTools(
            registry,
            config.DestructiveConfirmed,
            config.SignedFilePolicy,
            config.AllowedFetchHosts
        );

        // 3. Initialize memory store (optional)
        MemoryStore? memory = null;
        if (!string.IsNullOrWhiteSpace(config.MemoryPath))
        {
            try
            {
                memory = new MemoryStore(config.MemoryPath);
            }
            catch (Exception ex)
            {
                return $"Error initializing memory store: {ex.Message}";
            }
        }

        // 4. Initialize LLM client
        var llm = new LlmClient(config.Model);

        // 5. Create orchestrator
        var orchestrator = new AgentOrchestrator(
            llm,
            registry,
            tools,
            memory,
            config.Model,
            config.DestructiveConfirmed,
            config.SignedFilePolicy,
            config.MaxIterations,
            config.AutoRetryOnIterationLimit,
            config.DiagnosticTracePath,
            config.ExpectedOutputPath,
            config.RecentHistoryItemsInPrompt
        );

        // 6. Run the agent
        var result = await orchestrator.RunAsync(prompt).ConfigureAwait(false);

        // 7. Optionally attach metadata
        if (config.ReturnMetadata)
        {
            var metadata = new
            {
                Mode = config.Mode.ToString(),
                Model = config.Model,
                MaxIterations = config.MaxIterations,
                UsedTools = result.ToolNames,
                ToolCallCount = result.ToolCallCount,
                DurationMs = result.DurationMs,
                RetriedOnIterationLimit = result.RetriedOnIterationLimit,
                RetrySucceeded = result.RetrySucceeded,
                InitialIterationLimit = result.InitialIterationLimit,
                RetryIterationLimit = result.RetryIterationLimit,
            };

            var combined = new { Output = result.OutputText, Metadata = metadata };

            return System.Text.Json.JsonSerializer.Serialize(
                combined,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true }
            );
        }

        return result.OutputText;
    }
}
