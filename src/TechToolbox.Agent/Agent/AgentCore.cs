// Copyright (c) TechToolbox. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using TechToolbox.Agent.Configuration;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Provides core agent execution functionality for TechToolbox.
/// Manages tool registration, LLM interaction, and agent orchestration.
/// </summary>
public static class AgentCore
{
    /// <summary>
    /// Set of meta-tool names that are filtered out unless explicitly allowed.
    /// Meta-tools are internal helper tools used by the agent framework itself.
    /// </summary>
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
    /// <param name="config">The agent configuration containing all necessary settings.</param>
    /// <param name="prompt">The prompt to send to the agent.</param>
    /// <returns>The agent's response as a string.</returns>
    public static string RunAgent(AgentConfiguration config, string prompt)
    {
        return RunAgentAsync(config, prompt).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Runs an agent asynchronously with the specified configuration.
    /// </summary>
    /// <param name="config">The agent configuration containing all necessary settings.</param>
    /// <param name="prompt">The prompt to send to the agent.</param>
    /// <returns>A task representing the asynchronous operation, with the agent's response as its result.</returns>
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
    /// <param name="prompt">The prompt to send to the agent.</param>
    /// <param name="model">The LLM model to use. Defaults to "llama3".</param>
    /// <param name="verbose">Whether to enable verbose output. Defaults to true.</param>
    /// <param name="maxIterations">Maximum number of iterations for the agent. Defaults to 15.</param>
    /// <param name="destructiveConfirmed">Whether destructive operations are confirmed. Defaults to false.</param>
    /// <param name="memoryPath">Optional path to a memory store file.</param>
    /// <param name="autoRetryOnRecursion">Whether to automatically retry on recursion detection. Defaults to false.</param>
    /// <param name="returnMetadata">Whether to return metadata alongside the output. Defaults to false.</param>
    /// <param name="signedFilePolicy">Policy for handling signed files. Defaults to "ignore".</param>
    /// <param name="diagnosticTracePath">Optional path for diagnostic trace output.</param>
    /// <param name="expectedOutputPath">Optional path for expected output comparison.</param>
    /// <param name="recentHistoryItemsInPrompt">Number of recent history items to include in the prompt. Defaults to 2.</param>
    /// <param name="allowedFetchHosts">Collection of allowed hosts for fetch operations.</param>
    /// <param name="allowMetaTools">Whether to allow meta-tools. Defaults to false.</param>
    /// <returns>The agent's response as a string.</returns>
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
    /// <param name="prompt">The prompt to send to the agent.</param>
    /// <param name="model">The LLM model to use. Defaults to "llama3".</param>
    /// <param name="verbose">Whether to enable verbose output. Defaults to true.</param>
    /// <param name="maxIterations">Maximum number of iterations for the agent. Defaults to 15.</param>
    /// <param name="destructiveConfirmed">Whether destructive operations are confirmed. Defaults to false.</param>
    /// <param name="memoryPath">Optional path to a memory store file.</param>
    /// <param name="autoRetryOnRecursion">Whether to automatically retry on recursion detection. Defaults to false.</param>
    /// <param name="returnMetadata">Whether to return metadata alongside the output. Defaults to false.</param>
    /// <param name="signedFilePolicy">Policy for handling signed files. Defaults to "ignore".</param>
    /// <param name="diagnosticTracePath">Optional path for diagnostic trace output.</param>
    /// <param name="expectedOutputPath">Optional path for expected output comparison.</param>
    /// <param name="recentHistoryItemsInPrompt">Number of recent history items to include in the prompt. Defaults to 2.</param>
    /// <param name="allowedFetchHosts">Collection of allowed hosts for fetch operations.</param>
    /// <param name="allowMetaTools">Whether to allow meta-tools. Defaults to false.</param>
    /// <returns>A task representing the asynchronous operation, with the agent's response as its result.</returns>
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

    /// <summary>
    /// Internal method that performs the actual agent execution.
    /// Handles tool registration, memory initialization, LLM client setup, and orchestration.
    /// </summary>
    /// <param name="config">The agent configuration containing all necessary settings.</param>
    /// <param name="prompt">The prompt to send to the agent.</param>
    /// <returns>A task representing the asynchronous operation, with the agent's response as its result.</returns>
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
            config.AllowedFetchHosts,
            executor: PowerShellToolExecutor.Instance
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
