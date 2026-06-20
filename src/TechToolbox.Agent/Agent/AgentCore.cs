using TechToolbox.Agent.Registry;
using TechToolbox.Agent.Memory;

namespace TechToolbox.Agent.Agent;

public static class AgentCore
{
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
        string? diagnosticTracePath = null)
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
                diagnosticTracePath).GetAwaiter().GetResult();
    }

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
        string? diagnosticTracePath = null)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return "Error: prompt must not be empty.";

        // 1. Load tool registry
        var registry = ToolRegistry.BuildToolRegistry();
        if (registry.Count == 0)
            return "Error: No tools were discovered. Verify module import and manifest.";

        // 2. Build tool wrappers
        var tools = ToolWrapper.BuildTools(registry, destructiveConfirmed, signedFilePolicy);

        // 3. Initialize memory store (optional)
        MemoryStore? memory = null;
        if (!string.IsNullOrWhiteSpace(memoryPath))
        {
            try
            {
                memory = new MemoryStore(memoryPath);
            }
            catch (Exception ex)
            {
                return $"Error initializing memory store: {ex.Message}";
            }
        }

        // 4. Initialize LLM client
        var llm = new LlmClient(model);

        // 5. Create orchestrator
        var orchestrator = new AgentOrchestrator(
            llm,
            registry,
            tools,
            memory,
            maxIterations,
            autoRetryOnRecursion,
            diagnosticTracePath);

        // 6. Run the agent
        var result = await orchestrator.RunAsync(prompt).ConfigureAwait(false);

        // 7. Optionally attach metadata
        if (returnMetadata)
        {
            var metadata = new
            {
                Model = model,
                MaxIterations = maxIterations,
                UsedTools = result.ToolNames,
                ToolCallCount = result.ToolCallCount,
                DurationMs = result.DurationMs,
                RetriedOnIterationLimit = result.RetriedOnIterationLimit,
                RetrySucceeded = result.RetrySucceeded,
                InitialIterationLimit = result.InitialIterationLimit,
                RetryIterationLimit = result.RetryIterationLimit
            };

            var combined = new
            {
                Output = result.OutputText,
                Metadata = metadata
            };

            return System.Text.Json.JsonSerializer.Serialize(
                combined,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        }

        return result.OutputText;
    }
}
