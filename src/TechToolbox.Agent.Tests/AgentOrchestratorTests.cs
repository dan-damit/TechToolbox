using TechToolbox.Agent.Agent;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class AgentOrchestratorTests
{
    [Fact]
    public async Task RunAsync_ParsesMixedProseToolCall_AndExecutesTool()
    {
        var llm = new FakeLlmClient(new[]
        {
            "I will use a tool now. Echo {\"message\":\"hi\"}",
            "Completed successfully"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Echo"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Completed successfully", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("Echo", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_AutoRetryOnIterationLimit_CompletesOnRetry()
    {
        var llm = new FakeLlmClient(new[]
        {
            "Echo {}",
            "Final answer from retry"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Echo"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 1, autoRetry: true);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Final answer from retry", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_ParsesStructuredJsonToolEnvelope_AndExecutesTool()
    {
        var llm = new FakeLlmClient(new[]
        {
            "{\"tool\":\"Echo\",\"args\":{\"message\":\"hello\"}}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["Echo"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("Echo", result.ToolNames);
    }

    private sealed class FakeLlmClient : LlmClient
    {
        private readonly Queue<string> _responses;

        public FakeLlmClient(IEnumerable<string> responses)
            : base("test")
        {
            _responses = new Queue<string>(responses);
        }

        public override Task<LlmResponse> GenerateAsync(string prompt)
        {
            var next = _responses.Count > 0 ? _responses.Dequeue() : "No more responses";
            return Task.FromResult(new LlmResponse(next));
        }
    }
}
