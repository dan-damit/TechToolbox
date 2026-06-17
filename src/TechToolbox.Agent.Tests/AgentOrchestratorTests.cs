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

    [Fact]
    public async Task RunAsync_ParsesLegacyToolCallEnvelope_AndExecutesTool()
    {
        var llm = new FakeLlmClient(new[]
        {
            "TOOLCALL{GET-CONTENT} {\"path\":\"C:\\\\repo\\\\x.ps1\"}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["GET-CONTENT"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("GET-CONTENT", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_ParsesReadFileAlias_AndExecutesReadFileTool()
    {
        var llm = new FakeLlmClient(new[]
        {
            "read_file{\"path\":\"C:\\\\repo\\\\x.ps1\"}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["READ-FILE"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("READ-FILE", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_ParsesListDirectoryAlias_WithLooseObjectSyntax()
    {
        var llm = new FakeLlmClient(new[]
        {
            "list_directory{path: \"C:\\\\repo\"}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["LIST-DIRECTORY"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("LIST-DIRECTORY", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_ParsesCanonicalTool_WithLooseObjectSyntax()
    {
        var llm = new FakeLlmClient(new[]
        {
            "LIST-DIRECTORY{path: \"C:\\\\repo\"}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["LIST-DIRECTORY"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("LIST-DIRECTORY", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_ParsesCanonicalTool_WithEqualsObjectSyntax()
    {
        var llm = new FakeLlmClient(new[]
        {
            "WRITE-FILE{path=\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Start-NewPSRemoteSession.help.txt\", content=\"hello\"}",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
        {
            ["WRITE-FILE"] = _ => Task.FromResult("ok")
        };

        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_RetriesWhenLlmReturnsEmptyResponse()
    {
        var llm = new FakeLlmClient(new[]
        {
            "",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 2, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_ReturnsExplicitErrorWhenFinalIterationIsEmpty()
    {
        var llm = new FakeLlmClient(new[]
        {
            ""
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 1, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("LLM returned an empty response.", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_RetriesWhenLlmTimeoutTextIsReturned()
    {
        var llm = new FakeLlmClient(new[]
        {
            "LLM request timed out after 300 seconds.",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 2, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_FailsFastAfterConsecutiveEmptyResponses()
    {
        var llm = new FakeLlmClient(new[]
        {
            "",
            "",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 10, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains("LLM returned empty responses 2 times in a row.", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_FailsFastAfterConsecutiveRetryableLlmFailures()
    {
        var llm = new FakeLlmClient(new[]
        {
            "LLM request timed out after 300 seconds.",
            "LLM request timed out after 300 seconds.",
            "Done"
        });

        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 10, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains("LLM request repeatedly failed (2 consecutive attempts)", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_TruncatesLargeToolResult_InFollowUpPrompt()
    {
        Environment.SetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS", "500");

        try
        {
            var llm = new RecordingFakeLlmClient(new[]
            {
                "READ-FILE{}",
                "Done"
            });

            var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["READ-FILE"] = _ => Task.FromResult(new string('x', 1200))
            };

            var orchestrator = new AgentOrchestrator(llm, tools, memory: null, maxIterations: 5, autoRetry: false);

            var result = await orchestrator.RunAsync("test goal");

            Assert.Equal("Done", result.OutputText);
            Assert.True(llm.Prompts.Count >= 2);
            Assert.Contains("TRUNCATED_TOOL_RESULT", llm.Prompts[1]);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS", null);
        }
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

    private sealed class RecordingFakeLlmClient : LlmClient
    {
        private readonly Queue<string> _responses;

        public List<string> Prompts { get; } = new();

        public RecordingFakeLlmClient(IEnumerable<string> responses)
            : base("test")
        {
            _responses = new Queue<string>(responses);
        }

        public override Task<LlmResponse> GenerateAsync(string prompt)
        {
            Prompts.Add(prompt);
            var next = _responses.Count > 0 ? _responses.Dequeue() : "No more responses";
            return Task.FromResult(new LlmResponse(next));
        }
    }
}
