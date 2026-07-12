using System.Text.Json;
using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class AgentOrchestratorTests
{
    [Fact]
    public async Task RunAsync_ExecutesTool_AndReturnsFinalAnswer()
    {
        var llm = new FakeLlmClient(
            new[] { ToolDecision("Echo", "message", "hi"), FinalDecision("Completed successfully") }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["Echo"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Completed successfully", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("Echo", result.ToolNames);
    }

    [Fact]
    public async Task RunAsync_AutoRetryOnIterationLimit_CompletesOnRetry()
    {
        var llm = new RecordingFakeLlmClient(
            new[] { ToolDecision("Echo"), FinalDecision("Final answer from retry") }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["Echo"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 1, autoRetry: true);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Final answer from retry", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
        Assert.Empty(result.ToolNames);
        Assert.True(result.RetriedOnIterationLimit);
        Assert.True(result.RetrySucceeded);
        Assert.Equal(1, result.InitialIterationLimit);
        Assert.Equal(6, result.RetryIterationLimit);
        Assert.Equal(2, llm.MessageSnapshots.Count);
        Assert.Equal(llm.MessageSnapshots[0][1].Content, llm.MessageSnapshots[1][1].Content);
    }

    [Fact]
    public async Task RunAsync_AutoRetryOnIterationLimit_ReturnsDetailedMessageAfterRetryFailure()
    {
        var llm = new FakeLlmClient(Enumerable.Repeat(ToolDecision("Echo"), 7));

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["Echo"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 1, autoRetry: true);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains("## Agent Iteration Limit Reached", result.OutputText);
        Assert.Contains("- initial iteration_limit used: 1", result.OutputText);
        Assert.Contains("- retry iteration_limit used: 6", result.OutputText);
        Assert.Contains("- auto-retry attempts: 1", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
        Assert.Empty(result.ToolNames);
        Assert.True(result.RetriedOnIterationLimit);
        Assert.False(result.RetrySucceeded);
    }

    [Fact]
    public async Task RunAsync_UsesPythonStyleGoalPrompt()
    {
        var llm = new RecordingFakeLlmClient(new[] { FinalDecision("Done") });

        var orchestrator = CreateOrchestrator(
            llm,
            new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase),
            maxIterations: 5,
            autoRetry: false
        );

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Single(llm.MessageSnapshots);
        Assert.Contains(
            "continue iterating until the goal is completed",
            llm.MessageSnapshots[0][1].Content
        );
        Assert.Contains(
            "If confirmation is missing, stop and report exactly what confirmation is required.",
            llm.MessageSnapshots[0][1].Content
        );
        Assert.Contains("Goal: test goal", llm.MessageSnapshots[0][1].Content);
    }

    [Fact]
    public async Task RunAsync_UsesFailedEnvelopeWhenToolThrows()
    {
        var llm = new RecordingFakeLlmClient(new[] { ToolDecision("Echo"), FinalDecision("Done") });

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["Echo"] = _ => throw new InvalidOperationException("boom"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.True(llm.MessageSnapshots.Count >= 2);
        var followUpPrompt = llm.MessageSnapshots[1].Last().Content;
        Assert.Contains("Status: error", followUpPrompt);
        Assert.Contains("boom", followUpPrompt);
    }

    [Fact]
    public async Task RunAsync_PassesRawToolResultWithoutJsonEscaping()
    {
        var llm = new RecordingFakeLlmClient(
            new[] { ToolDecision("READ-FILE"), FinalDecision("Done") }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["READ-FILE"] = _ => Task.FromResult("function Demo-Tool {\n    Write-Output 'ok'\n}"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.True(llm.MessageSnapshots.Count >= 2);
        var followUpPrompt = llm.MessageSnapshots[1].Last().Content;
        Assert.Contains("BEGIN_TOOL_RESULT", followUpPrompt);
        Assert.Contains("function Demo-Tool", followUpPrompt);
        Assert.DoesNotContain("\\n", followUpPrompt);
        Assert.DoesNotContain("\"result\"", followUpPrompt);
    }

    [Fact]
    public async Task RunAsync_RepairsInvalidJsonOnce()
    {
        var llm = new FakeLlmClient(new[] { "not valid json", FinalDecision("Done") });

        var orchestrator = CreateOrchestrator(
            llm,
            new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase),
            maxIterations: 5,
            autoRetry: false
        );

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
    }

    [Fact]
    public async Task RunAsync_RepairsSchemaInvalidDecision_WhenFinalAnswerMissing()
    {
        var llm = new RecordingFakeLlmClient(
            new[] { "{\"needsTool\":false,\"finalAnswer\":\"\",\"reason\":\"done\"}", FinalDecision("Recovered") }
        );

        var orchestrator = CreateOrchestrator(
            llm,
            new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase),
            maxIterations: 5,
            autoRetry: false
        );

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Recovered", result.OutputText);
        Assert.True(llm.MessageSnapshots.Count >= 2);
        Assert.Contains("SCHEMA_ERROR", llm.MessageSnapshots[1].Last().Content);
    }

    [Fact]
    public async Task RunAsync_SalvagesMalformedWriteFileDecisionWithoutExtraLlmTurn()
    {
        string? capturedJsonArgs = null;

        var llm = new RecordingFakeLlmClient(
            new[]
            {
                "not valid json",
                "I will now write the file. {\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"hello\\nworld\"},\"reason\":\"recover\"}",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = args =>
            {
                capturedJsonArgs = args;
                return Task.FromResult("ok");
            },
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("write help file");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
        Assert.NotNull(capturedJsonArgs);
        Assert.Contains(
            "about_Invoke-RestartService.help.txt",
            capturedJsonArgs!,
            StringComparison.Ordinal
        );
        Assert.Contains("hello\\nworld", capturedJsonArgs!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_SalvagesTruncatedWriteFileContent_WithoutExtraLlmTurn()
    {
        // Truncated mid-content-value: "content":"unterminated  (no closing quote or braces)
        // The new TryExtractTruncatedJsonStringProperty fallback should recover this locally.
        string? capturedContent = null;

        var llm = new RecordingFakeLlmClient(
            new[]
            {
                "not valid json",
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"unterminated",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = args =>
            {
                var doc = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(args);
                capturedContent = doc?["content"].GetString();
                return Task.FromResult("ok");
            },
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 6, autoRetry: false);

        var result = await orchestrator.RunAsync("write help file");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
        // Salvaged content should be the truncated value (no extra LLM turn needed)
        Assert.Equal("unterminated", capturedContent);
    }

    [Fact]
    public async Task RunAsync_SalvagesTruncatedEscapedWriteFileContent_AndDecodesPayload()
    {
        // Truncated mid-content with escaped newlines. Recovery should decode one
        // escape layer so WRITE-FILE receives real line breaks.
        string? capturedContent = null;

        var llm = new RecordingFakeLlmClient(
            new[]
            {
                "not valid json",
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"line-1\\\\nline-2\\\\nusing\\\\tSystem.Diagnostics;",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = args =>
            {
                using var doc = JsonDocument.Parse(args);
                capturedContent = doc.RootElement.GetProperty("content").GetString();
                return Task.FromResult("ok");
            },
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 6, autoRetry: false);

        var result = await orchestrator.RunAsync("write help file");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
        Assert.NotNull(capturedContent);
        Assert.Contains("line-1", capturedContent!, StringComparison.Ordinal);
        Assert.Contains("line-2", capturedContent!, StringComparison.Ordinal);
        Assert.Contains("using\tSystem.Diagnostics;", capturedContent!, StringComparison.Ordinal);
        Assert.Contains('\n', capturedContent!);
        Assert.Contains('\t', capturedContent!);
        Assert.DoesNotContain("\\n", capturedContent!, StringComparison.Ordinal);
        Assert.DoesNotContain("\\t", capturedContent!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_UsesTargetedRecoveryTurn_ForUnrecoverableMalformedWriteFileDecision()
    {
        // Truncated BEFORE the opening quote of content value: "content": <no quote>
        // Both TryExtractJsonStringProperty and TryExtractTruncatedJsonStringProperty fail,
        // so the targeted recovery turn must fire.
        var llm = new RecordingFakeLlmClient(
            new[]
            {
                "not valid json",
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\": ",
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"Recovered content\"},\"reason\":\"recover write-file\"}",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 6, autoRetry: false);

        var result = await orchestrator.RunAsync("write help file");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
        Assert.True(llm.MessageSnapshots.Count >= 3);
        Assert.Contains(
            "Your previous response appears to be an intended WRITE-FILE tool call",
            llm.MessageSnapshots[2].Last().Content
        );
    }

    [Fact]
    public async Task RunAsync_BlocksFinalAnswerUntilWriteFileCompletes_WhenPromptRequiresOutputPath()
    {
        var llm = new RecordingFakeLlmClient(
            new[]
            {
                FinalDecision("Drafted help content"),
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"help content\"},\"reason\":\"write required file\"}",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 6, autoRetry: false);

        var prompt =
            "Create help doc\n\nHard requirement:\n- Create the output file at this exact path: C:\\repos\\TechToolbox\\en-US\\about_Invoke-RestartService.help.txt\n- Use WRITE-FILE to create/update the file.\n- Do not return a final answer until WRITE-FILE has succeeded.";

        var result = await orchestrator.RunAsync(prompt);

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(1, result.ToolCallCount);
        Assert.Contains("WRITE-FILE", result.ToolNames);
        Assert.True(llm.MessageSnapshots.Count >= 2);
        Assert.Contains(
            "Required WRITE-FILE step has not completed yet",
            llm.MessageSnapshots[1].Last().Content
        );
    }

    [Fact]
    public async Task RunAsync_InferWriteFilePath_WhenMissingAndPromptRequiresExactOutputPath()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"tt-agent-infer-path-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var expectedOutputPath = Path.Combine(tempRoot, "about_Test.help.txt");
            string? capturedJsonArgs = null;

            var llm = new RecordingFakeLlmClient(
                new[]
                {
                    "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"content\":\"updated\"},\"reason\":\"write file\"}",
                    FinalDecision("Done"),
                }
            );

            var tools = new Dictionary<string, Func<string, Task<string>>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["WRITE-FILE"] = args =>
                {
                    capturedJsonArgs = args;

                    using var doc = JsonDocument.Parse(args);
                    var path = doc.RootElement.GetProperty("path").GetString() ?? string.Empty;
                    var content = doc.RootElement.GetProperty("content").GetString() ?? string.Empty;

                    File.WriteAllText(path, content);
                    return Task.FromResult("ok");
                },
            };

            var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 4, autoRetry: false);

            var prompt =
                $"Create help doc\n\nHard requirement:\n- Create the output file at this exact path: {expectedOutputPath}\n- Use WRITE-FILE to create/update the file.\n- Do not return a final answer until WRITE-FILE has succeeded.";

            var result = await orchestrator.RunAsync(prompt);

            Assert.Equal("Done", result.OutputText);
            Assert.NotNull(capturedJsonArgs);
            Assert.True(File.Exists(expectedOutputPath));

            using var capturedDoc = JsonDocument.Parse(capturedJsonArgs!);
            Assert.Equal(
                expectedOutputPath,
                capturedDoc.RootElement.GetProperty("path").GetString(),
                ignoreCase: true
            );
            Assert.Equal("updated", capturedDoc.RootElement.GetProperty("content").GetString());
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task RunAsync_RejectsWrongWriteFilePath_WhenPromptRequiresExactOutputPath()
    {
        var llm = new RecordingFakeLlmClient(
            new[]
            {
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\temp\\\\wrong.help.txt\",\"content\":\"bad\"},\"reason\":\"write file\"}",
                FinalDecision("Done too early"),
                "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"path\":\"C:\\\\repos\\\\TechToolbox\\\\en-US\\\\about_Invoke-RestartService.help.txt\",\"content\":\"good\"},\"reason\":\"write required file\"}",
                FinalDecision("Done"),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["WRITE-FILE"] = _ => Task.FromResult("ok"),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 8, autoRetry: false);

        var prompt =
            "Create help doc\n\nHard requirement:\n- Create the output file at this exact path: C:\\repos\\TechToolbox\\en-US\\about_Invoke-RestartService.help.txt\n- Use WRITE-FILE to create/update the file.\n- Do not return a final answer until WRITE-FILE has succeeded.";

        var result = await orchestrator.RunAsync(prompt);

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(2, result.ToolCallCount);
        Assert.Equal(
            2,
            result.ToolNames.Count(name =>
                string.Equals(name, "WRITE-FILE", StringComparison.OrdinalIgnoreCase)
            )
        );
        Assert.Contains("must target expected path", llm.MessageSnapshots[1].Last().Content);
        Assert.Contains(
            "Required WRITE-FILE step has not completed yet",
            llm.MessageSnapshots[2].Last().Content
        );
    }

    [Fact]
    public async Task RunAsync_RetriesWriteFile_WhenToolReportsSuccessButExpectedFileIsMissing()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"tt-agent-writefile-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var expectedOutputPath = Path.Combine(tempRoot, "about_Invoke-RestartService.help.txt");
            var jsonPath = expectedOutputPath.Replace("\\", "\\\\", StringComparison.Ordinal);

            var llm = new RecordingFakeLlmClient(
                new[]
                {
                    $"{{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{{\"path\":\"{jsonPath}\",\"content\":\"first\"}},\"reason\":\"write required file\"}}",
                    $"{{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{{\"path\":\"{jsonPath}\",\"content\":\"second\"}},\"reason\":\"retry write required file\"}}",
                    FinalDecision("Done"),
                }
            );

            var writeCount = 0;
            var tools = new Dictionary<string, Func<string, Task<string>>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["WRITE-FILE"] = _ =>
                {
                    writeCount++;
                    if (writeCount == 2)
                    {
                        File.WriteAllText(expectedOutputPath, "second");
                    }

                    return Task.FromResult("ok");
                },
            };

            var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 8, autoRetry: false);

            var prompt =
                $"Create help doc\n\nHard requirement:\n- Create the output file at this exact path: {expectedOutputPath}\n- Use WRITE-FILE to create/update the file.\n- Do not return a final answer until WRITE-FILE has succeeded.";

            var result = await orchestrator.RunAsync(prompt);

            Assert.Equal("Done", result.OutputText);
            Assert.Equal(2, writeCount);
            Assert.True(File.Exists(expectedOutputPath));
            Assert.Contains(
                "expected output file does not exist yet",
                llm.MessageSnapshots[1].Last().Content
            );
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task RunAsync_RetriesWhenLlmReturnsEmptyResponse()
    {
        var llm = new FakeLlmClient(new[] { "", FinalDecision("Done") });

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );
        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 2, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_ReplacesReadFilePayloadWithCompactFallbackAfterEmptyContent()
    {
        var llm = new RecordingSequenceLlmClient(
            new[]
            {
                new LlmResponse(ToolDecision("READ-FILE"), ToolDecision("READ-FILE"), true),
                new LlmResponse(
                    "LLM returned empty content. done_reason=length; thinking_length=2500; body_preview={}",
                    "{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"thinking\":\""
                        + new string('x', 25)
                        + "\"},\"done_reason\":\"length\",\"eval_count\":512}",
                    false
                ),
                new LlmResponse(FinalDecision("Done"), FinalDecision("Done"), true),
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        )
        {
            ["READ-FILE"] = _ =>
                Task.FromResult(
                    "function Demo-Tool {\n<#\n.SYNOPSIS\n    Demo\n#>\nparam(\n    [string]$Name\n)\nbegin { }\nprocess { Write-Output $Name }\nend { }\n}"
                ),
        };

        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(3, llm.MessageSnapshots.Count);
        var retriedPrompt = llm.MessageSnapshots[2].Last().Content;
        Assert.Contains("READ_FILE_FALLBACK_COMPACT_VIEW", retriedPrompt);
        Assert.Contains("Functions: Demo-Tool", retriedPrompt);
        Assert.Contains("PriorEmptyContentDiagnostics: done_reason=length", retriedPrompt);
        Assert.DoesNotContain("BEGIN_TOOL_RESULT\nfunction Demo-Tool {\n<#", retriedPrompt);
    }

    [Fact]
    public async Task RunAsync_ProactivelyCompactsLargeReadFileScriptBeforeRetryIsNeeded()
    {
        Environment.SetEnvironmentVariable(
            "TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS",
            "200"
        );

        try
        {
            var llm = new RecordingFakeLlmClient(
                new[] { ToolDecision("READ-FILE"), FinalDecision("Done") }
            );

            var tools = new Dictionary<string, Func<string, Task<string>>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["READ-FILE"] = _ =>
                    Task.FromResult(
                        "function Demo-Tool {\n<#\n.SYNOPSIS\n    Demo\n.DESCRIPTION\n    Long description\n#>\n[CmdletBinding()]\nparam(\n    [string]$Name,\n    [string]$Value\n)\nbegin { }\nprocess { Write-Output $Name }\nend { }\n}\n"
                            + new string('x', 2000)
                    ),
            };

            var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

            var result = await orchestrator.RunAsync("test goal");

            Assert.Equal("Done", result.OutputText);
            Assert.True(llm.MessageSnapshots.Count >= 2);
            var followUpPrompt = llm.MessageSnapshots[1].Last().Content;
            Assert.Contains("READ_FILE_FALLBACK_COMPACT_VIEW", followUpPrompt);
            Assert.Contains("Functions: Demo-Tool", followUpPrompt);
            Assert.DoesNotContain(new string('x', 200), followUpPrompt);
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS",
                null
            );
        }
    }

    [Fact]
    public async Task RunAsync_ReturnsIterationLimitMessageWhenFinalIterationIsEmpty()
    {
        var llm = new FakeLlmClient(new[] { "" });

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );
        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 1, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains("## Agent Iteration Limit Reached", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_RetriesWhenLlmTimeoutTextIsReturned()
    {
        var llm = new FakeLlmClient(
            new[] { "LLM request timed out after 300 seconds.", FinalDecision("Done") }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );
        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 2, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Equal("Done", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_FailsFastAfterConsecutiveEmptyResponses()
    {
        var llm = new FakeLlmClient(new[] { "", "", "Done" });

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );
        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 10, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains("LLM request repeatedly failed", result.OutputText);
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_FailsFastAfterConsecutiveRetryableLlmFailures()
    {
        var llm = new FakeLlmClient(
            new[]
            {
                "LLM request timed out after 300 seconds.",
                "LLM request timed out after 300 seconds.",
                "Done",
            }
        );

        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );
        var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 10, autoRetry: false);

        var result = await orchestrator.RunAsync("test goal");

        Assert.Contains(
            "LLM request repeatedly failed (2 consecutive attempts)",
            result.OutputText
        );
        Assert.Equal(0, result.ToolCallCount);
    }

    [Fact]
    public async Task RunAsync_TruncatesLargeToolResult_InFollowUpPrompt()
    {
        Environment.SetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS", "500");

        try
        {
            var llm = new RecordingFakeLlmClient(
                new[] { ToolDecision("READ-FILE"), FinalDecision("Done") }
            );

            var tools = new Dictionary<string, Func<string, Task<string>>>(
                StringComparer.OrdinalIgnoreCase
            )
            {
                ["READ-FILE"] = _ => Task.FromResult(new string('x', 1200)),
            };

            var orchestrator = CreateOrchestrator(llm, tools, maxIterations: 5, autoRetry: false);

            var result = await orchestrator.RunAsync("test goal");

            Assert.Equal("Done", result.OutputText);
            Assert.True(llm.MessageSnapshots.Count >= 2);
            Assert.Contains("TRUNCATED_TOOL_RESULT", llm.MessageSnapshots[1].Last().Content);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS", null);
        }
    }

    [Fact]
    public async Task RunAsync_PersistsRunHistoryAndLearnsPreferencesAndFacts()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var llm = new FakeLlmClient(new[] { FinalDecision("Completed. model=qwen3.6:35b") });

            var memory = new MemoryStore(memoryPath);
            var orchestrator = new AgentOrchestrator(
                llm,
                CreateRegistry(Array.Empty<string>()),
                new Dictionary<string, Func<string, Task<string>>>(
                    StringComparer.OrdinalIgnoreCase
                ),
                memory,
                model: "test",
                destructiveConfirmed: false,
                signedFilePolicy: "ignore",
                maxIterations: 5,
                autoRetry: false
            );

            var prompt =
                "Prefer concise answers. Please use markdown bullet lists. My default model is qwen3.6:35b.";

            var result = await orchestrator.RunAsync(prompt);

            Assert.Equal("Completed. model=qwen3.6:35b", result.OutputText);
            Assert.Single(memory.History);
            Assert.Equal("success", memory.History[0].Status);
            Assert.Equal("completed", memory.History[0].Outcome);
            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                value => value.Contains("concise answers", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                value => value.Contains("markdown bullet lists", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.Facts.Values.OfType<string>(),
                value => string.Equals(value, "qwen3.6:35b", StringComparison.OrdinalIgnoreCase)
            );
            Assert.True(File.Exists(memoryPath));
            Assert.True(File.Exists(Path.Combine(tempRoot, "memory.history.json")));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task RunAsync_MarksInvalidJsonTerminalFailureAsErrorInMemoryHistory()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var llm = new FakeLlmClient(new[] { "not-json", "still-not-json" });
            var memory = new MemoryStore(memoryPath);
            var orchestrator = new AgentOrchestrator(
                llm,
                CreateRegistry(Array.Empty<string>()),
                new Dictionary<string, Func<string, Task<string>>>(
                    StringComparer.OrdinalIgnoreCase
                ),
                memory,
                model: "test",
                destructiveConfirmed: false,
                signedFilePolicy: "ignore",
                maxIterations: 5,
                autoRetry: false
            );

            var result = await orchestrator.RunAsync("test goal");

            Assert.Contains("Agent returned invalid JSON twice.", result.OutputText);
            Assert.Single(memory.History);
            Assert.Equal("error", memory.History[0].Status);
            Assert.Equal("invalid-json", memory.History[0].Outcome);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    private static AgentOrchestrator CreateOrchestrator(
        LlmClient llm,
        Dictionary<string, Func<string, Task<string>>> tools,
        int maxIterations,
        bool autoRetry
    )
    {
        return new AgentOrchestrator(
            llm,
            CreateRegistry(tools.Keys),
            tools,
            memory: null,
            model: "test",
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            maxIterations,
            autoRetry
        );
    }

    private static IReadOnlyDictionary<string, ToolSpec> CreateRegistry(
        IEnumerable<string> toolNames
    )
    {
        return toolNames.ToDictionary(
            name => name,
            name => new ToolSpec(
                name,
                $"Test tool {name}",
                new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase),
                "TestModule",
                new Dictionary<string, object?>()
            ),
            StringComparer.OrdinalIgnoreCase
        );
    }

    private static string ToolDecision(string toolName) =>
        $"{{\"needsTool\":true,\"toolName\":\"{toolName}\",\"toolArgs\":{{}},\"reason\":\"use tool\"}}";

    private static string ToolDecision(string toolName, string argName, string argValue) =>
        $"{{\"needsTool\":true,\"toolName\":\"{toolName}\",\"toolArgs\":{{\"{argName}\":\"{argValue}\"}},\"reason\":\"use tool\"}}";

    private static string FinalDecision(string answer) =>
        $"{{\"needsTool\":false,\"finalAnswer\":\"{answer}\",\"reason\":\"done\"}}";

    private sealed class FakeLlmClient : LlmClient
    {
        private readonly Queue<string> _responses;

        public FakeLlmClient(IEnumerable<string> responses)
            : base("test")
        {
            _responses = new Queue<string>(responses);
        }

        public override Task<LlmResponse> GenerateDecisionAsync(
            IReadOnlyList<AgentChatMessage> messages,
            CancellationToken cancellationToken = default
        )
        {
            var next = _responses.Count > 0 ? _responses.Dequeue() : "No more responses";
            return Task.FromResult(new LlmResponse(next, next, true));
        }
    }

    private sealed class RecordingFakeLlmClient : LlmClient
    {
        private readonly Queue<string> _responses;

        public List<List<AgentChatMessage>> MessageSnapshots { get; } = new();

        public RecordingFakeLlmClient(IEnumerable<string> responses)
            : base("test")
        {
            _responses = new Queue<string>(responses);
        }

        public override Task<LlmResponse> GenerateDecisionAsync(
            IReadOnlyList<AgentChatMessage> messages,
            CancellationToken cancellationToken = default
        )
        {
            MessageSnapshots.Add(
                messages
                    .Select(m => new AgentChatMessage { Role = m.Role, Content = m.Content })
                    .ToList()
            );

            var next = _responses.Count > 0 ? _responses.Dequeue() : "No more responses";
            return Task.FromResult(new LlmResponse(next, next, true));
        }
    }

    private sealed class RecordingSequenceLlmClient : LlmClient
    {
        private readonly Queue<LlmResponse> _responses;

        public List<List<AgentChatMessage>> MessageSnapshots { get; } = new();

        public RecordingSequenceLlmClient(IEnumerable<LlmResponse> responses)
            : base("test")
        {
            _responses = new Queue<LlmResponse>(responses);
        }

        public override Task<LlmResponse> GenerateDecisionAsync(
            IReadOnlyList<AgentChatMessage> messages,
            CancellationToken cancellationToken = default
        )
        {
            MessageSnapshots.Add(
                messages
                    .Select(m => new AgentChatMessage { Role = m.Role, Content = m.Content })
                    .ToList()
            );

            var next =
                _responses.Count > 0
                    ? _responses.Dequeue()
                    : new LlmResponse("No more responses", "", false);

            return Task.FromResult(next);
        }
    }
}
