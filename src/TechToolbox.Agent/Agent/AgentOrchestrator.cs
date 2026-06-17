using System.Diagnostics;
using System.Text.Json;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public class AgentOrchestrator
{
    private static readonly int MaxConsecutiveLlmFailures = GetMaxConsecutiveLlmFailures();

    private readonly LlmClient _llm;
    private readonly IReadOnlyDictionary<string, ToolSpec> _registry;
    private readonly Dictionary<string, Func<string, Task<string>>> _tools;
    private readonly Memory.MemoryStore? _memory;
    private readonly int _maxIterations;
    private readonly bool _autoRetry;
    private readonly string? _tracePath;
    private readonly object _traceLock = new();

    public AgentOrchestrator(
        LlmClient llm,
        IReadOnlyDictionary<string, ToolSpec> registry,
        Dictionary<string, Func<string, Task<string>>> tools,
        Memory.MemoryStore? memory,
        int maxIterations,
        bool autoRetry,
        string? tracePath = null)
    {
        _llm = llm;
        _registry = registry;
        _tools = tools;
        _memory = memory;
        _maxIterations = maxIterations;
        _autoRetry = autoRetry;
        _tracePath = tracePath;

        _llm.DiagnosticTrace = msg => Trace($"LlmClient {msg}");
    }

    public AgentResult Run(string prompt)
        => RunAsync(prompt).GetAwaiter().GetResult();

    public async Task<AgentResult> RunAsync(string prompt)
    {
        Trace($"RunAsync start maxIterations={_maxIterations} autoRetry={_autoRetry} promptLength={prompt?.Length ?? 0}");

        var toolNames = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        var attempt = await RunLoopAsync(prompt, _maxIterations, toolNames).ConfigureAwait(false);
        if (!attempt.ReachedIterationLimit)
        {
            stopwatch.Stop();
            return FinalizeResult(attempt.OutputText, toolNames, stopwatch.ElapsedMilliseconds);
        }

        if (_autoRetry)
        {
            var retryIterations = Math.Max(_maxIterations + 5, (int)Math.Ceiling(_maxIterations * 1.5));
            var retryPrompt =
                $"{prompt}\n\nPrevious attempt reached the iteration limit ({_maxIterations}). Continue from where you left off and return the final answer when complete.";

            var retryAttempt = await RunLoopAsync(retryPrompt, retryIterations, toolNames).ConfigureAwait(false);

            stopwatch.Stop();

            var output = retryAttempt.ReachedIterationLimit
                ? $"Iteration limit reached after retry ({retryIterations})."
                : retryAttempt.OutputText;

            return FinalizeResult(output, toolNames, stopwatch.ElapsedMilliseconds);
        }

        stopwatch.Stop();
        return FinalizeResult("Iteration limit reached.", toolNames, stopwatch.ElapsedMilliseconds);
    }

    private async Task<RunLoopResult> RunLoopAsync(string prompt, int iterationLimit, List<string> toolNames)
    {
        var messages = PromptBuilder.BuildInitialMessages(prompt, _registry, _memory);
        var consecutiveLlmFailures = 0;

        for (int i = 0; i < iterationLimit; i++)
        {
            Trace($"Iteration {i + 1}/{iterationLimit} start messages={messages.Count}");

            var llmResponse = await _llm.GenerateDecisionAsync(messages).ConfigureAwait(false);
            var raw = (llmResponse.Text ?? "").Trim();

            Trace($"Iteration {i + 1} response length={raw.Length} preview={Preview(raw)}");

            if (string.IsNullOrWhiteSpace(raw) || IsRetryableLlmFailure(raw))
            {
                consecutiveLlmFailures++;
                Trace($"Iteration {i + 1} consecutive LLM failures={consecutiveLlmFailures}");

                if (consecutiveLlmFailures >= MaxConsecutiveLlmFailures)
                {
                    return new RunLoopResult(
                        $"LLM request repeatedly failed ({consecutiveLlmFailures} consecutive attempts). Last error: {raw}",
                        ReachedIterationLimit: false);
                }

                continue;
            }

            consecutiveLlmFailures = 0;

            messages.Add(new AgentChatMessage
            {
                Role = "assistant",
                Content = raw
            });

            if (!JsonHelpers.TryParseDecision(raw, out var decision) || decision is null)
            {
                Trace($"Iteration {i + 1} invalid planner JSON; issuing repair prompt");

                messages.Add(PromptBuilder.BuildRepairMessage(raw));

                var repairResponse = await _llm.GenerateDecisionAsync(messages).ConfigureAwait(false);
                var repairedRaw = (repairResponse.Text ?? "").Trim();

                Trace($"Iteration {i + 1} repair response length={repairedRaw.Length} preview={Preview(repairedRaw)}");

                messages.Add(new AgentChatMessage
                {
                    Role = "assistant",
                    Content = repairedRaw
                });

                if (!JsonHelpers.TryParseDecision(repairedRaw, out decision) || decision is null)
                {
                    return new RunLoopResult(
                        $"Agent returned invalid JSON twice. Last response: {repairedRaw}",
                        ReachedIterationLimit: false);
                }
            }

            if (!decision.NeedsTool)
            {
                Trace($"Iteration {i + 1} final answer detected length={decision.FinalAnswer?.Length ?? 0}");
                return new RunLoopResult(decision.FinalAnswer, ReachedIterationLimit: false);
            }

            if (!_tools.TryGetValue(decision.ToolName, out var toolFunc))
            {
                Trace($"Iteration {i + 1} tool not found: {decision.ToolName}");

                var toolError = new
                {
                    tool = decision.ToolName,
                    ok = false,
                    error = $"Tool '{decision.ToolName}' was not found."
                };

                messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, JsonSerializer.Serialize(toolError)));
                continue;
            }

            toolNames.Add(decision.ToolName);

            string jsonArgs;
            try
            {
                jsonArgs = JsonSerializer.Serialize(decision.ToolArgs);
            }
            catch (Exception ex)
            {
                var serializationError = new
                {
                    tool = decision.ToolName,
                    ok = false,
                    error = $"Failed to serialize tool args: {ex.Message}"
                };

                messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, JsonSerializer.Serialize(serializationError)));
                continue;
            }

            Trace($"Iteration {i + 1} executing tool={decision.ToolName}");

            string toolResult;
            try
            {
                toolResult = await toolFunc(jsonArgs).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                toolResult = JsonSerializer.Serialize(new
                {
                    tool = decision.ToolName,
                    ok = false,
                    error = ex.Message
                });
            }

            var maxToolResultChars = GetMaxToolResultChars();
            var toolResultForPrompt = PrepareToolResultForPrompt(toolResult, maxToolResultChars, out var wasTruncated, out var originalLength);

            if (wasTruncated)
            {
                Trace($"Iteration {i + 1} tool result truncated originalLength={originalLength} maxChars={maxToolResultChars}");
            }

            var envelope = JsonSerializer.Serialize(new
            {
                tool = decision.ToolName,
                ok = true,
                result = toolResultForPrompt
            });

            messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, envelope));
        }

        Trace($"RunLoop reached iteration limit={iterationLimit}");
        return new RunLoopResult("Iteration limit reached.", ReachedIterationLimit: true);
    }

    private AgentResult FinalizeResult(string output, List<string> toolNames, long durationMs)
    {
        Trace($"FinalizeResult toolCalls={toolNames.Count} durationMs={durationMs} outputLength={output?.Length ?? 0}");

        output ??= "";

        var result = new AgentResult(output)
        {
            ToolNames = toolNames,
            ToolCallCount = toolNames.Count,
            DurationMs = (int)durationMs
        };

        _memory?.AddHistory(new Memory.RunHistory
        {
            Timestamp = DateTimeOffset.UtcNow,
            Intent = output[..Math.Min(output.Length, 200)],
            Status = "success",
            Outcome = "completed",
            ToolCalls = result.ToolCallCount,
            ToolNames = toolNames,
            DurationMs = result.DurationMs
        });

        return result;
    }

    private void Trace(string message)
    {
        if (string.IsNullOrWhiteSpace(_tracePath))
            return;

        try
        {
            var line = $"[{DateTime.UtcNow:O}] {message}{Environment.NewLine}";
            lock (_traceLock)
            {
                var dir = Path.GetDirectoryName(_tracePath);
                if (!string.IsNullOrWhiteSpace(dir))
                    Directory.CreateDirectory(dir);

                File.AppendAllText(_tracePath, line);
            }
        }
        catch
        {
            // Diagnostic tracing must never break orchestration.
        }
    }

    private static string Preview(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "(empty)";

        var normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return normalized.Length <= 120 ? normalized : normalized[..120];
    }

    private static bool IsRetryableLlmFailure(string text)
    {
        return text.StartsWith("LLM request timed out", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM response read timed out", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM request failed", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM error:", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM response parse failed", StringComparison.OrdinalIgnoreCase);
    }

    private static int GetMaxConsecutiveLlmFailures()
    {
        const int defaultFailures = 2;
        const int minFailures = 1;
        const int maxFailures = 10;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_MAX_CONSEC_LLM_FAILURES");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minFailures, maxFailures);

        return defaultFailures;
    }

    private static int GetMaxToolResultChars()
    {
        const int defaultChars = 12000;
        const int minChars = 500;
        const int maxChars = 200_000;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minChars, maxChars);

        return defaultChars;
    }

    private static string PrepareToolResultForPrompt(string? toolResult, int maxChars, out bool wasTruncated, out int originalLength)
    {
        var text = toolResult ?? "null";
        originalLength = text.Length;

        if (text.Length <= maxChars)
        {
            wasTruncated = false;
            return text;
        }

        wasTruncated = true;
        var head = text[..maxChars];
        return $"{head}\n\n[TRUNCATED_TOOL_RESULT original_length={text.Length} shown={maxChars}]";
    }
}

public record RunLoopResult(string OutputText, bool ReachedIterationLimit);

public class AgentResult
{
    public string OutputText { get; }
    public List<string> ToolNames { get; set; } = new();
    public int ToolCallCount { get; set; }
    public int DurationMs { get; set; }

    public AgentResult(string output)
    {
        OutputText = output;
    }
}