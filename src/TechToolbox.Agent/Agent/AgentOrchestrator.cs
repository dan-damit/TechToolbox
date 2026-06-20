using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public class AgentOrchestrator
{
    private static readonly int MaxConsecutiveLlmFailures = GetMaxConsecutiveLlmFailures();
    private static readonly Regex SectionHeadingRegex = new(@"^\s*(?:#\s*)?\.(?<name>[A-Z][A-Z0-9_-]*)\b", RegexOptions.Compiled);
    private static readonly Regex FunctionNameRegex = new(@"^\s*function\s+(?<name>[A-Za-z_][A-Za-z0-9_-]*)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

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
        prompt ??= string.Empty;
        Trace($"RunAsync start maxIterations={_maxIterations} autoRetry={_autoRetry} promptLength={prompt.Length}");

        var stopwatch = Stopwatch.StartNew();
        var initialToolNames = new List<string>();

        var attempt = await RunLoopAsync(prompt, _maxIterations, initialToolNames).ConfigureAwait(false);
        if (!attempt.ReachedIterationLimit)
        {
            stopwatch.Stop();
            return FinalizeResult(
                prompt,
                attempt.OutputText,
                initialToolNames,
                stopwatch.ElapsedMilliseconds,
                status: "success",
                outcome: "completed",
                retriedOnIterationLimit: false,
                retrySucceeded: false,
                initialIterationLimit: _maxIterations,
                retryIterationLimit: null);
        }

        if (_autoRetry)
        {
            var retryIterations = Math.Max(_maxIterations + 5, (int)Math.Ceiling(_maxIterations * 1.5));
            var retryToolNames = new List<string>();

            var retryAttempt = await RunLoopAsync(prompt, retryIterations, retryToolNames).ConfigureAwait(false);

            stopwatch.Stop();

            if (!retryAttempt.ReachedIterationLimit)
            {
                return FinalizeResult(
                    prompt,
                    retryAttempt.OutputText,
                    retryToolNames,
                    stopwatch.ElapsedMilliseconds,
                    status: "success",
                    outcome: "completed",
                    retriedOnIterationLimit: true,
                    retrySucceeded: true,
                    initialIterationLimit: _maxIterations,
                    retryIterationLimit: retryIterations);
            }

            return FinalizeResult(
                prompt,
                BuildIterationLimitMessage(_maxIterations, retryIterations),
                new List<string>(),
                stopwatch.ElapsedMilliseconds,
                status: "error",
                outcome: "iteration-limit",
                retriedOnIterationLimit: true,
                retrySucceeded: false,
                initialIterationLimit: _maxIterations,
                retryIterationLimit: retryIterations);
        }

        stopwatch.Stop();
        return FinalizeResult(
            prompt,
            BuildIterationLimitMessage(_maxIterations),
            new List<string>(),
            stopwatch.ElapsedMilliseconds,
            status: "error",
            outcome: "iteration-limit",
            retriedOnIterationLimit: false,
            retrySucceeded: false,
            initialIterationLimit: _maxIterations,
            retryIterationLimit: null);
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
                if (TryApplyReadFileFallback(messages, llmResponse.RawBody, out var fallbackReason))
                {
                    Trace($"Iteration {i + 1} applied READ-FILE fallback: {fallbackReason}");
                    continue;
                }

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
                return new RunLoopResult(decision.FinalAnswer ?? string.Empty, ReachedIterationLimit: false);
            }

            if (!_tools.TryGetValue(decision.ToolName, out var toolFunc))
            {
                Trace($"Iteration {i + 1} tool not found: {decision.ToolName}");

                var toolError = $"Tool '{decision.ToolName}' was not found.";

                messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, toolError, succeeded: false));
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
                var serializationError = $"Failed to serialize tool args: {ex.Message}";

                messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, serializationError, succeeded: false));
                continue;
            }

            Trace($"Iteration {i + 1} executing tool={decision.ToolName}");

            string toolResult;
            var toolExecutionSucceeded = true;
            try
            {
                toolResult = await toolFunc(jsonArgs).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                toolExecutionSucceeded = false;
                toolResult = ex.Message;
            }

            if (toolExecutionSucceeded && decision.ToolName.Equals("READ-FILE", StringComparison.OrdinalIgnoreCase))
            {
                var compactThreshold = GetReadFilePromptCompactThresholdChars();
                var compactedToolResult = MaybeCompactReadFileResultForPrompt(toolResult, compactThreshold);
                if (!string.Equals(compactedToolResult, toolResult, StringComparison.Ordinal))
                {
                    Trace($"Iteration {i + 1} compacted READ-FILE result for prompt originalLength={toolResult.Length} threshold={compactThreshold} compactLength={compactedToolResult.Length}");
                    toolResult = compactedToolResult;
                }
            }

            var maxToolResultChars = GetMaxToolResultChars();
            var toolResultForPrompt = PrepareToolResultForPrompt(toolResult, maxToolResultChars, out var wasTruncated, out var originalLength);

            if (wasTruncated)
            {
                Trace($"Iteration {i + 1} tool result truncated originalLength={originalLength} maxChars={maxToolResultChars}");
            }

            messages.Add(PromptBuilder.BuildToolResultMessage(decision.ToolName, toolResultForPrompt, toolExecutionSucceeded));
        }

        Trace($"RunLoop reached iteration limit={iterationLimit}");
        return new RunLoopResult("Iteration limit reached.", ReachedIterationLimit: true);
    }

    private AgentResult FinalizeResult(
        string prompt,
        string output,
        List<string> toolNames,
        long durationMs,
        string status,
        string outcome,
        bool retriedOnIterationLimit,
        bool retrySucceeded,
        int initialIterationLimit,
        int? retryIterationLimit)
    {
        Trace($"FinalizeResult toolCalls={toolNames.Count} durationMs={durationMs} outputLength={output?.Length ?? 0}");

        output ??= "";

        var result = new AgentResult(output)
        {
            ToolNames = toolNames,
            ToolCallCount = toolNames.Count,
            DurationMs = (int)durationMs,
            RetriedOnIterationLimit = retriedOnIterationLimit,
            RetrySucceeded = retrySucceeded,
            InitialIterationLimit = initialIterationLimit,
            RetryIterationLimit = retryIterationLimit
        };

        _memory?.AddHistory(new Memory.RunHistory
        {
            Timestamp = DateTimeOffset.UtcNow,
            Intent = output[..Math.Min(output.Length, 200)],
            Status = status,
            Outcome = outcome,
            ToolCalls = result.ToolCallCount,
            ToolNames = toolNames,
            DurationMs = result.DurationMs
        });

        if (_memory is not null)
        {
            MemoryLearner.LearnFromRun(_memory, prompt, output);
        }

        return result;
    }

    private static string BuildIterationLimitMessage(int initialIterationLimit, int? retryIterationLimit = null)
    {
        if (retryIterationLimit.HasValue)
        {
            return
$"""
## Agent Iteration Limit Reached

The agent stopped because it reached its internal reasoning/tool-call limit before a final stop condition.

- initial iteration_limit used: {initialIterationLimit}
- retry iteration_limit used: {retryIterationLimit.Value}
- max_iterations requested: {initialIterationLimit}
- auto-retry attempts: 1

Next best action:
- Retry with a narrower prompt or a higher --max-iterations value.
- If this repeats, inspect tool outputs for loops or missing termination cues.
""";
        }

        return
$"""
## Agent Iteration Limit Reached

The agent stopped because it reached its internal reasoning/tool-call limit before a final stop condition.

- iteration_limit used: {initialIterationLimit}
- max_iterations requested: {initialIterationLimit}

Next best action:
- Retry with a narrower prompt or a higher --max-iterations value.
- If this repeats, inspect tool outputs for loops or missing termination cues.
""";
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
            || text.StartsWith("LLM returned empty content", StringComparison.OrdinalIgnoreCase)
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

    private static int GetReadFilePromptCompactThresholdChars()
    {
        const int defaultChars = 6000;
        const int minChars = 1000;
        const int maxChars = 50000;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS");
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

    private static bool TryApplyReadFileFallback(List<AgentChatMessage> messages, string? rawBody, out string reason)
    {
        reason = string.Empty;

        if (messages.Count == 0)
            return false;

        var lastMessage = messages[^1];
        if (!string.Equals(lastMessage.Role, "user", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!TryExtractToolResult(lastMessage.Content, out var toolName, out var toolResult, out var status))
            return false;

        if (!string.Equals(toolName, "READ-FILE", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
            return false;

        if (toolResult.Contains("READ_FILE_FALLBACK_COMPACT_VIEW", StringComparison.Ordinal))
            return false;

        var compactResult = BuildReadFileFallbackCompactView(toolResult, rawBody);
        if (string.Equals(compactResult, toolResult, StringComparison.Ordinal))
            return false;

        messages[^1] = PromptBuilder.BuildToolResultMessage(toolName, compactResult, succeeded: true);
        reason = $"replaced READ-FILE raw content with compact fallback view length={compactResult.Length}";
        return true;
    }

    private static bool TryExtractToolResult(string content, out string toolName, out string toolResult, out string status)
    {
        toolName = string.Empty;
        toolResult = string.Empty;
        status = string.Empty;

        if (string.IsNullOrWhiteSpace(content))
            return false;

        var toolLine = content.Split('\n').FirstOrDefault(line => line.StartsWith("Tool:", StringComparison.OrdinalIgnoreCase));
        var statusLine = content.Split('\n').FirstOrDefault(line => line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase));
        var beginMarker = "BEGIN_TOOL_RESULT";
        var endMarker = "END_TOOL_RESULT";
        var beginIndex = content.IndexOf(beginMarker, StringComparison.Ordinal);
        var endIndex = content.IndexOf(endMarker, StringComparison.Ordinal);

        if (toolLine is null || statusLine is null || beginIndex < 0 || endIndex <= beginIndex)
            return false;

        toolName = toolLine["Tool:".Length..].Trim();
        status = statusLine["Status:".Length..].Trim();

        var resultStart = beginIndex + beginMarker.Length;
        toolResult = content[resultStart..endIndex].Trim();
        return !string.IsNullOrWhiteSpace(toolName);
    }

    private static string BuildReadFileFallbackCompactView(string toolResult, string? rawBody)
    {
        var normalized = toolResult.Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = normalized.Split('\n');
        var sections = lines
            .Select(line => SectionHeadingRegex.Match(line))
            .Where(match => match.Success)
            .Select(match => match.Groups["name"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var functions = lines
            .Select(line => FunctionNameRegex.Match(line))
            .Where(match => match.Success)
            .Select(match => match.Groups["name"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var paramBlock = ExtractParamBlock(lines, 18);
        var structureHints = lines
            .Where(line => Regex.IsMatch(line, "^\\s*(begin|process|end)\\s*\\{", RegexOptions.IgnoreCase))
            .Select(line => line.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var excerpt = BuildCompactExcerpt(lines, 40, 3200);
        var diagnostics = ExtractBodyDiagnostics(rawBody);

        var sb = new StringBuilder();
        sb.AppendLine("READ_FILE_FALLBACK_COMPACT_VIEW");
        sb.AppendLine("Reason: previous LLM response returned empty content after the full READ-FILE result.");
        sb.AppendLine($"OriginalLength: {toolResult.Length}");
        sb.AppendLine($"LineCount: {lines.Length}");
        if (!string.IsNullOrWhiteSpace(diagnostics))
            sb.AppendLine($"PriorEmptyContentDiagnostics: {diagnostics}");
        sb.AppendLine($"Functions: {(functions.Length == 0 ? "(none detected)" : string.Join(", ", functions))}");
        sb.AppendLine($"HelpSections: {(sections.Length == 0 ? "(none detected)" : string.Join(", ", sections))}");
        sb.AppendLine($"StructureHints: {(structureHints.Length == 0 ? "(none detected)" : string.Join(", ", structureHints))}");
        sb.AppendLine();
        sb.AppendLine("ParameterExcerpt:");
        sb.AppendLine(string.IsNullOrWhiteSpace(paramBlock) ? "(none detected)" : paramBlock);
        sb.AppendLine();
        sb.AppendLine("ContentExcerpt:");
        sb.Append(excerpt);
        return sb.ToString().TrimEnd();
    }

    private static string ExtractParamBlock(string[] lines, int maxLines)
    {
        var startIndex = Array.FindIndex(lines, line => line.Contains("param(", StringComparison.OrdinalIgnoreCase));
        if (startIndex < 0)
            return string.Empty;

        var collected = new List<string>();
        var balance = 0;

        for (int i = startIndex; i < lines.Length && collected.Count < maxLines; i++)
        {
            var line = lines[i];
            collected.Add(line);
            balance += line.Count(ch => ch == '(');
            balance -= line.Count(ch => ch == ')');

            if (i > startIndex && balance <= 0)
                break;
        }

        return string.Join(Environment.NewLine, collected).Trim();
    }

    private static string BuildCompactExcerpt(string[] lines, int maxLines, int maxChars)
    {
        const int maxLineChars = 180;

        var selected = lines
            .Take(maxLines)
            .Select(line => line.Length <= maxLineChars
                ? line
                : line[..maxLineChars] + " [LINE_TRUNCATED]")
            .ToArray();

        var text = string.Join(Environment.NewLine, selected).Trim();
        if (text.Length <= maxChars)
            return text;

        return text[..maxChars] + Environment.NewLine + "[COMPACT_EXCERPT_TRUNCATED]";
    }

    private static string ExtractBodyDiagnostics(string? rawBody)
    {
        if (string.IsNullOrWhiteSpace(rawBody))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawBody);
            var root = doc.RootElement;
            var fields = new List<string>();

            if (root.TryGetProperty("done_reason", out var doneReason) && doneReason.ValueKind == JsonValueKind.String)
                fields.Add($"done_reason={doneReason.GetString()}");

            if (root.TryGetProperty("eval_count", out var evalCount) && evalCount.ValueKind == JsonValueKind.Number)
                fields.Add($"eval_count={evalCount.GetInt32()}");

            if (root.TryGetProperty("message", out var message) && message.ValueKind == JsonValueKind.Object)
            {
                if (message.TryGetProperty("thinking", out var thinking) && thinking.ValueKind == JsonValueKind.String)
                    fields.Add($"thinking_length={thinking.GetString()?.Length ?? 0}");
            }

            return fields.Count == 0 ? Preview(rawBody) : string.Join(", ", fields);
        }
        catch
        {
            return Preview(rawBody);
        }
    }

    private static string MaybeCompactReadFileResultForPrompt(string toolResult, int thresholdChars)
    {
        if (string.IsNullOrWhiteSpace(toolResult))
            return toolResult;

        if (toolResult.Length <= thresholdChars)
            return toolResult;

        var trimmed = toolResult.TrimStart();
        if (trimmed.StartsWith("{", StringComparison.Ordinal)
            && trimmed.Contains("\"kind\":\"file-summary\"", StringComparison.OrdinalIgnoreCase))
        {
            return toolResult;
        }

        if (!LooksLikePowerShellScript(toolResult))
            return toolResult;

        return BuildReadFileFallbackCompactView(toolResult, rawBody: null);
    }

    private static bool LooksLikePowerShellScript(string text)
    {
        var normalized = text.Replace("\r\n", "\n");
        return normalized.Contains("function ", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("[CmdletBinding()]", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("param(", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("# SIG # Begin signature block", StringComparison.OrdinalIgnoreCase);
    }
}

public record RunLoopResult(string OutputText, bool ReachedIterationLimit);

public class AgentResult
{
    public string OutputText { get; }
    public List<string> ToolNames { get; set; } = new();
    public int ToolCallCount { get; set; }
    public int DurationMs { get; set; }
    public bool RetriedOnIterationLimit { get; set; }
    public bool RetrySucceeded { get; set; }
    public int InitialIterationLimit { get; set; }
    public int? RetryIterationLimit { get; set; }

    public AgentResult(string output)
    {
        OutputText = output;
    }
}
