using System.Diagnostics;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class AgentOrchestrator
{
    private readonly LlmClient _llm;
    private readonly Dictionary<string, Func<string, Task<string>>> _tools;
    private readonly Memory.MemoryStore? _memory;
    private readonly int _maxIterations;
    private readonly bool _autoRetry;

    public AgentOrchestrator(
        LlmClient llm,
        Dictionary<string, Func<string, Task<string>>> tools,
        Memory.MemoryStore? memory,
        int maxIterations,
        bool autoRetry)
    {
        _llm = llm;
        _tools = tools;
        _memory = memory;
        _maxIterations = maxIterations;
        _autoRetry = autoRetry;
    }

    public AgentResult Run(string prompt)
        => RunAsync(prompt).GetAwaiter().GetResult();

    public async Task<AgentResult> RunAsync(string prompt)
    {
        var toolNames = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        var firstAttempt = await RunLoopAsync(prompt, _maxIterations, toolNames).ConfigureAwait(false);
        if (!firstAttempt.ReachedIterationLimit)
        {
            stopwatch.Stop();
            return FinalizeResult(firstAttempt.OutputText, toolNames, stopwatch.ElapsedMilliseconds);
        }

        if (_autoRetry)
        {
            var retryIterations = Math.Max(_maxIterations + 5, (int)Math.Ceiling(_maxIterations * 1.5));
            var retryPrompt =
                $"{prompt}\n\nPrevious attempt reached the iteration limit ({_maxIterations}). " +
                "Continue from where you left off and provide a final answer when complete.";

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
        var messages = new List<string>();
        messages.Add(BuildGoalPrompt(prompt));

        for (int i = 0; i < iterationLimit; i++)
        {
            var combinedPrompt = string.Join("\n\n", messages);

            // 1. Ask the model
            var llmResponse = await _llm.GenerateAsync(combinedPrompt).ConfigureAwait(false);
            var text = llmResponse.Text.Trim();

            // 2. Detect tool call patterns from structured JSON or mixed prose.
            if (TryParseToolCall(text, out var toolName, out var toolArgs))
            {
                if (!_tools.TryGetValue(toolName, out var toolFunc))
                {
                    messages.Add($"Tool '{toolName}' not found.");
                    continue;
                }

                toolNames.Add(toolName);

                // 3. Execute tool
                var toolResult = await toolFunc(toolArgs).ConfigureAwait(false);

                // 4. Feed result back into the loop
                messages.Add($"ToolResult({toolName}): {toolResult}");
                continue;
            }

            // 5. No tool call -> final answer
            return new RunLoopResult(text, ReachedIterationLimit: false);
        }

        return new RunLoopResult("Iteration limit reached.", ReachedIterationLimit: true);
    }

    private AgentResult FinalizeResult(string output, List<string> toolNames, long durationMs)
    {
        var result = new AgentResult(output)
        {
            ToolNames = toolNames,
            ToolCallCount = toolNames.Count,
            DurationMs = (int)durationMs
        };

        // Optional memory integration
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

    private string BuildGoalPrompt(string prompt)
    {
        return
            "You are a local automation agent. " +
            "Work step-by-step. If a tool is needed, call it using the format TOOLNAME{json}. " +
            "Do not hallucinate tool names. " +
            "Stop when the task is complete.\n\n" +
            $"Goal: {prompt}";
    }

    private bool TryParseToolCall(string text, out string toolName, out string jsonArgs)
    {
        toolName = "";
        jsonArgs = "";

        if (string.IsNullOrWhiteSpace(text))
            return false;

        if (TryParseStructuredToolCall(text, out toolName, out jsonArgs))
            return true;

        var orderedToolNames = _tools.Keys
            .OrderByDescending(name => name.Length)
            .ToList();

        foreach (var candidate in orderedToolNames)
        {
            var searchStart = 0;
            while (searchStart < text.Length)
            {
                var nameIdx = text.IndexOf(candidate, searchStart, StringComparison.OrdinalIgnoreCase);
                if (nameIdx < 0)
                    break;

                if (!IsTokenBoundary(text, nameIdx - 1))
                {
                    searchStart = nameIdx + candidate.Length;
                    continue;
                }

                var cursor = nameIdx + candidate.Length;
                while (cursor < text.Length && char.IsWhiteSpace(text[cursor]))
                {
                    cursor++;
                }

                if (cursor >= text.Length || text[cursor] != '{')
                {
                    searchStart = nameIdx + candidate.Length;
                    continue;
                }

                if (!TryExtractJsonObject(text, cursor, out var parsedArgs, out _))
                {
                    searchStart = nameIdx + candidate.Length;
                    continue;
                }

                toolName = candidate;
                jsonArgs = parsedArgs;
                return true;
            }
        }

        return false;
    }

    private bool TryParseStructuredToolCall(string text, out string toolName, out string jsonArgs)
    {
        toolName = "";
        jsonArgs = "";

        var trimmed = text.Trim();
        if (!trimmed.StartsWith('{') || !TryExtractJsonObject(trimmed, 0, out var structuredJson, out _))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(structuredJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            if (!TryGetStringProperty(root, out var parsedName, "tool", "toolName", "name"))
                return false;

            if (!_tools.ContainsKey(parsedName))
                return false;

            if (TryGetObjectProperty(root, out var parsedArgs, "args", "arguments", "input"))
            {
                toolName = parsedName;
                jsonArgs = parsedArgs.GetRawText();
                return true;
            }

            toolName = parsedName;
            jsonArgs = "{}";
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetStringProperty(JsonElement source, out string value, params string[] names)
    {
        value = "";

        foreach (var property in source.EnumerateObject())
        {
            if (!names.Any(n => string.Equals(n, property.Name, StringComparison.OrdinalIgnoreCase)))
                continue;

            if (property.Value.ValueKind != JsonValueKind.String)
                continue;

            value = property.Value.GetString() ?? "";
            return !string.IsNullOrWhiteSpace(value);
        }

        return false;
    }

    private static bool TryGetObjectProperty(JsonElement source, out JsonElement value, params string[] names)
    {
        foreach (var property in source.EnumerateObject())
        {
            if (!names.Any(n => string.Equals(n, property.Name, StringComparison.OrdinalIgnoreCase)))
                continue;

            if (property.Value.ValueKind != JsonValueKind.Object)
                continue;

            value = property.Value;
            return true;
        }

        value = default;
        return false;
    }

    private static bool TryExtractJsonObject(string text, int startIndex, out string jsonText, out int endIndex)
    {
        jsonText = "";
        endIndex = -1;

        if (startIndex < 0 || startIndex >= text.Length || text[startIndex] != '{')
            return false;

        var depth = 0;
        var inString = false;
        var escaped = false;

        for (var i = startIndex; i < text.Length; i++)
        {
            var ch = text[i];

            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                    continue;
                }

                if (ch == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == '"')
                {
                    inString = false;
                }

                continue;
            }

            if (ch == '"')
            {
                inString = true;
                continue;
            }

            if (ch == '{')
            {
                depth++;
                continue;
            }

            if (ch != '}')
                continue;

            depth--;
            if (depth != 0)
                continue;

            var candidate = text[startIndex..(i + 1)];
            try
            {
                using var _ = JsonDocument.Parse(candidate);
                jsonText = candidate;
                endIndex = i;
                return true;
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    private static bool IsTokenBoundary(string text, int index)
    {
        if (index < 0 || index >= text.Length)
            return true;

        var ch = text[index];
        return !char.IsLetterOrDigit(ch) && ch != '_' && ch != '-';
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
