using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class AgentOrchestrator
{
    private static readonly Dictionary<string, string> ToolAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["read_file"] = "READ-FILE",
        ["list_directory"] = "LIST-DIRECTORY",
        ["write_file"] = "WRITE-FILE"
    };

    private readonly LlmClient _llm;
    private readonly Dictionary<string, Func<string, Task<string>>> _tools;
    private readonly Memory.MemoryStore? _memory;
    private readonly int _maxIterations;
    private readonly bool _autoRetry;
    private readonly string? _tracePath;
    private readonly object _traceLock = new();

    public AgentOrchestrator(
        LlmClient llm,
        Dictionary<string, Func<string, Task<string>>> tools,
        Memory.MemoryStore? memory,
        int maxIterations,
        bool autoRetry,
        string? tracePath = null)
    {
        _llm = llm;
        _tools = tools;
        _memory = memory;
        _maxIterations = maxIterations;
        _autoRetry = autoRetry;
        _tracePath = tracePath;
    }

    public AgentResult Run(string prompt)
        => RunAsync(prompt).GetAwaiter().GetResult();

    public async Task<AgentResult> RunAsync(string prompt)
    {
        Trace($"RunAsync start maxIterations={_maxIterations} autoRetry={_autoRetry} promptLength={prompt?.Length ?? 0}");
        var toolNames = new List<string>();
        var stopwatch = Stopwatch.StartNew();

        var firstAttempt = await RunLoopAsync(prompt, _maxIterations, toolNames).ConfigureAwait(false);
        if (!firstAttempt.ReachedIterationLimit)
        {
            Trace($"RunAsync completed first attempt outputLength={firstAttempt.OutputText?.Length ?? 0}");
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
            Trace($"RunAsync retry completed reachedLimit={retryAttempt.ReachedIterationLimit}");

            var output = retryAttempt.ReachedIterationLimit
                ? $"Iteration limit reached after retry ({retryIterations})."
                : retryAttempt.OutputText;

            return FinalizeResult(output, toolNames, stopwatch.ElapsedMilliseconds);
        }

        stopwatch.Stop();
        Trace("RunAsync iteration limit reached without retry");
        return FinalizeResult("Iteration limit reached.", toolNames, stopwatch.ElapsedMilliseconds);
    }

    private async Task<RunLoopResult> RunLoopAsync(string prompt, int iterationLimit, List<string> toolNames)
    {
        var messages = new List<string>();
        messages.Add(BuildGoalPrompt(prompt));

        for (int i = 0; i < iterationLimit; i++)
        {
            Trace($"Iteration {i + 1}/{iterationLimit} start messages={messages.Count}");
            var combinedPrompt = string.Join("\n\n", messages);

            // 1. Ask the model
            Trace($"Iteration {i + 1} LLM request promptLength={combinedPrompt.Length}");
            var llmResponse = await _llm.GenerateAsync(combinedPrompt).ConfigureAwait(false);
            var text = llmResponse.Text.Trim();
            Trace($"Iteration {i + 1} LLM response length={text.Length} preview={Preview(text)}");

            if (string.IsNullOrWhiteSpace(text))
            {
                var isLastIteration = i >= (iterationLimit - 1);
                if (isLastIteration)
                {
                    Trace($"Iteration {i + 1} empty LLM response on final iteration");
                    return new RunLoopResult("LLM returned an empty response.", ReachedIterationLimit: false);
                }

                Trace($"Iteration {i + 1} empty LLM response; retrying");
                messages.Add("LLM returned an empty response. Return either a valid tool call or a final answer.");
                continue;
            }

            // 2. Detect tool call patterns from structured JSON or mixed prose.
            if (TryParseToolCall(text, out var toolName, out var toolArgs))
            {
                Trace($"Iteration {i + 1} parsed tool={toolName} argsLength={toolArgs?.Length ?? 0}");
                if (!_tools.TryGetValue(toolName, out var toolFunc))
                {
                    Trace($"Iteration {i + 1} tool not found: {toolName}");
                    messages.Add($"Tool '{toolName}' not found.");
                    continue;
                }

                toolNames.Add(toolName);

                // 3. Execute tool
                Trace($"Iteration {i + 1} executing tool {toolName}");
                var toolResult = await toolFunc(toolArgs).ConfigureAwait(false);
                Trace($"Iteration {i + 1} tool {toolName} completed resultLength={toolResult?.Length ?? 0} preview={Preview(toolResult)}");

                // 4. Feed result back into the loop
                messages.Add($"ToolResult({toolName}): {toolResult}");
                continue;
            }

            // 5. No tool call -> final answer
            Trace($"Iteration {i + 1} final answer detected length={text.Length}");
            return new RunLoopResult(text, ReachedIterationLimit: false);
        }

        Trace($"RunLoop reached iteration limit={iterationLimit}");
        return new RunLoopResult("Iteration limit reached.", ReachedIterationLimit: true);
    }

    private AgentResult FinalizeResult(string output, List<string> toolNames, long durationMs)
    {
        Trace($"FinalizeResult toolCalls={toolNames.Count} durationMs={durationMs} outputLength={output?.Length ?? 0}");
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

    private string BuildGoalPrompt(string prompt)
    {
        var availableTools = string.Join(", ", _tools.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase));

        return
            "You are a local automation agent. " +
            "Work step-by-step. " +
            "You may only call one of the exact tool names listed below. " +
            "If a tool is needed, call it using the format TOOLNAME{json} or TOOLCALL{TOOLNAME} {json}. " +
            "Tool-call JSON must be strict JSON with double-quoted keys and values. " +
            "Do not emit pseudo-tools such as read_file, list_directory, or write_file unless they are explicitly listed in available tools. " +
            "When calling a tool, output only the tool call with no extra commentary. " +
            "Do not hallucinate tool names. " +
            "Stop when the task is complete.\n\n" +
            $"Available tools: {availableTools}\n\n" +
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

        if (TryParseLegacyToolCall(text, out toolName, out jsonArgs))
            return true;

        if (TryParseAliasToolCall(text, out toolName, out jsonArgs))
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

                if (!TryExtractJsonObject(text, cursor, out var parsedArgs, out _)
                    && !TryExtractLooseJsonObject(text, cursor, out parsedArgs, out _))
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

    private bool TryParseLegacyToolCall(string text, out string toolName, out string jsonArgs)
    {
        toolName = "";
        jsonArgs = "";

        if (string.IsNullOrWhiteSpace(text))
            return false;

        var marker = "TOOLCALL{";
        var markerIndex = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex < 0)
            return false;

        var toolStart = markerIndex + marker.Length;
        var toolEnd = text.IndexOf('}', toolStart);
        if (toolEnd <= toolStart)
            return false;

        var candidateToolName = text[toolStart..toolEnd].Trim();
        if (!TryResolveToolName(candidateToolName, out var resolvedToolName))
            return false;

        var cursor = toolEnd + 1;
        while (cursor < text.Length && char.IsWhiteSpace(text[cursor]))
        {
            cursor++;
        }

        if (cursor < text.Length && text[cursor] == '{' && TryExtractJsonObject(text, cursor, out var parsedArgs, out _))
        {
            toolName = resolvedToolName;
            jsonArgs = parsedArgs;
            return true;
        }

        toolName = resolvedToolName;
        jsonArgs = "{}";
        return true;
    }

    private bool TryParseAliasToolCall(string text, out string toolName, out string jsonArgs)
    {
        toolName = "";
        jsonArgs = "";

        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (var alias in ToolAliases.Keys)
        {
            var searchStart = 0;
            while (searchStart < text.Length)
            {
                var aliasIdx = text.IndexOf(alias, searchStart, StringComparison.OrdinalIgnoreCase);
                if (aliasIdx < 0)
                    break;

                if (!IsTokenBoundary(text, aliasIdx - 1))
                {
                    searchStart = aliasIdx + alias.Length;
                    continue;
                }

                var cursor = aliasIdx + alias.Length;
                while (cursor < text.Length && char.IsWhiteSpace(text[cursor]))
                {
                    cursor++;
                }

                if (cursor >= text.Length || text[cursor] != '{')
                {
                    searchStart = aliasIdx + alias.Length;
                    continue;
                }

                if (!TryExtractJsonObject(text, cursor, out var parsedArgs, out _)
                    && !TryExtractLooseJsonObject(text, cursor, out parsedArgs, out _))
                {
                    searchStart = aliasIdx + alias.Length;
                    continue;
                }

                if (!TryResolveToolName(alias, out var resolvedToolName))
                {
                    searchStart = aliasIdx + alias.Length;
                    continue;
                }

                toolName = resolvedToolName;
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

            if (!TryResolveToolName(parsedName, out var resolvedToolName))
                return false;

            if (TryGetObjectProperty(root, out var parsedArgs, "args", "arguments", "input"))
            {
                toolName = resolvedToolName;
                jsonArgs = parsedArgs.GetRawText();
                return true;
            }

            toolName = resolvedToolName;
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

    private static bool TryExtractLooseJsonObject(string text, int startIndex, out string jsonText, out int endIndex)
    {
        jsonText = "";
        endIndex = -1;

        if (!TryExtractBalancedObject(text, startIndex, out var candidate, out endIndex))
            return false;

        // Convert simple JS-like object syntax (e.g., {path: "x"}) into strict JSON.
        var normalized = Regex.Replace(
            candidate,
            @"(?<=[\{,]\s*)([A-Za-z_][A-Za-z0-9_-]*)\s*:",
            "\"$1\":");

        try
        {
            using var _ = JsonDocument.Parse(normalized);
            jsonText = normalized;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryExtractBalancedObject(string text, int startIndex, out string jsonText, out int endIndex)
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

            jsonText = text[startIndex..(i + 1)];
            endIndex = i;
            return true;
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

    private bool TryResolveToolName(string candidateName, out string resolvedName)
    {
        resolvedName = "";
        if (string.IsNullOrWhiteSpace(candidateName))
            return false;

        if (_tools.ContainsKey(candidateName))
        {
            resolvedName = candidateName;
            return true;
        }

        if (ToolAliases.TryGetValue(candidateName, out var mapped) && _tools.ContainsKey(mapped))
        {
            resolvedName = mapped;
            return true;
        }

        return false;
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
