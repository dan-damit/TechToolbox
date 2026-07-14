using System.Text;
using TechToolbox.Agent.Configuration;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Provides methods for building system prompts, goal prompts, and message structures
/// used by the TechToolbox agent to communicate with language models.
/// </summary>
public static class PromptBuilder
{
    /// <summary>
    /// The default number of recent history items included in memory context.
    /// </summary>
    private const int DefaultRecentHistoryItems = 2;

    /// <summary>
    /// The maximum number of recent history items that can be included in memory context.
    /// </summary>
    private const int MaxRecentHistoryItems = 20;

    /// <summary>
    /// Instruction string for formatting final answers as plain ASCII Markdown.
    /// </summary>
    private const string AsciiMarkdownInstruction =
        "Format the final answer as plain Markdown using ASCII characters only. "
        + "Do not use emoji, smart quotes, Unicode bullets, box-drawing characters, or arrow glyphs. "
        + "Use '-' for bullets, '##'/'###' for headings, and '->' when an arrow is needed.";

    /// <summary>
    /// Legacy method: builds initial messages with TechToolbox system prompt.
    /// Maintained for backward compatibility.
    /// </summary>
    /// <param name="userPrompt">The user's goal or task description.</param>
    /// <param name="registry">The tool registry containing available tools and their specifications.</param>
    /// <param name="memory">Optional memory store for persistent context. Can be null.</param>
    /// <returns>A list of initial chat messages including system and user messages.</returns>
    public static List<AgentChatMessage> BuildInitialMessages(
        string userPrompt,
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory
    )
    {
        // Auto-detect mode from registry
        var mode = AgentModeDetector.DetectMode(registry);
        return BuildInitialMessages(
            userPrompt,
            registry,
            memory,
            mode,
            null,
            DefaultRecentHistoryItems
        );
    }

    /// <summary>
    /// Builds initial messages and allows overriding the number of recent history items
    /// injected into prompt memory context.
    /// </summary>
    /// <param name="userPrompt">The user's goal or task description.</param>
    /// <param name="registry">The tool registry containing available tools and their specifications.</param>
    /// <param name="memory">Optional memory store for persistent context. Can be null.</param>
    /// <param name="recentHistoryItems">Number of recent history items to include (clamped to MaxRecentHistoryItems).</param>
    /// <returns>A list of initial chat messages including system and user messages.</returns>
    public static List<AgentChatMessage> BuildInitialMessages(
        string userPrompt,
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory,
        int recentHistoryItems
    )
    {
        var mode = AgentModeDetector.DetectMode(registry);
        return BuildInitialMessages(userPrompt, registry, memory, mode, null, recentHistoryItems);
    }

    /// <summary>
    /// Builds initial messages for a specific agent mode.
    /// </summary>
    /// <param name="userPrompt">The user's goal or task description.</param>
    /// <param name="registry">The tool registry containing available tools and their specifications.</param>
    /// <param name="memory">Optional memory store for persistent context. Can be null.</param>
    /// <param name="mode">The agent mode to use (TechToolbox, Assistant, CodingAgent, or Custom).</param>
    /// <param name="systemPromptOverride">Optional override for the system prompt. If null, a default is generated.</param>
    /// <param name="recentHistoryItems">Number of recent history items to include (clamped to MaxRecentHistoryItems). Default is DefaultRecentHistoryItems.</param>
    /// <returns>A list of initial chat messages including system and user messages.</returns>
    public static List<AgentChatMessage> BuildInitialMessages(
        string userPrompt,
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory,
        AgentMode mode,
        string? systemPromptOverride = null,
        int recentHistoryItems = DefaultRecentHistoryItems
    )
    {
        var systemPrompt =
            systemPromptOverride ?? BuildSystemPrompt(registry, mode);

        var messages = new List<AgentChatMessage>
        {
            new() { Role = "system", Content = systemPrompt },
            new() { Role = "user", Content = BuildGoalPrompt(userPrompt, memory, recentHistoryItems) },
        };

        return messages;
    }

    /// <summary>
    /// Builds a tool result message to be sent back to the agent after a tool execution.
    /// </summary>
    /// <param name="toolName">The name of the tool that was executed.</param>
    /// <param name="toolResult">The result output from the tool execution.</param>
    /// <param name="succeeded">Whether the tool execution succeeded. Default is true.</param>
    /// <returns>An AgentChatMessage containing the tool result formatted for agent consumption.</returns>
    public static AgentChatMessage BuildToolResultMessage(
        string toolName,
        string toolResult,
        bool succeeded = true
    )
    {
        var readFileSafetyGuidance = BuildReadFileSafetyGuidance(toolName, toolResult, succeeded);
        var safetySection = string.IsNullOrWhiteSpace(readFileSafetyGuidance)
            ? string.Empty
            : $"{readFileSafetyGuidance}{Environment.NewLine}{Environment.NewLine}";

        return new AgentChatMessage
        {
            Role = "user",
            Content = $"""
Tool result received.

Tool: {toolName}
Status: {(succeeded ? "success" : "error")}

BEGIN_TOOL_RESULT
{toolResult}
END_TOOL_RESULT

{safetySection}Return only the next JSON decision object.

If the goal can now be completed, set needsTool=false and provide finalAnswer.
If another tool is still required, set needsTool=true with the exact toolName and toolArgs.
""",
        };
    }

    /// <summary>
    /// Builds a repair message for invalid JSON responses from the agent.
    /// </summary>
    /// <param name="invalidResponse">The invalid response that needs to be repaired.</param>
    /// <returns>An AgentChatMessage containing instructions for the agent to fix its response.</returns>
    public static AgentChatMessage BuildRepairMessage(string invalidResponse)
    {
        return new AgentChatMessage
        {
            Role = "user",
            Content = JsonHelpers.BuildRepairPrompt(invalidResponse),
        };
    }

    /// <summary>
    /// Builds a recovery message for failed WRITE-FILE operations.
    /// </summary>
    /// <param name="invalidResponse">The invalid response that attempted to write a file.</param>
    /// <returns>An AgentChatMessage containing instructions for the agent to properly format a WRITE-FILE call.</returns>
    public static AgentChatMessage BuildWriteFileRecoveryMessage(string invalidResponse)
    {
        const int maxChars = 4000;
        var snippet = invalidResponse ?? string.Empty;
        if (snippet.Length > maxChars)
        {
            snippet = snippet[..maxChars] + "\n[truncated]";
        }

        return new AgentChatMessage
        {
            Role = "user",
            Content =
                $@"Your previous response appears to be an intended WRITE-FILE tool call, but the JSON envelope is invalid.

Return ONLY one valid JSON object using this exact minimal shape:
{{""needsTool"":true,""toolName"":""WRITE-FILE"",""toolArgs"":{{""path"":""..."",""content"":""...""}},""reason"":""recover write-file""}}

Rules:
- Use toolName exactly WRITE-FILE.
- Include only path and content inside toolArgs.
- Escape all newlines inside content as \n.
- No markdown, no code fences, no commentary.

Invalid response snippet:
{snippet}"
        };
    }

    /// <summary>
    /// Builds the system prompt based on the agent mode and available tools.
    /// </summary>
    /// <param name="registry">The tool registry containing available tools and their specifications.</param>
    /// <param name="mode">The agent mode to use (TechToolbox, Assistant, CodingAgent, or Custom).</param>
    /// <returns>A formatted system prompt string including preamble, JSON schema, rules, and available tools.</returns>
    private static string BuildSystemPrompt(
        IReadOnlyDictionary<string, ToolSpec> registry,
        AgentMode mode
    )
    {
        var preamble = mode switch
        {
            AgentMode.TechToolbox =>
                "You are a local automation agent running inside TechToolbox.\n"
                + "Work step-by-step, use tools when helpful, and complete the task safely.\n"
                + "Never execute destructive actions without explicit confirmation.\n"
                + "If blocked, explain exactly what is missing and propose the next step.",
            AgentMode.Assistant =>
                "You are a helpful assistant focused on clarity and safety.\n"
                + "Help the user with writing, analysis, coding questions, and other tasks.\n"
                + "Use available tools to read files, inspect code, or create documents as needed.\n"
                + "Always explain your reasoning clearly and provide actionable advice.",
            AgentMode.CodingAgent =>
                "You are an expert coding assistant specialized in analysis, generation, and debugging.\n"
                + "Analyze code structures, explain issues, generate solutions, and help debug problems.\n"
                + "Work step-by-step, inspect files thoroughly, and provide well-reasoned recommendations.\n"
                + "Follow best practices for the relevant programming language and framework.",
            AgentMode.Custom =>
                "You are an automated agent with access to specialized tools.\n"
                + "Use tools effectively to complete tasks and provide clear explanations.",
            _ =>
                "You are an automated agent. Work step-by-step and use available tools as needed."
        };

        var sb = new StringBuilder();

        sb.AppendLine(preamble);
        sb.AppendLine();
        sb.AppendLine("For every turn, return ONLY a valid JSON object matching this schema:");
        sb.AppendLine(@"{");
        sb.AppendLine(@"  ""needsTool"": true|false,");
        sb.AppendLine(@"  ""toolName"": ""string"",");
        sb.AppendLine(@"  ""toolArgs"": {},");
        sb.AppendLine(@"  ""finalAnswer"": ""string"",");
        sb.AppendLine(@"  ""reason"": ""short explanation""");
        sb.AppendLine(@"}");
        sb.AppendLine();
        sb.AppendLine("Rules:");
        sb.AppendLine("- Output valid JSON only.");
        sb.AppendLine("- No markdown outside the JSON object.");
        sb.AppendLine("- No code fences.");
        sb.AppendLine("- If a tool is needed, set needsTool=true and provide toolName/toolArgs.");
        sb.AppendLine("- If no tool is needed, set needsTool=false and provide finalAnswer.");
        sb.AppendLine(
            $"- When needsTool=false, finalAnswer must follow this style: {AsciiMarkdownInstruction}"
        );
        sb.AppendLine(
            "- If the goal asks to create or write a file at a specific path/name, you must call WRITE-FILE and only return finalAnswer after WRITE-FILE succeeds."
        );
        sb.AppendLine(
            "- For localized edits to an existing large file, prefer REPLACE-IN-FILE instead of rewriting the entire file with WRITE-FILE."
        );
        sb.AppendLine(
            "- For very large generated outputs, prefer APPEND-FILE in multiple chunks (set truncateFirst=true on the first chunk) to avoid truncated single-response writes."
        );
        sb.AppendLine(
            "- If you used APPEND-FILE chunks for a required output file, call FINALIZE-FILE-WRITE on the same path before returning finalAnswer."
        );
        sb.AppendLine("- Never invent tool results.");
        sb.AppendLine("- Use only exact tool names from the available tools list.");
        sb.AppendLine("- Prefer the smallest useful number of tool calls.");
        sb.AppendLine(
            "- For large files, use READ-FILE chunking with startLine/endLine/maxLines and verify coverage before final conclusions."
        );

        sb.AppendLine();
        sb.AppendLine("Available tools:");
        foreach (var tool in registry.Values.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase))
        {
            var required = tool
                .Parameters.Where(p => p.Value.Mandatory)
                .Select(p => p.Key)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var requiredText = required.Length == 0 ? "none" : string.Join(", ", required);

            sb.AppendLine($"- {tool.Name}: {tool.Description} (required params: {requiredText})");
        }
        return sb.ToString();
    }

    private static string BuildReadFileSafetyGuidance(string toolName, string toolResult, bool succeeded)
    {
        if (!succeeded)
            return string.Empty;

        if (!string.Equals(toolName, "READ-FILE", StringComparison.OrdinalIgnoreCase))
            return string.Empty;

        var trimmed = toolResult?.TrimStart() ?? string.Empty;
        var isSummary =
            trimmed.StartsWith("{", StringComparison.Ordinal)
            && trimmed.Contains("\"kind\":\"file-summary\"", StringComparison.OrdinalIgnoreCase);

        if (!isSummary)
            return string.Empty;

        return "Large-file protocol: use READ-FILE chunking (startLine/endLine/maxLines), verify all relevant symbols across chunks, then finalize.";
    }

    /// <summary>
    /// Builds the goal prompt with optional memory context.
    /// </summary>
    /// <param name="prompt">The user's goal or task description.</param>
    /// <param name="memory">Optional memory store for persistent context. Can be null.</param>
    /// <param name="recentHistoryItems">Number of recent history items to include.</param>
    /// <returns>A formatted goal prompt string with optional memory context.</returns>
    private static string BuildGoalPrompt(
        string prompt,
        MemoryStore? memory,
        int recentHistoryItems
    )
    {
        var header =
            "You are a local automation agent. "
            + "Work step-by-step, call tools as needed, and continue iterating until the goal is completed "
            + "or you can clearly justify why it cannot be completed safely. "
            + "Never execute destructive actions without explicit confirmation. "
            + "If confirmation is missing, stop and report exactly what confirmation is required. "
            + "If blocked, explain the blocker and provide the next best action. "
            + $"{AsciiMarkdownInstruction}";

        var memoryContext = BuildMemoryContext(memory, recentHistoryItems);
        if (string.IsNullOrWhiteSpace(memoryContext))
            return $"{header}{Environment.NewLine}{Environment.NewLine}Goal: {prompt}";

        return $"""
{header}

Persistent memory context (advisory):
{memoryContext}

Goal: {prompt}
""";
    }

    /// <summary>
    /// Builds the memory context string from the provided MemoryStore.
    /// </summary>
    /// <param name="memory">The memory store to extract context from. Can be null.</param>
    /// <param name="recentHistoryItems">Number of recent history items to include (clamped to MaxRecentHistoryItems).</param>
    /// <returns>A formatted memory context string, or empty string if no memory is provided.</returns>
    private static string BuildMemoryContext(MemoryStore? memory, int recentHistoryItems)
    {
        if (memory is null)
            return string.Empty;

        var clampedRecentHistoryItems = Math.Clamp(recentHistoryItems, 0, MaxRecentHistoryItems);

        var prefs = memory.Preferences.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
        var facts = memory.Facts.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
        var history = memory
            .History.TakeLast(clampedRecentHistoryItems)
            .Select(h =>
            {
                var intent = h.RunSummary?.Intent;
                if (string.IsNullOrWhiteSpace(intent))
                {
                    intent = !string.IsNullOrWhiteSpace(h.Prompt) ? h.Prompt : h.OutputPreview;
                }

                var actions = h.RunSummary?.ActionsTaken ?? h.ToolNames;
                return $"{h.TimestampUtc:u} | {intent} | tools={string.Join(",", actions)}";
            });

        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Preferences: {(prefs.Any() ? string.Join("; ", prefs) : "none")}",
                $"Facts: {(facts.Any() ? string.Join("; ", facts) : "none")}",
                $"Recent history: {(history.Any() ? string.Join(" || ", history) : "none")}",
            }
        );
    }
}
