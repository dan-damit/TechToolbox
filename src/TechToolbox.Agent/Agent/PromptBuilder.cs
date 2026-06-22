using System.Text;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public static class PromptBuilder
{
    private const string AsciiMarkdownInstruction =
        "Format the final answer as plain Markdown using ASCII characters only. "
        + "Do not use emoji, smart quotes, Unicode bullets, box-drawing characters, or arrow glyphs. "
        + "Use '-' for bullets, '##'/'###' for headings, and '->' when an arrow is needed.";

    public static List<AgentChatMessage> BuildInitialMessages(
        string userPrompt,
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory
    )
    {
        var messages = new List<AgentChatMessage>
        {
            new() { Role = "system", Content = BuildSystemPrompt(registry) },
            new() { Role = "user", Content = BuildGoalPrompt(userPrompt, memory) },
        };

        return messages;
    }

    public static AgentChatMessage BuildToolResultMessage(
        string toolName,
        string toolResult,
        bool succeeded = true
    )
    {
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

Return only the next JSON decision object.
If the goal can now be completed, set needsTool=false and provide finalAnswer.
If another tool is still required, set needsTool=true with the exact toolName and toolArgs.
""",
        };
    }

    public static AgentChatMessage BuildRepairMessage(string invalidResponse)
    {
        return new AgentChatMessage
        {
            Role = "user",
            Content = JsonHelpers.BuildRepairPrompt(invalidResponse),
        };
    }

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
{snippet}",
        };
    }

    private static string BuildSystemPrompt(IReadOnlyDictionary<string, ToolSpec> registry)
    {
        var sb = new StringBuilder();

        sb.AppendLine("You are a local automation agent running inside TechToolbox.");
        sb.AppendLine("Work step-by-step, use tools when helpful, and complete the task safely.");
        sb.AppendLine("Never execute destructive actions without explicit confirmation.");
        sb.AppendLine("If blocked, explain exactly what is missing and propose the next step.");
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
        sb.AppendLine("- Never invent tool results.");
        sb.AppendLine("- Use only exact tool names from the available tools list.");
        sb.AppendLine("- Prefer the smallest useful number of tool calls.");
        sb.AppendLine("- For destructive actions, require confirmation.");
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

    private static string BuildGoalPrompt(string prompt, MemoryStore? memory)
    {
        var header =
            "You are a local automation agent. "
            + "Work step-by-step, call tools as needed, and continue iterating until the goal is completed "
            + "or you can clearly justify why it cannot be completed safely. "
            + "Never execute destructive actions without explicit confirmation. "
            + "If confirmation is missing, stop and report exactly what confirmation is required. "
            + "If blocked, explain the blocker and provide the next best action. "
            + $"{AsciiMarkdownInstruction}";

        var memoryContext = BuildMemoryContext(memory);
        if (string.IsNullOrWhiteSpace(memoryContext))
            return $"{header}{Environment.NewLine}{Environment.NewLine}Goal: {prompt}";

        return $"""
{header}

Persistent memory context (advisory):
{memoryContext}

Goal: {prompt}
""";
    }

    private static string BuildMemoryContext(MemoryStore? memory)
    {
        if (memory is null)
            return string.Empty;

        var prefs = memory.Preferences.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
        var facts = memory.Facts.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
        var history = memory
            .History.TakeLast(3)
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
