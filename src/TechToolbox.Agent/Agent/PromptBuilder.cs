using TechToolbox.Agent.Registry;
using TechToolbox.Agent.Memory;
using System.Text;

namespace TechToolbox.Agent.Agent;

public static class PromptBuilder
{
    public static List<AgentChatMessage> BuildInitialMessages(
        string userPrompt,
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory)
    {
        var messages = new List<AgentChatMessage>
        {
            new()
            {
                Role = "system",
                Content = BuildSystemPrompt(registry, memory)
            },
            new()
            {
                Role = "user",
                Content = userPrompt
            }
        };

        return messages;
    }

    public static AgentChatMessage BuildToolResultMessage(string toolName, string toolResult)
    {
        return new AgentChatMessage
        {
            Role = "user",
            Content =
$"""
Tool execution completed.

Tool name: {toolName}

Tool result:
{toolResult}

Based on this result, return the next JSON decision object only.
"""
        };
    }

    public static AgentChatMessage BuildRepairMessage(string invalidResponse)
    {
        return new AgentChatMessage
        {
            Role = "user",
            Content = JsonHelpers.BuildRepairPrompt(invalidResponse)
        };
    }

    private static string BuildSystemPrompt(
        IReadOnlyDictionary<string, ToolSpec> registry,
        MemoryStore? memory)
    {
        var sb = new StringBuilder();

        sb.AppendLine("You are a local automation agent running inside TechToolbox.");
        sb.AppendLine("Think briefly and act precisely.");
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
        sb.AppendLine("- No markdown.");
        sb.AppendLine("- No code fences.");
        sb.AppendLine("- If a tool is needed, set needsTool=true and provide toolName/toolArgs.");
        sb.AppendLine("- If no tool is needed, set needsTool=false and provide finalAnswer.");
        sb.AppendLine("- Never invent tool results.");
        sb.AppendLine("- Use only exact tool names from the available tools list.");
        sb.AppendLine("- Prefer the smallest useful number of tool calls.");
        sb.AppendLine("- For destructive actions, require confirmation.");
        sb.AppendLine();

        sb.AppendLine("Available tools:");
        foreach (var tool in registry.Values.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase))
        {
            var required = tool.Parameters
                .Where(p => p.Value.Mandatory)
                .Select(p => p.Key)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var requiredText = required.Length == 0
                ? "none"
                : string.Join(", ", required);

            sb.AppendLine($"- {tool.Name}: {tool.Description} (required params: {requiredText})");
        }

        if (memory is not null)
        {
            var prefs = memory.Preferences.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
            var facts = memory.Facts.Take(5).Select(kv => $"{kv.Key}={kv.Value}");
            var history = memory.History.TakeLast(3)
                .Select(h => $"{h.Timestamp:u} | {h.Intent} | tools={string.Join(",", h.ToolNames)}");

            sb.AppendLine();
            sb.AppendLine("Persistent memory:");
            sb.AppendLine($"Preferences: {(prefs.Any() ? string.Join("; ", prefs) : "none")}");
            sb.AppendLine($"Facts: {(facts.Any() ? string.Join("; ", facts) : "none")}");
            sb.AppendLine($"Recent history: {(history.Any() ? string.Join(" || ", history) : "none")}");
        }

        return sb.ToString();
    }
}
