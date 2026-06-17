using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// JSON helper utilities for agent processing and decision parsing.
/// </summary>
public static class JsonHelpers
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Attempts to parse a JSON string into an AgentDecision object.
    /// </summary>
    /// <param name="json">The JSON string to parse.</param>
    /// <param name="decision">The parsed AgentDecision, or null if parsing fails.</param>
    /// <returns>True if parsing succeeded, false otherwise.</returns>
    public static bool TryParseDecision(string json, out AgentDecision? decision)
    {
        decision = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            decision = JsonSerializer.Deserialize<AgentDecision>(json, JsonOptions);
            return decision is not null;
        }
        catch (JsonException)
        {
            return false;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Builds a repair prompt to help the LLM fix invalid JSON responses.
    /// </summary>
    /// <param name="invalidResponse">The invalid JSON response from the LLM.</param>
    /// <returns>A prompt string instructing the LLM to fix the JSON.</returns>
    public static string BuildRepairPrompt(string invalidResponse)
    {
        return $$"""
Your previous response was not valid JSON:

```
{{invalidResponse}}
```

Please provide a corrected JSON response that matches the required schema exactly:
{
  "needsTool": true|false,
  "toolName": "string (only if needsTool is true)",
  "toolArgs": { "key": "value" } (only if needsTool is true),
  "finalAnswer": "string (only if needsTool is false)",
  "reason": "string (brief explanation)"
}

Respond with ONLY the JSON object, no additional text or markdown formatting.
""";
    }
}