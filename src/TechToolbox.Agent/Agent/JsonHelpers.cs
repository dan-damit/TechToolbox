using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// JSON helper utilities for agent processing and decision parsing.
/// </summary>
public static class JsonHelpers
{
    private static readonly Regex WriteFileToolNameRegex = new(
        "\"toolName\"\\s*:\\s*\"(?<name>[^\"]+)\"",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    private const string JsonStringPropertyPatternTemplate =
        "\"{0}\"\\s*:\\s*\"(?<value>(?:\\\\.|[^\"\\\\])*)\"";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
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

    /// <summary>
    /// Returns true when text appears to contain a WRITE-FILE planner response,
    /// even if the envelope is malformed.
    /// </summary>
    public static bool LooksLikeWriteFileDecision(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        return text.Contains("\"toolName\"", StringComparison.OrdinalIgnoreCase)
            && text.Contains("WRITE-FILE", StringComparison.OrdinalIgnoreCase)
            && text.Contains("\"toolArgs\"", StringComparison.OrdinalIgnoreCase)
            && text.Contains("\"path\"", StringComparison.OrdinalIgnoreCase)
            && text.Contains("\"content\"", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Attempts to recover a WRITE-FILE decision from malformed JSON text.
    /// </summary>
    public static bool TryExtractWriteFileDecision(
        string text,
        out AgentDecision? decision,
        out string reason
    )
    {
        decision = null;
        reason = string.Empty;

        if (!LooksLikeWriteFileDecision(text))
        {
            reason = "write-file markers missing";
            return false;
        }

        var toolNameMatch = WriteFileToolNameRegex.Match(text);
        if (!toolNameMatch.Success)
        {
            reason = "toolName not found";
            return false;
        }

        var toolName = toolNameMatch.Groups["name"].Value.Trim();
        if (!toolName.Equals("WRITE-FILE", StringComparison.OrdinalIgnoreCase))
        {
            reason = "toolName is not WRITE-FILE";
            return false;
        }

        if (!TryExtractJsonStringProperty(text, "path", out var path, out var pathReason))
        {
            reason = $"path extraction failed: {pathReason}";
            return false;
        }

        if (!TryExtractJsonStringProperty(text, "content", out var content, out var contentReason))
        {
            reason = $"content extraction failed: {contentReason}";
            return false;
        }

        if (string.IsNullOrWhiteSpace(path))
        {
            reason = "path is empty";
            return false;
        }

        decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "WRITE-FILE",
            ToolArgs = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["path"] = path,
                ["content"] = content,
            },
            Reason = "Recovered malformed WRITE-FILE decision",
        };

        reason = "recovered write-file decision from malformed JSON";
        return true;
    }

    private static bool TryExtractJsonStringProperty(
        string text,
        string propertyName,
        out string value,
        out string reason
    )
    {
        value = string.Empty;
        reason = string.Empty;

        var pattern = string.Format(JsonStringPropertyPatternTemplate, Regex.Escape(propertyName));
        var regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        var match = regex.Match(text);
        if (!match.Success)
        {
            reason = $"{propertyName} property not found";
            return false;
        }

        var escapedValue = match.Groups["value"].Value;
        try
        {
            // Decode JSON string escapes (for example \n, \" and \\).
            value = JsonSerializer.Deserialize<string>($"\"{escapedValue}\"") ?? string.Empty;
            return true;
        }
        catch (Exception ex)
        {
            reason = $"{propertyName} decode failed: {ex.Message}";
            return false;
        }
    }
}
