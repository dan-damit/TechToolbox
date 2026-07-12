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
            // Fallback: try to recover content from a truncated (unclosed) JSON string —
            // this happens when num_predict cuts the model response mid-output.
            if (!TryExtractTruncatedJsonStringProperty(text, "content", out content, out contentReason))
            {
                reason = $"content extraction failed: {contentReason}";
                return false;
            }
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

    /// <summary>
    /// Attempts to extract a potentially truncated JSON string property value.
    /// Used as a fallback when the model output was cut off before the closing quote.
    /// </summary>
    private static bool TryExtractTruncatedJsonStringProperty(
        string text,
        string propertyName,
        out string value,
        out string reason
    )
    {
        value = string.Empty;
        reason = string.Empty;

        // Match everything after the opening quote, even if the string is never closed.
        var pattern = $"\"(?:{Regex.Escape(propertyName)})\"\\s*:\\s*\"(?<value>.+)";
        var match = Regex.Match(text, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (!match.Success)
        {
            reason = $"{propertyName} truncated property not found";
            return false;
        }

        // The captured tail may contain trailing JSON envelope characters — strip them.
        var raw = match.Groups["value"].Value.TrimEnd();

        // Unescape what we can; errors here just mean we use the raw string.
        try
        {
            // Append a synthetic closing quote so the deserializer can parse it.
            value = JsonSerializer.Deserialize<string>($"\"{raw}\"") ?? raw;
        }
        catch
        {
            value = raw;
        }

        // If recovery fell back to raw escaped content (for example "\\n" and "\\\""),
        // decode one escape layer to avoid writing single-line escaped blobs to disk.
        if (TryDecodeLikelyEscapedPayload(value, out var decoded))
        {
            value = decoded;
            reason = $"{propertyName} recovered from truncated JSON and decoded escaped payload";
            return !string.IsNullOrWhiteSpace(value);
        }

        reason = $"{propertyName} recovered from truncated JSON";
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryDecodeLikelyEscapedPayload(string text, out string decoded)
    {
        decoded = string.Empty;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        // Already contains real line breaks; this does not look like an escaped blob.
        if (text.Contains('\n') || text.Contains('\r'))
            return false;

        var decodeSignals = 0;
        if (text.Contains("\\n", StringComparison.Ordinal))
            decodeSignals++;
        if (text.Contains("\\r", StringComparison.Ordinal))
            decodeSignals++;
        if (text.Contains("\\t", StringComparison.Ordinal))
            decodeSignals++;
        if (text.Contains("\\\"", StringComparison.Ordinal))
            decodeSignals++;

        if (decodeSignals < 2)
            return false;

        decoded = text
            .Replace("\\r\\n", "\r\n", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal)
            .Replace("\\\"", "\"", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal);

        return !string.Equals(decoded, text, StringComparison.Ordinal);
    }
}
