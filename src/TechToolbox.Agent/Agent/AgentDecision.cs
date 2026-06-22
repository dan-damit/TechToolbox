using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechToolbox.Agent.Agent;

public sealed class AgentDecision
{
    [JsonPropertyName("needsTool")]
    public bool NeedsTool { get; set; }

    [JsonPropertyName("toolName")]
    public string ToolName { get; set; } = "";

    [JsonPropertyName("toolArgs")]
    public Dictionary<string, object?> ToolArgs { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    [JsonPropertyName("finalAnswer")]
    public string FinalAnswer { get; set; } = "";

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = "";
}

public sealed class AgentChatMessage
{
    [JsonPropertyName("role")]
    public string Role { get; set; } = "";

    [JsonPropertyName("content")]
    public string Content { get; set; } = "";
}

public sealed class OllamaChatRequest
{
    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    [JsonPropertyName("messages")]
    public List<AgentChatMessage> Messages { get; set; } = new();

    [JsonPropertyName("stream")]
    public bool Stream { get; set; } = false;

    [JsonPropertyName("think")]
    public bool? Think { get; set; }

    [JsonPropertyName("format")]
    public object? Format { get; set; } = "json";

    [JsonPropertyName("options")]
    public Dictionary<string, object?> Options { get; set; } = new();
}

public sealed class OllamaChatMessage
{
    [JsonPropertyName("role")]
    public string? Role { get; set; }

    [JsonPropertyName("content")]
    public string? Content { get; set; }
}

public sealed class OllamaChatResponse
{
    [JsonPropertyName("model")]
    public string? Model { get; set; }

    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }

    [JsonPropertyName("message")]
    public OllamaChatMessage? Message { get; set; }

    [JsonPropertyName("done")]
    public bool Done { get; set; }

    [JsonPropertyName("total_duration")]
    public long? TotalDuration { get; set; }

    [JsonPropertyName("load_duration")]
    public long? LoadDuration { get; set; }

    [JsonPropertyName("prompt_eval_count")]
    public int? PromptEvalCount { get; set; }

    [JsonPropertyName("prompt_eval_duration")]
    public long? PromptEvalDuration { get; set; }

    [JsonPropertyName("eval_count")]
    public int? EvalCount { get; set; }

    [JsonPropertyName("eval_duration")]
    public long? EvalDuration { get; set; }
}

public sealed record LlmResponse(string Text, string RawBody = "", bool Success = true);
