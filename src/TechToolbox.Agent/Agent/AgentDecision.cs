// AgentDecision.cs
// Defines data models for agent decision-making and LLM communication.
// Contains classes for tool invocation decisions, chat messages, and Ollama API request/response structures.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Represents a decision made by the agent about whether to invoke a tool or provide a final answer.
/// Used for JSON serialization/deserialization when communicating with the LLM.
/// </summary>
public sealed class AgentDecision
{
    /// <summary>
    /// Indicates whether the agent needs to invoke a tool to complete the task.
    /// When true, toolName and toolArgs should be populated.
    /// When false, finalAnswer should contain the response.
    /// </summary>
    [JsonPropertyName("needsTool")]
    public bool NeedsTool { get; set; }

    /// <summary>
    /// The name of the tool to invoke when NeedsTool is true.
    /// Must match one of the available tool names in TechToolbox.
    /// </summary>
    [JsonPropertyName("toolName")]
    public string ToolName { get; set; } = "";

    /// <summary>
    /// Dictionary of arguments to pass to the tool.
    /// Keys are case-insensitive and values can be null.
    /// Only used when NeedsTool is true.
    /// </summary>
    [JsonPropertyName("toolArgs")]
    public Dictionary<string, object?> ToolArgs { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The final answer to return to the user when NeedsTool is false.
    /// Should contain a complete response or explanation.
    /// </summary>
    [JsonPropertyName("finalAnswer")]
    public string FinalAnswer { get; set; } = "";

    /// <summary>
    /// Brief explanation of why the agent made this decision.
    /// Useful for debugging and understanding agent reasoning.
    /// </summary>
    [JsonPropertyName("reason")]
    public string Reason { get; set; } = "";
}

/// <summary>
/// Represents a chat message in the conversation history.
/// Used for building LLM request payloads with role-based messaging.
/// </summary>
public sealed class AgentChatMessage
{
    /// <summary>
    /// The role of the message sender (e.g., "system", "user", "assistant").
    /// Determines how the LLM interprets and responds to the message.
    /// </summary>
    [JsonPropertyName("role")]
    public string Role { get; set; } = "";

    /// <summary>
    /// The content text of the message.
    /// Contains the actual information being communicated.
    /// </summary>
    [JsonPropertyName("content")]
    public string Content { get; set; } = "";
}

/// <summary>
/// Represents a request payload for the Ollama chat API.
/// Contains model selection, conversation history, and optional parameters.
/// </summary>
public sealed class OllamaChatRequest
{
    /// <summary>
    /// The name of the Ollama model to use for inference.
    /// Must be a model available in the local Ollama instance.
    /// </summary>
    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    /// <summary>
    /// List of chat messages forming the conversation context.
    /// Includes system, user, and assistant messages in chronological order.
    /// </summary>
    [JsonPropertyName("messages")]
    public List<AgentChatMessage> Messages { get; set; } = new();

    /// <summary>
    /// When true, enables streaming mode for incremental response delivery.
    /// When false, returns the complete response at once.
    /// </summary>
    [JsonPropertyName("stream")]
    public bool Stream { get; set; } = false;

    /// <summary>
    /// Optional flag to enable extended thinking/reasoning mode.
    /// May improve response quality for complex tasks.
    /// </summary>
    [JsonPropertyName("think")]
    public bool? Think { get; set; }

    /// <summary>
    /// Response format specification. Typically set to "json" for structured output.
    /// Controls how the LLM formats its response.
    /// </summary>
    [JsonPropertyName("format")]
    public object? Format { get; set; } = "json";

    /// <summary>
    /// Additional model-specific options and parameters.
    /// Can include temperature, top_p, and other inference controls.
    /// </summary>
    [JsonPropertyName("options")]
    public Dictionary<string, object?> Options { get; set; } = new();
}

/// <summary>
/// Represents a chat message in Ollama API responses.
/// Contains role and content fields for received messages.
/// </summary>
public sealed class OllamaChatMessage
{
    /// <summary>
    /// The role of the message sender in the response (e.g., "assistant").
    /// </summary>
    [JsonPropertyName("role")]
    public string? Role { get; set; }

    /// <summary>
    /// The content text of the response message.
    /// Contains the LLM's generated text.
    /// </summary>
    [JsonPropertyName("content")]
    public string? Content { get; set; }
}

/// <summary>
/// Represents a response from the Ollama chat API.
/// Contains the generated message and optional performance metrics.
/// </summary>
public sealed class OllamaChatResponse
{
    /// <summary>
    /// The model name that generated this response.
    /// Useful for tracking which model was used.
    /// </summary>
    [JsonPropertyName("model")]
    public string? Model { get; set; }

    /// <summary>
    /// ISO 8601 timestamp indicating when the response was created.
    /// </summary>
    [JsonPropertyName("created_at")]
    public string? CreatedAt { get; set; }

    /// <summary>
    /// The generated message from the LLM.
    /// Contains role and content fields with the response text.
    /// </summary>
    [JsonPropertyName("message")]
    public OllamaChatMessage? Message { get; set; }

    /// <summary>
    /// Indicates whether the response generation is complete.
    /// True when the full response has been received.
    /// </summary>
    [JsonPropertyName("done")]
    public bool Done { get; set; }

    /// <summary>
    /// Total duration of the inference in nanoseconds.
    /// Includes both prompt evaluation and generation time.
    /// </summary>
    [JsonPropertyName("total_duration")]
    public long? TotalDuration { get; set; }

    /// <summary>
    /// Duration spent loading the model into memory in nanoseconds.
    /// Only relevant for the first request or when model changes.
    /// </summary>
    [JsonPropertyName("load_duration")]
    public long? LoadDuration { get; set; }

    /// <summary>
    /// Number of tokens in the prompt that were evaluated.
    /// Useful for understanding input size and context window usage.
    /// </summary>
    [JsonPropertyName("prompt_eval_count")]
    public int? PromptEvalCount { get; set; }

    /// <summary>
    /// Duration spent evaluating the prompt tokens in nanoseconds.
    /// Part of the total inference time.
    /// </summary>
    [JsonPropertyName("prompt_eval_duration")]
    public long? PromptEvalDuration { get; set; }

    /// <summary>
    /// Number of tokens generated in the response.
    /// Indicates the length of the LLM's output.
    /// </summary>
    [JsonPropertyName("eval_count")]
    public int? EvalCount { get; set; }

    /// <summary>
    /// Duration spent generating the response tokens in nanoseconds.
    /// Part of the total inference time.
    /// </summary>
    [JsonPropertyName("eval_duration")]
    public long? EvalDuration { get; set; }
}

/// <summary>
/// Represents a simplified LLM response with text content and metadata.
/// Provides a convenient wrapper for extracted response data.
/// </summary>
/// <param name="Text">The extracted text content from the LLM response.</param>
/// <param name="RawBody">The complete raw JSON body from the API response (optional).</param>
/// <param name="Success">Indicates whether the LLM call was successful.</param>
public sealed record LlmResponse(string Text, string RawBody = "", bool Success = true);
