// LlmClient.cs - Ollama LLM Client for TechToolbox Agent
// Provides communication with local Ollama instance for AI decision generation.

using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Client for communicating with a local Ollama LLM instance.
/// Handles request formatting, timeout management, and response parsing.
/// </summary>
public class LlmClient
{
    // Request timeout in seconds (configurable via environment variable)
    private static readonly int RequestTimeoutSeconds = GetTimeoutSeconds();
    
    // Maximum tokens to predict (configurable via environment variable)
    private static readonly int NumPredict = GetNumPredict();
    
    // HTTP client for Ollama API calls
    private readonly HttpClient _http;
    
    // Model name to use for LLM requests
    private readonly string _model;

    // JSON serialization options with case-insensitive property matching
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Optional callback for diagnostic tracing of LLM operations.
    /// </summary>
    public Action<string>? DiagnosticTrace { get; set; }

    /// <summary>
    /// Initializes a new instance of the LlmClient with the specified model.
    /// </summary>
    /// <param name="model">The Ollama model name to use.</param>
    public LlmClient(string model)
    {
        _model = model;
        _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <summary>
    /// Generates a decision from the LLM based on the provided chat messages.
    /// Sends a non-streaming chat request to Ollama and parses the JSON response.
    /// </summary>
    /// <param name="messages">The conversation history as chat messages.</param>
    /// <param name="cancellationToken">Token for cancelling the operation.</param>
    /// <returns>An LlmResponse containing the LLM's output or error information.</returns>
    public virtual async Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default
    )
    {
        // Return empty response if no messages provided
        if (messages is null || messages.Count == 0)
            return new LlmResponse("", "", false);

        // Build the Ollama chat request payload with model, messages, and options
        var payload = new OllamaChatRequest
        {
            Model = _model,
            Messages = messages.ToList(),
            Stream = false,
            Think = false,
            Format = "json",
            Options = new Dictionary<string, object?>
            {
                ["temperature"] = 0.2,
                ["top_p"] = 0.9,
                ["repeat_penalty"] = 1.05,
                ["num_predict"] = NumPredict,
            },
        };

        // Create linked cancellation token with timeout
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(RequestTimeoutSeconds));

        HttpResponseMessage response;
        try
        {
            // Send POST request to Ollama chat API endpoint
            response = await _http.PostAsJsonAsync(
                "http://localhost:11434/api/chat",
                payload,
                JsonOptions,
                cts.Token
            );

            Trace($"HTTP status={(int)response.StatusCode} ({response.StatusCode})");
        }
        catch (OperationCanceledException)
        {
            // Handle request timeout
            Trace($"Request timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse(
                $"LLM request timed out after {RequestTimeoutSeconds} seconds.",
                "",
                false
            );
        }
        catch (Exception ex)
        {
            // Handle general request failures
            Trace($"Request failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM request failed: {ex.Message}", "", false);
        }

        string body;
        try
        {
            // Read the response body content
            body = await response.Content.ReadAsStringAsync(cts.Token);
            Trace($"Body length={body.Length}");
        }
        catch (OperationCanceledException)
        {
            // Handle response read timeout
            Trace($"Response read timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse(
                $"LLM response read timed out after {RequestTimeoutSeconds} seconds.",
                "",
                false
            );
        }
        catch (Exception ex)
        {
            // Handle response read failures
            Trace($"Response read failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM response read failed: {ex.Message}", "", false);
        }

        // Check for HTTP error status codes
        if (!response.IsSuccessStatusCode)
        {
            return new LlmResponse($"LLM error: {response.StatusCode} - {body}", body, false);
        }

        try
        {
            // Deserialize and parse the JSON response
            var parsed = JsonSerializer.Deserialize<OllamaChatResponse>(body, JsonOptions);
            var content = parsed?.Message?.Content ?? "";
            Trace($"Parsed content length={content.Length}");

            // Handle empty content case with diagnostic information
            if (string.IsNullOrWhiteSpace(content))
            {
                var emptyContentDiagnostics = BuildEmptyContentDiagnostics(body);
                Trace($"Parsed content was empty. {emptyContentDiagnostics}");
                return new LlmResponse(
                    $"LLM returned empty content. {emptyContentDiagnostics}",
                    body,
                    false
                );
            }

            // Return successful response with parsed content
            return new LlmResponse(content, body, true);
        }
        catch (Exception ex)
        {
            // Handle JSON parsing failures
            Trace($"JSON parse failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM response parse failed: {ex.Message}", body, false);
        }
    }

    /// <summary>
    /// Invokes the diagnostic trace callback with the given message.
    /// Safely handles exceptions to prevent tracing from breaking LLM calls.
    /// </summary>
    /// <param name="message">The diagnostic message to trace.</param>
    private void Trace(string message)
    {
        try
        {
            DiagnosticTrace?.Invoke(message);
        }
        catch
        {
            // Diagnostic tracing must never break LLM calls.
        }
    }

    /// <summary>
    /// Gets the request timeout in seconds from environment variable or default value.
    /// Clamps the value between 15 and 600 seconds.
    /// </summary>
    /// <returns>The timeout in seconds.</returns>
    private static int GetTimeoutSeconds()
    {
        const int defaultSeconds = 180;
        const int minSeconds = 15;
        const int maxSeconds = 600;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_LLM_TIMEOUT_SECONDS");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minSeconds, maxSeconds);

        return defaultSeconds;
    }

    /// <summary>
    /// Gets the num_predict value from environment variable or default value.
    /// Supports Ollama sentinel values (-1 for infinite, -2 for fill context).
    /// Clamps valid values between 128 and 16384 tokens.
    /// </summary>
    /// <returns>The num_predict value.</returns>
    private static int GetNumPredict()
    {
        const int defaultNumPredict = 4096;
        const int minNumPredict = 128;
        const int maxNumPredict = 16384;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_LLM_NUM_PREDICT");
        if (int.TryParse(raw, out var parsed))
        {
            // Ollama sentinels: -1 = infinite, -2 = fill context. Pass through unchanged.
            if (parsed < 0)
                return parsed;
            return Math.Clamp(parsed, minNumPredict, maxNumPredict);
        }

        return defaultNumPredict;
    }

    /// <summary>
    /// Creates a truncated preview of text for diagnostic purposes.
    /// Replaces newlines and carriage returns with spaces.
    /// </summary>
    /// <param name="text">The text to preview.</param>
    /// <returns>A truncated string (max 240 characters) or "(empty)" if null/whitespace.</returns>
    private static string Preview(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "(empty)";

        var normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return normalized.Length <= 240 ? normalized : normalized[..240];
    }

    /// <summary>
    /// Builds diagnostic information when LLM returns empty content.
    /// Parses the response body to extract relevant Ollama fields for debugging.
    /// </summary>
    /// <param name="body">The raw response body.</param>
    /// <returns>A string containing diagnostic information about the empty response.</returns>
    private static string BuildEmptyContentDiagnostics(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "Body was empty.";

        try
        {
            // Parse JSON and extract diagnostic fields
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var sb = new StringBuilder();

            if (
                root.TryGetProperty("done_reason", out var doneReason)
                && doneReason.ValueKind == JsonValueKind.String
            )
                sb.Append($"done_reason={doneReason.GetString()}; ");

            if (
                root.TryGetProperty("done", out var done)
                && (done.ValueKind == JsonValueKind.True || done.ValueKind == JsonValueKind.False)
            )
                sb.Append($"done={done.GetBoolean()}; ");

            if (
                root.TryGetProperty("eval_count", out var evalCount)
                && evalCount.ValueKind == JsonValueKind.Number
            )
                sb.Append($"eval_count={evalCount.GetInt32()}; ");

            if (
                root.TryGetProperty("prompt_eval_count", out var promptEvalCount)
                && promptEvalCount.ValueKind == JsonValueKind.Number
            )
                sb.Append($"prompt_eval_count={promptEvalCount.GetInt32()}; ");

            if (
                root.TryGetProperty("message", out var message)
                && message.ValueKind == JsonValueKind.Object
            )
            {
                if (
                    message.TryGetProperty("role", out var role)
                    && role.ValueKind == JsonValueKind.String
                )
                    sb.Append($"message_role={role.GetString()}; ");

                if (
                    message.TryGetProperty("content", out var messageContent)
                    && messageContent.ValueKind == JsonValueKind.String
                )
                    sb.Append(
                        $"message_content_length={messageContent.GetString()?.Length ?? 0}; "
                    );

                if (
                    message.TryGetProperty("thinking", out var thinking)
                    && thinking.ValueKind == JsonValueKind.String
                )
                    sb.Append($"thinking_length={thinking.GetString()?.Length ?? 0}; ");
            }

            sb.Append($"body_preview={Preview(body)}");
            return sb.ToString().Trim();
        }
        catch
        {
            // Fallback if JSON parsing fails
            return $"Body preview: {Preview(body)}";
        }
    }
}
