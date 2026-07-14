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
    /// Generates a decision from the LLM with incremental callback support.
    /// Streams content to a callback for early decision validation and completion.
    /// </summary>
    /// <param name="messages">The conversation history as chat messages.</param>
    /// <param name="onContentAccumulated">Callback invoked with accumulated content. Return true to stop streaming early.</param>
    /// <param name="cancellationToken">Token for cancelling the operation.</param>
    /// <returns>An LlmResponse containing the accumulated LLM output or error information.</returns>
    public virtual async Task<LlmResponse> GenerateDecisionWithCallbackAsync(
        IReadOnlyList<AgentChatMessage> messages,
        Func<string, Task<bool>>? onContentAccumulated = null,
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
            Stream = true,
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
            // Send POST request to Ollama chat API endpoint with streaming enabled
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

        // Check for HTTP error status codes
        if (!response.IsSuccessStatusCode)
        {
            try
            {
                var errorBody = await response.Content.ReadAsStringAsync(cts.Token);
                return new LlmResponse($"LLM error: {response.StatusCode} - {errorBody}", errorBody, false);
            }
            catch
            {
                return new LlmResponse($"LLM error: {response.StatusCode}", "", false);
            }
        }

        // Accumulate streamed content from newline-delimited JSON
        var accumulatedContent = new StringBuilder();
        var lastRawLine = "";
        var stoppedEarly = false;

        try
        {
            // Read streaming response line by line
            using var stream = await response.Content.ReadAsStreamAsync();
            using var reader = new StreamReader(stream);

            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                // Skip empty lines
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                lastRawLine = line;
                Trace($"Received stream line length={line.Length}");

                try
                {
                    // Parse each newline-delimited JSON object
                    var parsed = JsonSerializer.Deserialize<OllamaChatResponse>(line, JsonOptions);
                    
                    // Accumulate content from message
                    if (parsed?.Message?.Content is not null)
                    {
                        accumulatedContent.Append(parsed.Message.Content);
                        Trace($"Accumulated content length={accumulatedContent.Length}");

                        // Invoke callback with current accumulated content
                        if (onContentAccumulated is not null)
                        {
                            var shouldStop = await onContentAccumulated(accumulatedContent.ToString());
                            if (shouldStop)
                            {
                                Trace($"Early stop requested by callback at content length={accumulatedContent.Length}");
                                stoppedEarly = true;
                                break;
                            }
                        }
                    }

                    // Check if this is the final chunk
                    if (parsed?.Done == true)
                    {
                        Trace($"Stream complete. Total content length={accumulatedContent.Length}");
                        break;
                    }
                }
                catch (JsonException ex)
                {
                    // Log parse error but continue streaming
                    Trace($"Failed to parse stream line: {ex.Message}");
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Handle stream timeout
            Trace($"Stream timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse(
                $"LLM stream timed out after {RequestTimeoutSeconds} seconds.",
                lastRawLine,
                false
            );
        }
        catch (Exception ex)
        {
            // Handle stream read failures
            Trace($"Stream read failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM stream read failed: {ex.Message}", lastRawLine, false);
        }

        var content = accumulatedContent.ToString().Trim();

        // Handle empty content case with diagnostic information
        if (string.IsNullOrWhiteSpace(content))
        {
            var emptyContentDiagnostics = BuildEmptyContentDiagnostics(lastRawLine);
            Trace($"Accumulated content was empty. {emptyContentDiagnostics}");
            return new LlmResponse(
                $"LLM returned empty content. {emptyContentDiagnostics}",
                lastRawLine,
                false
            );
        }

        // Return successful response with accumulated streamed content
        return new LlmResponse(content, lastRawLine, stoppedEarly);
    }

    /// <summary>
    /// Generates a decision from the LLM based on the provided chat messages.
    /// Uses streaming to incrementally receive the response and accumulates the content.
    /// </summary>
    /// <param name="messages">The conversation history as chat messages.</param>
    /// <param name="cancellationToken">Token for cancelling the operation.</param>
    /// <returns>An LlmResponse containing the accumulated LLM output or error information.</returns>
    public virtual async Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default
    ) => await GenerateDecisionWithCallbackAsync(messages, null, cancellationToken);

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
