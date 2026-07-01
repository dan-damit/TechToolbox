using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class LlmClient
{
    private static readonly int RequestTimeoutSeconds = GetTimeoutSeconds();
    private static readonly int NumPredict = GetNumPredict();
    private readonly HttpClient _http;
    private readonly string _model;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public Action<string>? DiagnosticTrace { get; set; }

    public LlmClient(string model)
    {
        _model = model;
        _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    }

    public virtual async Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default
    )
    {
        if (messages is null || messages.Count == 0)
            return new LlmResponse("", "", false);

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

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(RequestTimeoutSeconds));

        HttpResponseMessage response;
        try
        {
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
            Trace($"Request timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse(
                $"LLM request timed out after {RequestTimeoutSeconds} seconds.",
                "",
                false
            );
        }
        catch (Exception ex)
        {
            Trace($"Request failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM request failed: {ex.Message}", "", false);
        }

        string body;
        try
        {
            body = await response.Content.ReadAsStringAsync(cts.Token);
            Trace($"Body length={body.Length}");
        }
        catch (OperationCanceledException)
        {
            Trace($"Response read timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse(
                $"LLM response read timed out after {RequestTimeoutSeconds} seconds.",
                "",
                false
            );
        }
        catch (Exception ex)
        {
            Trace($"Response read failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM response read failed: {ex.Message}", "", false);
        }

        if (!response.IsSuccessStatusCode)
        {
            return new LlmResponse($"LLM error: {response.StatusCode} - {body}", body, false);
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<OllamaChatResponse>(body, JsonOptions);
            var content = parsed?.Message?.Content ?? "";
            Trace($"Parsed content length={content.Length}");

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

            return new LlmResponse(content, body, true);
        }
        catch (Exception ex)
        {
            Trace($"JSON parse failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM response parse failed: {ex.Message}", body, false);
        }
    }

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

    private static string Preview(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "(empty)";

        var normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return normalized.Length <= 240 ? normalized : normalized[..240];
    }

    private static string BuildEmptyContentDiagnostics(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return "Body was empty.";

        try
        {
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
            return $"Body preview: {Preview(body)}";
        }
    }
}
