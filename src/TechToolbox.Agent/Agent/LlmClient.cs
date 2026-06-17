using System.Net.Http.Json;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class LlmClient
{
    private static readonly int RequestTimeoutSeconds = GetTimeoutSeconds();
    private readonly HttpClient _http;
    private readonly string _model;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public Action<string>? DiagnosticTrace { get; set; }

    public LlmClient(string model)
    {
        _model = model;
        _http = new HttpClient
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    public virtual async Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default)
    {
        if (messages is null || messages.Count == 0)
            return new LlmResponse("", "", false);

        var payload = new OllamaChatRequest
        {
            Model = _model,
            Messages = messages.ToList(),
            Stream = false,
            Format = "json",
            Options = new Dictionary<string, object?>
            {
                ["temperature"] = 0.2,
                ["top_p"] = 0.9,
                ["repeat_penalty"] = 1.05,
                ["num_predict"] = 1024
            }
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
                cts.Token);

            Trace($"HTTP status={(int)response.StatusCode} ({response.StatusCode})");
        }
        catch (OperationCanceledException)
        {
            Trace($"Request timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse($"LLM request timed out after {RequestTimeoutSeconds} seconds.", "", false);
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
            return new LlmResponse($"LLM response read timed out after {RequestTimeoutSeconds} seconds.", "", false);
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
}