using System.Net.Http.Json;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class LlmClient
{
    private static readonly int RequestTimeoutSeconds = GetTimeoutSeconds();

    private readonly HttpClient _http;
    private readonly string _model;

    public Action<string>? DiagnosticTrace { get; set; }

    public LlmClient(string model)
    {
        _model = model;
        _http = new HttpClient
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    public virtual async Task<LlmResponse> GenerateAsync(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return new LlmResponse("");

        var payload = new
        {
            model = _model,
            prompt = prompt,
            stream = false
        };

        HttpResponseMessage response;
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(RequestTimeoutSeconds));

        try
        {
            response = await _http.PostAsJsonAsync(
                "http://localhost:11434/api/generate",
                payload,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase },
                cts.Token);
            Trace($"HTTP status={(int)response.StatusCode} ({response.StatusCode})");
        }
        catch (OperationCanceledException)
        {
            Trace($"Request timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse($"LLM request timed out after {RequestTimeoutSeconds} seconds.");
        }
        catch (Exception ex)
        {
            Trace($"Request failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM request failed: {ex.Message}");
        }

        if (!response.IsSuccessStatusCode)
        {
            string err;
            try
            {
                err = await response.Content.ReadAsStringAsync(cts.Token);
                Trace($"Non-success body length={err.Length}");
            }
            catch (OperationCanceledException)
            {
                err = "(error body read timed out)";
                Trace("Non-success body read timed out");
            }

            return new LlmResponse($"LLM error: {response.StatusCode} - {err}");
        }

        try
        {
            var body = await response.Content.ReadAsStringAsync(cts.Token);
            Trace($"Success body length={body.Length}");

            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(body);
            }
            catch (JsonException jsonEx)
            {
                Trace($"JSON parse failed: {jsonEx.Message}");
                return new LlmResponse($"LLM response parse failed: {jsonEx.Message}");
            }

            using (doc)
            {
                if (!doc.RootElement.TryGetProperty("response", out var responseElement))
                {
                    Trace("JSON parsed but missing 'response' field");
                    return new LlmResponse("");
                }

                if (responseElement.ValueKind != JsonValueKind.String)
                {
                    Trace($"JSON parsed but 'response' field is non-string ({responseElement.ValueKind})");
                    return new LlmResponse("");
                }

                var responseText = responseElement.GetString() ?? "";
                Trace($"Parsed 'response' length={responseText.Length}");
                return new LlmResponse(responseText);
            }
        }
        catch (OperationCanceledException)
        {
            Trace($"Response read timeout after {RequestTimeoutSeconds}s");
            return new LlmResponse($"LLM response read timed out after {RequestTimeoutSeconds} seconds.");
        }
        catch (Exception ex)
        {
            Trace($"Response handling failed: {ex.GetType().Name}: {ex.Message}");
            return new LlmResponse($"LLM response parse failed: {ex.Message}");
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
        {
            return Math.Clamp(parsed, minSeconds, maxSeconds);
        }

        return defaultSeconds;
    }
}

public record LlmResponse(string Text);

public class OllamaResponse
{
    public string? Model { get; set; }
    public string? CreatedAt { get; set; }
    public string? Response { get; set; }
    public bool Done { get; set; }
    public int? TotalDuration { get; set; }
    public int? LoadDuration { get; set; }
    public int? PromptEvalCount { get; set; }
    public int? PromptEvalDuration { get; set; }
    public int? EvalCount { get; set; }
    public int? EvalDuration { get; set; }
}
