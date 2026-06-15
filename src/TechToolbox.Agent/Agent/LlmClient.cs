using System.Net.Http.Json;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

public class LlmClient
{
    private readonly HttpClient _http;
    private readonly string _model;

    public LlmClient(string model)
    {
        _model = model;
        _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(120)
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
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(90));

        try
        {
            response = await _http.PostAsJsonAsync(
                "http://localhost:11434/api/generate",
                payload,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
            return new LlmResponse("LLM request timed out after 90 seconds.");
        }
        catch (Exception ex)
        {
            return new LlmResponse($"LLM request failed: {ex.Message}");
        }

        if (!response.IsSuccessStatusCode)
        {
            string err;
            try
            {
                err = await response.Content.ReadAsStringAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                err = "(error body read timed out)";
            }

            return new LlmResponse($"LLM error: {response.StatusCode} - {err}");
        }

        try
        {
            var body = await response.Content.ReadAsStringAsync(cts.Token);
            var json = JsonSerializer.Deserialize<OllamaResponse>(body);
            return new LlmResponse(json?.Response ?? "");
        }
        catch (OperationCanceledException)
        {
            return new LlmResponse("LLM response read timed out after 90 seconds.");
        }
        catch (Exception ex)
        {
            return new LlmResponse($"LLM response parse failed: {ex.Message}");
        }
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
