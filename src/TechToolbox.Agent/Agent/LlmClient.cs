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

        try
        {
            response = await _http.PostAsJsonAsync(
                "http://localhost:11434/api/generate",
                payload,
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }
        catch (Exception ex)
        {
            return new LlmResponse($"LLM request failed: {ex.Message}");
        }

        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync();
            return new LlmResponse($"LLM error: {response.StatusCode} - {err}");
        }

        var json = await response.Content.ReadFromJsonAsync<OllamaResponse>();
        return new LlmResponse(json?.Response ?? "");
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
