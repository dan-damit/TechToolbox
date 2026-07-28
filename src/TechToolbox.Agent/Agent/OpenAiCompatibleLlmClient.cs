using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// LLM client for OpenAI-compatible chat completion APIs, including Azure OpenAI.
/// </summary>
public sealed class OpenAiCompatibleLlmClient : ILlmClient
{
    private enum OpenAiApiStyle
    {
        ChatCompletions,
        Responses,
    }

    private static readonly int RequestTimeoutSeconds = GetTimeoutSeconds();
    private static readonly int MaxOutputTokens = GetMaxOutputTokens();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _http;
    private readonly string _provider;
    private readonly string _model;
    private readonly string? _endpoint;
    private readonly string? _deployment;
    private readonly string _apiVersion;

    /// <summary>
    /// Optional callback for diagnostic tracing of LLM operations.
    /// </summary>
    public Action<string>? DiagnosticTrace { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="OpenAiCompatibleLlmClient"/> class.
    /// </summary>
    public OpenAiCompatibleLlmClient(
        string provider,
        string model,
        string? endpoint,
        string? deployment,
        string? apiVersion
    )
    {
        _provider = NormalizeProvider(provider);
        _model = model ?? string.Empty;
        _endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint;
        _deployment = string.IsNullOrWhiteSpace(deployment) ? null : deployment;
        _apiVersion = string.IsNullOrWhiteSpace(apiVersion) ? "2024-10-21" : apiVersion;
        _http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    }

    /// <inheritdoc/>
    public async Task<LlmResponse> GenerateDecisionWithCallbackAsync(
        IReadOnlyList<AgentChatMessage> messages,
        Func<string, Task<bool>>? onContentAccumulated = null,
        CancellationToken cancellationToken = default
    )
    {
        if (messages is null || messages.Count == 0)
            return new LlmResponse("", "", false);

        var apiKey = Environment.GetEnvironmentVariable("TT_AGENT_LLM_API_KEY");
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return new LlmResponse(
                "LLM request failed: TT_AGENT_LLM_API_KEY is not set for cloud provider.",
                "",
                false
            );
        }

        var apiStyle = OpenAiApiStyle.ChatCompletions;

        string requestUrl;
        try
        {
            requestUrl = BuildRequestUrl(apiStyle);
        }
        catch (Exception ex)
        {
            return new LlmResponse($"LLM request failed: {ex.Message}", "", false);
        }

        var attempt = await SendRequestAsync(
            messages,
            apiKey,
            requestUrl,
            apiStyle,
            cancellationToken
        ).ConfigureAwait(false);

        if (!attempt.Success && ShouldFallbackToResponsesEndpoint(attempt.ErrorBody))
        {
            apiStyle = OpenAiApiStyle.Responses;

            try
            {
                requestUrl = BuildRequestUrl(apiStyle);
            }
            catch (Exception ex)
            {
                return new LlmResponse($"LLM request failed: {ex.Message}", "", false);
            }

            Trace($"Retrying request via OpenAI responses endpoint url={requestUrl}");

            attempt = await SendRequestAsync(
                messages,
                apiKey,
                requestUrl,
                apiStyle,
                cancellationToken
            ).ConfigureAwait(false);
        }

        if (!attempt.Success)
        {
            if (!string.IsNullOrWhiteSpace(attempt.ErrorMessage))
                return new LlmResponse(attempt.ErrorMessage, attempt.RawBody ?? string.Empty, false);

            return new LlmResponse("LLM request failed with unknown error.", attempt.RawBody ?? string.Empty, false);
        }

        var content = ExtractContent(attempt.RawBody ?? string.Empty, apiStyle);
        if (string.IsNullOrWhiteSpace(content))
            return new LlmResponse("LLM returned empty content.", attempt.RawBody ?? string.Empty, false);

        content = content.Trim();
        if (onContentAccumulated is not null)
            _ = await onContentAccumulated(content).ConfigureAwait(false);

        return new LlmResponse(content, attempt.RawBody ?? string.Empty, true);
    }

    /// <inheritdoc/>
    public Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default
    ) => GenerateDecisionWithCallbackAsync(messages, null, cancellationToken);

    private object BuildPayload(IReadOnlyList<AgentChatMessage> messages, OpenAiApiStyle apiStyle)
    {
        if (IsAzureProvider())
        {
            return new
            {
                messages,
                temperature = 0.2,
                top_p = 0.9,
                stream = false,
                response_format = new { type = "json_object" },
                max_tokens = MaxOutputTokens,
            };
        }

        if (apiStyle == OpenAiApiStyle.Responses)
        {
            return new
            {
                model = _model,
                input = messages.Select(m => new
                {
                    role = NormalizeResponseRole(m.Role),
                    content = m.Content,
                }),
                temperature = 0.2,
                top_p = 0.9,
                max_output_tokens = MaxOutputTokens,
                text = new
                {
                    format = new
                    {
                        type = "json_object",
                    },
                },
            };
        }

        return new
        {
            model = _model,
            messages,
            temperature = 0.2,
            top_p = 0.9,
            stream = false,
            response_format = new { type = "json_object" },
            max_tokens = MaxOutputTokens,
        };
    }

    private string BuildRequestUrl(OpenAiApiStyle apiStyle)
    {
        if (IsAzureProvider())
        {
            if (string.IsNullOrWhiteSpace(_endpoint))
                throw new InvalidOperationException(
                    "Azure OpenAI provider requires a non-empty endpoint."
                );

            if (string.IsNullOrWhiteSpace(_deployment))
                throw new InvalidOperationException(
                    "Azure OpenAI provider requires a non-empty deployment name."
                );

            var baseEndpoint = _endpoint!.TrimEnd('/');
            return $"{baseEndpoint}/openai/deployments/{_deployment}/chat/completions?api-version={_apiVersion}";
        }

        if (!string.IsNullOrWhiteSpace(_endpoint))
            return BuildNonAzureEndpointUrl(_endpoint!, apiStyle);

        return apiStyle == OpenAiApiStyle.Responses
            ? "https://api.openai.com/v1/responses"
            : "https://api.openai.com/v1/chat/completions";
    }

    private bool IsAzureProvider()
    {
        return _provider.Equals("azure-openai", StringComparison.Ordinal)
            || _provider.Equals("azure_openai", StringComparison.Ordinal)
            || _provider.Equals("azureopenai", StringComparison.Ordinal);
    }

    private static string NormalizeProvider(string provider)
    {
        return string.IsNullOrWhiteSpace(provider) ? "openai" : provider.Trim().ToLowerInvariant();
    }

    private static string ExtractContent(string rawBody, OpenAiApiStyle apiStyle)
    {
        if (string.IsNullOrWhiteSpace(rawBody))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawBody);
            var root = doc.RootElement;

            if (apiStyle == OpenAiApiStyle.Responses)
            {
                var extracted = ExtractResponsesContent(root);
                if (!string.IsNullOrWhiteSpace(extracted))
                    return extracted;
            }

            if (!root.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array)
                return string.Empty;

            foreach (var choice in choices.EnumerateArray())
            {
                if (!choice.TryGetProperty("message", out var message))
                    continue;

                if (!message.TryGetProperty("content", out var contentElement))
                    continue;

                switch (contentElement.ValueKind)
                {
                    case JsonValueKind.String:
                        return contentElement.GetString() ?? string.Empty;

                    case JsonValueKind.Array:
                    {
                        var sb = new StringBuilder();
                        foreach (var item in contentElement.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.Object)
                            {
                                if (
                                    item.TryGetProperty("text", out var text)
                                    && text.ValueKind == JsonValueKind.String
                                )
                                {
                                    sb.Append(text.GetString());
                                }
                            }
                        }

                        return sb.ToString();
                    }
                }
            }
        }
        catch
        {
            return string.Empty;
        }

        return string.Empty;
    }

    private static string ExtractResponsesContent(JsonElement root)
    {
        if (
            root.TryGetProperty("output_text", out var outputText)
            && outputText.ValueKind == JsonValueKind.String
        )
        {
            return outputText.GetString() ?? string.Empty;
        }

        if (
            root.TryGetProperty("output", out var output)
            && output.ValueKind == JsonValueKind.Array
        )
        {
            var sb = new StringBuilder();

            foreach (var outputItem in output.EnumerateArray())
            {
                if (
                    !outputItem.TryGetProperty("content", out var content)
                    || content.ValueKind != JsonValueKind.Array
                )
                {
                    continue;
                }

                foreach (var part in content.EnumerateArray())
                {
                    if (
                        part.TryGetProperty("text", out var text)
                        && text.ValueKind == JsonValueKind.String
                    )
                    {
                        sb.Append(text.GetString());
                    }
                }
            }

            return sb.ToString();
        }

        return string.Empty;
    }

    private bool ShouldFallbackToResponsesEndpoint(string? rawBody)
    {
        if (IsAzureProvider())
            return false;

        if (!_provider.Equals("openai", StringComparison.Ordinal))
            return false;

        if (string.IsNullOrWhiteSpace(rawBody))
            return false;

        return rawBody.Contains("v1/responses endpoint", StringComparison.OrdinalIgnoreCase)
            || rawBody.Contains("not supported in the v1/chat/completions", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeResponseRole(string? role)
    {
        if (string.IsNullOrWhiteSpace(role))
            return "user";

        return role.Trim().ToLowerInvariant() switch
        {
            "system" => "system",
            "assistant" => "assistant",
            "user" => "user",
            _ => "user",
        };
    }

    private static string BuildNonAzureEndpointUrl(string endpoint, OpenAiApiStyle apiStyle)
    {
        var normalizedEndpoint = endpoint.Trim();
        var suffix = apiStyle == OpenAiApiStyle.Responses
            ? "/v1/responses"
            : "/v1/chat/completions";

        if (
            normalizedEndpoint.EndsWith("/v1/chat/completions", StringComparison.OrdinalIgnoreCase)
            || normalizedEndpoint.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase)
        )
        {
            return apiStyle == OpenAiApiStyle.Responses
                ? normalizedEndpoint[..normalizedEndpoint.LastIndexOf("/chat/completions", StringComparison.OrdinalIgnoreCase)] + "/responses"
                : normalizedEndpoint;
        }

        if (
            normalizedEndpoint.EndsWith("/v1/responses", StringComparison.OrdinalIgnoreCase)
            || normalizedEndpoint.EndsWith("/responses", StringComparison.OrdinalIgnoreCase)
        )
        {
            return apiStyle == OpenAiApiStyle.ChatCompletions
                ? normalizedEndpoint[..normalizedEndpoint.LastIndexOf("/responses", StringComparison.OrdinalIgnoreCase)] + "/chat/completions"
                : normalizedEndpoint;
        }

        if (!Uri.TryCreate(normalizedEndpoint, UriKind.Absolute, out var absoluteUri))
            return normalizedEndpoint;

        var path = absoluteUri.AbsolutePath;
        if (string.IsNullOrWhiteSpace(path) || path == "/")
        {
            return normalizedEndpoint.TrimEnd('/') + suffix;
        }

        return normalizedEndpoint;
    }

    private async Task<RequestAttemptResult> SendRequestAsync(
        IReadOnlyList<AgentChatMessage> messages,
        string apiKey,
        string requestUrl,
        OpenAiApiStyle apiStyle,
        CancellationToken cancellationToken
    )
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, requestUrl);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        if (IsAzureProvider())
            request.Headers.Add("api-key", apiKey);
        else
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        var payload = BuildPayload(messages, apiStyle);
        request.Content = JsonContent.Create(payload, options: JsonOptions);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(RequestTimeoutSeconds));

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cts.Token).ConfigureAwait(false);
            Trace($"HTTP status={(int)response.StatusCode} ({response.StatusCode}) url={requestUrl}");
        }
        catch (OperationCanceledException)
        {
            return new RequestAttemptResult(
                Success: false,
                RawBody: string.Empty,
                ErrorBody: string.Empty,
                ErrorMessage: $"LLM request timed out after {RequestTimeoutSeconds} seconds."
            );
        }
        catch (Exception ex)
        {
            return new RequestAttemptResult(
                Success: false,
                RawBody: string.Empty,
                ErrorBody: string.Empty,
                ErrorMessage: $"LLM request failed: {ex.Message}"
            );
        }

        string rawBody;
        try
        {
            rawBody = await response.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new RequestAttemptResult(
                Success: false,
                RawBody: string.Empty,
                ErrorBody: string.Empty,
                ErrorMessage: $"LLM response read timed out: {ex.Message}"
            );
        }

        if (!response.IsSuccessStatusCode)
        {
            return new RequestAttemptResult(
                Success: false,
                RawBody: rawBody,
                ErrorBody: rawBody,
                ErrorMessage: $"LLM error: {response.StatusCode} - {rawBody}"
            );
        }

        return new RequestAttemptResult(
            Success: true,
            RawBody: rawBody,
            ErrorBody: null,
            ErrorMessage: null
        );
    }

    private sealed record RequestAttemptResult(
        bool Success,
        string? RawBody,
        string? ErrorBody,
        string? ErrorMessage
    );

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

    private static int GetMaxOutputTokens()
    {
        const int defaultTokens = 4096;
        const int minTokens = 128;
        const int maxTokens = 16384;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_LLM_MAX_OUTPUT_TOKENS");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minTokens, maxTokens);

        return defaultTokens;
    }
}
