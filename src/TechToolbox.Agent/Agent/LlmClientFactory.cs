namespace TechToolbox.Agent.Agent;

/// <summary>
/// Creates <see cref="ILlmClient"/> implementations from agent configuration values.
/// </summary>
public static class LlmClientFactory
{
    /// <summary>
    /// Creates an <see cref="ILlmClient"/> instance based on the configured LLM provider.
    /// </summary>
    /// <param name="config">The agent configuration containing provider and model settings.</param>
    /// <returns>A provider-specific <see cref="ILlmClient"/> implementation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="config"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the configured provider is unsupported.</exception>
    public static ILlmClient Create(Configuration.AgentConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var provider = NormalizeProvider(config.LlmProvider);

        return provider switch
        {
            "ollama" => new LlmClient(config.Model, ResolveThinkingEnabled(config)),
            "openai" =>
                CreateOpenAiCompatible(
                    provider,
                    config.Model,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            "openai-compatible" =>
                CreateOpenAiCompatible(
                    provider,
                    config.Model,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            "azure-openai" =>
                CreateOpenAiCompatible(
                    provider,
                    config.Model,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            _ => throw new InvalidOperationException(
                $"Unsupported LLM provider '{provider}'. Supported values: ollama, openai, openai-compatible, azure-openai."
            ),
        };
    }

    private static ILlmClient CreateOpenAiCompatible(
        string provider,
        string model,
        string? endpoint,
        string? deployment,
        string? apiVersion
    )
    {
        if (
            !provider.Equals("azure-openai", StringComparison.Ordinal)
            && string.IsNullOrWhiteSpace(model)
        )
        {
            throw new InvalidOperationException(
                "A non-empty model is required for openai/openai-compatible providers."
            );
        }

        return new OpenAiCompatibleLlmClient(provider, model, endpoint, deployment, apiVersion);
    }

    private static bool ResolveThinkingEnabled(Configuration.AgentConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config.ThinkingMode switch
        {
            "on" => true,
            "off" => false,
            _ => string.Equals(config.ExecutionMode, "analyze", StringComparison.OrdinalIgnoreCase)
                || string.Equals(config.ExecutionMode, "plan", StringComparison.OrdinalIgnoreCase),
        };
    }

    private static string NormalizeProvider(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
            return "ollama";

        var normalized = provider.Trim().ToLowerInvariant();
        return normalized switch
        {
            "azureopenai" => "azure-openai",
            "azure_openai" => "azure-openai",
            _ => normalized,
        };
    }
}
