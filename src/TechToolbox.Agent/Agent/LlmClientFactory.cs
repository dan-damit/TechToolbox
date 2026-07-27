namespace TechToolbox.Agent.Agent;

/// <summary>
/// Creates LLM client implementations from agent configuration.
/// </summary>
public static class LlmClientFactory
{
    /// <summary>
    /// Creates an <see cref="ILlmClient"/> from the supplied configuration.
    /// </summary>
    /// <param name="config">Agent configuration.</param>
    /// <returns>A provider-specific LLM client.</returns>
    public static ILlmClient Create(Configuration.AgentConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var provider = NormalizeProvider(config.LlmProvider);

        return provider switch
        {
            "ollama" => new LlmClient(config.Model),
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
