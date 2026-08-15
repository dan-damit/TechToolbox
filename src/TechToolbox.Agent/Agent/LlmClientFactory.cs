namespace TechToolbox.Agent.Agent;

/// <summary>
/// Creates <see cref="ILlmClient"/> implementations from agent configuration values.
/// </summary>
public static class LlmClientFactory
{
    private const string DeepReasoningModel = "qwen3.8:27b";
    private const string FastModel = "qwen3.6:35b";

    /// <summary>
    /// Creates an <see cref="ILlmClient"/> instance based on the configured LLM provider.
    /// </summary>
    /// <param name="config">The agent configuration containing provider and model settings.</param>
    /// <returns>A provider-specific <see cref="ILlmClient"/> implementation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="config"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Thrown when the configured provider is unsupported.</exception>
    public static ILlmClient Create(Configuration.AgentConfiguration config, string? prompt = null)
    {
        ArgumentNullException.ThrowIfNull(config);

        var provider = NormalizeProvider(config.LlmProvider);
        var effectiveModel = ResolveEffectiveModel(config, prompt);

        return provider switch
        {
            "ollama" => new LlmClient(effectiveModel, ResolveThinkingEnabled(config)),
            "openai" =>
                CreateOpenAiCompatible(
                    provider,
                    effectiveModel,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            "openai-compatible" =>
                CreateOpenAiCompatible(
                    provider,
                    effectiveModel,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            "azure-openai" =>
                CreateOpenAiCompatible(
                    provider,
                    effectiveModel,
                    config.LlmEndpoint,
                    config.LlmDeployment,
                    config.LlmApiVersion
                ),
            _ => throw new InvalidOperationException(
                $"Unsupported LLM provider '{provider}'. Supported values: ollama, openai, openai-compatible, azure-openai."
            ),
        };
    }

    public static string SelectModelForPrompt(
        string? prompt,
        string executionMode = "execute",
        int preflightScore = 0,
        int toolCount = 0,
        string? explicitModel = null,
        bool enableAutoRouting = true,
        int routingThreshold = 50
    )
    {
        if (!string.IsNullOrWhiteSpace(explicitModel))
        {
            return explicitModel.Trim();
        }

        if (!enableAutoRouting)
        {
            return FastModel;
        }

        var normalizedPrompt = prompt ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedPrompt))
        {
            return FastModel;
        }

        var score = 0;
        var lower = normalizedPrompt.Trim();
        var tokens = lower.Split(
            (char[]?)null,
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
        );

        if (tokens.Length > 120)
            score += 20;
        if (tokens.Length > 220)
            score += 20;
        if (tokens.Length > 400)
            score += 15;

        if (lower.Contains("debug", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("diagnos", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("root cause", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("investigate", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("refactor", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("patch", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("fix", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("rewrite", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("migration", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("architecture", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("compare", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("tradeoff", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("failure", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("error", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("issue", StringComparison.OrdinalIgnoreCase))
        {
            score += 30;
        }

        if (lower.Contains("multiple files", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("across files", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("several files", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("file set", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("project", StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
        }

        if (lower.Contains("summarize", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("quick", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("simple", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("one paragraph", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("short answer", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("status", StringComparison.OrdinalIgnoreCase)
            || lower.Contains("what is", StringComparison.OrdinalIgnoreCase))
        {
            score -= 20;
        }

        if (toolCount > 0)
            score += 10;
        if (toolCount > 2)
            score += 15;

        if (preflightScore >= 65)
            score += 15;
        if (preflightScore >= 85)
            score += 15;

        if (string.Equals(executionMode, "plan", StringComparison.OrdinalIgnoreCase)
            || string.Equals(executionMode, "analyze", StringComparison.OrdinalIgnoreCase)
            || string.Equals(executionMode, "chat", StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
        }

        var effectiveThreshold = Math.Clamp(routingThreshold, 0, 100);
        return score >= effectiveThreshold ? DeepReasoningModel : FastModel;
    }

    private static string ResolveEffectiveModel(Configuration.AgentConfiguration config, string? prompt)
    {
        var configured = config.Model?.Trim();
        if (!string.IsNullOrWhiteSpace(configured)
            && !string.Equals(configured, "llama3", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(configured, "auto", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(configured, "default", StringComparison.OrdinalIgnoreCase))
        {
            return configured;
        }

        var resolvedThreshold = Math.Clamp(config.AutoModelRoutingThreshold, 0, 100);
        var selected = SelectModelForPrompt(
            prompt,
            config.ExecutionMode,
            config.PromptPreflightScore,
            config.ToolProviders?.Count ?? 0,
            enableAutoRouting: config.EnableAutoModelRouting,
            routingThreshold: resolvedThreshold
        );

        config.Model = selected;
        return selected;
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
            _ => string.Equals(config.ExecutionMode, "chat", StringComparison.OrdinalIgnoreCase)
                || string.Equals(config.ExecutionMode, "analyze", StringComparison.OrdinalIgnoreCase)
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
