namespace TechToolbox.Agent.Agent;

/// <summary>
/// Contract for LLM providers used by the agent orchestrator.
/// </summary>
public interface ILlmClient
{
    /// <summary>
    /// Optional callback for diagnostic tracing of LLM operations.
    /// </summary>
    Action<string>? DiagnosticTrace { get; set; }

    /// <summary>
    /// Configures reasoning-effort metadata for the next model calls.
    /// Providers that do not support reasoning effort may ignore these values.
    /// </summary>
    /// <param name="reasoningEffort">Effective reasoning effort (low, medium, high, xhigh), or <see langword="null"/>.</param>
    /// <param name="usedOverride"><see langword="true"/> when explicit override selected the value; otherwise <see langword="false"/>.</param>
    /// <param name="usedAuto"><see langword="true"/> when automatic policy selected the value; otherwise <see langword="false"/>.</param>
    void ConfigureReasoningEffort(string? reasoningEffort, bool usedOverride, bool usedAuto);

    /// <summary>
    /// Generates a decision from the LLM with optional incremental callback support.
    /// </summary>
    /// <param name="messages">The conversation history as chat messages.</param>
    /// <param name="onContentAccumulated">Callback invoked with accumulated content. Return true to stop early.</param>
    /// <param name="cancellationToken">Token for cancellation.</param>
    /// <returns>An <see cref="LlmResponse"/> with response text and metadata.</returns>
    Task<LlmResponse> GenerateDecisionWithCallbackAsync(
        IReadOnlyList<AgentChatMessage> messages,
        Func<string, Task<bool>>? onContentAccumulated = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Generates a decision from the LLM.
    /// </summary>
    /// <param name="messages">The conversation history as chat messages.</param>
    /// <param name="cancellationToken">Token for cancellation.</param>
    /// <returns>An <see cref="LlmResponse"/> with response text and metadata.</returns>
    Task<LlmResponse> GenerateDecisionAsync(
        IReadOnlyList<AgentChatMessage> messages,
        CancellationToken cancellationToken = default
    );
}
