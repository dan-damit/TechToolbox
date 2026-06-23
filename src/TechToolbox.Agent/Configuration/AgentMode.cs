namespace TechToolbox.Agent.Configuration;

/// <summary>
/// Defines the operating mode of the agent, which determines available tools,
/// system prompts, and behavior expectations.
/// </summary>
public enum AgentMode
{
    /// <summary>
    /// TechToolbox automation mode: PowerShell-based system administration
    /// and maintenance tasks. Includes destructive operation safeguards.
    /// </summary>
    TechToolbox,

    /// <summary>
    /// Assistant mode: General-purpose helper for chat, Q&A, writing assistance,
    /// document editing, and other non-destructive helper tasks.
    /// No module-specific tools; focuses on file I/O and reasoning.
    /// </summary>
    Assistant,

    /// <summary>
    /// Coding agent mode: Code analysis, generation, debugging, and refactoring.
    /// Tools for file inspection, code review, and execution context.
    /// </summary>
    CodingAgent,

    /// <summary>
    /// Generic mode: Minimal built-in tools (file I/O only).
    /// Allows full customization via external tool providers.
    /// </summary>
    Custom
}
