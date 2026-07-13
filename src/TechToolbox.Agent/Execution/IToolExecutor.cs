namespace TechToolbox.Agent.Execution;

/// <summary>
/// Abstraction for executing a named tool with argument payload.
/// </summary>
public interface IToolExecutor
{
    object? RunTool(string toolName, IDictionary<string, object?> args);
}
