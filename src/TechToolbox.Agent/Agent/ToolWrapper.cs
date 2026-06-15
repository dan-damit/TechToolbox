using System.Text.Json;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public static class ToolWrapper
{
    private static readonly HashSet<string> SignedFilePolicyValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "ignore",
        "strip"
    };

    public static Dictionary<string, Func<string, Task<string>>> BuildTools(
        IReadOnlyDictionary<string, ToolSpec> registry,
        bool destructiveConfirmed,
        string signedFilePolicy,
        Func<string, IDictionary<string, object?>, object?>? toolExecutor = null)
    {
        var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase);
        var normalizedSignedFilePolicy = NormalizeSignedFilePolicy(signedFilePolicy);
        var executor = toolExecutor ?? PowerShellBridge.RunTool;

        foreach (var kv in registry)
        {
            var toolName = kv.Key;
            var spec = kv.Value;

            tools[toolName] = async (jsonArgs) =>
            {
                Dictionary<string, object?> args;

                // Parse JSON args safely
                try
                {
                    args = string.IsNullOrWhiteSpace(jsonArgs)
                        ? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                        : new Dictionary<string, object?>(
                            JsonSerializer.Deserialize<Dictionary<string, object?>>(jsonArgs)
                                ?? new Dictionary<string, object?>(),
                            StringComparer.OrdinalIgnoreCase);
                }
                catch
                {
                    return $"Error: Invalid JSON arguments for tool '{toolName}'.";
                }

                // Required parameters enforcement
                var missing = GetMissingRequiredParams(spec, args);
                if (missing.Count > 0)
                {
                    return $"Missing required parameter(s): {string.Join(", ", missing)}.";
                }

                // Auto-confirm destructive tools if allowed
                if (Safety.IsDestructive(toolName) && destructiveConfirmed)
                {
                    args["__confirm_destructive"] = true;
                }

                // Preserve Python agent behavior by passing signed-file policy to tools that support it.
                if (HasParameter(spec, "SignedFilePolicy") && !HasArgument(args, "SignedFilePolicy"))
                {
                    args["SignedFilePolicy"] = normalizedSignedFilePolicy;
                }

                // Execute via PowerShell bridge
                object? result;
                try
                {
                    result = executor(toolName, args);
                }
                catch (Exception ex)
                {
                    return $"Tool '{toolName}' failed: {ex.Message}";
                }

                // Normalize output
                return result switch
                {
                    null => "null",
                    string s => s,
                    _ => JsonSerializer.Serialize(result)
                };
            };
        }

        return tools;
    }

    private static List<string> GetMissingRequiredParams(ToolSpec spec, Dictionary<string, object?> args)
    {
        var missing = new List<string>();

        var argsLookup = new Dictionary<string, object?>(args, StringComparer.OrdinalIgnoreCase);

        foreach (var param in spec.Parameters)
        {
            if (param.Value.Mandatory)
            {
                if (!argsLookup.TryGetValue(param.Key, out var value) ||
                    value is null ||
                    (value is string s && string.IsNullOrWhiteSpace(s)))
                {
                    missing.Add(param.Key);
                }
            }
        }

        return missing;
    }

    private static string NormalizeSignedFilePolicy(string? policy)
    {
        if (string.IsNullOrWhiteSpace(policy))
            return "ignore";

        var normalized = policy.Trim().ToLowerInvariant();
        return SignedFilePolicyValues.Contains(normalized) ? normalized : "ignore";
    }

    private static bool HasParameter(ToolSpec spec, string parameterName)
        => spec.Parameters.Keys.Any(k => string.Equals(k, parameterName, StringComparison.OrdinalIgnoreCase));

    private static bool HasArgument(Dictionary<string, object?> args, string parameterName)
        => args.Keys.Any(k => string.Equals(k, parameterName, StringComparison.OrdinalIgnoreCase));
}
