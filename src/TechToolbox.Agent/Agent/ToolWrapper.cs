// <copyright file="ToolWrapper.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

using System.Text.Json;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Provides static methods for building and managing a dictionary of tool functions.
/// Each tool function wraps a <see cref="ToolSpec"/> with argument parsing, validation,
/// safety checks, and execution via the PowerShell bridge.
/// </summary>
public static class ToolWrapper
{
    /// <summary>
    /// A set of valid values for the signed-file policy configuration.
    /// Valid values are: "ignore", "strip".
    /// </summary>
    private static readonly HashSet<string> SignedFilePolicyValues = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        "ignore",
        "strip",
    };

    /// <summary>
    /// Builds a dictionary mapping tool names to their corresponding async execution functions.
    /// Each function handles JSON argument parsing, required parameter validation, safety checks,
    /// and delegation to the PowerShell bridge for actual execution.
    /// </summary>
    /// <param name="registry">
    /// An immutable dictionary of tool specifications keyed by tool name.
    /// </param>
    /// <param name="destructiveConfirmed">
    /// Indicates whether destructive operations have been pre-confirmed by the user.
    /// When true, destructive tools will auto-confirm without additional prompts.
    /// </param>
    /// <param name="signedFilePolicy">
    /// The policy for handling signed files during tool execution.
    /// Valid values are "ignore" or "strip". Invalid values default to "ignore".
    /// </param>
    /// <param name="allowedFetchHosts">
    /// An optional collection of hostnames allowed for FETCH-URL operations.
    /// Hostnames are normalized by trimming whitespace, removing trailing dots,
    /// and converting to lowercase.
    /// </param>
    /// <param name="toolExecutor">
    /// An optional custom executor function. When null, defaults to
    /// <see cref="PowerShellBridge.RunTool"/> for standard PowerShell execution.
    /// </param>
    /// <returns>
    /// A dictionary mapping tool names (case-insensitive) to async functions that accept
    /// a JSON string of arguments and return a task producing a string result.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="registry"/> is null.
    /// </exception>
    public static Dictionary<string, Func<string, Task<string>>> BuildTools(
        IReadOnlyDictionary<string, ToolSpec> registry,
        bool destructiveConfirmed,
        string signedFilePolicy,
        IEnumerable<string>? allowedFetchHosts = null,
        Func<string, IDictionary<string, object?>, object?>? toolExecutor = null
    )
    {
        // Initialize the tools dictionary with case-insensitive key comparison
        var tools = new Dictionary<string, Func<string, Task<string>>>(
            StringComparer.OrdinalIgnoreCase
        );

        // Normalize the signed file policy to a valid value
        var normalizedSignedFilePolicy = NormalizeSignedFilePolicy(signedFilePolicy);

        // Normalize the allowed fetch hosts list
        var normalizedFetchHosts = NormalizeFetchHosts(allowedFetchHosts);

        // Use the provided executor or default to PowerShellBridge.RunTool
        var executor = toolExecutor ?? PowerShellBridge.RunTool;

        // Iterate over each tool specification in the registry
        foreach (var kv in registry)
        {
            var toolName = kv.Key;
            var spec = kv.Value;

            // Create an async function for each tool that wraps execution logic
            tools[toolName] = async (jsonArgs) =>
            {
                Dictionary<string, object?> args;

                // Parse JSON arguments safely with error handling
                try
                {
                    // If jsonArgs is null or whitespace, use an empty dictionary
                    // Otherwise, deserialize the JSON into a dictionary
                    args = string.IsNullOrWhiteSpace(jsonArgs)
                        ? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                        : new Dictionary<string, object?>(
                            JsonSerializer.Deserialize<Dictionary<string, object?>>(jsonArgs)
                                ?? new Dictionary<string, object?>(),
                            StringComparer.OrdinalIgnoreCase
                        );
                }
                catch
                {
                    // Return an error message if JSON parsing fails
                    return $"Error: Invalid JSON arguments for tool '{toolName}'.";
                }

                // Validate that all required parameters are present
                var missing = GetMissingRequiredParams(spec, args);
                if (missing.Count > 0)
                {
                    // Return an error listing the missing required parameters
                    return $"Missing required parameter(s): {string.Join(", ", missing)}.";
                }

                // Auto-confirm destructive tools if destructive operations are pre-confirmed
                if (Safety.IsDestructive(toolName) && destructiveConfirmed)
                {
                    args["__confirm_destructive"] = true;
                }

                // Preserve signed-file policy behavior by passing it to tools that support it.
                if (
                    HasParameter(spec, "SignedFilePolicy") && !HasArgument(args, "SignedFilePolicy")
                )
                {
                    args["SignedFilePolicy"] = normalizedSignedFilePolicy;
                }

                if (
                    string.Equals(toolName, "FETCH-URL", StringComparison.OrdinalIgnoreCase)
                    && !args.ContainsKey("__allowed_fetch_hosts")
                )
                {
                    args["__allowed_fetch_hosts"] = normalizedFetchHosts;
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
                    _ => JsonSerializer.Serialize(result),
                };
            };
        }

        return tools;
    }

    /// <summary>
    /// Determines which required parameters are missing from the provided arguments.
    /// A parameter is considered missing if it is marked as mandatory in the tool specification
    /// and is either not present in the arguments dictionary, null, or an empty/whitespace string.
    /// </summary>
    /// <param name="spec">
    /// The tool specification containing parameter definitions.
    /// </param>
    /// <param name="args">
    /// The dictionary of provided arguments to validate against the specification.
    /// </param>
    /// <returns>
    /// A list of parameter names that are required but missing from the arguments.
    /// Returns an empty list if all required parameters are present and valid.
    /// </returns>
    private static List<string> GetMissingRequiredParams(
        ToolSpec spec,
        Dictionary<string, object?> args
    )
    {
        var missing = new List<string>();

        // Create a case-insensitive lookup for efficient parameter checking
        var argsLookup = new Dictionary<string, object?>(args, StringComparer.OrdinalIgnoreCase);

        // Check each parameter defined in the specification
        foreach (var param in spec.Parameters)
        {
            // Only check mandatory parameters
            if (param.Value.Mandatory)
            {
                // Check if the argument is missing, null, or an empty/whitespace string
                if (
                    !argsLookup.TryGetValue(param.Key, out var value)
                    || value is null
                    || (value is string s && string.IsNullOrWhiteSpace(s))
                )
                {
                    missing.Add(param.Key);
                }
            }
        }

        return missing;
    }

    /// <summary>
    /// Normalizes a signed-file policy value to a valid policy string.
    /// If the input is null, empty, or whitespace, returns "ignore".
    /// If the input matches a valid policy value (case-insensitive), returns the normalized value.
    /// Otherwise, defaults to "ignore" for invalid inputs.
    /// </summary>
    /// <param name="policy">
    /// The raw signed-file policy string to normalize. May be null.
    /// </param>
    /// <returns>
    /// A valid signed-file policy value: either "ignore" or "strip".
    /// Returns "ignore" for any invalid or missing input.
    /// </returns>
    private static string NormalizeSignedFilePolicy(string? policy)
    {
        // Return default if policy is null, empty, or whitespace
        if (string.IsNullOrWhiteSpace(policy))
            return "ignore";

        // Trim and convert to lowercase for case-insensitive comparison
        var normalized = policy.Trim().ToLowerInvariant();

        // Return the normalized value if it's valid, otherwise default to "ignore"
        return SignedFilePolicyValues.Contains(normalized) ? normalized : "ignore";
    }

    /// <summary>
    /// Checks whether a tool specification contains a parameter with the specified name.
    /// The comparison is case-insensitive.
    /// </summary>
    /// <param name="spec">
    /// The tool specification to search for the parameter.
    /// </param>
    /// <param name="parameterName">
    /// The name of the parameter to search for.
    /// </param>
    /// <returns>
    /// True if the parameter exists in the specification; otherwise, false.
    /// </returns>
    private static bool HasParameter(ToolSpec spec, string parameterName) =>
        spec.Parameters.Keys.Any(k =>
            string.Equals(k, parameterName, StringComparison.OrdinalIgnoreCase)
        );

    /// <summary>
    /// Checks whether an arguments dictionary contains a key with the specified name.
    /// The comparison is case-insensitive.
    /// </summary>
    /// <param name="args">
    /// The arguments dictionary to search for the key.
    /// </param>
    /// <param name="parameterName">
    /// The name of the key to search for.
    /// </param>
    /// <returns>
    /// True if the key exists in the dictionary; otherwise, false.
    /// </returns>
    private static bool HasArgument(Dictionary<string, object?> args, string parameterName) =>
        args.Keys.Any(k => string.Equals(k, parameterName, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Normalizes a collection of allowed fetch hostnames for FETCH-URL operations.
    /// Each hostname is trimmed, trailing dots are removed, and the result is converted to lowercase.
    /// Duplicate hostnames (case-insensitive) are removed, and null/empty entries are filtered out.
    /// </summary>
    /// <param name="allowedFetchHosts">
    /// An optional collection of raw hostnames to normalize. May be null.
    /// </param>
    /// <returns>
    /// An array of normalized, deduplicated hostnames. Returns an empty array if the input is null.
    /// </returns>
    private static string[] NormalizeFetchHosts(IEnumerable<string>? allowedFetchHosts)
    {
        // Return empty array if no hosts are provided
        if (allowedFetchHosts is null)
            return Array.Empty<string>();

        // Filter, trim, normalize, and deduplicate the hostnames
        return allowedFetchHosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h.Trim().Trim('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
