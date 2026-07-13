// <copyright file="Saftey.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

using System.Text.RegularExpressions;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Provides safety checks for tool invocations, including detection of destructive operations
/// and enforcement of explicit confirmation requirements.
/// </summary>
public static class Safety
{
    // PowerShell destructive verbs (aligned with your Python version)
    private static readonly HashSet<string> DestructiveVerbs = new(StringComparer.OrdinalIgnoreCase)
    {
        "clear",
        "disable",
        "remove",
        "restart",
        "stop",
        "uninstall",
    };

    // Name keywords that imply destructive behavior
    private static readonly string[] DestructiveKeywords =
    {
        "cleanup",
        "delete",
        "destroy",
        "format",
        "purge",
        "wipe",
    };

    // Exact built-in tool names that are always treated as destructive regardless of verb/keyword.
    // WRITE-FILE is included because overwriting an existing file is irreversible without a backup.
    private static readonly HashSet<string> DestructiveToolNames = new(
        StringComparer.OrdinalIgnoreCase
    )
    {
        "WRITE-FILE",
        "REPLACE-IN-FILE",
    };

    /// <summary>
    /// Determines whether the specified tool name represents a destructive operation.
    /// </summary>
    /// <param name="toolName">The name of the tool to evaluate.</param>
    /// <returns>
    /// <c>true</c> if the tool is considered destructive; otherwise, <c>false</c>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="toolName"/> is null.
    /// </exception>
    public static bool IsDestructive(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            return false;

        var normalized = toolName.Trim();

        // Exact built-in tool name match
        if (DestructiveToolNames.Contains(normalized))
            return true;

        var lower = normalized.ToLowerInvariant();

        // Check verb (PowerShell verb-noun)
        var verb = lower.Split('-', 2)[0];
        if (DestructiveVerbs.Contains(verb))
            return true;

        // Check keyword presence
        return DestructiveKeywords.Any(k => lower.Contains(k));
    }

    /// <summary>
    /// Determines whether the specified value represents an explicit destructive confirmation.
    /// </summary>
    /// <param name="value">The value to evaluate for confirmation intent.</param>
    /// <returns>
    /// <c>true</c> if the value indicates explicit confirmation; otherwise, <c>false</c>.
    /// </returns>
    internal static bool IsExplicitConfirmation(object? value)
    {
        if (value is bool b)
            return b;

        if (value is int i)
            return i == 1;

        if (value is string s)
        {
            var v = s.Trim().ToLowerInvariant();
            return v is "1" or "true" or "yes" or "approved" or "confirm";
        }

        return false;
    }

    /// <summary>
    /// Enforces destructive confirmation by checking for the <c>__confirm_destructive</c> parameter.
    /// </summary>
    /// <param name="toolName">The name of the tool being invoked.</param>
    /// <param name="args">The dictionary of arguments passed to the tool.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a destructive tool is invoked without explicit confirmation.
    /// </exception>
    public static void RequireDestructiveConfirmation(
        string toolName,
        IDictionary<string, object?> args
    )
    {
        if (!IsDestructive(toolName))
            return;

        if (
            args.TryGetValue("__confirm_destructive", out var value)
            && IsExplicitConfirmation(value)
        )
            return;

        throw new InvalidOperationException(
            $"Destructive tool '{toolName}' requires explicit confirmation via __confirm_destructive=true."
        );
    }
}
