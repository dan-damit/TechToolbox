namespace TechToolbox.Agent.Agent;

/// <summary>
/// Applies lightweight heuristics to estimate how confident the agent should be in a proposed tool action.
/// The scoring layer is designed to catch ambiguous or low-signal tool decisions and ask for clarification
/// instead of blindly executing a potentially costly tool path.
/// </summary>
public sealed class HeuristicScoringEngine
{
    private const double ClarificationThreshold = 0.66;
    private const double InvestigationExploratoryThresholdReduction = 0.06;
    private const double MaxPenaltyFromFailures = 0.12;

    private static readonly Dictionary<string, double> BaseToolWeights =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["READ-FILE"] = 0.72,
            ["WRITE-FILE"] = 0.74,
            ["APPEND-FILE"] = 0.72,
            ["REPLACE-IN-FILE"] = 0.76,
            ["LIST-DIRECTORY"] = 0.66,
            ["SEARCH-WEB"] = 0.7,
            ["FETCH-URL"] = 0.68,
            ["ECHO"] = 0.56,
        };

    private static readonly Dictionary<string, double> ToolCosts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["READ-FILE"] = 0.1,
            ["LIST-DIRECTORY"] = 0.3,
            ["SEARCH-WEB"] = 0.4,
            ["WRITE-FILE"] = 0.5,
            ["APPEND-FILE"] = 0.45,
            ["REPLACE-IN-FILE"] = 0.42,
            ["FETCH-URL"] = 0.35,
            ["ECHO"] = 0.15,
        };

    private static readonly Dictionary<string, double> GoalFitBoosts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["summarize"] = 0.1,
            ["extract"] = 0.08,
            ["compare"] = 0.09,
            ["scan"] = 0.07,
            ["locate"] = 0.06,
        };

    private static readonly Dictionary<string, double> PatternBoosts =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["troubleshoot"] = 0.1,
            ["file analysis"] = 0.1,
            ["network diagnosis"] = 0.1,
        };

    private static readonly string[] InvestigationTerms =
    [
        "investigate",
        "troubleshoot",
        "diagnose",
        "issue",
        "problem",
        "error",
        "failure",
        "figure out",
        "find out",
        "what is wrong",
        "check why",
        "debug",
    ];

    private static readonly string[] IntentTerms =
    [
        "read",
        "inspect",
        "view",
        "open",
        "show",
        "check",
        "review",
        "analyze",
        "examine",
        "look at",
    ];

    private static readonly string[] WriteTerms =
    [
        "write",
        "create",
        "draft",
        "save",
        "update",
        "edit",
        "modify",
        "generate",
        "document",
        "prepare",
    ];

    private static readonly string[] TargetTerms =
    [
        "file",
        "path",
        "directory",
        "folder",
        "log",
        "config",
        "script",
        "code",
        "service",
        "class",
        "function",
        "url",
    ];

    /// <summary>
    /// Evaluates the confidence of a proposed tool action based on heuristics such as prompt clarity, target specificity, and recent failure history.
    /// Returns an evaluation indicating whether clarification is needed before proceeding.
    /// </summary>
    /// <param name="prompt">The user's original prompt or instruction.</param>
    /// <param name="decision">The agent's proposed decision containing the tool name and arguments.</param>
    /// <param name="recentToolFailures">A collection of recently failed tool names to penalize repeated failures.</param>
    /// <param name="lastSuccessfulTool">Optional: The name of the last successfully executed tool for context matching.</param>
    /// <param name="lastSuccessfulTargetHint">Optional: A hint about the target from the last successful tool execution.</param>
    /// <param name="clarificationCycles">The number of clarification cycles already performed.</param>
    /// <param name="hasNewConcreteTargetHint">Whether a new, concrete target hint has been provided in this cycle.</param>
    /// <returns>A HeuristicEvaluation containing confidence score, clarification flag, and message if needed.</returns>
    public HeuristicEvaluation Evaluate(
        string? prompt,
        AgentDecision decision,
        IReadOnlyCollection<string> recentToolFailures,
        string? lastSuccessfulTool = null,
        string? lastSuccessfulTargetHint = null,
        int clarificationCycles = 0,
        bool hasNewConcreteTargetHint = false
    )
    {
        if (decision is null || !decision.NeedsTool)
        {
            return new HeuristicEvaluation(1.0, false, string.Empty);
        }

        var promptText = (prompt ?? string.Empty).Trim();
        var normalizedPrompt = promptText.ToLowerInvariant();
        var toolName = decision.ToolName ?? string.Empty;
        var normalizedToolName = NormalizeToolName(toolName);
        var hasSpecificTargetHint = HasSpecificTargetHint(promptText, decision.ToolArgs);
        var isInvestigationPrompt = IsInvestigationPrompt(normalizedPrompt);
        var isLowRiskExploratoryTool = IsLowRiskExploratoryTool(normalizedToolName);

        var confidence = 0.72;

        if (BaseToolWeights.TryGetValue(normalizedToolName, out var baseWeight))
        {
            confidence = Math.Clamp(baseWeight, 0.0, 1.0);
        }

        if (isInvestigationPrompt)
        {
            confidence += 0.04;
            if (isLowRiskExploratoryTool)
            {
                confidence += 0.02;
            }
        }

        var patternBoost = MatchPatternBoost(normalizedPrompt, normalizedToolName);
        confidence += patternBoost;

        var goalFitBoost = MatchGoalFitBoost(normalizedPrompt, normalizedToolName);
        confidence += goalFitBoost;

        if (IsSessionContextMatch(lastSuccessfulTool, lastSuccessfulTargetHint, promptText, normalizedToolName))
        {
            confidence += 0.06;
        }

        if (ContainsAny(normalizedPrompt, IntentTerms))
        {
            confidence += 0.06;
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.04;
            }
        }

        if (ContainsAny(normalizedPrompt, WriteTerms))
        {
            confidence += 0.06;
            if (string.Equals(normalizedToolName, "write-file", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.04;
            }
        }

        if (ContainsAny(normalizedPrompt, TargetTerms))
        {
            confidence += 0.08;
        }

        if (hasSpecificTargetHint)
        {
            confidence += 0.08;
        }

        if (hasNewConcreteTargetHint)
        {
            confidence += 0.06;
        }

        if (string.IsNullOrWhiteSpace(promptText))
        {
            confidence -= 0.08;
        }

        if (IsVeryVaguePrompt(normalizedPrompt))
        {
            confidence -= 0.08;
        }

        if (IsVeryVaguePrompt(normalizedPrompt) && IsAmbiguousToolChoice(normalizedToolName))
        {
            confidence -= 0.12;
        }
        else if (IsVeryVaguePrompt(normalizedPrompt))
        {
            confidence = Math.Max(confidence, 0.74);
        }

        if (recentToolFailures is not null)
        {
            var repeatedFailures = recentToolFailures.Count(failure =>
                string.Equals(failure, toolName, StringComparison.OrdinalIgnoreCase)
            );
            if (repeatedFailures > 0)
            {
                var failurePenalty = Math.Min(MaxPenaltyFromFailures, repeatedFailures * 0.04);
                if (isInvestigationPrompt && isLowRiskExploratoryTool)
                {
                    failurePenalty = Math.Max(0.0, failurePenalty - 0.03);
                }

                if (hasNewConcreteTargetHint)
                {
                    failurePenalty = 0.0;
                }

                confidence -= failurePenalty;
            }
        }

        if (ToolCosts.TryGetValue(normalizedToolName, out var toolCost))
        {
            confidence -= toolCost * 0.15;
        }

        confidence = Math.Clamp(confidence, 0.0, 1.0);

        var clarificationThreshold = ClarificationThreshold;
        if (isInvestigationPrompt && isLowRiskExploratoryTool)
        {
            clarificationThreshold -= InvestigationExploratoryThresholdReduction;
        }

        if (hasNewConcreteTargetHint)
        {
            clarificationThreshold -= 0.02;
        }

        clarificationThreshold = Math.Clamp(clarificationThreshold, 0.45, ClarificationThreshold);

        var needsClarification = confidence < clarificationThreshold;
        var clarificationMessage = needsClarification
            ? BuildClarificationMessage(
                promptText,
                decision.ToolArgs,
                normalizedToolName,
                clarificationCycles
            )
            : string.Empty;

        return new HeuristicEvaluation(confidence, needsClarification, clarificationMessage);
    }

    private static string BuildClarificationMessage(
        string prompt,
        IDictionary<string, object?>? toolArgs,
        string normalizedToolName,
        int clarificationCycles
    )
    {
        var missingArgKey = GetMissingPrimaryArgKey(normalizedToolName, toolArgs);
        var cyclePrefix = clarificationCycles > 0
            ? $"Clarification needed (attempt {clarificationCycles + 1}): "
            : "Clarification needed: ";

        if (!string.IsNullOrWhiteSpace(missingArgKey))
        {
            return $"{cyclePrefix}Please provide exactly one value for '{missingArgKey}' so I can run the next step safely.";
        }

        if (IsInvestigationPrompt(prompt.ToLowerInvariant()) && !HasSpecificTargetHint(prompt, toolArgs))
        {
            return $"{cyclePrefix}I can keep probing, but I need one concrete target such as a file path, service name, or the exact error message to avoid wasting steps.";
        }

        if (IsLowRiskExploratoryTool(normalizedToolName))
        {
            return $"{cyclePrefix}I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.";
        }

        return $"{cyclePrefix}I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.";
    }

    private static string GetMissingPrimaryArgKey(
        string normalizedToolName,
        IDictionary<string, object?>? toolArgs
    )
    {
        var requiredKey = normalizedToolName switch
        {
            "read-file" => "path",
            "write-file" => "path",
            "append-file" => "path",
            "replace-in-file" => "path",
            "list-directory" => "path",
            "fetch-url" => "url",
            "search-web" => "query",
            _ => string.Empty,
        };

        if (string.IsNullOrWhiteSpace(requiredKey))
        {
            return string.Empty;
        }

        if (!TryGetToolArgString(toolArgs, requiredKey, out _))
        {
            return requiredKey;
        }

        return string.Empty;
    }

    private static bool TryGetToolArgString(
        IDictionary<string, object?>? toolArgs,
        string key,
        out string value
    )
    {
        value = string.Empty;

        if (toolArgs is null)
        {
            return false;
        }

        foreach (var kvp in toolArgs)
        {
            if (!string.Equals(kvp.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var raw = kvp.Value?.ToString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(raw))
            {
                return false;
            }

            value = raw;
            return true;
        }

        return false;
    }

    private static bool HasSpecificTargetHint(string prompt, IDictionary<string, object?>? toolArgs)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return false;

        if (toolArgs is not null)
        {
            foreach (var kvp in toolArgs)
            {
                if (string.Equals(kvp.Key, "path", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(kvp.Key, "file", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(kvp.Key, "target", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(kvp.Key, "service", StringComparison.OrdinalIgnoreCase))
                {
                    if (kvp.Value is not null && !string.IsNullOrWhiteSpace(kvp.Value.ToString()))
                        return true;
                }
            }
        }

        return prompt.Contains(':') || prompt.Contains('/') || prompt.Contains('\\');
    }

    private static double MatchPatternBoost(string normalizedPrompt, string normalizedToolName)
    {
        var boost = 0.0;

        foreach (var kvp in PatternBoosts)
        {
            if (!normalizedPrompt.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (
                (string.Equals(kvp.Key, "troubleshoot", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(kvp.Key, "file analysis", StringComparison.OrdinalIgnoreCase))
                && (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase))
            )
            {
                boost = Math.Max(boost, kvp.Value);
            }

            if (
                string.Equals(kvp.Key, "network diagnosis", StringComparison.OrdinalIgnoreCase)
                && (string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            )
            {
                boost = Math.Max(boost, kvp.Value);
            }
        }

        if (normalizedPrompt.Contains("summarize", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("analyze", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("inspect", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                return 0.1;
            }
        }

        if (normalizedPrompt.Contains("network", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("ping", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("traceroute", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase)
                || string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                return 0.1;
            }
        }

        return boost;
    }

    private static double MatchGoalFitBoost(string normalizedPrompt, string normalizedToolName)
    {
        foreach (var kvp in GoalFitBoosts)
        {
            if (normalizedPrompt.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Value;
                }
            }
        }

        return 0;
    }

    private static bool IsSessionContextMatch(
        string? lastSuccessfulTool,
        string? lastSuccessfulTargetHint,
        string prompt,
        string normalizedToolName
    )
    {
        if (string.IsNullOrWhiteSpace(lastSuccessfulTargetHint)
            || string.IsNullOrWhiteSpace(prompt))
        {
            return false;
        }

        if (!IsLowRiskExploratoryTool(NormalizeToolName(lastSuccessfulTool ?? string.Empty)))
        {
            return false;
        }

        if (!IsLowRiskExploratoryTool(normalizedToolName))
        {
            return false;
        }

        return prompt.Contains(lastSuccessfulTargetHint, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsVeryVaguePrompt(string normalizedPrompt)
    {
        if (string.IsNullOrWhiteSpace(normalizedPrompt))
            return true;

        var words = normalizedPrompt.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length <= 3)
            return true;

        return !ContainsAny(normalizedPrompt, TargetTerms)
            && !ContainsAny(normalizedPrompt, InvestigationTerms)
            && !ContainsAny(normalizedPrompt, IntentTerms)
            && !ContainsAny(normalizedPrompt, WriteTerms);
    }

    private static bool IsAmbiguousToolChoice(string normalizedToolName)
    {
        return string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAny(string text, IEnumerable<string> terms)
    {
        foreach (var term in terms)
        {
            if (text.Contains(term, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool IsInvestigationPrompt(string normalizedPrompt)
    {
        return ContainsAny(normalizedPrompt, InvestigationTerms);
    }

    private static bool IsLowRiskExploratoryTool(string normalizedToolName)
    {
        return string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeToolName(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            return string.Empty;

        return toolName.Trim().ToLowerInvariant().Replace('_', '-');
    }
}

/// <summary>
/// Represents the result of a heuristic evaluation for a proposed tool action.
/// </summary>
/// <param name="Confidence">A score between 0.0 and 1.0 indicating confidence in the decision.</param>
/// <param name="NeedsClarification">True if more information is needed before proceeding; false otherwise.</param>
/// <param name="ClarificationMessage">A message explaining what clarification is required, if any.</param>
public sealed record HeuristicEvaluation(double Confidence, bool NeedsClarification, string ClarificationMessage);
