namespace TechToolbox.Agent.Agent;

/// <summary>
/// Applies lightweight heuristics to estimate how confident the agent should be in a proposed tool action.
/// The scoring layer is designed to catch ambiguous or low-signal tool decisions and ask for clarification
/// instead of blindly executing a potentially costly tool path.
/// </summary>
public sealed class HeuristicScoringEngine
{
    private const double ClarificationThreshold = 0.66;
    private const double MaxPenaltyFromFailures = 0.18;

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

    public HeuristicEvaluation Evaluate(
        string? prompt,
        AgentDecision decision,
        IReadOnlyCollection<string> recentToolFailures,
        string? lastSuccessfulTool = null,
        string? lastSuccessfulTargetHint = null
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

        var confidence = 0.72;

        if (BaseToolWeights.TryGetValue(normalizedToolName, out var baseWeight))
        {
            confidence = Math.Clamp(baseWeight, 0.0, 1.0);
        }

        if (ContainsAny(normalizedPrompt, InvestigationTerms))
        {
            confidence -= 0.08;
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

        if (HasSpecificTargetHint(promptText, decision.ToolArgs))
        {
            confidence += 0.08;
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
            confidence -= 0.22;
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
                confidence -= Math.Min(MaxPenaltyFromFailures, repeatedFailures * 0.08);
            }
        }

        if (ToolCosts.TryGetValue(normalizedToolName, out var toolCost))
        {
            confidence -= toolCost * 0.15;
        }

        confidence = Math.Clamp(confidence, 0.0, 1.0);

        var needsClarification = confidence < ClarificationThreshold;
        var clarificationMessage = needsClarification
            ? "Clarification needed: I need a bit more detail about the target file, service, or symptom before I can choose the safest next step."
            : string.Empty;

        return new HeuristicEvaluation(confidence, needsClarification, clarificationMessage);
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
        if (normalizedPrompt.Contains("troubleshoot", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("troubleshooting", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase)
                || string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase))
            {
                return 0.1;
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

        return 0;
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

        if (!string.Equals(lastSuccessfulTool, "READ-FILE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
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
        return string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "list-directory", StringComparison.OrdinalIgnoreCase)
            || string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase);
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

    private static string NormalizeToolName(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            return string.Empty;

        return toolName.Trim().ToLowerInvariant().Replace('-', '_');
    }
}

public sealed record HeuristicEvaluation(double Confidence, bool NeedsClarification, string ClarificationMessage);
