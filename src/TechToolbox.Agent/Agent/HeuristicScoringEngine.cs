namespace TechToolbox.Agent.Agent;

using TechToolbox.Agent.Memory;

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

    private static readonly string[] HighImpactWorkloadTerms =
    [
        "database",
        "sql",
        "postgres",
        "mysql",
        "mssql",
        "production",
        "deploy",
        "deployment",
        "migration",
        "cutover",
    ];

    private static readonly string[] LowImpactWorkloadTerms =
    [
        "summarize",
        "readme",
        "documentation",
        "docs",
        "note",
        "explain",
    ];

    private static readonly string[] CorrelatedWarningTerms =
    [
        "cpu",
        "disk",
        "i/o",
        "latency",
        "memory pressure",
    ];

    private static readonly string[] ConversationalDialogueTerms =
    [
        "hello",
        "hi",
        "hey",
        "thanks",
        "thank you",
        "please",
        "can you",
        "could you",
        "would you",
        "tell me",
        "help me",
        "i am curious",
        "chat",
        "conversation",
    ];

    /// <summary>
    /// Evaluates preflight quality as a risk score by combining raw preflight telemetry,
    /// prompt context, and recent historical outcomes.
    /// </summary>
    /// <param name="prompt">The user prompt or run objective.</param>
    /// <param name="signals">Current preflight score, warning, and critical counts.</param>
    /// <param name="history">Optional run history for context-aware thresholds and trend learning.</param>
    /// <returns>A preflight risk assessment used to bias runtime decision confidence.</returns>
    public PreflightRiskAssessment EvaluatePreflightRisk(
        string? prompt,
        PreflightSignalSnapshot signals,
        IReadOnlyList<RunHistory>? history = null
    )
    {
        var promptText = (prompt ?? string.Empty).Trim();
        var normalizedPrompt = promptText.ToLowerInvariant();
        var factors = new List<string>();

        var warningWeight = 0.08;
        var criticalWeight = 0.22;
        var scoreWeight = 0.55;

        if (ContainsAny(normalizedPrompt, HighImpactWorkloadTerms))
        {
            warningWeight *= 1.3;
            criticalWeight *= 1.2;
            scoreWeight *= 1.15;
            factors.Add("high-impact workload context increased warning severity");
        }
        else if (ContainsAny(normalizedPrompt, LowImpactWorkloadTerms))
        {
            warningWeight *= 0.75;
            criticalWeight *= 0.8;
            scoreWeight *= 0.9;
            factors.Add("low-impact workload context reduced warning severity");
        }

        var normalizedScore = Math.Clamp(signals.Score, 0, 100);
        var warnings = Math.Max(0, signals.WarningCount);
        var critical = Math.Max(0, signals.CriticalCount);
        var hasExplicitPreflightTelemetry = normalizedScore > 0 || warnings > 0 || critical > 0;

        var risk = hasExplicitPreflightTelemetry
            ? ((100.0 - normalizedScore) / 100.0) * scoreWeight
            : 0.32;
        risk += warnings * warningWeight;
        risk += critical * criticalWeight;

        if (!hasExplicitPreflightTelemetry)
        {
            factors.Add("preflight telemetry unavailable; using neutral baseline risk");
        }

        if (warnings >= 2 && critical >= 1)
        {
            risk += 0.1;
            factors.Add("multiple warnings combined with critical findings predict likely failure");
        }

        if (warnings >= 3 && normalizedScore < 70)
        {
            risk += 0.07;
            factors.Add("high warning volume with low score indicates fragile baseline");
        }

        if (critical >= 2)
        {
            risk += 0.12;
            factors.Add("multiple critical findings require stronger guardrails");
        }

        if (warnings >= 2 && ContainsAny(normalizedPrompt, CorrelatedWarningTerms))
        {
            risk += 0.05;
            factors.Add("correlated minor warning signals suggest elevated runtime risk");
        }

        var profile = BuildHistoricalProfile(history, normalizedScore, warnings, critical);
        if (profile.SampleSize >= 5)
        {
            if (profile.SuccessRate >= 0.8)
            {
                risk -= 0.07;
                factors.Add("historical runs with similar preflight signals were mostly successful");
            }

            if (profile.SuccessRate <= 0.55)
            {
                risk += 0.08;
                factors.Add("historical runs with similar preflight signals had frequent failures");
            }

            if (profile.UnstableOutcomeRate >= 0.2)
            {
                risk += 0.06;
                factors.Add("historical instability (iteration-limit/llm-failure) increased predicted risk");
            }
        }

        risk = Math.Clamp(risk, 0.0, 1.0);

        var thresholdAdjustment = risk switch
        {
            >= 0.8 => 0.08,
            >= 0.65 => 0.04,
            <= 0.3 => -0.03,
            <= 0.45 => -0.01,
            _ => 0.0,
        };

        var predictiveFailureLikely =
            risk >= 0.72 || (warnings >= 2 && critical >= 1) || profile.UnstableOutcomeRate >= 0.25;

        var remediationSuggestion = BuildRemediationSuggestion(
            risk,
            warnings,
            critical,
            normalizedPrompt,
            profile
        );

        return new PreflightRiskAssessment(
            risk,
            thresholdAdjustment,
            predictiveFailureLikely,
            remediationSuggestion,
            factors
        );
    }

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
        bool hasNewConcreteTargetHint = false,
        PreflightRiskAssessment? preflightRisk = null
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
        var isFactualOrExternalQuestion = IsFactualOrExternalQuestion(normalizedPrompt);
        var isConversationalDialogue = IsConversationalDialoguePrompt(normalizedPrompt);

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

        if (isFactualOrExternalQuestion)
        {
            if (string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.12;
            }
            else if (string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.1;
            }
            else if (string.Equals(normalizedToolName, "echo", StringComparison.OrdinalIgnoreCase))
            {
                confidence -= 0.12;
            }
        }

        if (isConversationalDialogue)
        {
            if (string.Equals(normalizedToolName, "search-web", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.24;
            }
            else if (string.Equals(normalizedToolName, "fetch-url", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.22;
            }
            else if (string.Equals(normalizedToolName, "echo", StringComparison.OrdinalIgnoreCase))
            {
                confidence -= 0.16;
            }
            else if (isLowRiskExploratoryTool)
            {
                confidence -= 0.05;
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

        if (ContainsAny(normalizedPrompt, ["large file", "big file", "huge file", "very large", "scale", "full context"]))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.12;
            }
        }

        if (ContainsAny(normalizedPrompt, ["oldtext", "old text", "symbol", "method", "class", "replace", "locate", "find this", "search for"]))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.14;
            }
        }

        if (ContainsAny(normalizedPrompt, ["plan", "overview", "structure", "imports", "function names", "file shape", "header", "footer"]))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
            {
                confidence += 0.1;
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

        var isVeryVagueConversationPrompt = isConversationalDialogue && IsVeryVaguePrompt(normalizedPrompt);

        if (isVeryVagueConversationPrompt)
        {
            confidence = Math.Max(confidence, 0.88);
        }
        else if (IsVeryVaguePrompt(normalizedPrompt))
        {
            confidence -= 0.08;
        }

        if (IsVeryVaguePrompt(normalizedPrompt) && IsAmbiguousToolChoice(normalizedToolName))
        {
            if (isVeryVagueConversationPrompt)
            {
                confidence = Math.Max(confidence, 0.88);
            }
            else
            {
                confidence -= 0.12;
            }
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

        if (preflightRisk is not null)
        {
            confidence -= preflightRisk.RiskScore * 0.14;

            if (preflightRisk.RiskScore <= 0.3)
            {
                confidence += 0.02;
            }

            if (
                preflightRisk.PredictiveFailureLikely
                && IsAmbiguousToolChoice(normalizedToolName)
                && !hasSpecificTargetHint
            )
            {
                confidence -= 0.05;
            }
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

        if (preflightRisk is not null)
        {
            clarificationThreshold += preflightRisk.ClarificationThresholdAdjustment;
        }

        clarificationThreshold = Math.Clamp(clarificationThreshold, 0.45, 0.82);

        var needsClarification = confidence < clarificationThreshold;
        var clarificationMessage = needsClarification
            ? BuildClarificationMessage(
                promptText,
                decision.ToolArgs,
                normalizedToolName,
                clarificationCycles,
                preflightRisk?.RemediationSuggestion
            )
            : string.Empty;

        return new HeuristicEvaluation(confidence, needsClarification, clarificationMessage);
    }

    private static string BuildClarificationMessage(
        string prompt,
        IDictionary<string, object?>? toolArgs,
        string normalizedToolName,
        int clarificationCycles,
        string? remediationSuggestion
    )
    {
        var missingArgKey = GetMissingPrimaryArgKey(normalizedToolName, toolArgs);
        var cyclePrefix = clarificationCycles > 0
            ? $"Clarification needed (attempt {clarificationCycles + 1}): "
            : "Clarification needed: ";

        if (!string.IsNullOrWhiteSpace(missingArgKey))
        {
            return AppendRemediation(
                $"{cyclePrefix}Please provide exactly one value for '{missingArgKey}' so I can run the next step safely.",
                remediationSuggestion
            );
        }

        if (IsInvestigationPrompt(prompt.ToLowerInvariant()) && !HasSpecificTargetHint(prompt, toolArgs))
        {
            return AppendRemediation(
                $"{cyclePrefix}I can keep probing, but I need one concrete target such as a file path, service name, or the exact error message to avoid wasting steps.",
                remediationSuggestion
            );
        }

        if (IsLowRiskExploratoryTool(normalizedToolName))
        {
            return AppendRemediation(
                $"{cyclePrefix}I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.",
                remediationSuggestion
            );
        }

        return AppendRemediation(
            $"{cyclePrefix}I need a bit more detail about the target file, service, or symptom before I can choose the safest next step.",
            remediationSuggestion
        );
    }

    private static string AppendRemediation(string message, string? remediationSuggestion)
    {
        if (string.IsNullOrWhiteSpace(remediationSuggestion))
        {
            return message;
        }

        return $"{message} Suggested preflight remediation: {remediationSuggestion}";
    }

    private static string BuildRemediationSuggestion(
        double risk,
        int warnings,
        int critical,
        string normalizedPrompt,
        HistoricalPreflightProfile profile
    )
    {
        if (risk >= 0.8)
        {
            return "Resolve all critical preflight findings, reduce warning count below 2, and rerun validation before executing mutating tools.";
        }

        if (critical > 0)
        {
            return "Address critical preflight findings first, then proceed with bounded read-only verification steps.";
        }

        if (warnings >= 3)
        {
            return "Mitigate at least one warning and provide a concrete target path or service so execution can remain bounded.";
        }

        if (profile.SampleSize >= 5 && profile.UnstableOutcomeRate >= 0.2)
        {
            return "Use narrower scope and explicit termination criteria; similar runs showed instability in recent history.";
        }

        if (ContainsAny(normalizedPrompt, HighImpactWorkloadTerms))
        {
            return "Confirm capacity and backup posture before taking write actions in a high-impact workload context.";
        }

        return risk >= 0.6
            ? "Add one concrete target and run a quick read-only probe before higher-cost actions."
            : "Preflight posture is acceptable; continue with explicit target hints to keep execution efficient.";
    }

    private static HistoricalPreflightProfile BuildHistoricalProfile(
        IReadOnlyList<RunHistory>? history,
        int score,
        int warnings,
        int critical
    )
    {
        if (history is null || history.Count == 0)
        {
            return HistoricalPreflightProfile.Empty;
        }

        var window = history
            .TakeLast(40)
            .Where(h =>
                Math.Abs(h.PromptPreflightScore - score) <= 15
                && Math.Abs(h.PromptPreflightWarningCount - warnings) <= 1
                && Math.Abs(h.PromptPreflightCriticalCount - critical) <= 1
            )
            .ToArray();

        if (window.Length == 0)
        {
            return HistoricalPreflightProfile.Empty;
        }

        var successCount = window.Count(h =>
            string.Equals(h.Status, "success", StringComparison.OrdinalIgnoreCase)
        );
        var unstableCount = window.Count(h =>
            string.Equals(h.Outcome, "iteration-limit", StringComparison.OrdinalIgnoreCase)
            || string.Equals(h.Outcome, "llm-failure", StringComparison.OrdinalIgnoreCase)
        );

        return new HistoricalPreflightProfile(
            window.Length,
            (double)successCount / window.Length,
            (double)unstableCount / window.Length
        );
    }

    private readonly record struct HistoricalPreflightProfile(
        int SampleSize,
        double SuccessRate,
        double UnstableOutcomeRate
    )
    {
        public static HistoricalPreflightProfile Empty => new(0, 0, 0);
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

        if (normalizedPrompt.Contains("large file", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("huge file", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("big file", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("full context", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
                return 0.14;
        }

        if (normalizedPrompt.Contains("replace", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("oldtext", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("symbol", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("locate", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
                return 0.16;
        }

        if (normalizedPrompt.Contains("header", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("footer", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("structure", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("imports", StringComparison.OrdinalIgnoreCase)
            || normalizedPrompt.Contains("function names", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(normalizedToolName, "read-file", StringComparison.OrdinalIgnoreCase))
                return 0.12;
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

    private static bool IsFactualOrExternalQuestion(string normalizedPrompt)
    {
        if (string.IsNullOrWhiteSpace(normalizedPrompt))
        {
            return false;
        }

        var factualQuestionTerms = new[]
        {
            "what is",
            "who is",
            "when did",
            "where is",
            "why does",
            "how does",
            "latest",
            "current",
            "news",
            "official",
            "documentation",
            "docs",
            "release notes",
            "version",
            "cve",
            "vulnerability",
            "according to",
            "source",
            "citation",
            "references",
            "website",
            "web",
            "internet",
            "online",
            "external",
        };

        return normalizedPrompt.Contains('?', StringComparison.OrdinalIgnoreCase)
            || ContainsAny(normalizedPrompt, factualQuestionTerms);
    }

    private static bool IsConversationalDialoguePrompt(string normalizedPrompt)
    {
        if (string.IsNullOrWhiteSpace(normalizedPrompt))
        {
            return false;
        }

        return ContainsAny(normalizedPrompt, ConversationalDialogueTerms);
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

/// <summary>
/// Captures prompt preflight telemetry used by heuristic risk scoring.
/// </summary>
/// <param name="Score">Prompt preflight score (0..100).</param>
/// <param name="WarningCount">Prompt preflight warning count.</param>
/// <param name="CriticalCount">Prompt preflight critical issue count.</param>
public sealed record PreflightSignalSnapshot(int Score, int WarningCount, int CriticalCount);

/// <summary>
/// Represents the risk assessment derived from preflight telemetry and historical context.
/// </summary>
/// <param name="RiskScore">Risk score from 0.0 (low risk) to 1.0 (high risk).</param>
/// <param name="ClarificationThresholdAdjustment">Adjustment applied to clarification threshold for runtime tool decisions.</param>
/// <param name="PredictiveFailureLikely">Whether correlated signals indicate elevated failure likelihood.</param>
/// <param name="RemediationSuggestion">Adaptive remediation guidance based on risk factors.</param>
/// <param name="RiskFactors">Detected risk factors used to explain the score.</param>
public sealed record PreflightRiskAssessment(
    double RiskScore,
    double ClarificationThresholdAdjustment,
    bool PredictiveFailureLikely,
    string RemediationSuggestion,
    IReadOnlyList<string> RiskFactors
);
