using System.Text;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Memory;

namespace TechToolbox.Agent.Agent;

internal enum ConversationCompassAction
{
    Clarify,
    Answer,
    Propose,
    Challenge,
    Summarize,
    Escalate,
    Close,
}

internal enum ConversationalGoal
{
    Clarify,
    Inform,
    Solve,
    Reassure,
    Challenge,
    Redirect,
    Escalate,
    Close,
}

internal enum ResponseStrategy
{
    AnswerFirst,
    ActFirst,
}

internal enum ToolHesitationLevel
{
    Low,
    Medium,
    High,
}

internal sealed record PersonaProfile(
    string Tone,
    string Pacing,
    string EmotionalTemperature,
    string Assertiveness,
    string Curiosity,
    string HumorTolerance,
    string TechnicalDepthBias
);

internal sealed record IntentDecomposition(
    string ExplicitIntent,
    string ImplicitIntent,
    string LatentIntent,
    IReadOnlyList<string> Constraints,
    IReadOnlyList<string> ContextualSignals,
    int AmbiguityLevel,
    int RiskLevel,
    bool IsMixedIntent,
    bool IsOperational
);

internal sealed record ContinuityContext(
    IReadOnlyList<string> UnresolvedQuestions,
    IReadOnlyList<string> PriorPreferences,
    IReadOnlyList<string> EarlierFrustrations,
    IReadOnlyList<string> EarlierSuccesses,
    IReadOnlyList<string> PriorWarnings
);

internal sealed record MicroContextWindows(
    string TopicWindow,
    string PreferenceWindow,
    string ConstraintWindow,
    string ToolWindow,
    string EmotionWindow
);

internal sealed record StyleControls(
    string VerbosityTarget,
    string ExplanationDepth,
    string DirectnessLevel,
    string QuestionAskingTendency
);

internal sealed record ToolHesitationAssessment(
    ToolHesitationLevel Level,
    int Score,
    string Reason,
    string ClarificationPrompt
);

internal sealed record ChatTurnPlan(
    PersonaProfile Persona,
    IntentDecomposition Intent,
    ContinuityContext Continuity,
    MicroContextWindows Windows,
    ConversationCompassAction CompassAction,
    ConversationalGoal Goal,
    ResponseStrategy Strategy,
    StyleControls Style,
    ToolHesitationAssessment Hesitation
);

internal static class ChatModeOrchestration
{
    private const string ExplicitWebTargetSignal = "explicit-web-target";
    private const string FactualLookupSignal = "factual-lookup";

    private static readonly string[] ActionVerbs =
    [
        "run", "execute", "create", "write", "edit", "modify", "fix", "update", "open", "search", "fetch", "look up"
    ];

    private static readonly string[] AmbiguousTerms = ["help", "something", "stuff", "this", "that", "whatever"];
    private static readonly string[] ConstraintMarkers = ["must", "only", "do not", "don't", "without", "exactly", "required", "constraint"];
    private static readonly string[] UrgencyMarkers = ["urgent", "asap", "immediately", "right now", "quickly"];
    private static readonly string[] FrustrationMarkers = ["frustrated", "annoyed", "stuck", "not working", "broken", "again"];
    private static readonly string[] TechnicalMarkers = ["schema", "json", "api", "orchestrator", "pipeline", "module", "deterministic", "test", "refactor"];
    private static readonly string[] FactualLookupMarkers = ["weather", "temperature", "forecast", "current", "currently", "today", "now", "latest", "present moment", "news", "price"];
    private static readonly string[] WebTargetMarkers = ["http://", "https://", "website", "web site", "domain", "url", "weather.gov"];

    // Persona is stable across turns; it is not regenerated per turn.
    private static readonly PersonaProfile DefaultPersona = new(
        Tone: "friendly, direct, technically competent",
        Pacing: "steady, non-rushed",
        EmotionalTemperature: "calm, confident",
        Assertiveness: "medium",
        Curiosity: "asks clarifying questions when needed",
        HumorTolerance: "light, optional",
        TechnicalDepthBias: "high when user is technical"
    );

    public static ChatTurnPlan BuildTurnPlan(
        string userPrompt,
        MemoryStore? memory,
        IReadOnlyList<AgentChatMessage> messages,
        IReadOnlyList<string> toolHistory,
        IReadOnlyList<string> recentToolFailures,
        int preflightScore,
        int preflightWarningCount,
        int preflightCriticalCount
    )
    {
        var intent = DecomposeIntent(userPrompt, memory, preflightScore, preflightCriticalCount);
        var continuity = BuildContinuityContext(memory);
        var windows = BuildMicroContextWindows(userPrompt, intent, continuity, toolHistory, messages);
        var compassAction = ChooseCompassAction(intent, continuity, preflightWarningCount, preflightCriticalCount);
        var goal = ChooseGoal(compassAction, intent);
        var strategy = ChooseResponseStrategy(intent, compassAction);
        var style = ChooseStyleControls(userPrompt, intent, memory);
        var hesitation = EvaluateToolHesitation(
            intent,
            recentToolFailures,
            preflightScore,
            preflightCriticalCount,
            strategy,
            toolHistory.Count
        );

        return new ChatTurnPlan(
            Persona: DefaultPersona,
            Intent: intent,
            Continuity: continuity,
            Windows: windows,
            CompassAction: compassAction,
            Goal: goal,
            Strategy: strategy,
            Style: style,
            Hesitation: hesitation
        );
    }

    public static string BuildPromptInjection(ChatTurnPlan plan)
    {
        var sb = new StringBuilder();
        sb.AppendLine("CHAT_ORCHESTRATION_CONTEXT");
        sb.AppendLine("Use this deterministic chat turn context before choosing tools or final answer.");
        sb.AppendLine();
        sb.AppendLine("Persona:");
        sb.AppendLine($"- tone: {plan.Persona.Tone}");
        sb.AppendLine($"- pacing: {plan.Persona.Pacing}");
        sb.AppendLine($"- emotional temperature: {plan.Persona.EmotionalTemperature}");
        sb.AppendLine($"- assertiveness: {plan.Persona.Assertiveness}");
        sb.AppendLine($"- curiosity: {plan.Persona.Curiosity}");
        sb.AppendLine($"- humor tolerance: {plan.Persona.HumorTolerance}");
        sb.AppendLine($"- technical depth bias: {plan.Persona.TechnicalDepthBias}");
        sb.AppendLine();
        sb.AppendLine("Intent Decomposition:");
        sb.AppendLine($"- explicit intent: {plan.Intent.ExplicitIntent}");
        sb.AppendLine($"- implicit intent: {plan.Intent.ImplicitIntent}");
        sb.AppendLine($"- latent intent: {plan.Intent.LatentIntent}");
        sb.AppendLine($"- constraints: {(plan.Intent.Constraints.Count == 0 ? "none" : string.Join(" | ", plan.Intent.Constraints))}");
        sb.AppendLine($"- contextual signals: {(plan.Intent.ContextualSignals.Count == 0 ? "neutral" : string.Join(" | ", plan.Intent.ContextualSignals))}");
        sb.AppendLine();
        sb.AppendLine("Conversation Compass:");
        sb.AppendLine($"- action: {plan.CompassAction}");
        sb.AppendLine($"- conversational goal: {plan.Goal}");
        sb.AppendLine($"- response strategy: {plan.Strategy}");
        sb.AppendLine();
        sb.AppendLine("Tool Hesitation Curve:");
        sb.AppendLine($"- hesitation level: {plan.Hesitation.Level}");
        sb.AppendLine($"- hesitation score: {plan.Hesitation.Score}");
        sb.AppendLine($"- reasoning: {plan.Hesitation.Reason}");
        sb.AppendLine();
        sb.AppendLine("Continuity Context:");
        sb.AppendLine($"- unresolved questions: {RenderList(plan.Continuity.UnresolvedQuestions)}");
        sb.AppendLine($"- prior preferences: {RenderList(plan.Continuity.PriorPreferences)}");
        sb.AppendLine($"- earlier frustrations: {RenderList(plan.Continuity.EarlierFrustrations)}");
        sb.AppendLine($"- earlier successes: {RenderList(plan.Continuity.EarlierSuccesses)}");
        sb.AppendLine($"- prior warnings: {RenderList(plan.Continuity.PriorWarnings)}");
        sb.AppendLine();
        sb.AppendLine("Micro-Context Windows:");
        sb.AppendLine($"- topic window: {plan.Windows.TopicWindow}");
        sb.AppendLine($"- preference window: {plan.Windows.PreferenceWindow}");
        sb.AppendLine($"- constraint window: {plan.Windows.ConstraintWindow}");
        sb.AppendLine($"- tool window: {plan.Windows.ToolWindow}");
        sb.AppendLine($"- emotion window: {plan.Windows.EmotionWindow}");
        sb.AppendLine();
        sb.AppendLine("Style Controls:");
        sb.AppendLine($"- verbosity target: {plan.Style.VerbosityTarget}");
        sb.AppendLine($"- explanation depth: {plan.Style.ExplanationDepth}");
        sb.AppendLine($"- directness level: {plan.Style.DirectnessLevel}");
        sb.AppendLine($"- question-asking tendency: {plan.Style.QuestionAskingTendency}");
        sb.AppendLine();
        sb.AppendLine("Output Contract Adaptation:");
        sb.AppendLine("- Preserve contract-safe formatting while allowing a natural conversational wrapper.");
        sb.AppendLine("- Avoid robotic phrasing and keep responses human-readable.");
        sb.AppendLine("END_CHAT_ORCHESTRATION_CONTEXT");
        return sb.ToString();
    }

    private static IntentDecomposition DecomposeIntent(
        string prompt,
        MemoryStore? memory,
        int preflightScore,
        int preflightCriticalCount
    )
    {
        var normalized = (prompt ?? string.Empty).Trim();
        var explicitIntent = string.IsNullOrWhiteSpace(normalized)
            ? "No explicit request detected."
            : normalized;
        var isOperational = ContainsAny(normalized, ActionVerbs);
        var isMixedIntent = normalized.Contains('?') && isOperational;

        var ambiguity = 0;
        if (normalized.Length < 25)
        {
            ambiguity += 2;
        }

        if (ContainsAny(normalized, AmbiguousTerms))
        {
            ambiguity += 2;
        }

        if (isMixedIntent)
        {
            ambiguity += 1;
        }

        var preflightTelemetryUnavailable = preflightScore == 0 && preflightCriticalCount == 0;
        var risk = preflightCriticalCount > 0
            ? 3
            : preflightTelemetryUnavailable
                ? 1
                : preflightScore < 45
                    ? 2
                    : 1;
        if (ContainsAny(normalized, ["delete", "destructive", "overwrite", "credentials", "secret"]))
        {
            risk = Math.Max(risk, 3);
        }

        var implicitIntent = isOperational
            ? "User expects practical progress with minimal back-and-forth."
            : "User expects explanation and confident guidance.";

        var recentFailure = memory?.History.LastOrDefault(h =>
            h.Status.Equals("error", StringComparison.OrdinalIgnoreCase));
        var latentIntent = recentFailure is null
            ? "Build momentum and reduce uncertainty on the next step."
            : "Avoid repeating prior failure patterns and increase reliability.";

        var constraints = ExtractConstraints(normalized);
        var contextualSignals = ExtractSignals(normalized, memory);

        return new IntentDecomposition(
            ExplicitIntent: explicitIntent,
            ImplicitIntent: implicitIntent,
            LatentIntent: latentIntent,
            Constraints: constraints,
            ContextualSignals: contextualSignals,
            AmbiguityLevel: Math.Clamp(ambiguity, 0, 5),
            RiskLevel: Math.Clamp(risk, 1, 3),
            IsMixedIntent: isMixedIntent,
            IsOperational: isOperational
        );
    }

    private static ContinuityContext BuildContinuityContext(MemoryStore? memory)
    {
        if (memory is null)
        {
            return new ContinuityContext([], [], [], [], []);
        }

        var unresolved = memory
            .History
            .Where(h => !h.Status.Equals("success", StringComparison.OrdinalIgnoreCase))
            .TakeLast(3)
            .Select(h => TruncateForPrompt(h.RunSummary?.NextBestStep ?? h.Outcome, 120))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var preferences = memory
            .Preferences
            .Take(6)
            .Select(kv => $"{kv.Key}={kv.Value}")
            .ToArray();

        var frustrations = memory
            .History
            .Where(h => h.Status.Equals("error", StringComparison.OrdinalIgnoreCase))
            .TakeLast(3)
            .Select(h => TruncateForPrompt(h.Error ?? h.Outcome, 120))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        var successes = memory
            .History
            .Where(h => h.Status.Equals("success", StringComparison.OrdinalIgnoreCase))
            .TakeLast(3)
            .Select(h => TruncateForPrompt(h.RunSummary?.Intent ?? h.Prompt, 120))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        var warnings = memory
            .History
            .Where(h => !string.IsNullOrWhiteSpace(h.RunSummary?.Blockers))
            .TakeLast(3)
            .Select(h => TruncateForPrompt(h.RunSummary!.Blockers, 120))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();

        return new ContinuityContext(unresolved, preferences, frustrations, successes, warnings);
    }

    private static MicroContextWindows BuildMicroContextWindows(
        string prompt,
        IntentDecomposition intent,
        ContinuityContext continuity,
        IReadOnlyList<string> toolHistory,
        IReadOnlyList<AgentChatMessage> messages
    )
    {
        var topicWindow = TruncateForPrompt(prompt, 220);
        var preferenceWindow = continuity.PriorPreferences.Count == 0
            ? "none"
            : string.Join(" | ", continuity.PriorPreferences.Take(4));
        var constraintWindow = intent.Constraints.Count == 0
            ? "none"
            : string.Join(" | ", intent.Constraints.Take(4));
        var toolWindow = toolHistory.Count == 0
            ? "none"
            : string.Join(" -> ", toolHistory.TakeLast(5));

        var recentText = string.Join(
            " ",
            messages
                .TakeLast(4)
                .Select(m => m.Content)
                .Where(s => !string.IsNullOrWhiteSpace(s))
        );
        var emotionWindow = InferEmotionWindow(recentText, intent.ContextualSignals);

        return new MicroContextWindows(topicWindow, preferenceWindow, constraintWindow, toolWindow, emotionWindow);
    }

    private static ConversationCompassAction ChooseCompassAction(
        IntentDecomposition intent,
        ContinuityContext continuity,
        int preflightWarningCount,
        int preflightCriticalCount
    )
    {
        if (preflightCriticalCount > 0 || intent.RiskLevel >= 3)
            return ConversationCompassAction.Escalate;

        if (intent.AmbiguityLevel >= 3)
            return ConversationCompassAction.Clarify;

        if (intent.IsMixedIntent)
            return ConversationCompassAction.Propose;

        if (continuity.UnresolvedQuestions.Count >= 2)
            return ConversationCompassAction.Summarize;

        if (preflightWarningCount >= 3)
            return ConversationCompassAction.Challenge;

        if (Regex.IsMatch(intent.ExplicitIntent, @"\bthanks|done|that's all|close\b", RegexOptions.IgnoreCase))
            return ConversationCompassAction.Close;

        return intent.IsOperational ? ConversationCompassAction.Propose : ConversationCompassAction.Answer;
    }

    private static ConversationalGoal ChooseGoal(
        ConversationCompassAction action,
        IntentDecomposition intent
    )
    {
        return action switch
        {
            ConversationCompassAction.Clarify => ConversationalGoal.Clarify,
            ConversationCompassAction.Answer => intent.ContextualSignals.Any(s => s.Contains("frustration", StringComparison.OrdinalIgnoreCase))
                ? ConversationalGoal.Reassure
                : ConversationalGoal.Inform,
            ConversationCompassAction.Propose => ConversationalGoal.Solve,
            ConversationCompassAction.Challenge => ConversationalGoal.Challenge,
            ConversationCompassAction.Summarize => ConversationalGoal.Redirect,
            ConversationCompassAction.Escalate => ConversationalGoal.Escalate,
            ConversationCompassAction.Close => ConversationalGoal.Close,
            _ => ConversationalGoal.Inform,
        };
    }

    private static ResponseStrategy ChooseResponseStrategy(
        IntentDecomposition intent,
        ConversationCompassAction action
    )
    {
        if (action is ConversationCompassAction.Clarify or ConversationCompassAction.Answer)
            return ResponseStrategy.AnswerFirst;

        var hasExplicitWebTarget = HasSignal(intent.ContextualSignals, ExplicitWebTargetSignal);
        var isConcreteLowRiskOperational =
            intent.IsOperational
            && intent.AmbiguityLevel <= 1
            && intent.RiskLevel <= 1
            && (!intent.IsMixedIntent || hasExplicitWebTarget);

        if (isConcreteLowRiskOperational)
            return ResponseStrategy.ActFirst;

        return ResponseStrategy.AnswerFirst;
    }

    private static StyleControls ChooseStyleControls(
        string prompt,
        IntentDecomposition intent,
        MemoryStore? memory
    )
    {
        var verbosity = "medium";
        var depth = "medium-high";
        var directness = "medium-high";
        var questions = "medium";

        if (prompt.Length < 40)
            verbosity = "short";

        if (intent.IsOperational && intent.AmbiguityLevel <= 1)
            questions = "low";

        if (intent.AmbiguityLevel >= 3)
            questions = "high";

        if (ContainsAny(prompt, TechnicalMarkers))
        {
            depth = "deep";
            verbosity = verbosity == "short" ? "medium" : verbosity;
        }

        if (memory?.Preferences.TryGetValue("response_directness", out var directnessOverride) == true)
        {
            var parsed = (directnessOverride?.ToString() ?? string.Empty).Trim().ToLowerInvariant();
            if (parsed is "low" or "medium" or "high" or "medium-high")
            {
                directness = parsed;
            }
        }

        return new StyleControls(verbosity, depth, directness, questions);
    }

    private static ToolHesitationAssessment EvaluateToolHesitation(
        IntentDecomposition intent,
        IReadOnlyList<string> recentToolFailures,
        int preflightScore,
        int preflightCriticalCount,
        ResponseStrategy strategy,
        int historicalToolUsageCount
    )
    {
        var hasExplicitWebTarget = HasSignal(intent.ContextualSignals, ExplicitWebTargetSignal);
        var isFactualLookup = HasSignal(intent.ContextualSignals, FactualLookupSignal);

        var score = 0;
        score += intent.AmbiguityLevel * 18;
        score += intent.RiskLevel * 14;
        score += intent.IsMixedIntent ? 10 : 0;
        score += preflightCriticalCount > 0 ? 25 : 0;
        score += preflightScore < 50 ? 12 : 0;
        score += Math.Min(recentToolFailures.Count, 3) * 8;
        score += historicalToolUsageCount >= 6 ? 6 : 0;
        score += strategy == ResponseStrategy.AnswerFirst ? 8 : -6;

        if (hasExplicitWebTarget && isFactualLookup && intent.RiskLevel <= 1)
        {
            // Fast path for concrete low-risk factual web lookups.
            score -= 30;
        }

        score = Math.Clamp(score, 0, 100);

        var level = score >= 65
            ? ToolHesitationLevel.High
            : score >= 40
                ? ToolHesitationLevel.Medium
                : ToolHesitationLevel.Low;

        var reason = level switch
        {
            ToolHesitationLevel.High => "High ambiguity/risk or repeated tool friction suggests clarification before acting.",
            ToolHesitationLevel.Medium => "Mixed intent suggests a brief answer or scope-check before tool use.",
            _ when hasExplicitWebTarget && isFactualLookup => "Concrete low-risk factual web target detected; proceed with targeted lookup.",
            _ => "Intent is concrete enough to proceed with a lightweight operational step.",
        };

        var clarificationPrompt = level switch
        {
            ToolHesitationLevel.High => "Do you want me to analyze this, plan something, or execute something?",
            ToolHesitationLevel.Medium => "I can proceed, but do you want a quick explanation first or should I run a targeted lookup now?",
            _ => string.Empty,
        };

        return new ToolHesitationAssessment(level, score, reason, clarificationPrompt);
    }

    private static string InferEmotionWindow(string recentText, IReadOnlyList<string> contextualSignals)
    {
        if (contextualSignals.Any(s => s.Contains("frustration", StringComparison.OrdinalIgnoreCase)))
            return "frustrated/blocked";

        if (contextualSignals.Any(s => s.Contains("urgency", StringComparison.OrdinalIgnoreCase)))
            return "urgent and task-focused";

        if (contextualSignals.Any(s => s.Contains("excitement", StringComparison.OrdinalIgnoreCase)))
            return "positive and engaged";

        if (recentText.Contains("?", StringComparison.Ordinal))
            return "curious and exploratory";

        return "neutral";
    }

    private static IReadOnlyList<string> ExtractConstraints(string text)
    {
        var constraints = ConstraintMarkers
            .Where(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase))
            .Select(marker => $"contains '{marker}'")
            .ToList();

        var lineMatches = Regex.Matches(text, @"\b(do not|don't|must|only|without)\b[^\n\r.?!]{0,80}", RegexOptions.IgnoreCase);
        foreach (Match match in lineMatches)
        {
            var candidate = match.Value.Trim();
            if (!string.IsNullOrWhiteSpace(candidate))
            {
                constraints.Add(TruncateForPrompt(candidate, 90));
            }
        }

        return constraints
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToArray();
    }

    private static IReadOnlyList<string> ExtractSignals(string text, MemoryStore? memory)
    {
        List<string> signals = [];
        if (ContainsAny(text, UrgencyMarkers))
            signals.Add("urgency");
        if (ContainsAny(text, FrustrationMarkers))
            signals.Add("frustration");
        if (Regex.IsMatch(text, "!{1,}", RegexOptions.None))
            signals.Add("excitement");
        if (ContainsAny(text, TechnicalMarkers))
            signals.Add("technical-depth requested");
        if (ContainsAny(text, WebTargetMarkers))
            signals.Add(ExplicitWebTargetSignal);
        if (ContainsAny(text, FactualLookupMarkers))
            signals.Add(FactualLookupSignal);

        var recentErrorCount = memory?.History.TakeLast(4)
            .Count(h => h.Status.Equals("error", StringComparison.OrdinalIgnoreCase)) ?? 0;
        if (recentErrorCount >= 2)
            signals.Add("recent retry fatigue");

        return signals.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool HasSignal(IReadOnlyList<string> signals, string signal)
    {
        return signals.Any(s => string.Equals(s, signal, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsAny(string text, IEnumerable<string> terms)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (var term in terms)
        {
            if (text.Contains(term, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string TruncateForPrompt(string value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var trimmed = value.Trim();
        return trimmed.Length <= maxChars ? trimmed : trimmed[..maxChars] + "...";
    }

    private static string RenderList(IReadOnlyList<string> values)
    {
        return values.Count == 0
            ? "none"
            : string.Join(" | ", values.Where(v => !string.IsNullOrWhiteSpace(v)).Take(5));
    }
}
