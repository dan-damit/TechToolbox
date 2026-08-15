using System.Reflection;
using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Memory;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class ChatModeOrchestrationTests
{
    [Fact]
    public void BuildTurnPlan_OperationalPrompt_PrefersActFirstWithLowHesitation()
    {
        var plan = BuildTurnPlan(
            userPrompt: "Please fetch https://example.com release notes and summarize the key changes.",
            memory: null,
            messages: new List<AgentChatMessage>(),
            toolHistory: ["SEARCH-WEB"],
            recentToolFailures: [],
            preflightScore: 90,
            preflightWarningCount: 0,
            preflightCriticalCount: 0
        );

        var strategy = GetNestedStringProperty(plan, "Strategy");
        var hesitationLevel = GetNestedStringProperty(plan, "Hesitation", "Level");
        var isOperational = GetNestedProperty<bool>(plan, "Intent", "IsOperational");

        Assert.True(isOperational);
        Assert.Equal("ActFirst", strategy);
        Assert.Equal("Low", hesitationLevel);
    }

    [Fact]
    public void BuildTurnPlan_AmbiguousPrompt_PrefersClarifyAndHighHesitation()
    {
        var plan = BuildTurnPlan(
            userPrompt: "help with this?",
            memory: null,
            messages: new List<AgentChatMessage>(),
            toolHistory: [],
            recentToolFailures: ["SEARCH-WEB", "FETCH-URL"],
            preflightScore: 30,
            preflightWarningCount: 2,
            preflightCriticalCount: 0
        );

        var action = GetNestedStringProperty(plan, "CompassAction");
        var goal = GetNestedStringProperty(plan, "Goal");
        var strategy = GetNestedStringProperty(plan, "Strategy");
        var hesitationLevel = GetNestedStringProperty(plan, "Hesitation", "Level");
        var clarificationPrompt = GetNestedProperty<string>(plan, "Hesitation", "ClarificationPrompt");
        var ambiguity = GetNestedProperty<int>(plan, "Intent", "AmbiguityLevel");

        Assert.True(ambiguity >= 3);
        Assert.Equal("Clarify", action);
        Assert.Equal("Clarify", goal);
        Assert.Equal("AnswerFirst", strategy);
        Assert.Equal("High", hesitationLevel);
        Assert.Equal(
            "Do you want me to analyze this, plan something, or execute something?",
            clarificationPrompt
        );
    }

    [Fact]
    public void BuildTurnPlan_MixedIntent_UsesAnswerFirstAndMediumHesitation()
    {
        var plan = BuildTurnPlan(
            userPrompt: "Can you fetch release notes and summarize the main changes?",
            memory: null,
            messages: new List<AgentChatMessage>(),
            toolHistory: [],
            recentToolFailures: [],
            preflightScore: 90,
            preflightWarningCount: 0,
            preflightCriticalCount: 0
        );

        var strategy = GetNestedStringProperty(plan, "Strategy");
        var hesitationLevel = GetNestedStringProperty(plan, "Hesitation", "Level");
        var isMixedIntent = GetNestedProperty<bool>(plan, "Intent", "IsMixedIntent");

        Assert.True(isMixedIntent);
        Assert.Equal("AnswerFirst", strategy);
        Assert.Equal("Medium", hesitationLevel);
    }

    [Fact]
    public void BuildTurnPlan_FactualWebLookupWithExplicitTarget_UsesLowHesitationAndWebSignals()
    {
        var plan = BuildTurnPlan(
            userPrompt: "How is the weather in Belfast right now? Use https://weather.gov and summarize the result.",
            memory: null,
            messages: new List<AgentChatMessage>(),
            toolHistory: [],
            recentToolFailures: [],
            preflightScore: 100,
            preflightWarningCount: 0,
            preflightCriticalCount: 0
        );

        var hesitationLevel = GetNestedStringProperty(plan, "Hesitation", "Level");
        var contextualSignals = GetNestedStringListProperty(plan, "Intent", "ContextualSignals");

        Assert.Equal("Low", hesitationLevel);
        Assert.Contains(contextualSignals, s => s.Equals("explicit-web-target", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(contextualSignals, s => s.Equals("factual-lookup", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildTurnPlan_HighRiskOperationalPrompt_DoesNotUseActFirst()
    {
        var plan = BuildTurnPlan(
            userPrompt: "Please execute this and overwrite credentials now.",
            memory: null,
            messages: new List<AgentChatMessage>(),
            toolHistory: [],
            recentToolFailures: [],
            preflightScore: 90,
            preflightWarningCount: 0,
            preflightCriticalCount: 1
        );

        var strategy = GetNestedStringProperty(plan, "Strategy");
        var riskLevel = GetNestedProperty<int>(plan, "Intent", "RiskLevel");
        var action = GetNestedStringProperty(plan, "CompassAction");

        Assert.True(riskLevel >= 3);
        Assert.Equal("Escalate", action);
        Assert.Equal("AnswerFirst", strategy);
    }

    [Fact]
    public void BuildTurnPlan_StitchesContinuityAndRespectsPreferenceOverrides()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);

        try
        {
            var memoryPath = Path.Combine(tempRoot, "memory.json");
            var memory = new MemoryStore(memoryPath);
            memory.SetPreference("response_directness", "high");

            memory.AddRun(
                new RunHistory
                {
                    TimestampUtc = DateTimeOffset.UtcNow.AddMinutes(-3),
                    Status = "error",
                    Outcome = "failed",
                    Prompt = "first",
                    Error = "network timeout",
                    RunSummary = new RunSummary
                    {
                        Intent = "look up endpoint",
                        Blockers = "remote host unavailable",
                        NextBestStep = "retry with constrained query",
                    },
                }
            );

            memory.AddRun(
                new RunHistory
                {
                    TimestampUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                    Status = "success",
                    Outcome = "completed",
                    Prompt = "second",
                    RunSummary = new RunSummary
                    {
                        Intent = "collected docs successfully",
                        Blockers = string.Empty,
                        NextBestStep = string.Empty,
                    },
                }
            );

            var plan = BuildTurnPlan(
                userPrompt: "Please summarize and propose next steps.",
                memory: memory,
                messages: [new AgentChatMessage { Role = "user", Content = "I am stuck and annoyed." }],
                toolHistory: ["SEARCH-WEB", "FETCH-URL"],
                recentToolFailures: ["FETCH-URL"],
                preflightScore: 55,
                preflightWarningCount: 1,
                preflightCriticalCount: 0
            );

            var priorPreferences = GetNestedStringListProperty(plan, "Continuity", "PriorPreferences");
            var earlierFrustrations = GetNestedStringListProperty(plan, "Continuity", "EarlierFrustrations");
            var priorWarnings = GetNestedStringListProperty(plan, "Continuity", "PriorWarnings");
            var unresolvedQuestions = GetNestedStringListProperty(plan, "Continuity", "UnresolvedQuestions");
            var directness = GetNestedProperty<string>(plan, "Style", "DirectnessLevel");

            Assert.Contains(priorPreferences, p => p.Contains("response_directness=high", StringComparison.OrdinalIgnoreCase));
            Assert.NotEmpty(earlierFrustrations);
            Assert.NotEmpty(priorWarnings);
            Assert.NotEmpty(unresolvedQuestions);
            Assert.Equal("high", directness);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void BuildPromptInjection_ContainsExpectedArchitectureSections()
    {
        var plan = BuildTurnPlan(
            userPrompt: "Explain tradeoffs and suggest an action.",
            memory: null,
            messages: [new AgentChatMessage { Role = "user", Content = "Need this quickly!" }],
            toolHistory: ["SEARCH-WEB"],
            recentToolFailures: [],
            preflightScore: 70,
            preflightWarningCount: 0,
            preflightCriticalCount: 0
        );

        var orchestrationType = GetChatOrchestrationType();
        var buildPromptMethod = orchestrationType.GetMethod(
            "BuildPromptInjection",
            BindingFlags.Public | BindingFlags.Static
        );

        Assert.NotNull(buildPromptMethod);
        var promptText = (string?)buildPromptMethod!.Invoke(null, [plan]) ?? string.Empty;

        Assert.Contains("CHAT_ORCHESTRATION_CONTEXT", promptText, StringComparison.Ordinal);
        Assert.Contains("Intent Decomposition:", promptText, StringComparison.Ordinal);
        Assert.Contains("Conversation Compass:", promptText, StringComparison.Ordinal);
        Assert.Contains("Tool Hesitation Curve:", promptText, StringComparison.Ordinal);
        Assert.Contains("Micro-Context Windows:", promptText, StringComparison.Ordinal);
        Assert.Contains("Style Controls:", promptText, StringComparison.Ordinal);
        Assert.Contains("END_CHAT_ORCHESTRATION_CONTEXT", promptText, StringComparison.Ordinal);
    }

    private static object BuildTurnPlan(
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
        var orchestrationType = GetChatOrchestrationType();
        var method = orchestrationType.GetMethod(
            "BuildTurnPlan",
            BindingFlags.Public | BindingFlags.Static
        );

        Assert.NotNull(method);

        var plan = method!.Invoke(
            null,
            [
                userPrompt,
                memory,
                messages,
                toolHistory,
                recentToolFailures,
                preflightScore,
                preflightWarningCount,
                preflightCriticalCount,
            ]
        );

        Assert.NotNull(plan);
        return plan!;
    }

    private static Type GetChatOrchestrationType()
    {
        var type = typeof(AgentOrchestrator).Assembly.GetType(
            "TechToolbox.Agent.Agent.ChatModeOrchestration",
            throwOnError: false,
            ignoreCase: false
        );

        Assert.NotNull(type);
        return type!;
    }

    private static T GetNestedProperty<T>(object root, string property, string? nestedProperty = null)
    {
        var first = root.GetType().GetProperty(property, BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(first);

        var firstValue = first!.GetValue(root);
        Assert.NotNull(firstValue);

        if (string.IsNullOrWhiteSpace(nestedProperty))
        {
            return (T)firstValue!;
        }

        var nested = firstValue!.GetType().GetProperty(
            nestedProperty,
            BindingFlags.Public | BindingFlags.Instance
        );
        Assert.NotNull(nested);

        var nestedValue = nested!.GetValue(firstValue);
        Assert.NotNull(nestedValue);
        return (T)nestedValue!;
    }

    private static string GetNestedStringProperty(object root, string property, string? nestedProperty = null)
    {
        var value = GetNestedProperty<object>(root, property, nestedProperty);
        return value.ToString() ?? string.Empty;
    }

    private static IReadOnlyList<string> GetNestedStringListProperty(
        object root,
        string property,
        string nestedProperty
    )
    {
        var value = GetNestedProperty<object>(root, property, nestedProperty);
        var enumerable = value as IEnumerable<string>;
        Assert.NotNull(enumerable);
        return enumerable!.ToArray();
    }
}
