using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Memory;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class HeuristicScoringEngineTests
{
    [Fact]
    public void Evaluate_UsesGoalFitAndSessionContextBoostsForReadFile()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "READ-FILE",
            ToolArgs = new Dictionary<string, object?> { ["path"] = "C:/repo/app/config.json" },
        };

        var evaluation = engine.Evaluate(
            "Please summarize the contents of C:/repo/app/config.json",
            decision,
            recentToolFailures: [],
            lastSuccessfulTool: "READ-FILE",
            lastSuccessfulTargetHint: "C:/repo/app/config.json"
        );

        Assert.False(evaluation.NeedsClarification);
        Assert.True(evaluation.Confidence >= 0.78, $"Expected confidence to be boosted, but got {evaluation.Confidence}");
    }

    [Fact]
    public void Evaluate_DoesNotAskForClarification_ForRoutineInvestigationPrompt()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "READ-FILE",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var evaluation = engine.Evaluate(
            "Investigate the issue and figure out what is wrong.",
            decision,
            recentToolFailures: []
        );

        Assert.False(evaluation.NeedsClarification);
        Assert.True(
            evaluation.Confidence >= 0.66,
            $"Expected confidence to remain above the clarification threshold, but got {evaluation.Confidence}"
        );
    }

    [Fact]
    public void Evaluate_DoesNotAskForClarification_AfterRepeatedFailuresOnTroubleshootingPrompt()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "READ-FILE",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var evaluation = engine.Evaluate(
            "Investigate the issue and figure out what is wrong.",
            decision,
            recentToolFailures: ["READ-FILE", "READ-FILE"]
        );

        Assert.False(evaluation.NeedsClarification);
        Assert.True(
            evaluation.Confidence >= 0.66,
            $"Expected confidence to remain above the clarification threshold, but got {evaluation.Confidence}"
        );
    }

    [Fact]
    public void Evaluate_UsesLowerClarificationThreshold_ForLowRiskInvestigationTools()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "SEARCH-WEB",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var evaluation = engine.Evaluate(
            "Investigate issue quickly today",
            decision,
            recentToolFailures: ["SEARCH-WEB", "SEARCH-WEB", "SEARCH-WEB"]
        );

        Assert.InRange(evaluation.Confidence, 0.60, 0.66);
        Assert.False(evaluation.NeedsClarification);
    }

    [Fact]
    public void Evaluate_ProducesStatefulClarificationMessage_WithSpecificMissingArgKey()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "SEARCH-WEB",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var evaluation = engine.Evaluate(
            "Help",
            decision,
            recentToolFailures: [],
            clarificationCycles: 1
        );

        Assert.True(evaluation.NeedsClarification);
        Assert.Contains("attempt 2", evaluation.ClarificationMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("'query'", evaluation.ClarificationMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Evaluate_UsesSessionCarryover_ForListDirectoryToReadFile()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "LIST-DIRECTORY",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var withoutCarryover = engine.Evaluate(
            "Review logs",
            decision,
            recentToolFailures: []
        );

        var withCarryover = engine.Evaluate(
            "Review logs",
            decision,
            recentToolFailures: [],
            lastSuccessfulTool: "SEARCH-WEB",
            lastSuccessfulTargetHint: "logs"
        );

        Assert.True(withCarryover.Confidence > withoutCarryover.Confidence);
    }

    [Fact]
    public void Evaluate_ResetsFailurePenalty_WhenNewConcreteTargetHintIsProvided()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "READ-FILE",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var withoutNewHint = engine.Evaluate(
            "Investigate the issue and figure out what is wrong.",
            decision,
            recentToolFailures: ["READ-FILE", "READ-FILE"]
        );

        var withNewHint = engine.Evaluate(
            "Investigate the issue and figure out what is wrong.",
            decision,
            recentToolFailures: ["READ-FILE", "READ-FILE"],
            hasNewConcreteTargetHint: true
        );

        Assert.True(withNewHint.Confidence > withoutNewHint.Confidence);
    }

    [Fact]
    public void EvaluatePreflightRisk_IncreasesWeight_ForHighImpactContext()
    {
        var engine = new HeuristicScoringEngine();

        var lowImpact = engine.EvaluatePreflightRisk(
            "Summarize the README quickly",
            new PreflightSignalSnapshot(Score: 70, WarningCount: 1, CriticalCount: 0)
        );

        var highImpact = engine.EvaluatePreflightRisk(
            "Deploy database migration to production",
            new PreflightSignalSnapshot(Score: 70, WarningCount: 1, CriticalCount: 0)
        );

        Assert.True(highImpact.RiskScore > lowImpact.RiskScore);
        Assert.True(highImpact.ClarificationThresholdAdjustment >= lowImpact.ClarificationThresholdAdjustment);
    }

    [Fact]
    public void EvaluatePreflightRisk_ReducesRisk_WhenHistoricalRunsAreStable()
    {
        var engine = new HeuristicScoringEngine();

        List<RunHistory> history =
        [
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 72, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 70, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 71, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 69, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 73, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
            new() { Status = "success", Outcome = "completed", PromptPreflightScore = 70, PromptPreflightWarningCount = 1, PromptPreflightCriticalCount = 0 },
        ];

        var withoutHistory = engine.EvaluatePreflightRisk(
            "Review config before run",
            new PreflightSignalSnapshot(Score: 70, WarningCount: 1, CriticalCount: 0)
        );

        var withHistory = engine.EvaluatePreflightRisk(
            "Review config before run",
            new PreflightSignalSnapshot(Score: 70, WarningCount: 1, CriticalCount: 0),
            history
        );

        Assert.True(withHistory.RiskScore < withoutHistory.RiskScore);
        Assert.Contains(
            withHistory.RiskFactors,
            factor => factor.Contains("historical runs", StringComparison.OrdinalIgnoreCase)
        );
    }

    [Fact]
    public void Evaluate_AppendsAdaptiveRemediation_WhenClarificationIsNeededUnderHighRisk()
    {
        var engine = new HeuristicScoringEngine();
        var decision = new AgentDecision
        {
            NeedsTool = true,
            ToolName = "SEARCH-WEB",
            ToolArgs = new Dictionary<string, object?>(),
        };

        var preflightRisk = engine.EvaluatePreflightRisk(
            "Investigate cpu and disk i/o issue during production deploy",
            new PreflightSignalSnapshot(Score: 40, WarningCount: 3, CriticalCount: 1)
        );

        var evaluation = engine.Evaluate(
            "Help",
            decision,
            recentToolFailures: [],
            preflightRisk: preflightRisk
        );

        Assert.True(evaluation.NeedsClarification);
        Assert.Contains(
            "Suggested preflight remediation",
            evaluation.ClarificationMessage,
            StringComparison.OrdinalIgnoreCase
        );
    }
}
