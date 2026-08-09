using TechToolbox.Agent.Agent;
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
}
