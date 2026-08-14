using System.Reflection;
using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Configuration;
using TechToolbox.Agent.Registry;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class LlmClientTests
{
    [Theory]
    [InlineData(null, 4096)]
    [InlineData("not-a-number", 4096)]
    [InlineData("64", 128)]
    [InlineData("256", 256)]
    [InlineData("20000", 16384)]
    [InlineData("-1", -1)]
    [InlineData("-2", -2)]
    public void GetNumPredict_RespectsEnvironmentOverride_WithBounds(string? rawValue, int expected)
    {
        var previous = Environment.GetEnvironmentVariable("TT_AGENT_LLM_NUM_PREDICT");

        try
        {
            Environment.SetEnvironmentVariable("TT_AGENT_LLM_NUM_PREDICT", rawValue);
            var actual = InvokeGetNumPredict();
            Assert.Equal(expected, actual);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_LLM_NUM_PREDICT", previous);
        }
    }

    [Fact]
    public void BuildInitialMessages_IncludesThinkingGuidance_WhenThinkingModeIsOn()
    {
        var messages = PromptBuilder.BuildInitialMessages(
            "Investigate the failing workflow",
            new Dictionary<string, ToolSpec>(),
            null,
            0,
            "analyze",
            "markdown",
            "on"
        );

        Assert.Contains("deeper reasoning", messages[0].Content, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildInitialMessages_DoesNotIncludeThinkingGuidance_WhenThinkingModeIsOff()
    {
        var messages = PromptBuilder.BuildInitialMessages(
            "Investigate the failing workflow",
            new Dictionary<string, ToolSpec>(),
            null,
            0,
            "analyze",
            "markdown",
            "off"
        );

        Assert.DoesNotContain("deeper reasoning", messages[0].Content, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildInitialMessages_ChatMode_IsSandboxedAndClarificationFirst()
    {
        var messages = PromptBuilder.BuildInitialMessages(
            "Help me decide what to do next",
            new Dictionary<string, ToolSpec>
            {
                ["Echo"] = new ToolSpec(
                    "Echo",
                    "Test tool",
                    new Dictionary<string, ParameterSpec>(),
                    "TestModule",
                    new Dictionary<string, object?>()
                ),
            },
            null,
            AgentMode.TechToolbox,
            null,
            0,
            "chat",
            "markdown",
            "auto"
        );

        Assert.Contains("sandboxed and read-only", messages[0].Content, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(
            "Do you want me to analyze this, plan something, or execute something?",
            messages[0].Content,
            StringComparison.OrdinalIgnoreCase
        );
        Assert.DoesNotContain("WRITE-FILE", messages[0].Content, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Execution mode: chat", messages[1].Content, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BuildInitialMessages_ChatMode_PrefersWebSearchAndNaturalConversation()
    {
        var messages = PromptBuilder.BuildInitialMessages(
            "What is the current weather in Green Bay, Wisconsin?",
            new Dictionary<string, ToolSpec>
            {
                ["SEARCH-WEB"] = new ToolSpec(
                    "SEARCH-WEB",
                    "Searches the web",
                    new Dictionary<string, ParameterSpec>(),
                    "TestModule",
                    new Dictionary<string, object?>()
                ),
                ["FETCH-URL"] = new ToolSpec(
                    "FETCH-URL",
                    "Fetches a URL",
                    new Dictionary<string, ParameterSpec>(),
                    "TestModule",
                    new Dictionary<string, object?>()
                ),
            },
            null,
            AgentMode.TechToolbox,
            null,
            0,
            "chat",
            "markdown",
            "auto"
        );

        var promptText = messages[0].Content + messages[1].Content;

        Assert.Contains("web search", promptText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("natural conversational", promptText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("SEARCH-WEB", promptText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("FETCH-URL", promptText, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AgentConfiguration_DefaultsToChatExecutionMode()
    {
        var config = new TechToolbox.Agent.Configuration.AgentConfiguration();

        Assert.Equal("chat", config.ExecutionMode);
    }

    private static int InvokeGetNumPredict()
    {
        var method = typeof(LlmClient).GetMethod(
            "GetNumPredict",
            BindingFlags.NonPublic | BindingFlags.Static
        );

        Assert.NotNull(method);
        var result = method!.Invoke(null, null);
        Assert.NotNull(result);

        return (int)result!;
    }
}
