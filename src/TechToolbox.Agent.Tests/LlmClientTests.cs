using System.Reflection;
using TechToolbox.Agent.Agent;
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
