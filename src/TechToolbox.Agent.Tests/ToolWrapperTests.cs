using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Registry;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class ToolWrapperTests
{
    [Fact]
    public async Task BuildTools_AddsSignedFilePolicy_WhenToolSupportsParameter()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["Write-Thing"] = new ToolSpec(
                Name: "Write-Thing",
                Description: "Writes a file",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Path"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                    ["SignedFilePolicy"] = new ParameterSpec(Mandatory: false, Type: "string", Help: null)
                },
                Module: "TechToolbox",
                Meta: new Dictionary<string, object?>())
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "strip",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(args, StringComparer.OrdinalIgnoreCase);
                return "ok";
            });

        var result = await tools["Write-Thing"]("{\"Path\":\"abc.ps1\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.Equal("strip", capturedArgs!["SignedFilePolicy"]?.ToString());
    }

    [Fact]
    public async Task BuildTools_AutoConfirmsDestructiveTool_WhenAuthorized()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["Remove-Thing"] = new ToolSpec(
                Name: "Remove-Thing",
                Description: "Deletes a thing",
                Parameters: new Dictionary<string, ParameterSpec>(),
                Module: "TechToolbox",
                Meta: new Dictionary<string, object?>())
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: true,
            signedFilePolicy: "ignore",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(args, StringComparer.OrdinalIgnoreCase);
                return "ok";
            });

        var result = await tools["Remove-Thing"]("{}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("__confirm_destructive"));
        Assert.Equal("True", capturedArgs["__confirm_destructive"]?.ToString());
    }
}
