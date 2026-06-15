using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Registry;
using System.Text.Json;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class ToolWrapperTests
{
    [Fact]
    public async Task BuildTools_RequiredParameterValidation_IsCaseInsensitive()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["LIST-DIRECTORY"] = new ToolSpec(
                Name: "LIST-DIRECTORY",
                Description: "Lists entries",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null)
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>())
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(args, StringComparer.OrdinalIgnoreCase);
                return "ok";
            });

        var result = await tools["LIST-DIRECTORY"]("{\"Path\":\"C:\\\\repos\\\\TechToolbox\\\\Public\\\\Start_Stop\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("path"));
        Assert.Equal("C:\\repos\\TechToolbox\\Public\\Start_Stop", capturedArgs["path"]?.ToString());
    }

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

    [Fact]
    public void RunTool_ReadFile_ReturnsStructuredSummary_ForLargeFiles()
    {
        var originalThreshold = Environment.GetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS");
        var tempFile = Path.Combine(Path.GetTempPath(), $"TechToolbox-ReadFile-{Guid.NewGuid():N}.ps1");

        Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", "1000");

        try
        {
            var content = string.Join(Environment.NewLine, new[]
            {
                "function Demo-Tool {",
                "<#",
                ".SYNOPSIS",
                "    Demo summary.",
                ".DESCRIPTION",
                "    Demo description.",
                "#>",
                "    param([string]$Name)",
                "    Write-Output $Name",
                "}",
                new string('x', 1500)
            });

            File.WriteAllText(tempFile, content);

            var result = PowerShellBridge.RunTool("READ-FILE", new Dictionary<string, object?>
            {
                ["path"] = tempFile
            });

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("file-summary", doc.RootElement.GetProperty("kind").GetString());
            Assert.Equal("Demo-Tool", doc.RootElement.GetProperty("functionNames")[0].GetString());
            Assert.Contains("SYNOPSIS", doc.RootElement.GetProperty("sections").EnumerateArray().Select(x => x.GetString()));
            Assert.Equal(Path.GetFileName(tempFile), doc.RootElement.GetProperty("fileName").GetString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", originalThreshold);
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }
}
