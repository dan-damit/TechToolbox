using System.Text.Json;
using TechToolbox.Agent.Agent;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Registry;
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
                    ["path"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        var result = await tools["LIST-DIRECTORY"]
            ("{\"Path\":\"C:\\\\repos\\\\TechToolbox\\\\Public\\\\Start_Stop\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("path"));
        Assert.Equal(
            "C:\\repos\\TechToolbox\\Public\\Start_Stop",
            capturedArgs["path"]?.ToString()
        );
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
                    ["SignedFilePolicy"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "string",
                        Help: null
                    ),
                },
                Module: "TechToolbox",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "strip",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        var result = await tools["Write-Thing"]("{\"Path\":\"abc.ps1\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.Equal("strip", capturedArgs!["SignedFilePolicy"]?.ToString());
    }

    [Fact]
    public async Task BuildTools_PassesAllowedFetchHosts_ForFetchTool()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["FETCH-URL"] = new ToolSpec(
                Name: "FETCH-URL",
                Description: "Fetches URL",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["url"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            allowedFetchHosts: new[] { "learn.microsoft.com", "api.github.com" },
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        var result = await tools["FETCH-URL"]("{\"url\":\"https://learn.microsoft.com\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("__allowed_fetch_hosts"));

        var hosts = Assert.IsType<string[]>(capturedArgs["__allowed_fetch_hosts"]);
        Assert.Contains("learn.microsoft.com", hosts, StringComparer.OrdinalIgnoreCase);
        Assert.Contains("api.github.com", hosts, StringComparer.OrdinalIgnoreCase);
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
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: true,
            signedFilePolicy: "ignore",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        var result = await tools["Remove-Thing"]("{}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("__confirm_destructive"));
        Assert.Equal("True", capturedArgs["__confirm_destructive"]?.ToString());
    }

    [Fact]
    public async Task BuildTools_UsesIToolExecutor_WhenProvided()
    {
        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["LIST-DIRECTORY"] = new ToolSpec(
                Name: "LIST-DIRECTORY",
                Description: "Lists entries",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var fakeExecutor = new FakeToolExecutor();
        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            executor: fakeExecutor
        );

        var result = await tools["LIST-DIRECTORY"]("{\"path\":\"C:\\\\repos\\\\TechToolbox\"}");

        Assert.Equal("ok-from-interface", result);
        Assert.Single(fakeExecutor.Calls);
        Assert.Equal("LIST-DIRECTORY", fakeExecutor.Calls[0].ToolName);
    }

    [Fact]
    public void RunTool_ReadFile_ReturnsStructuredSummary_ForLargeFiles()
    {
        var originalThreshold = Environment.GetEnvironmentVariable(
            "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS"
        );
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-{Guid.NewGuid():N}.ps1"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", "1000");

        try
        {
            var content = string.Join(
                Environment.NewLine,
                new[]
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
                    new string('x', 1500),
                }
            );

            File.WriteAllText(tempFile, content);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("file-summary", doc.RootElement.GetProperty("kind").GetString());
            Assert.Equal("Demo-Tool", doc.RootElement.GetProperty("functionNames")[0].GetString());
            Assert.Contains(
                "SYNOPSIS",
                doc.RootElement.GetProperty("sections").EnumerateArray().Select(x => x.GetString())
            );
            Assert.Equal(
                Path.GetFileName(tempFile),
                doc.RootElement.GetProperty("fileName").GetString()
            );
            Assert.DoesNotContain(
                doc.RootElement.GetProperty("tail")
                    .EnumerateArray()
                    .Select(x => x.GetString() ?? string.Empty),
                line =>
                    line.Contains("SIG # Begin signature block", StringComparison.OrdinalIgnoreCase)
            );
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS",
                originalThreshold
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_ReturnsRequestedChunk_ByLineRange()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-Chunk-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var lines = Enumerable.Range(1, 12).Select(i => $"line-{i}");
            File.WriteAllLines(tempFile, lines);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["startLine"] = 4,
                    ["endLine"] = 7,
                }
            );

            var text = Assert.IsType<string>(result);
            Assert.Equal(
                string.Join(Environment.NewLine, new[] { "line-4", "line-5", "line-6", "line-7" }),
                text
            );
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_SummaryIncludesChunkingHintsAndVerificationChecklist()
    {
        var originalThreshold = Environment.GetEnvironmentVariable(
            "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS"
        );
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-SummaryHints-{Guid.NewGuid():N}.ps1"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", "1000");

        try
        {
            var content = string.Join(
                Environment.NewLine,
                new[]
                {
                    "function Demo-Tool {",
                    "    [CmdletBinding()]",
                    "    param([string]$Name)",
                    "    Write-Output $Name",
                    "}",
                    new string('x', 2000),
                }
            );

            File.WriteAllText(tempFile, content);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("file-summary", doc.RootElement.GetProperty("kind").GetString());
            Assert.True(doc.RootElement.GetProperty("suggestedChunks").GetArrayLength() > 0);
            Assert.True(doc.RootElement.GetProperty("verificationChecklist").GetArrayLength() > 0);
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS",
                originalThreshold
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_UsesDefaultSummaryThreshold_WhenEnvVarUnset()
    {
        var originalThreshold = Environment.GetEnvironmentVariable(
            "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS"
        );
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-DefaultThreshold-{Guid.NewGuid():N}.txt"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", null);

        try
        {
            File.WriteAllText(tempFile, new string('x', 13_000));

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);
            Assert.Equal("file-summary", doc.RootElement.GetProperty("kind").GetString());
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS",
                originalThreshold
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_SummaryIncludesPublicSymbolHints_ForCSharpFiles()
    {
        var originalThreshold = Environment.GetEnvironmentVariable(
            "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS"
        );
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-CSharpSummary-{Guid.NewGuid():N}.cs"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS", "1000");

        try
        {
            var content = string.Join(
                Environment.NewLine,
                new[]
                {
                    "public class DemoService",
                    "{",
                    "    public DemoService() { }",
                    "    public string Run(string input) => input;",
                    "}",
                    new string('x', 3000),
                }
            );

            File.WriteAllText(tempFile, content);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("file-summary", doc.RootElement.GetProperty("kind").GetString());
            var hints = doc.RootElement
                .GetProperty("publicSymbolHints")
                .EnumerateArray()
                .Select(x => x.GetString() ?? string.Empty)
                .ToArray();

            Assert.Contains(hints, h => h.Contains("public class DemoService", StringComparison.Ordinal));
            Assert.Contains(hints, h => h.Contains("public method Run", StringComparison.Ordinal));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS",
                originalThreshold
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    // ---------------------------------------------------------------------------
    // WRITE-FILE destructive-overwrite safety tests
    // ---------------------------------------------------------------------------

    [Fact]
    public void IsDestructive_WriteFile_ReturnsTrue()
    {
        Assert.True(Safety.IsDestructive("WRITE-FILE"));
        Assert.True(Safety.IsDestructive("write-file"));
    }

    [Fact]
    public async Task BuildTools_AutoConfirmsWriteFile_WhenDestructiveConfirmed()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["WRITE-FILE"] = new ToolSpec(
                Name: "WRITE-FILE",
                Description: "Writes a file",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                    ["content"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: true,
            signedFilePolicy: "ignore",
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        await tools["WRITE-FILE"]("{\"path\":\"c:\\\\temp\\\\test.txt\",\"content\":\"hello\"}");

        Assert.NotNull(capturedArgs);
        Assert.True(capturedArgs!.ContainsKey("__confirm_destructive"));
        Assert.Equal("True", capturedArgs["__confirm_destructive"]?.ToString());
    }

    [Fact]
    public void RunTool_WriteFile_CreatesNewFile_WhenDestructiveConfirmed()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteNew-{Guid.NewGuid():N}.txt"
        );

        try
        {
            Assert.False(File.Exists(tempFile));

            var result = PowerShellBridge.RunTool(
                "WRITE-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["content"] = "new content",
                    ["__confirm_destructive"] = true,
                }
            );

            Assert.Equal("ok", result);
            Assert.Equal("new content", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_WriteFile_BlocksOverwrite_WhenDestructiveNotConfirmed()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteBlock-{Guid.NewGuid():N}.txt"
        );
        File.WriteAllText(tempFile, "original");

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                PowerShellBridge.RunTool(
                    "WRITE-FILE",
                    new Dictionary<string, object?>
                    {
                        ["path"] = tempFile,
                        ["content"] = "overwritten",
                    }
                )
            );

            Assert.Contains(
                "__confirm_destructive=true",
                ex.Message,
                StringComparison.OrdinalIgnoreCase
            );
            Assert.Equal("original", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_WriteFile_AllowsOverwrite_WhenDestructiveConfirmed()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteAllow-{Guid.NewGuid():N}.txt"
        );
        File.WriteAllText(tempFile, "original");

        try
        {
            var result = PowerShellBridge.RunTool(
                "WRITE-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["content"] = "overwritten",
                    ["__confirm_destructive"] = true,
                }
            );

            Assert.Equal("ok", result);
            Assert.Equal("overwritten", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_WriteFile_BlocksSuspiciousShortOverwrite_ByDefault()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteShortGuard-{Guid.NewGuid():N}.txt"
        );
        var originalRatio = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO"
        );
        var originalMinChars = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO", null);
        Environment.SetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
            null
        );

        File.WriteAllText(tempFile, new string('a', 5000));

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                PowerShellBridge.RunTool(
                    "WRITE-FILE",
                    new Dictionary<string, object?>
                    {
                        ["path"] = tempFile,
                        ["content"] = new string('b', 300),
                        ["__confirm_destructive"] = true,
                    }
                )
            );

            Assert.Contains("blocked suspicious short overwrite", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(new string('a', 5000), File.ReadAllText(tempFile));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO",
                originalRatio
            );
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
                originalMinChars
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_WriteFile_AllowsSuspiciousShortOverwrite_WithExplicitOverride()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteShortGuardAllow-{Guid.NewGuid():N}.txt"
        );
        var originalRatio = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO"
        );
        var originalMinChars = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO", null);
        Environment.SetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
            null
        );

        File.WriteAllText(tempFile, new string('a', 5000));

        try
        {
            var result = PowerShellBridge.RunTool(
                "WRITE-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["content"] = new string('b', 300),
                    ["__confirm_destructive"] = true,
                    ["__allow_short_write"] = true,
                }
            );

            Assert.Equal("ok", result);
            Assert.Equal(new string('b', 300), File.ReadAllText(tempFile));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO",
                originalRatio
            );
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
                originalMinChars
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_WriteFile_BlocksFirstChunkStyleOverwrite_WhenLineRatioIsTooLow()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-WriteLineGuard-{Guid.NewGuid():N}.txt"
        );
        var originalRatio = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO"
        );
        var originalLineRatio = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_LINE_RATIO"
        );
        var originalMinChars = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS"
        );

        Environment.SetEnvironmentVariable("TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO", "0.10");
        Environment.SetEnvironmentVariable("TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_LINE_RATIO", "0.60");
        Environment.SetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
            "1200"
        );

        var existing = string.Join(
            Environment.NewLine,
            Enumerable.Range(1, 900).Select(i => $"line-{i}")
        );
        File.WriteAllText(tempFile, existing);

        // Simulate a first-chunk rewrite: many chars retained, but only a fraction of lines.
        var firstChunkLike = string.Join(
            Environment.NewLine,
            Enumerable.Range(1, 220).Select(i => new string('x', 80))
        );

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                PowerShellBridge.RunTool(
                    "WRITE-FILE",
                    new Dictionary<string, object?>
                    {
                        ["path"] = tempFile,
                        ["content"] = firstChunkLike,
                        ["__confirm_destructive"] = true,
                    }
                )
            );

            Assert.Contains("lineRatio", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(existing, File.ReadAllText(tempFile));
        }
        finally
        {
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO",
                originalRatio
            );
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_LINE_RATIO",
                originalLineRatio
            );
            Environment.SetEnvironmentVariable(
                "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS",
                originalMinChars
            );
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReplaceInFile_ReplacesSingleExactOccurrence()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReplaceInFile-{Guid.NewGuid():N}.txt"
        );

        File.WriteAllText(tempFile, "alpha\nbeta\ngamma");

        try
        {
            var result = PowerShellBridge.RunTool(
                "REPLACE-IN-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["oldText"] = "beta",
                    ["newText"] = "beta-updated",
                    ["__confirm_destructive"] = true,
                }
            );

            Assert.Equal("ok", result);
            Assert.Equal("alpha\nbeta-updated\ngamma", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReplaceInFile_BlocksWhenMultipleMatchesExist_WithoutReplaceAll()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReplaceInFile-Multi-{Guid.NewGuid():N}.txt"
        );

        File.WriteAllText(tempFile, "repeat\nrepeat\nfinal");

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                PowerShellBridge.RunTool(
                    "REPLACE-IN-FILE",
                    new Dictionary<string, object?>
                    {
                        ["path"] = tempFile,
                        ["oldText"] = "repeat",
                        ["newText"] = "updated",
                        ["__confirm_destructive"] = true,
                    }
                )
            );

            Assert.Contains("more specific snippet", ex.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_FetchUrl_BlocksDisallowedHost()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            PowerShellBridge.RunTool(
                "FETCH-URL",
                new Dictionary<string, object?>
                {
                    ["url"] = "https://example.com/",
                    ["__allowed_fetch_hosts"] = new[] { "learn.microsoft.com" },
                }
            )
        );

        Assert.Contains("blocked host", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RunTool_TtModuleRootImport_WorksInPooledAndIsolatedModes()
    {
        var originalMode = Environment.GetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE");
        var originalModuleRoot = Environment.GetEnvironmentVariable("TT_ModuleRoot");
        var tempModuleRoot = CreateTempTechToolboxModuleRoot();

        try
        {
            Environment.SetEnvironmentVariable("TT_ModuleRoot", tempModuleRoot);

            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", "pooled");
            PowerShellBridge.ResetExecutionStateForTests();
            var pooled = PowerShellBridge.RunTool(
                "Get-TestModuleMarker",
                new Dictionary<string, object?>()
            );

            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", "isolated");
            PowerShellBridge.ResetExecutionStateForTests();
            var isolated = PowerShellBridge.RunTool(
                "Get-TestModuleMarker",
                new Dictionary<string, object?>()
            );

            Assert.Equal("module-ok", pooled?.ToString());
            Assert.Equal("module-ok", isolated?.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", originalMode);
            Environment.SetEnvironmentVariable("TT_ModuleRoot", originalModuleRoot);
            PowerShellBridge.ResetExecutionStateForTests();

            if (Directory.Exists(tempModuleRoot))
                Directory.Delete(tempModuleRoot, recursive: true);
        }
    }

    [Fact]
    public void RunTool_Telemetry_TracksPooledReuseAndIsolatedExecutions()
    {
        var originalMode = Environment.GetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE");
        var originalModuleRoot = Environment.GetEnvironmentVariable("TT_ModuleRoot");
        var tempModuleRoot = CreateTempTechToolboxModuleRoot();

        try
        {
            Environment.SetEnvironmentVariable("TT_ModuleRoot", tempModuleRoot);
            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", "pooled");
            PowerShellBridge.ResetExecutionStateForTests();

            PowerShellBridge.RunTool("Get-TestModuleMarker", new Dictionary<string, object?>());
            PowerShellBridge.RunTool("Get-TestModuleMarker", new Dictionary<string, object?>());

            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", "isolated");
            PowerShellBridge.RunTool("Get-TestModuleMarker", new Dictionary<string, object?>());

            var telemetry = PowerShellBridge.GetTelemetrySnapshot();
            Assert.Equal(3, telemetry.TotalToolExecutions);
            Assert.Equal(2, telemetry.PooledExecutions);
            Assert.Equal(1, telemetry.IsolatedExecutions);
            Assert.Equal(1, telemetry.RunspacePoolCreations);
            Assert.Equal(1, telemetry.RunspacePoolReuses);
        }
        finally
        {
            Environment.SetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE", originalMode);
            Environment.SetEnvironmentVariable("TT_ModuleRoot", originalModuleRoot);
            PowerShellBridge.ResetExecutionStateForTests();

            if (Directory.Exists(tempModuleRoot))
                Directory.Delete(tempModuleRoot, recursive: true);
        }
    }

    private static string CreateTempTechToolboxModuleRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"TechToolbox-TempModule-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);

        var manifestPath = Path.Combine(root, "TechToolbox.psd1");
        var modulePath = Path.Combine(root, "TechToolbox.psm1");

        File.WriteAllText(
            modulePath,
            "function Get-TestModuleMarker { [CmdletBinding()] param() 'module-ok' }"
        );

        File.WriteAllText(
            manifestPath,
            "@{\n"
                + "RootModule = 'TechToolbox.psm1'\n"
                + "ModuleVersion = '1.0.0'\n"
                + "GUID = 'd3fbb7f5-97c3-4812-8f99-c76ce76bd555'\n"
                + "FunctionsToExport = @('Get-TestModuleMarker')\n"
                + "CmdletsToExport = @()\n"
                + "VariablesToExport = '*'\n"
                + "AliasesToExport = @()\n"
                + "}\n"
        );

        return root;
    }

    private sealed class FakeToolExecutor : IToolExecutor
    {
        public List<(string ToolName, IDictionary<string, object?> Args)> Calls { get; } = [];

        public object? RunTool(string toolName, IDictionary<string, object?> args)
        {
            Calls.Add((toolName, args));
            return "ok-from-interface";
        }
    }
}
