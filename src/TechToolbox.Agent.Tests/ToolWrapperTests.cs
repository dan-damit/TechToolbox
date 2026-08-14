using System.Reflection;
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
    public void ParseFetchUri_NormalizesDnsAndQueryShape()
    {
        var method = typeof(PowerShellBridge).GetMethod(
            "ParseFetchUri",
            BindingFlags.NonPublic | BindingFlags.Static
        );

        Assert.NotNull(method);

        var uri = method!.Invoke(null, ["https://Example.COM:443/Path/.././?b=2&a=1"]);

        Assert.NotNull(uri);
        Assert.IsType<Uri>(uri);
        Assert.Equal("https://example.com/?a=1&b=2", ((Uri)uri).AbsoluteUri);
    }

    [Fact]
    public void EnsureAllowedFetchHost_AllowsWildcardHosts()
    {
        var method = typeof(PowerShellBridge).GetMethod(
            "EnsureAllowedFetchHost",
            BindingFlags.NonPublic | BindingFlags.Static
        );

        Assert.NotNull(method);

        var allowedHosts = new[] { "*.weather.gov" };
        var ex = Record.Exception(() => method!.Invoke(null, ["alerts.weather.gov", allowedHosts]));

        Assert.Null(ex);
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
    public async Task BuildTools_PassesSearchWebDefaults_ForSearchWebTool()
    {
        IDictionary<string, object?>? capturedArgs = null;

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase)
        {
            ["SEARCH-WEB"] = new ToolSpec(
                Name: "SEARCH-WEB",
                Description: "Searches the web",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["query"] = new ParameterSpec(Mandatory: true, Type: "string", Help: null),
                    ["count"] = new ParameterSpec(Mandatory: false, Type: "int", Help: null),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };

        var tools = ToolWrapper.BuildTools(
            registry,
            destructiveConfirmed: false,
            signedFilePolicy: "ignore",
            searchWebProvider: "brave",
            searchWebEndpoint: "https://api.search.brave.com/res/v1/web/search",
            searchWebApiKeyEnvVar: "TT_AGENT_SEARCH_WEB_API_KEY",
            searchWebCountry: "us",
            searchWebLanguage: "en",
            searchWebSafeSearch: "moderate",
            searchWebDefaultCount: 7,
            toolExecutor: (_, args) =>
            {
                capturedArgs = new Dictionary<string, object?>(
                    args,
                    StringComparer.OrdinalIgnoreCase
                );
                return "ok";
            }
        );

        var result = await tools["SEARCH-WEB"]("{\"query\":\"TechToolbox Fetch Tool\"}");

        Assert.Equal("ok", result);
        Assert.NotNull(capturedArgs);
        Assert.Equal("brave", capturedArgs!["__search_web_provider"]?.ToString());
        Assert.Equal("https://api.search.brave.com/res/v1/web/search", capturedArgs["__search_web_endpoint"]?.ToString());
        Assert.Equal("TT_AGENT_SEARCH_WEB_API_KEY", capturedArgs["__search_web_api_key_env_var"]?.ToString());
        Assert.Equal("us", capturedArgs["__search_web_country"]?.ToString());
        Assert.Equal("en", capturedArgs["__search_web_language"]?.ToString());
        Assert.Equal("moderate", capturedArgs["__search_web_safe_search"]?.ToString());
        Assert.Equal("7", capturedArgs["count"]?.ToString());
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
    public void RunTool_ReadFile_AutoChunk_ProducesStructuredChunks_ForLargeFiles()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-AutoChunk-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var lines = Enumerable.Range(1, 1200).Select(i => $"line-{i}").ToArray();
            File.WriteAllLines(tempFile, lines);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["autoChunk"] = true,
                    ["chunkSize"] = 500,
                }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("auto-chunk", doc.RootElement.GetProperty("kind").GetString());
            Assert.Equal(1200, doc.RootElement.GetProperty("totalLines").GetInt32());
            Assert.Equal(500, doc.RootElement.GetProperty("chunkSize").GetInt32());
            Assert.True(doc.RootElement.GetProperty("chunks").GetArrayLength() >= 2);
            Assert.Equal(1, doc.RootElement.GetProperty("chunks")[0].GetProperty("startLine").GetInt32());
            Assert.Equal(500, doc.RootElement.GetProperty("chunks")[0].GetProperty("endLine").GetInt32());
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_SemanticAndHeaderFooterModes_ReturnStructuredResults()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-Semantic-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var lines = new[]
            {
                "header-1",
                "header-2",
                "method start",
                "alpha",
                "beta",
                "target token",
                "gamma",
                "delta",
                "method end",
                "footer-1",
                "footer-2",
            };
            File.WriteAllLines(tempFile, lines);

            var semanticResult = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["semantic"] = "target token",
                    ["contextLines"] = 2,
                }
            );

            var semanticJson = Assert.IsType<string>(semanticResult);
            using var semanticDoc = JsonDocument.Parse(semanticJson);
            Assert.Equal("semantic-chunk", semanticDoc.RootElement.GetProperty("kind").GetString());
            Assert.Equal(1, semanticDoc.RootElement.GetProperty("matches").GetArrayLength());

            var headerFooterResult = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["headerLines"] = 2,
                    ["footerLines"] = 2,
                }
            );

            var headerFooterJson = Assert.IsType<string>(headerFooterResult);
            using var headerFooterDoc = JsonDocument.Parse(headerFooterJson);
            Assert.Equal("header-footer", headerFooterDoc.RootElement.GetProperty("kind").GetString());
            Assert.Equal(2, headerFooterDoc.RootElement.GetProperty("header").GetArrayLength());
            Assert.Equal(2, headerFooterDoc.RootElement.GetProperty("footer").GetArrayLength());

            var metaResult = PowerShellBridge.RunTool(
                "READ-FILE-META",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var metaJson = Assert.IsType<string>(metaResult);
            using var metaDoc = JsonDocument.Parse(metaJson);
            Assert.Equal("file-meta", metaDoc.RootElement.GetProperty("kind").GetString());
            Assert.Equal(12, metaDoc.RootElement.GetProperty("totalLines").GetInt32());
            Assert.Equal(".txt", metaDoc.RootElement.GetProperty("fileType").GetString());
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_ReadFile_Stream_ReturnsNextTokenAndContent()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-ReadFile-Stream-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var lines = Enumerable.Range(1, 1200).Select(i => $"line-{i}").ToArray();
            File.WriteAllLines(tempFile, lines);

            var result = PowerShellBridge.RunTool(
                "READ-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["stream"] = true,
                    ["chunkSize"] = 300,
                }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);

            Assert.Equal("stream", doc.RootElement.GetProperty("kind").GetString());
            Assert.True(doc.RootElement.TryGetProperty("nextToken", out var nextToken));
            Assert.False(string.IsNullOrWhiteSpace(nextToken.GetString()));
            Assert.Contains("line-1", doc.RootElement.GetProperty("content").GetString());
        }
        finally
        {
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
    public void IsDestructive_AppendFile_ReturnsTrue()
    {
        Assert.True(Safety.IsDestructive("APPEND-FILE"));
        Assert.True(Safety.IsDestructive("append-file"));
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
    public void RunTool_AppendFile_TruncatesThenAppends_WhenRequested()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-Append-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var firstResult = PowerShellBridge.RunTool(
                "APPEND-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["content"] = "line-1\n",
                    ["truncateFirst"] = true,
                    ["__confirm_destructive"] = true,
                }
            );

            var secondResult = PowerShellBridge.RunTool(
                "APPEND-FILE",
                new Dictionary<string, object?>
                {
                    ["path"] = tempFile,
                    ["content"] = "line-2\n",
                    ["__confirm_destructive"] = true,
                }
            );

            Assert.Equal("ok", firstResult);
            Assert.Equal("ok", secondResult);
            Assert.Equal("line-1\nline-2\n", File.ReadAllText(tempFile));
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_AppendFile_BlocksWhenDestructiveNotConfirmed()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-AppendBlocked-{Guid.NewGuid():N}.txt"
        );

        try
        {
            var ex = Assert.Throws<InvalidOperationException>(() =>
                PowerShellBridge.RunTool(
                    "APPEND-FILE",
                    new Dictionary<string, object?>
                    {
                        ["path"] = tempFile,
                        ["content"] = "line-1\n",
                    }
                )
            );

            Assert.Contains(
                "__confirm_destructive=true",
                ex.Message,
                StringComparison.OrdinalIgnoreCase
            );
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_FinalizeFileWrite_ReturnsFileStats()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-Finalize-{Guid.NewGuid():N}.txt"
        );

        try
        {
            File.WriteAllText(tempFile, "line-1\nline-2\n");

            var result = PowerShellBridge.RunTool(
                "FINALIZE-FILE-WRITE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            );

            var json = Assert.IsType<string>(result);
            using var doc = JsonDocument.Parse(json);
            Assert.Equal("finalize-file-write", doc.RootElement.GetProperty("kind").GetString());
            Assert.Equal(tempFile, doc.RootElement.GetProperty("path").GetString());
            Assert.True(doc.RootElement.GetProperty("chars").GetInt32() > 0);
            Assert.True(doc.RootElement.GetProperty("lines").GetInt32() >= 2);
            Assert.True(doc.RootElement.GetProperty("bytes").GetInt64() > 0);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    [Fact]
    public void RunTool_FinalizeFileWrite_ThrowsWhenFileMissing()
    {
        var tempFile = Path.Combine(
            Path.GetTempPath(),
            $"TechToolbox-FinalizeMissing-{Guid.NewGuid():N}.txt"
        );

        var ex = Assert.Throws<FileNotFoundException>(() =>
            PowerShellBridge.RunTool(
                "FINALIZE-FILE-WRITE",
                new Dictionary<string, object?> { ["path"] = tempFile }
            )
        );

        Assert.Contains("File not found", ex.Message, StringComparison.OrdinalIgnoreCase);
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
