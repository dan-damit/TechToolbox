using System.Management.Automation;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Agent;

namespace TechToolbox.Agent.Execution;

public static class PowerShellBridge
{
    private static readonly Regex AuthenticodeSignatureBlockRegex = new(
        @"(?ims)^\s*#\s*SIG\s*#\s*Begin signature block\b.*?^\s*#\s*SIG\s*#\s*End signature block\s*$",
        RegexOptions.Compiled
    );

    private static readonly JsonSerializerOptions SummaryJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static object? RunTool(string toolName, IDictionary<string, object?> args)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            throw new ArgumentException("Tool name must not be empty.", nameof(toolName));

        if (TryRunBuiltInTool(toolName, args, out var builtInResult))
            return builtInResult;

        // Safety check for destructive tools
        Safety.RequireDestructiveConfirmation(toolName, args);

        using var ps = PowerShell.Create();

        // Import the TechToolbox module explicitly
        // (Assumes the module is discoverable via PSModulePath)
        ps.AddCommand("Import-Module")
            .AddParameter("Name", "TechToolbox")
            .AddParameter("ErrorAction", "Stop")
            .Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException(
                $"Failed to import TechToolbox module: {ps.Streams.Error[0]}"
            );

        ps.Commands.Clear();

        // Add the tool command
        ps.AddCommand(toolName);

        // Add parameters
        foreach (var kv in args)
        {
            // Skip internal agent control keys
            if (kv.Key.StartsWith("__", StringComparison.Ordinal))
                continue;

            ps.AddParameter(kv.Key, kv.Value);
        }

        // Execute
        var results = ps.Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Tool '{toolName}' failed: {ps.Streams.Error[0]}");

        // Normalize output
        if (results is null || results.Count == 0)
            return null;

        if (results.Count == 1)
            return results[0].BaseObject;

        return results.Select(r => r.BaseObject).ToList();
    }

    private static bool TryRunBuiltInTool(
        string toolName,
        IDictionary<string, object?> args,
        out object? result
    )
    {
        result = null;

        if (toolName.Equals("READ-FILE", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            if (!File.Exists(path))
                throw new FileNotFoundException($"File not found: {path}", path);

            var content = File.ReadAllText(path);
            result = ShouldSummarizeFile(content) ? BuildFileSummaryJson(path, content) : content;
            return true;
        }

        if (toolName.Equals("LIST-DIRECTORY", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            var entries = Directory
                .EnumerateFileSystemEntries(path)
                .Select(p =>
                {
                    var name = Path.GetFileName(p);
                    return Directory.Exists(p) ? $"{name}/" : name;
                })
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();

            result = entries;
            return true;
        }

        if (toolName.Equals("WRITE-FILE", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            var content = GetRequiredStringArg(args, "content");

            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(path, content);
            result = "ok";
            return true;
        }

        return false;
    }

    private static string GetRequiredStringArg(IDictionary<string, object?> args, string name)
    {
        var arg = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)
        );
        var value = arg.Value;

        string? text = value switch
        {
            null => null,
            string s => s,
            System.Text.Json.JsonElement el
                when el.ValueKind == System.Text.Json.JsonValueKind.String => el.GetString(),
            System.Text.Json.JsonElement el => el.ToString(),
            _ => value.ToString(),
        };

        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException($"Missing required parameter '{name}'.", name);

        return text;
    }

    private static bool ShouldSummarizeFile(string content)
    {
        var threshold = GetReadFileSummaryThresholdChars();
        return content.Length > threshold;
    }

    private static int GetReadFileSummaryThresholdChars()
    {
        const int defaultChars = 50000;
        const int minChars = 1000;
        const int maxChars = 200_000;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_READ_FILE_SUMMARY_THRESHOLD_CHARS");
        if (int.TryParse(raw, out var parsed))
        {
            return Math.Clamp(parsed, minChars, maxChars);
        }

        return defaultChars;
    }

    private static string BuildFileSummaryJson(string path, string content)
    {
        var contentForSummary = StripAuthenticodeSignatureBlock(content);
        var lines = SplitLines(contentForSummary);
        var head = lines.Take(12).ToArray();
        var tail =
            lines.Length <= 12
                ? Array.Empty<string>()
                : lines.Skip(Math.Max(0, lines.Length - 12)).ToArray();
        var sectionHeadings = ExtractSectionHeadings(lines);
        var functionNames = ExtractFunctionNames(lines);

        var summary = new FileSummaryResult(
            Kind: "file-summary",
            Path: path,
            FileName: System.IO.Path.GetFileName(path),
            Extension: System.IO.Path.GetExtension(path),
            SizeBytes: Encoding.UTF8.GetByteCount(content),
            LineCount: lines.Length,
            Sections: sectionHeadings,
            FunctionNames: functionNames,
            Head: head,
            Tail: tail
        );

        return JsonSerializer.Serialize(summary, SummaryJsonOptions);
    }

    private static string StripAuthenticodeSignatureBlock(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return content;

        var stripped = AuthenticodeSignatureBlockRegex.Replace(content, string.Empty).TrimEnd();
        return string.IsNullOrWhiteSpace(stripped) ? content : stripped;
    }

    private static string[] SplitLines(string content) =>
        content.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

    private static string[] ExtractSectionHeadings(IEnumerable<string> lines)
    {
        var headings = new List<string>();
        var sectionRegex = new Regex(
            @"^\s*(?:#\s*)?\.(?<name>[A-Z][A-Z0-9_-]*)\b",
            RegexOptions.Compiled
        );

        foreach (var line in lines)
        {
            var match = sectionRegex.Match(line);
            if (!match.Success)
                continue;

            var heading = match.Groups["name"].Value;
            if (!headings.Contains(heading, StringComparer.OrdinalIgnoreCase))
            {
                headings.Add(heading);
            }
        }

        return headings.ToArray();
    }

    private static string[] ExtractFunctionNames(IEnumerable<string> lines)
    {
        var names = new List<string>();
        var functionRegex = new Regex(
            @"^\s*function\s+(?<name>[A-Za-z_][A-Za-z0-9_-]*)\b",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        );

        foreach (var line in lines)
        {
            var match = functionRegex.Match(line);
            if (!match.Success)
                continue;

            var name = match.Groups["name"].Value;
            if (!names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(name);
            }
        }

        return names.ToArray();
    }

    private sealed record FileSummaryResult(
        string Kind,
        string Path,
        string FileName,
        string Extension,
        long SizeBytes,
        int LineCount,
        string[] Sections,
        string[] FunctionNames,
        string[] Head,
        string[] Tail
    );
}
