using System.Management.Automation;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Agent;

namespace TechToolbox.Agent.Execution;

public static class PowerShellBridge
{
    private const int DefaultFetchMaxChars = 20_000;
    private const int AbsoluteFetchMaxChars = 200_000;
    private static readonly HttpClient _httpClient = CreateHttpClient();

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

        // Import the TechToolbox module explicitly.
        // Prefer manifest-path import so repo/dev layouts work even when
        // TechToolbox is not discoverable through PSModulePath.
        var modulePath = ResolveModuleManifestPath();
        if (!string.IsNullOrWhiteSpace(modulePath))
        {
            ps.AddCommand("Import-Module")
                .AddParameter("Name", modulePath)
                .AddParameter("Force")
                .AddParameter("ErrorAction", "Stop")
                .Invoke();
        }
        else
        {
            ps.AddCommand("Import-Module")
                .AddParameter("Name", "TechToolbox")
                .AddParameter("Force")
                .AddParameter("ErrorAction", "Stop")
                .Invoke();
        }

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
            Safety.RequireDestructiveConfirmation(toolName, args);

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

        if (toolName.Equals("FETCH-URL", StringComparison.OrdinalIgnoreCase))
        {
            var url = GetRequiredStringArg(args, "url");
            var maxChars = GetOptionalIntArg(args, "maxChars") ?? DefaultFetchMaxChars;
            maxChars = Math.Clamp(maxChars, 1, AbsoluteFetchMaxChars);

            var requestedUri = ParseFetchUri(url);
            var allowedHosts = GetAllowedFetchHosts(args);
            EnsureAllowedFetchHost(requestedUri.Host, allowedHosts);

            var response = FetchWithValidatedRedirects(requestedUri, allowedHosts);
            var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            var contentType = response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream";
            var rawBody = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            var truncated = rawBody.Length > maxChars;
            var body = truncated ? rawBody[..maxChars] : rawBody;

            result = JsonSerializer.Serialize(
                new
                {
                    kind = "fetch-result",
                    url = response.RequestMessage?.RequestUri?.ToString() ?? requestedUri.ToString(),
                    statusCode = (int)response.StatusCode,
                    reasonPhrase = response.ReasonPhrase,
                    contentType,
                    isTextLike = IsTextLikeContentType(mediaType),
                    truncated,
                    maxChars,
                    content = body,
                },
                SummaryJsonOptions
            );

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

    private static int? GetOptionalIntArg(IDictionary<string, object?> args, string name)
    {
        var arg = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)
        );

        if (arg.Equals(default(KeyValuePair<string, object?>)) || arg.Value is null)
            return null;

        return arg.Value switch
        {
            int i => i,
            long l => checked((int)l),
            JsonElement el when el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out var parsed) =>
                parsed,
            JsonElement el when el.ValueKind == JsonValueKind.String && int.TryParse(el.GetString(), out var parsed) =>
                parsed,
            _ when int.TryParse(arg.Value.ToString(), out var parsed) => parsed,
            _ => null,
        };
    }

    private static Uri ParseFetchUri(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            throw new ArgumentException($"Invalid URL: {url}", nameof(url));

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("FETCH-URL only allows HTTPS URLs.");

        if (string.IsNullOrWhiteSpace(uri.Host))
            throw new InvalidOperationException("FETCH-URL requires a URL with a valid host.");

        return uri;
    }

    private static string[] GetAllowedFetchHosts(IDictionary<string, object?> args)
    {
        var arg = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, "__allowed_fetch_hosts", StringComparison.OrdinalIgnoreCase)
        );

        if (arg.Value is null)
            return Array.Empty<string>();

        return arg.Value switch
        {
            string single => NormalizeAllowedHostValues(new[] { single }),
            string[] many => NormalizeAllowedHostValues(many),
            IEnumerable<string> enumerable => NormalizeAllowedHostValues(enumerable),
            JsonElement el when el.ValueKind == JsonValueKind.Array => NormalizeAllowedHostValues(
                el.EnumerateArray().Select(x => x.ToString())
            ),
            _ => Array.Empty<string>(),
        };
    }

    private static string[] NormalizeAllowedHostValues(IEnumerable<string?> hosts)
    {
        return hosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => h!.Trim().Trim('.').ToLowerInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void EnsureAllowedFetchHost(string host, IReadOnlyCollection<string> allowedHosts)
    {
        if (allowedHosts == null || allowedHosts.Count == 0)
        {
            throw new InvalidOperationException(
                "FETCH-URL is disabled because no allowed hosts are configured."
            );
        }

        var normalizedHost = host.Trim().Trim('.').ToLowerInvariant();
        if (!allowedHosts.Contains(normalizedHost, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"FETCH-URL blocked host '{host}'. Allowed hosts: {string.Join(", ", allowedHosts.OrderBy(h => h, StringComparer.OrdinalIgnoreCase))}"
            );
        }
    }

    private static HttpResponseMessage FetchWithValidatedRedirects(
        Uri initialUri,
        IReadOnlyCollection<string> allowedHosts
    )
    {
        const int maxRedirects = 5;
        var currentUri = initialUri;

        for (var redirectCount = 0; redirectCount <= maxRedirects; redirectCount++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, currentUri);
            request.Headers.UserAgent.ParseAdd("TechToolbox-Agent/1.0");

            var response = _httpClient
                .SendAsync(request, HttpCompletionOption.ResponseContentRead)
                .GetAwaiter()
                .GetResult();

            if (!IsRedirect(response.StatusCode))
            {
                if ((int)response.StatusCode >= 400)
                {
                    var statusCode = (int)response.StatusCode;
                    var reason = response.ReasonPhrase ?? "HTTP error";
                    response.Dispose();
                    throw new InvalidOperationException(
                        $"FETCH-URL failed with status {statusCode} ({reason})."
                    );
                }

                return response;
            }

            var location = response.Headers.Location;
            response.Dispose();

            if (location is null)
                throw new InvalidOperationException("FETCH-URL received redirect with no Location header.");

            currentUri = location.IsAbsoluteUri ? location : new Uri(currentUri, location);
            if (!string.Equals(currentUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("FETCH-URL blocked redirect to non-HTTPS URL.");

            EnsureAllowedFetchHost(currentUri.Host, allowedHosts);
        }

        throw new InvalidOperationException("FETCH-URL exceeded maximum redirect count.");
    }

    private static bool IsRedirect(HttpStatusCode statusCode)
    {
        return statusCode is HttpStatusCode.Moved
            or HttpStatusCode.Redirect
            or HttpStatusCode.RedirectMethod
            or HttpStatusCode.TemporaryRedirect
            or HttpStatusCode.PermanentRedirect;
    }

    private static bool IsTextLikeContentType(string mediaType)
    {
        if (string.IsNullOrWhiteSpace(mediaType))
            return false;

        var normalized = mediaType.Trim().ToLowerInvariant();
        return normalized.StartsWith("text/", StringComparison.Ordinal)
            || normalized.Contains("json", StringComparison.Ordinal)
            || normalized.Contains("xml", StringComparison.Ordinal)
            || normalized.Contains("javascript", StringComparison.Ordinal)
            || normalized.Contains("yaml", StringComparison.Ordinal)
            || normalized.Contains("html", StringComparison.Ordinal);
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    private static string? ResolveModuleManifestPath()
    {
        var envRoot = Environment.GetEnvironmentVariable("TT_ModuleRoot");
        if (!string.IsNullOrWhiteSpace(envRoot))
        {
            var candidate = Path.Combine(envRoot, "TechToolbox.psd1");
            if (File.Exists(candidate))
                return candidate;
        }

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "TechToolbox.psd1");
            if (File.Exists(candidate))
                return candidate;

            dir = dir.Parent;
        }

        return null;
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
