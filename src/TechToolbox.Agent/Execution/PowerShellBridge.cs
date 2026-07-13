using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Agent;

namespace TechToolbox.Agent.Execution;

public static class PowerShellBridge
{
    private enum RunspaceExecutionMode
    {
        Pooled,
        Isolated,
    }

    private const int DefaultFetchMaxChars = 20_000;
    private const int AbsoluteFetchMaxChars = 200_000;
    private const double DefaultWriteFileShortGuardMinRatio = 0.35;
    private const double DefaultWriteFileShortGuardMinLineRatio = 0.60;
    private const int DefaultWriteFileShortGuardMinExistingChars = 1200;
    private static readonly HttpClient _httpClient = CreateHttpClient();
    private static readonly object RunspacePoolSync = new();
    private static readonly string InitialWorkingDirectory = Environment.CurrentDirectory;
    private static RunspacePool? _runspacePool;
    private static string? _runspacePoolModuleIdentity;
    private static long _totalToolExecutions;
    private static long _pooledExecutions;
    private static long _isolatedExecutions;
    private static long _runspacePoolCreations;
    private static long _runspacePoolReuses;

    private static readonly Regex AuthenticodeSignatureBlockRegex = new(
        @"(?ims)^\s*#\s*SIG\s*#\s*Begin signature block\b.*?^\s*#\s*SIG\s*#\s*End signature block\s*$",
        RegexOptions.Compiled
    );

    private static readonly JsonSerializerOptions SummaryJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static PowerShellBridgeTelemetry GetTelemetrySnapshot()
    {
        return new PowerShellBridgeTelemetry(
            TotalToolExecutions: Interlocked.Read(ref _totalToolExecutions),
            PooledExecutions: Interlocked.Read(ref _pooledExecutions),
            IsolatedExecutions: Interlocked.Read(ref _isolatedExecutions),
            RunspacePoolCreations: Interlocked.Read(ref _runspacePoolCreations),
            RunspacePoolReuses: Interlocked.Read(ref _runspacePoolReuses)
        );
    }

    public static void ResetExecutionStateForTests()
    {
        lock (RunspacePoolSync)
        {
            if (_runspacePool is not null)
            {
                try
                {
                    _runspacePool.Dispose();
                }
                catch
                {
                    // Test reset should not throw on pool cleanup.
                }

                _runspacePool = null;
            }

            _runspacePoolModuleIdentity = null;
        }

        Interlocked.Exchange(ref _totalToolExecutions, 0);
        Interlocked.Exchange(ref _pooledExecutions, 0);
        Interlocked.Exchange(ref _isolatedExecutions, 0);
        Interlocked.Exchange(ref _runspacePoolCreations, 0);
        Interlocked.Exchange(ref _runspacePoolReuses, 0);
    }

    public static object? RunTool(string toolName, IDictionary<string, object?> args)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            throw new ArgumentException("Tool name must not be empty.", nameof(toolName));

        if (TryRunBuiltInTool(toolName, args, out var builtInResult))
            return builtInResult;

        Interlocked.Increment(ref _totalToolExecutions);

        // Safety check for destructive tools
        Safety.RequireDestructiveConfirmation(toolName, args);

        using var ps = PowerShell.Create();
        IDisposable? isolatedRunspace = null;
        try
        {
            var executionMode = GetRunspaceExecutionMode();
            if (executionMode == RunspaceExecutionMode.Isolated)
            {
                Interlocked.Increment(ref _isolatedExecutions);
                isolatedRunspace = AttachIsolatedRunspace(ps);
            }
            else
            {
                Interlocked.Increment(ref _pooledExecutions);
                ps.RunspacePool = GetOrCreateRunspacePool(out var reusedPool);
                if (reusedPool)
                    Interlocked.Increment(ref _runspacePoolReuses);
                else
                    Interlocked.Increment(ref _runspacePoolCreations);
            }

            ResetRunspaceState(ps);

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
        finally
        {
            isolatedRunspace?.Dispose();
        }
    }

    private static RunspaceExecutionMode GetRunspaceExecutionMode()
    {
        var raw = Environment.GetEnvironmentVariable("TT_AGENT_RUNSPACE_EXECUTION_MODE");
        if (string.Equals(raw, "isolated", StringComparison.OrdinalIgnoreCase))
            return RunspaceExecutionMode.Isolated;

        return RunspaceExecutionMode.Pooled;
    }

    private static Runspace AttachIsolatedRunspace(PowerShell ps)
    {
        var runspace = RunspaceFactory.CreateRunspace(CreateInitialSessionState(GetModuleImportTarget()));
        runspace.Open();
        ps.Runspace = runspace;
        return runspace;
    }

    private static RunspacePool GetOrCreateRunspacePool(out bool reusedPool)
    {
        lock (RunspacePoolSync)
        {
            var moduleImportTarget = GetModuleImportTarget();

            if (_runspacePool is not null)
            {
                var state = _runspacePool.RunspacePoolStateInfo.State;
                var moduleMatches = string.Equals(
                    _runspacePoolModuleIdentity,
                    moduleImportTarget,
                    StringComparison.OrdinalIgnoreCase
                );

                if (state is RunspacePoolState.Opening or RunspacePoolState.Opened && moduleMatches)
                {
                    reusedPool = true;
                    return _runspacePool;
                }

                try
                {
                    _runspacePool.Dispose();
                }
                catch
                {
                    // Pool teardown should not block recreation.
                }

                _runspacePool = null;
            }

            _runspacePool = CreateRunspacePool(moduleImportTarget);
            _runspacePoolModuleIdentity = moduleImportTarget;
            reusedPool = false;
            return _runspacePool;
        }
    }

    private static RunspacePool CreateRunspacePool(string moduleImportTarget)
    {
        var initialState = CreateInitialSessionState(moduleImportTarget);

        var maxRunspaces = GetMaxRunspaces();
        var pool = RunspaceFactory.CreateRunspacePool(1, maxRunspaces, initialState, host: null);
        pool.ThreadOptions = PSThreadOptions.ReuseThread;
        pool.ApartmentState = ApartmentState.Unknown;
        pool.Open();
        return pool;
    }

    private static InitialSessionState CreateInitialSessionState(string moduleToImport)
    {
        var initialState = InitialSessionState.CreateDefault();
        initialState.ImportPSModule(new[] { moduleToImport });
        return initialState;
    }

    private static string GetModuleImportTarget()
    {
        var moduleToImport = ResolveModuleManifestPath();
        return string.IsNullOrWhiteSpace(moduleToImport) ? "TechToolbox" : moduleToImport;
    }

    private static int GetMaxRunspaces()
    {
        const int defaultRunspaces = 2;
        const int minRunspaces = 1;
        const int maxRunspaces = 8;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_MAX_RUNSPACES");
        if (!int.TryParse(raw, out var parsed))
            return defaultRunspaces;

        return Math.Clamp(parsed, minRunspaces, maxRunspaces);
    }

    private static void ResetRunspaceState(PowerShell ps)
    {
        ps.AddScript("$Error.Clear(); Set-Location -LiteralPath $args[0]")
            .AddArgument(InitialWorkingDirectory)
            .Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Failed to initialize runspace state: {ps.Streams.Error[0]}");

        ps.Commands.Clear();
        ps.Streams.Error.Clear();
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

            var startLine = GetOptionalIntArg(args, "startLine");
            var endLine = GetOptionalIntArg(args, "endLine");
            var maxLines = GetOptionalIntArg(args, "maxLines");

            if (startLine.HasValue || endLine.HasValue || maxLines.HasValue)
            {
                result = ReadFileChunk(path, startLine, endLine, maxLines);
                return true;
            }

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

            if (File.Exists(path))
            {
                var existingContent = File.ReadAllText(path);
                if (ShouldBlockSuspiciousShortOverwrite(existingContent, content, args, out var reason))
                {
                    throw new InvalidOperationException(reason);
                }
            }

            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(path, content);
            result = "ok";
            return true;
        }

        if (toolName.Equals("REPLACE-IN-FILE", StringComparison.OrdinalIgnoreCase))
        {
            Safety.RequireDestructiveConfirmation(toolName, args);

            var path = GetRequiredStringArg(args, "path");
            var oldText = GetRequiredStringArg(args, "oldText");
            var newText = GetRequiredStringArg(args, "newText");
            var replaceAll = GetOptionalBoolArg(args, "replaceAll");

            if (!File.Exists(path))
                throw new FileNotFoundException($"File not found: {path}", path);

            var content = File.ReadAllText(path);
            var matchCount = CountExactOccurrences(content, oldText);
            if (matchCount == 0)
            {
                throw new InvalidOperationException(
                    "REPLACE-IN-FILE found no exact matches for oldText. Read the file again and provide an exact snippet."
                );
            }

            if (!replaceAll && matchCount > 1)
            {
                throw new InvalidOperationException(
                    $"REPLACE-IN-FILE found {matchCount} matches for oldText. Provide a more specific snippet or set replaceAll=true."
                );
            }

            var updated = replaceAll
                ? content.Replace(oldText, newText, StringComparison.Ordinal)
                : ReplaceFirstExactOccurrence(content, oldText, newText);

            File.WriteAllText(path, updated);
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

    private static bool GetOptionalBoolArg(IDictionary<string, object?> args, string name)
    {
        var arg = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)
        );

        if (arg.Equals(default(KeyValuePair<string, object?>)) || arg.Value is null)
            return false;

        return arg.Value switch
        {
            bool b => b,
            JsonElement el when el.ValueKind == JsonValueKind.True => true,
            JsonElement el when el.ValueKind == JsonValueKind.False => false,
            JsonElement el
                when el.ValueKind == JsonValueKind.String
                    && bool.TryParse(el.GetString(), out var parsed) => parsed,
            _ when bool.TryParse(arg.Value.ToString(), out var parsed) => parsed,
            _ => false,
        };
    }

    private static bool ShouldBlockSuspiciousShortOverwrite(
        string existingContent,
        string newContent,
        IDictionary<string, object?> args,
        out string reason
    )
    {
        reason = string.Empty;

        if (GetOptionalBoolArg(args, "__allow_short_write"))
            return false;

        var minRatio = GetWriteFileShortGuardMinRatio();
        if (minRatio <= 0)
            return false;

        var minExistingChars = GetWriteFileShortGuardMinExistingChars();
        if (existingContent.Length < minExistingChars)
            return false;

        var existingLength = Math.Max(1, existingContent.Length);
        var charRatio = (double)newContent.Length / existingLength;

        var existingLineCount = CountLines(existingContent);
        var newLineCount = CountLines(newContent);
        var lineRatio = (double)newLineCount / Math.Max(1, existingLineCount);
        var minLineRatio = GetWriteFileShortGuardMinLineRatio();

        var charRatioTooShort = charRatio < minRatio;
        var lineRatioTooShort = minLineRatio > 0 && lineRatio < minLineRatio;

        if (!charRatioTooShort && !lineRatioTooShort)
            return false;

        reason =
            $"WRITE-FILE blocked suspicious short overwrite. Existing chars={existingContent.Length}, new chars={newContent.Length}, charRatio={charRatio:F3}, minCharRatio={minRatio:F3}, existingLines={existingLineCount}, newLines={newLineCount}, lineRatio={lineRatio:F3}, minLineRatio={minLineRatio:F3}. "
            + "This often means only a partial chunk was written. Read remaining chunks before overwrite, or set __allow_short_write=true to intentionally allow this replacement.";
        return true;
    }

    private static int CountLines(string text)
    {
        if (string.IsNullOrEmpty(text))
            return 0;

        var count = 1;
        foreach (var ch in text)
        {
            if (ch == '\n')
                count++;
        }

        return count;
    }

    private static int CountExactOccurrences(string text, string value)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(value))
            return 0;

        var count = 0;
        var searchIndex = 0;
        while (searchIndex <= text.Length - value.Length)
        {
            var matchIndex = text.IndexOf(value, searchIndex, StringComparison.Ordinal);
            if (matchIndex < 0)
                break;

            count++;
            searchIndex = matchIndex + value.Length;
        }

        return count;
    }

    private static string ReplaceFirstExactOccurrence(string text, string oldValue, string newValue)
    {
        var matchIndex = text.IndexOf(oldValue, StringComparison.Ordinal);
        if (matchIndex < 0)
            return text;

        return string.Concat(
            text.AsSpan(0, matchIndex),
            newValue,
            text.AsSpan(matchIndex + oldValue.Length)
        );
    }

    private static double GetWriteFileShortGuardMinRatio()
    {
        const double minRatio = 0.01;
        const double maxRatio = 1.00;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_RATIO");
        if (!double.TryParse(raw, out var parsed))
            return DefaultWriteFileShortGuardMinRatio;

        return Math.Clamp(parsed, minRatio, maxRatio);
    }

    private static double GetWriteFileShortGuardMinLineRatio()
    {
        const double minRatio = 0.00;
        const double maxRatio = 1.00;

        var raw = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_LINE_RATIO"
        );
        if (!double.TryParse(raw, out var parsed))
            return DefaultWriteFileShortGuardMinLineRatio;

        return Math.Clamp(parsed, minRatio, maxRatio);
    }

    private static int GetWriteFileShortGuardMinExistingChars()
    {
        const int minChars = 0;
        const int maxChars = 1_000_000;

        var raw = Environment.GetEnvironmentVariable(
            "TT_AGENT_WRITE_FILE_SHORT_GUARD_MIN_EXISTING_CHARS"
        );
        if (!int.TryParse(raw, out var parsed))
            return DefaultWriteFileShortGuardMinExistingChars;

        return Math.Clamp(parsed, minChars, maxChars);
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

    private static string ReadFileChunk(
        string path,
        int? startLine,
        int? endLine,
        int? maxLines
    )
    {
        const int defaultChunkLines = 200;
        const int maxChunkLines = 1000;

        var lines = File.ReadAllLines(path);
        if (lines.Length == 0)
            return string.Empty;

        var start = Math.Max(1, startLine ?? 1);
        var chunkSize = Math.Clamp(maxLines ?? defaultChunkLines, 1, maxChunkLines);
        var end = endLine ?? (start + chunkSize - 1);

        end = Math.Max(start, end);

        if (start > lines.Length)
            return string.Empty;

        var clampedEnd = Math.Min(end, lines.Length);
        var count = clampedEnd - start + 1;
        if (count <= 0)
            return string.Empty;

        return string.Join(Environment.NewLine, lines.Skip(start - 1).Take(count));
    }

    private static int GetReadFileSummaryThresholdChars()
    {
        const int defaultChars = 12000;
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
        var extension = System.IO.Path.GetExtension(path);
        var head = lines.Take(12).ToArray();
        var tail =
            lines.Length <= 12
                ? Array.Empty<string>()
                : lines.Skip(Math.Max(0, lines.Length - 12)).ToArray();
        var sectionHeadings = ExtractSectionHeadings(lines);
        var functionNames = ExtractFunctionNames(lines);
        var publicSymbolHints = ExtractPublicSymbolHints(lines, extension);
        var suggestedChunks = BuildSuggestedChunks(lines.Length);

        var summary = new FileSummaryResult(
            Kind: "file-summary",
            Path: path,
            FileName: System.IO.Path.GetFileName(path),
            Extension: extension,
            SizeBytes: Encoding.UTF8.GetByteCount(content),
            LineCount: lines.Length,
            Sections: sectionHeadings,
            FunctionNames: functionNames,
            PublicSymbolHints: publicSymbolHints,
            Head: head,
            Tail: tail,
            SuggestedChunks: suggestedChunks,
            VerificationChecklist:
            [
                "Read the file in chunks with READ-FILE using startLine/endLine.",
                "Cover all public types and methods before writing conclusions.",
                "Cross-check each documented symbol against exact signatures from chunked reads.",
            ]
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

    private static string[] ExtractPublicSymbolHints(string[] lines, string? extension)
    {
        if (!string.Equals(extension, ".cs", StringComparison.OrdinalIgnoreCase))
            return [];

        var hints = new List<string>();
        var typeRegex = new Regex(
            @"^\s*public\s+(?:sealed\s+|static\s+|abstract\s+|partial\s+|readonly\s+|unsafe\s+|new\s+)*(class|record|struct|interface|enum)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)",
            RegexOptions.Compiled
        );
        var methodRegex = new Regex(
            @"^\s*public\s+(?:static\s+|virtual\s+|override\s+|abstract\s+|sealed\s+|async\s+|partial\s+|new\s+)*(?:[A-Za-z_][A-Za-z0-9_<>\[\],?.\s]*)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
            RegexOptions.Compiled
        );

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var typeMatch = typeRegex.Match(line);
            if (typeMatch.Success)
            {
                var kind = typeMatch.Groups[1].Value;
                var name = typeMatch.Groups["name"].Value;
                AddDistinctHint(hints, $"public {kind} {name}");
                continue;
            }

            var methodMatch = methodRegex.Match(line);
            if (!methodMatch.Success)
                continue;

            var methodName = methodMatch.Groups["name"].Value;
            AddDistinctHint(hints, $"public method {methodName}(...)");
        }

        return hints.Take(80).ToArray();
    }

    private static void AddDistinctHint(List<string> hints, string hint)
    {
        if (string.IsNullOrWhiteSpace(hint))
            return;

        if (hints.Contains(hint, StringComparer.OrdinalIgnoreCase))
            return;

        hints.Add(hint);
    }

    private static FileChunkHint[] BuildSuggestedChunks(int lineCount)
    {
        if (lineCount <= 0)
            return [];

        const int chunkSize = 200;
        var hints = new List<FileChunkHint>();

        for (var start = 1; start <= lineCount; start += chunkSize)
        {
            var end = Math.Min(start + chunkSize - 1, lineCount);
            hints.Add(new FileChunkHint(start, end));
        }

        return hints.ToArray();
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
        string[] PublicSymbolHints,
        string[] Head,
        string[] Tail,
        FileChunkHint[] SuggestedChunks,
        string[] VerificationChecklist
    );

    private sealed record FileChunkHint(int StartLine, int EndLine);
}

public readonly record struct PowerShellBridgeTelemetry(
    long TotalToolExecutions,
    long PooledExecutions,
    long IsolatedExecutions,
    long RunspacePoolCreations,
    long RunspacePoolReuses
);
