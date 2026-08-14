using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Globalization;
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
    private const int DefaultSearchWebCount = 5;
    private const int AbsoluteSearchWebCount = 50;
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
            var autoChunk = GetOptionalBoolArg(args, "autoChunk");
            var chunkSize = GetOptionalIntArg(args, "chunkSize") ?? 500;
            var semantic = GetOptionalStringArg(args, "semantic");
            var contextLines = GetOptionalIntArg(args, "contextLines") ?? 40;
            var headerLines = GetOptionalIntArg(args, "headerLines");
            var footerLines = GetOptionalIntArg(args, "footerLines");
            var stream = GetOptionalBoolArg(args, "stream");
            var nextToken = GetOptionalStringArg(args, "nextToken");

            if (startLine.HasValue || endLine.HasValue || maxLines.HasValue)
            {
                result = ReadFileChunk(path, startLine, endLine, maxLines);
                return true;
            }

            if (autoChunk)
            {
                result = ReadFileAutoChunk(path, chunkSize);
                return true;
            }

            if (!string.IsNullOrWhiteSpace(semantic))
            {
                result = ReadFileSemanticMatches(path, semantic, contextLines);
                return true;
            }

            if (headerLines.HasValue || footerLines.HasValue)
            {
                result = ReadFileHeaderFooter(path, headerLines ?? 0, footerLines ?? 0);
                return true;
            }

            if (stream)
            {
                result = ReadFileStream(path, nextToken, chunkSize);
                return true;
            }

            var content = File.ReadAllText(path);
            result = ShouldSummarizeFile(content) ? BuildFileSummaryJson(path, content) : content;
            return true;
        }

        if (toolName.Equals("READ-FILE-META", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            if (!File.Exists(path))
                throw new FileNotFoundException($"File not found: {path}", path);

            result = ReadFileMeta(path);
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

        if (toolName.Equals("APPEND-FILE", StringComparison.OrdinalIgnoreCase))
        {
            Safety.RequireDestructiveConfirmation(toolName, args);

            var path = GetRequiredStringArg(args, "path");
            var content = GetRequiredStringArg(args, "content");
            var truncateFirst = GetOptionalBoolArg(args, "truncateFirst");

            if (truncateFirst && File.Exists(path))
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

            if (truncateFirst)
            {
                File.WriteAllText(path, content);
            }
            else
            {
                File.AppendAllText(path, content);
            }

            result = "ok";
            return true;
        }

        if (toolName.Equals("FINALIZE-FILE-WRITE", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");

            if (!File.Exists(path))
            {
                throw new FileNotFoundException($"File not found: {path}", path);
            }

            var text = File.ReadAllText(path);
            var bytes = new FileInfo(path).Length;

            result = JsonSerializer.Serialize(
                new
                {
                    kind = "finalize-file-write",
                    path,
                    chars = text.Length,
                    lines = CountLines(text),
                    bytes,
                },
                SummaryJsonOptions
            );
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

        if (toolName.Equals("SEARCH-WEB", StringComparison.OrdinalIgnoreCase))
        {
            var query = GetRequiredStringArg(args, "query");
            var count = GetOptionalIntArg(args, "count") ?? DefaultSearchWebCount;
            count = Math.Clamp(count, 1, AbsoluteSearchWebCount);

            var offset = GetOptionalIntArg(args, "offset") ?? 0;
            offset = Math.Max(0, offset);

            var provider = NormalizeSearchWebProvider(
                GetOptionalStringArg(args, "__search_web_provider") ?? "brave"
            );
            var endpoint = GetOptionalStringArg(args, "__search_web_endpoint")
                ?? "https://api.search.brave.com/res/v1/web/search";
            var apiKeyEnvVar = GetOptionalStringArg(args, "__search_web_api_key_env_var")
                ?? "TT_AGENT_SEARCH_WEB_API_KEY";
            var apiKey = Environment.GetEnvironmentVariable(apiKeyEnvVar);
            if (string.IsNullOrWhiteSpace(apiKey))
                throw new InvalidOperationException(
                    $"SEARCH-WEB requires API key environment variable '{apiKeyEnvVar}'."
                );

            var country = GetOptionalStringArg(args, "country")
                ?? GetOptionalStringArg(args, "__search_web_country")
                ?? "us";
            var searchLanguage = GetOptionalStringArg(args, "searchLang")
                ?? GetOptionalStringArg(args, "__search_web_language")
                ?? "en";
            var safeSearch = NormalizeSearchWebSafeSearch(
                GetOptionalStringArg(args, "safeSearch")
                ?? GetOptionalStringArg(args, "__search_web_safe_search")
            );

            var requestUri = BuildBraveSearchUri(
                endpoint,
                query,
                count,
                offset,
                country,
                searchLanguage,
                safeSearch
            );

            using var response = SendBraveSearchRequest(requestUri, apiKey);
            var rawBody = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var parsed = JsonDocument.Parse(rawBody);
            if (!parsed.RootElement.TryGetProperty("web", out var webElement))
            {
                result = JsonSerializer.Serialize(
                    new
                    {
                        kind = "search-web-result",
                        provider,
                        query,
                        endpoint = requestUri.ToString(),
                        country,
                        searchLanguage,
                        safeSearch,
                        count,
                        offset,
                        results = Array.Empty<object>(),
                    },
                    SummaryJsonOptions
                );

                return true;
            }

            var results = webElement
                .TryGetProperty("results", out var valueElement)
                ? valueElement.EnumerateArray().Select(item => new
                {
                    title = item.TryGetProperty("title", out var title) ? title.GetString() : null,
                    url = item.TryGetProperty("url", out var url) ? url.GetString() : null,
                    displayUrl = item.TryGetProperty("profile", out var profile)
                        && profile.TryGetProperty("long_name", out var longName)
                        ? longName.GetString()
                        : null,
                    snippet = item.TryGetProperty("description", out var description)
                        ? description.GetString()
                        : null,
                    age = item.TryGetProperty("age", out var age) ? age.GetString() : null,
                }).ToArray()
                : Array.Empty<object>();

            result = JsonSerializer.Serialize(
                new
                {
                    kind = "search-web-result",
                    provider,
                    query,
                    endpoint = requestUri.ToString(),
                    country,
                    searchLanguage,
                    safeSearch,
                    count,
                    offset,
                    results,
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

    private static string? GetOptionalStringArg(IDictionary<string, object?> args, string name)
    {
        var arg = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)
        );

        if (arg.Equals(default(KeyValuePair<string, object?>)) || arg.Value is null)
            return null;

        return arg.Value switch
        {
            string s when !string.IsNullOrWhiteSpace(s) => s,
            JsonElement el when el.ValueKind == JsonValueKind.String => el.GetString(),
            JsonElement el when el.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => el.ToString(),
            _ => arg.Value.ToString(),
        };
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

    private static string NormalizeSearchWebProvider(string value)
    {
        return string.Equals(value, "brave", StringComparison.OrdinalIgnoreCase)
            ? "brave"
            : "brave";
    }

    private static string NormalizeSearchWebSafeSearch(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "moderate";

        var normalized = value.Trim().ToLowerInvariant();
        return normalized == "off"
            || normalized == "moderate"
            || normalized == "strict"
            ? normalized
            : "moderate";
    }

    private static Uri BuildBraveSearchUri(
        string endpoint,
        string query,
        int count,
        int offset,
        string country,
        string searchLanguage,
        string safeSearch
    )
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
            throw new ArgumentException($"Invalid SEARCH-WEB endpoint: {endpoint}", nameof(endpoint));

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("SEARCH-WEB only allows HTTPS endpoints.");

        var builder = new StringBuilder();
        builder.Append(uri.GetLeftPart(UriPartial.Path));
        builder.Append('?');
        builder.Append("q=").Append(Uri.EscapeDataString(query));
        builder.Append("&count=").Append(count.ToString(CultureInfo.InvariantCulture));
        builder.Append("&offset=").Append(offset.ToString(CultureInfo.InvariantCulture));
        builder.Append("&country=").Append(Uri.EscapeDataString(country));
        builder.Append("&search_lang=").Append(Uri.EscapeDataString(searchLanguage));
        builder.Append("&safesearch=").Append(Uri.EscapeDataString(safeSearch));

        return new Uri(builder.ToString(), UriKind.Absolute);
    }

    private static HttpResponseMessage SendBraveSearchRequest(Uri requestUri, string apiKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Add("X-Subscription-Token", apiKey);
        request.Headers.UserAgent.ParseAdd("TechToolbox-Agent/1.0");

        var response = _httpClient
            .SendAsync(request, HttpCompletionOption.ResponseContentRead)
            .GetAwaiter()
            .GetResult();

        if ((int)response.StatusCode >= 400)
        {
            var statusCode = (int)response.StatusCode;
            var reason = response.ReasonPhrase ?? "HTTP error";
            response.Dispose();
            throw new InvalidOperationException($"SEARCH-WEB failed with status {statusCode} ({reason}).");
        }

        return response;
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

        var normalizedUri = NormalizeFetchUri(uri);
        return normalizedUri;
    }

    private static Uri NormalizeFetchUri(Uri uri)
    {
        if (uri is null)
            throw new ArgumentNullException(nameof(uri));

        var builder = new UriBuilder(uri)
        {
            Scheme = Uri.UriSchemeHttps,
            Host = NormalizeHost(uri.Host),
            Port = -1,
            Fragment = string.Empty,
        };

        var path = uri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        builder.Path = NormalizePath(path);

        var query = uri.GetComponents(UriComponents.Query, UriFormat.UriEscaped);
        builder.Query = NormalizeQuery(query);

        var normalizedUri = builder.Uri;
        if (!normalizedUri.IsAbsoluteUri || string.IsNullOrWhiteSpace(normalizedUri.Host))
            throw new InvalidOperationException("FETCH-URL requires a URL with a valid host.");

        return normalizedUri;
    }

    private static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return string.Empty;

        var trimmed = host.Trim().Trim('.');
        if (trimmed.Length == 0)
            return string.Empty;

        return trimmed.ToLowerInvariant();
    }

    private static string NormalizePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return "/";

        if (!path.StartsWith('/'))
            path = "/" + path;

        return path.TrimEnd('/') switch
        {
            "" => "/",
            string trimmed => trimmed,
        };
    }

    private static string NormalizeQuery(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return string.Empty;

        if (query.StartsWith('?'))
            query = query[1..];

        if (string.IsNullOrWhiteSpace(query))
            return string.Empty;

        var segments = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
        return string.Join("&", segments.OrderBy(s => s, StringComparer.Ordinal));
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

        var normalizedHost = NormalizeHost(host);
        if (!HostMatchesAnyAllowedPattern(normalizedHost, allowedHosts))
        {
            throw new InvalidOperationException(
                $"FETCH-URL blocked host '{host}'. Allowed hosts: {string.Join(", ", allowedHosts.OrderBy(h => h, StringComparer.OrdinalIgnoreCase))}"
            );
        }
    }

    private static bool HostMatchesAnyAllowedPattern(string host, IReadOnlyCollection<string> allowedHosts)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;

        foreach (var allowedHost in allowedHosts)
        {
            if (string.IsNullOrWhiteSpace(allowedHost))
                continue;

            var normalizedAllowedHost = NormalizeHost(allowedHost);
            if (string.IsNullOrWhiteSpace(normalizedAllowedHost))
                continue;

            if (string.Equals(host, normalizedAllowedHost, StringComparison.OrdinalIgnoreCase))
                return true;

            if (normalizedAllowedHost.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = normalizedAllowedHost[2..];
                if (string.IsNullOrWhiteSpace(suffix))
                    continue;

                if (host.Equals(suffix, StringComparison.OrdinalIgnoreCase))
                    return true;

                if (host.EndsWith($".{suffix}", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
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

            currentUri = NormalizeFetchUri(currentUri);
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

    private static string ReadFileMeta(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var bytes = new FileInfo(fullPath).Length;
        var text = File.ReadAllText(fullPath);
        var lines = SplitLines(text);
        var totalLines = text.Length == 0 ? 0 : lines.Length;
        var extension = Path.GetExtension(fullPath);
        var isLarge = text.Length > GetReadFileSummaryThresholdChars();

        var thresholdChars = GetReadFileSummaryThresholdChars();
        var meta = new
        {
            kind = "file-meta",
            path = fullPath,
            bytes,
            chars = text.Length,
            totalLines,
            fileType = string.IsNullOrEmpty(extension) ? "unknown" : extension.ToLowerInvariant(),
            isLarge,
            exceedsSummaryThreshold = isLarge,
            summaryThresholdChars = thresholdChars,
        };

        return JsonSerializer.Serialize(meta, SummaryJsonOptions);
    }

    private static string ReadFileAutoChunk(string path, int chunkSize)
    {
        var lines = File.ReadAllLines(path);
        var totalLines = lines.Length;
        var safeChunkSize = Math.Clamp(chunkSize <= 0 ? 500 : chunkSize, 1, 5000);

        var chunks = new List<object>();
        for (var i = 0; i < totalLines; i += safeChunkSize)
        {
            var startLine = i + 1;
            var endLine = Math.Min(i + safeChunkSize, totalLines);
            var content = string.Join(Environment.NewLine, lines.Skip(i).Take(endLine - startLine + 1));
            chunks.Add(new
            {
                startLine,
                endLine,
                content,
            });
        }

        var autoChunk = new
        {
            kind = "auto-chunk",
            path,
            totalLines,
            chunkSize = safeChunkSize,
            chunks,
        };

        return JsonSerializer.Serialize(autoChunk, SummaryJsonOptions);
    }

    private static string ReadFileSemanticMatches(string path, string semantic, int contextLines)
    {
        var pattern = semantic;
        var safeContextLines = Math.Max(0, contextLines);
        var lines = File.ReadAllLines(path);
        var matches = new List<object>();

        if (lines.Length == 0)
        {
            return JsonSerializer.Serialize(new { kind = "semantic-chunk", matches = Array.Empty<object>() }, SummaryJsonOptions);
        }

        for (var index = 0; index < lines.Length; index++)
        {
            var current = lines[index];
            if (!Regex.IsMatch(current, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                continue;

            var startLine = Math.Max(1, index + 1 - safeContextLines);
            var endLine = Math.Min(lines.Length, index + 1 + safeContextLines);
            var content = string.Join(
                Environment.NewLine,
                lines.Skip(startLine - 1).Take(endLine - startLine + 1)
            );

            matches.Add(new
            {
                lineNumber = index + 1,
                startLine,
                endLine,
                content,
            });
        }

        return JsonSerializer.Serialize(new { kind = "semantic-chunk", matches }, SummaryJsonOptions);
    }

    private static string ReadFileHeaderFooter(string path, int headerLines, int footerLines)
    {
        var lines = File.ReadAllLines(path);
        var safeHeader = Math.Max(0, headerLines);
        var safeFooter = Math.Max(0, footerLines);

        var header = lines.Take(safeHeader).ToArray();
        var footer = safeFooter == 0 || lines.Length == 0
            ? Array.Empty<string>()
            : lines.Skip(Math.Max(0, lines.Length - safeFooter)).ToArray();

        var payload = new
        {
            kind = "header-footer",
            header,
            footer,
        };

        return JsonSerializer.Serialize(payload, SummaryJsonOptions);
    }

    private static string ReadFileStream(string path, string? nextToken, int chunkSize)
    {
        var lines = File.ReadAllLines(path);
        var safeChunkSize = Math.Clamp(chunkSize <= 0 ? 500 : chunkSize, 1, 5000);
        var streamIndex = 0;

        if (!string.IsNullOrWhiteSpace(nextToken) && long.TryParse(nextToken, out var parsedNextToken))
        {
            streamIndex = Math.Clamp((int)parsedNextToken, 0, lines.Length);
        }

        var contentLines = lines.Skip(streamIndex).Take(safeChunkSize).ToArray();
        var content = string.Join(Environment.NewLine, contentLines);
        var next = streamIndex + contentLines.Length >= lines.Length ? string.Empty : (streamIndex + contentLines.Length).ToString(CultureInfo.InvariantCulture);

        return JsonSerializer.Serialize(
            new
            {
                kind = "stream",
                nextToken = next,
                content,
            },
            SummaryJsonOptions
        );
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
