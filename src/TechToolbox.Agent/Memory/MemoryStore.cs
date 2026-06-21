using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechToolbox.Agent.Memory;

public class MemoryStore
{
    private const int BaseHistoryWindow = 30;
    private const int HistoryFileWindow = 250;
    private readonly string _basePath;
    private readonly string _historyPath;

    public Dictionary<string, object?> Preferences { get; private set; } = new();
    public Dictionary<string, object?> Facts { get; private set; } = new();
    public List<RunHistory> History { get; private set; } = new();

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public MemoryStore(string path)
    {
        _basePath = path;
        _historyPath = Path.Combine(
            Path.GetDirectoryName(path)!,
            Path.GetFileNameWithoutExtension(path) + ".history.json");

        Load();
    }

    private void Load()
    {
        if (File.Exists(_basePath))
        {
            try
            {
                var json = File.ReadAllText(_basePath);
                var payload = JsonSerializer.Deserialize<MemoryPayload>(json, _jsonOptions)
                              ?? new MemoryPayload();

                Preferences = payload.Preferences ?? new();
                Facts = payload.Facts ?? new();
                History = payload.History ?? new();
            }
            catch
            {
                Preferences = new();
                Facts = new();
                History = new();
            }
        }

        if (File.Exists(_historyPath))
        {
            try
            {
                var json = File.ReadAllText(_historyPath);
                var hist = JsonSerializer.Deserialize<List<RunHistory>>(json, _jsonOptions)
                           ?? new List<RunHistory>();
                if (hist.Count > 0)
                {
                    History = hist;
                }
            }
            catch
            {
                // Keep whatever was loaded from the base file.
            }
        }

        NormalizeHistory();
        UpdateTrendSummary();
    }

    public void Save()
    {
        NormalizeHistory();
        UpdateTrendSummary();

        var payload = new MemoryPayload
        {
            Preferences = Preferences,
            Facts = Facts,
            History = History.TakeLast(BaseHistoryWindow).ToList(),
            MemoryFormatVersion = 2
        };

        Directory.CreateDirectory(Path.GetDirectoryName(_basePath)!);
        File.WriteAllText(_basePath, JsonSerializer.Serialize(payload, _jsonOptions));

        Directory.CreateDirectory(Path.GetDirectoryName(_historyPath)!);
        File.WriteAllText(_historyPath, JsonSerializer.Serialize(History.TakeLast(HistoryFileWindow).ToList(), _jsonOptions));
    }

    public void AddRun(RunHistory entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        History.Add(entry);

        if (History.Count > HistoryFileWindow)
        {
            History = History.TakeLast(HistoryFileWindow).ToList();
        }

        Save();
    }

    public void AddHistory(RunHistory entry)
        => AddRun(entry);

    public void SetPreference(string key, object? value)
    {
        Preferences[key] = value;
        Save();
    }

    public void SetFact(string key, object? value)
    {
        Facts[key] = value;
        Save();
    }

    public object? GetPreference(string key)
        => Preferences.TryGetValue(key, out var v) ? v : null;

    public object? GetFact(string key)
        => Facts.TryGetValue(key, out var v) ? v : null;

    private void NormalizeHistory()
    {
        foreach (var entry in History)
        {
            if (entry.TimestampUtc == default)
            {
                entry.TimestampUtc = DateTimeOffset.UtcNow;
            }

            entry.Status = string.IsNullOrWhiteSpace(entry.Status) ? "success" : entry.Status;
            entry.Outcome = string.IsNullOrWhiteSpace(entry.Outcome) ? "completed" : entry.Outcome;
            entry.Prompt ??= string.Empty;
            entry.Model ??= string.Empty;
            entry.SignedFilePolicy = string.IsNullOrWhiteSpace(entry.SignedFilePolicy) ? "ignore" : entry.SignedFilePolicy;
            entry.ToolNames ??= new List<string>();
            entry.OutputPreview ??= string.Empty;
            entry.RunSummary ??= new RunSummary
            {
                Intent = BuildIntent(entry.Prompt, entry.OutputPreview),
                ActionsTaken = entry.ToolNames.Select(NormalizeActionName).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                Blockers = entry.Outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
                    ? string.Empty
                    : BuildBlockers(entry.OutputPreview),
                NextBestStep = BuildNextBestStep(entry.OutputPreview, entry.Outcome)
            };
        }
    }

    private void UpdateTrendSummary()
    {
        var window = History.TakeLast(BaseHistoryWindow).ToList();
        if (window.Count == 0)
        {
            return;
        }

        var statusCounts = window
            .GroupBy(h => string.IsNullOrWhiteSpace(h.Status) ? "unknown" : h.Status, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key.ToLowerInvariant(), g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var outcomeCounts = window
            .GroupBy(h => string.IsNullOrWhiteSpace(h.Outcome) ? "unknown" : h.Outcome, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key.ToLowerInvariant(), g => g.Count(), StringComparer.OrdinalIgnoreCase);

        var successCount = statusCounts.TryGetValue("success", out var count) ? count : 0;
        var avgDuration = (int)Math.Round(window.Average(h => h.DurationMs), MidpointRounding.AwayFromZero);
        var avgToolCalls = Math.Round(window.Average(h => h.ToolCalls), 2, MidpointRounding.AwayFromZero);
        var latest = window[^1];

        Facts["trendSummary"] = new TrendSummary
        {
            WindowItems = BaseHistoryWindow,
            RunCount = window.Count,
            SuccessRate = Math.Round((double)successCount / window.Count, 3, MidpointRounding.AwayFromZero),
            AvgDurationMs = avgDuration,
            AvgToolCalls = avgToolCalls,
            StatusCounts = statusCounts,
            OutcomeCounts = outcomeCounts,
            LastStatus = latest.Status,
            LastOutcome = latest.Outcome,
            LastModel = latest.Model,
            LastRunTimestampUtc = latest.TimestampUtc.ToString("o"),
            TrendLastUpdatedUtc = DateTimeOffset.UtcNow.ToString("o")
        };
    }

    private static string BuildIntent(string prompt, string output)
    {
        if (!string.IsNullOrWhiteSpace(prompt))
        {
            return Truncate(prompt, 220);
        }

        return Truncate(output, 220);
    }

    private static string BuildBlockers(string output)
        => string.IsNullOrWhiteSpace(output) ? string.Empty : Truncate(output, 320);

    private static string BuildNextBestStep(string output, string outcome)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : "Review the run output and resolve the blocker before retrying.";
        }

        var lines = output
            .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .ToArray();

        foreach (var line in lines)
        {
            if (line.StartsWith("Next best action", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Next step", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("What Is Required", StringComparison.OrdinalIgnoreCase))
            {
                return Truncate(line, 220);
            }
        }

        return outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : "Retry after addressing the error details captured in outputPreview.";
    }

    private static string NormalizeActionName(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return string.Empty;
        }

        return toolName.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
    }

    private static string Truncate(string value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return normalized.Length <= maxChars ? normalized : normalized[..maxChars] + "...";
    }
}
