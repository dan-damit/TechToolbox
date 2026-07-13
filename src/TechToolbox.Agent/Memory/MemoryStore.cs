// <copyright file="MemoryStore.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechToolbox.Agent.Memory;

/// <summary>
/// Provides persistent storage for agent memory, including preferences,
/// facts, and run history. Data is serialized to JSON files on disk.
/// </summary>
public class MemoryStore
{
    /// <summary>
    /// The number of recent history entries retained in the base memory file.
    /// </summary>
    private const int BaseHistoryWindow = 20;

    /// <summary>
    /// The maximum number of history entries retained in the dedicated history file.
    /// </summary>
    private const int HistoryFileWindow = 250;

    /// <summary>
    /// Gets or sets the base path for the primary memory JSON file.
    /// </summary>
    private readonly string _basePath;

    /// <summary>
    /// Gets or sets the path for the dedicated history JSON file.
    /// </summary>
    private readonly string _historyPath;

    /// <summary>
    /// Gets or sets a dictionary containing user preferences persisted across sessions.
    /// </summary>
    public Dictionary<string, object?> Preferences { get; private set; } = new();

    /// <summary>
    /// Gets or sets a dictionary containing factual data persisted across sessions.
    /// </summary>
    public Dictionary<string, object?> Facts { get; private set; } = new();

    /// <summary>
    /// Gets or sets the list of run history entries recorded during agent execution.
    /// </summary>
    public List<RunHistory> History { get; private set; } = new();

    /// <summary>
    /// Gets the JSON serialization options used for reading and writing memory files.
    /// Configured to produce human-readable output with lenient parsing.
    /// </summary>
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Initializes a new instance of the <see cref="MemoryStore"/> class.
    /// </summary>
    /// <param name="path">
    /// The file path where the primary memory JSON file will be stored.
    /// A companion history file will be created in the same directory.
    /// </param>
    public MemoryStore(string path)
    {
        _basePath = path;
        _historyPath = Path.Combine(
            Path.GetDirectoryName(path)!,
            Path.GetFileNameWithoutExtension(path) + ".history.json"
        );

        Load();
    }

    /// <summary>
    /// Loads memory data from disk. Reads the primary memory file and the
    /// companion history file, merging them into the current instance state.
    /// If either file does not exist or fails to parse, safe defaults are used.
    /// </summary>
    private void Load()
    {
        if (File.Exists(_basePath))
        {
            try
            {
                var json = File.ReadAllText(_basePath);
                var payload =
                    JsonSerializer.Deserialize<MemoryPayload>(json, _jsonOptions)
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
                var hist =
                    JsonSerializer.Deserialize<List<RunHistory>>(json, _jsonOptions)
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

    /// <summary>
    /// Saves the current state of preferences, facts, and history to disk.
    /// The history is truncated to the configured window sizes before persistence.
    /// </summary>
    public void Save()
    {
        NormalizeHistory();
        UpdateTrendSummary();

        var payload = new MemoryPayload
        {
            Preferences = Preferences,
            Facts = Facts,
            History = History.TakeLast(BaseHistoryWindow).ToList(),
            MemoryFormatVersion = 2,
        };

        Directory.CreateDirectory(Path.GetDirectoryName(_basePath)!);
        File.WriteAllText(_basePath, JsonSerializer.Serialize(payload, _jsonOptions));

        Directory.CreateDirectory(Path.GetDirectoryName(_historyPath)!);
        File.WriteAllText(
            _historyPath,
            JsonSerializer.Serialize(History.TakeLast(HistoryFileWindow).ToList(), _jsonOptions)
        );
    }

    /// <summary>
    /// Adds a single run history entry to the history list and persists the changes.
    /// </summary>
    /// <param name="entry">The run history entry to add. Must not be null.</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="entry"/> is null.
    /// </exception>
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

    /// <summary>
    /// Adds a single run history entry to the history list and persists the changes.
    /// This is an alias for <see cref="AddRun(RunHistory)"/>.
    /// </summary>
    /// <param name="entry">The run history entry to add. Must not be null.</param>
    public void AddHistory(RunHistory entry) => AddRun(entry);

    /// <summary>
    /// Sets a preference value and persists the changes to disk.
    /// </summary>
    /// <param name="key">The preference key to set or update.</param>
    /// <param name="value">The preference value. Can be null to clear the preference.</param>
    public void SetPreference(string key, object? value)
    {
        Preferences[key] = value;
        Save();
    }

    /// <summary>
    /// Sets a fact value and persists the changes to disk.
    /// </summary>
    /// <param name="key">The fact key to set or update.</param>
    /// <param name="value">The fact value. Can be null to clear the fact.</param>
    public void SetFact(string key, object? value)
    {
        Facts[key] = value;
        Save();
    }

    /// <summary>
    /// Retrieves a preference value by its key.
    /// </summary>
    /// <param name="key">The preference key to look up.</param>
    /// <returns>
    /// The preference value if found; otherwise, null.
    /// </returns>
    public object? GetPreference(string key) => Preferences.TryGetValue(key, out var v) ? v : null;

    /// <summary>
    /// Retrieves a fact value by its key.
    /// </summary>
    /// <param name="key">The fact key to look up.</param>
    /// <returns>
    /// The fact value if found; otherwise, null.
    /// </returns>
    public object? GetFact(string key) => Facts.TryGetValue(key, out var v) ? v : null;

    /// <summary>
    /// Normalizes all history entries by ensuring required fields have valid defaults.
    /// Sets missing timestamps to the current UTC time, normalizes status and outcome
    /// values, and builds run summary data including intent, actions taken, blockers,
    /// and next best step suggestions.
    /// </summary>
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
            entry.SignedFilePolicy = string.IsNullOrWhiteSpace(entry.SignedFilePolicy)
                ? "ignore"
                : entry.SignedFilePolicy;
            entry.ToolNames ??= new List<string>();
            entry.OutputPreview ??= string.Empty;
            entry.RunSummary ??= new RunSummary
            {
                Intent = BuildIntent(entry.Prompt, entry.OutputPreview),
                ActionsTaken = entry
                    .ToolNames.Select(NormalizeActionName)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList(),
                Blockers = entry.Outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
                    ? string.Empty
                    : BuildBlockers(entry.OutputPreview),
                NextBestStep = BuildNextBestStep(entry.OutputPreview, entry.Outcome),
            };
        }
    }

    /// <summary>
    /// Updates the trend summary fact by analyzing recent run history.
    /// Computes statistics including success rate, average duration, average tool calls,
    /// and status/outcome distributions over the configured history window.
    /// </summary>
    private void UpdateTrendSummary()
    {
        var window = History.TakeLast(BaseHistoryWindow).ToList();
        if (window.Count == 0)
        {
            return;
        }

        var statusCounts = window
            .GroupBy(
                h => string.IsNullOrWhiteSpace(h.Status) ? "unknown" : h.Status,
                StringComparer.OrdinalIgnoreCase
            )
            .ToDictionary(
                g => g.Key.ToLowerInvariant(),
                g => g.Count(),
                StringComparer.OrdinalIgnoreCase
            );

        var outcomeCounts = window
            .GroupBy(
                h => string.IsNullOrWhiteSpace(h.Outcome) ? "unknown" : h.Outcome,
                StringComparer.OrdinalIgnoreCase
            )
            .ToDictionary(
                g => g.Key.ToLowerInvariant(),
                g => g.Count(),
                StringComparer.OrdinalIgnoreCase
            );

        var successCount = statusCounts.TryGetValue("success", out var count) ? count : 0;
        var avgDuration = (int)
            Math.Round(window.Average(h => h.DurationMs), MidpointRounding.AwayFromZero);
        var avgToolCalls = Math.Round(
            window.Average(h => h.ToolCalls),
            2,
            MidpointRounding.AwayFromZero
        );
        var latest = window[^1];

        Facts["trendSummary"] = new TrendSummary
        {
            WindowItems = BaseHistoryWindow,
            RunCount = window.Count,
            SuccessRate = Math.Round(
                (double)successCount / window.Count,
                3,
                MidpointRounding.AwayFromZero
            ),
            AvgDurationMs = avgDuration,
            AvgToolCalls = avgToolCalls,
            StatusCounts = statusCounts,
            OutcomeCounts = outcomeCounts,
            LastStatus = latest.Status,
            LastOutcome = latest.Outcome,
            LastModel = latest.Model,
            LastRunTimestampUtc = latest.TimestampUtc.ToString("o"),
            TrendLastUpdatedUtc = DateTimeOffset.UtcNow.ToString("o"),
        };
    }

    /// <summary>
    /// Builds an intent string from the prompt or output preview.
    /// </summary>
    /// <param name="prompt">The original user prompt.</param>
    /// <param name="output">The run output preview.</param>
    /// <returns>
    /// A truncated string representing the intent, up to 220 characters.
    /// </returns>
    private static string BuildIntent(string prompt, string output)
    {
        if (!string.IsNullOrWhiteSpace(prompt))
        {
            return Truncate(prompt, 220);
        }

        return Truncate(output, 220);
    }

    /// <summary>
    /// Builds a blockers string from the output preview.
    /// </summary>
    /// <param name="output">The run output preview.</param>
    /// <returns>
    /// A truncated string representing blockers, up to 320 characters.
    /// Returns empty string if output is null or whitespace.
    /// </returns>
    private static string BuildBlockers(string output) =>
        string.IsNullOrWhiteSpace(output) ? string.Empty : Truncate(output, 320);

    /// <summary>
    /// Builds a next best step suggestion from the output preview and outcome.
    /// Looks for explicit "Next best action" or similar markers in the output.
    /// </summary>
    /// <param name="output">The run output preview.</param>
    /// <param name="outcome">The run outcome status.</param>
    /// <returns>
    /// A suggested next step string, up to 220 characters.
    /// Returns empty string if the run completed successfully.
    /// </returns>
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
            if (
                line.StartsWith("Next best action", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Next step", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("What Is Required", StringComparison.OrdinalIgnoreCase)
            )
            {
                return Truncate(line, 220);
            }
        }

        return outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : "Retry after addressing the error details captured in outputPreview.";
    }

    /// <summary>
    /// Normalizes a tool name by trimming, lowercasing, and replacing hyphens and spaces with underscores.
    /// </summary>
    /// <param name="toolName">The original tool name.</param>
    /// <returns>
    /// A normalized tool name string. Returns empty string if input is null or whitespace.
    /// </returns>
    private static string NormalizeActionName(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return string.Empty;
        }

        return toolName.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
    }

    /// <summary>
    /// Truncates a string to a maximum character count, appending an ellipsis if truncated.
    /// </summary>
    /// <param name="value">The string to truncate.</param>
    /// <param name="maxChars">The maximum number of characters to retain.</param>
    /// <returns>
    /// The truncated string with ellipsis if it exceeded the limit, or the original
    /// trimmed string if within the limit. Returns empty string if input is null or whitespace.
    /// </returns>
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