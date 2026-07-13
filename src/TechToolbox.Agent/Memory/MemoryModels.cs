// <copyright file="MemoryModels.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

namespace TechToolbox.Agent.Memory;

using System.Text.Json.Serialization;

/// <summary>
/// Represents the payload structure for agent memory persistence.
/// Contains preferences, facts, and run history used by the memory system.
/// </summary>
public class MemoryPayload
{
    /// <summary>
    /// Gets or sets a dictionary of user preferences stored in memory.
    /// Keys are preference identifiers; values may be any serializable object.
    /// </summary>
    [JsonPropertyName("preferences")]
    public Dictionary<string, object?> Preferences { get; set; } = new();

    /// <summary>
    /// Gets or sets a dictionary of factual data stored in memory.
    /// Keys are fact identifiers; values may be any serializable object.
    /// </summary>
    [JsonPropertyName("facts")]
    public Dictionary<string, object?> Facts { get; set; } = new();

    /// <summary>
    /// Gets or sets the list of recent run history entries.
    /// Each entry captures details about a completed agent execution.
    /// </summary>
    [JsonPropertyName("history")]
    public List<RunHistory> History { get; set; } = new();

    /// <summary>
    /// Gets or sets the memory format version number.
    /// Used for schema compatibility checks during deserialization.
    /// </summary>
    [JsonPropertyName("_memoryFormatVersion")]
    public int MemoryFormatVersion { get; set; } = 2;
}

/// <summary>
/// Represents a single run history entry capturing details about an agent execution.
/// Includes metadata such as timestamps, outcomes, tool usage, and a summary of actions taken.
/// </summary>
public class RunHistory
{
    /// <summary>
    /// Gets or sets the UTC timestamp when the run was recorded.
    /// </summary>
    [JsonPropertyName("timestampUtc")]
    public DateTimeOffset TimestampUtc { get; set; }

    /// <summary>
    /// Gets or sets the status of the run (e.g., "success", "failed", "blocked").
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    /// <summary>
    /// Gets or sets the outcome description of the run.
    /// </summary>
    [JsonPropertyName("outcome")]
    public string Outcome { get; set; } = "";

    /// <summary>
    /// Gets or sets the original prompt that initiated the run.
    /// </summary>
    [JsonPropertyName("prompt")]
    public string Prompt { get; set; } = "";

    /// <summary>
    /// Gets or sets the model identifier used for the run.
    /// </summary>
    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    /// <summary>
    /// Gets or sets the duration of the run in milliseconds.
    /// </summary>
    [JsonPropertyName("durationMs")]
    public int DurationMs { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of iterations allowed for the run.
    /// </summary>
    [JsonPropertyName("maxIterations")]
    public int MaxIterations { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether destructive actions were explicitly confirmed.
    /// </summary>
    [JsonPropertyName("destructiveConfirmed")]
    public bool DestructiveConfirmed { get; set; }

    /// <summary>
    /// Gets or sets the policy for handling unsigned files (e.g., "ignore", "block", "warn").
    /// </summary>
    [JsonPropertyName("signedFilePolicy")]
    public string SignedFilePolicy { get; set; } = "ignore";

    /// <summary>
    /// Gets or sets a value indicating whether automatic retry is enabled on recursion detection.
    /// </summary>
    [JsonPropertyName("autoRetryOnRecursion")]
    public bool AutoRetryOnRecursion { get; set; }

    /// <summary>
    /// Gets or sets the total number of tool calls made during the run.
    /// </summary>
    [JsonPropertyName("toolCalls")]
    public int ToolCalls { get; set; }

    /// <summary>
    /// Gets or sets the list of tool names invoked during the run.
    /// </summary>
    [JsonPropertyName("toolNames")]
    public List<string> ToolNames { get; set; } = new();

    /// <summary>
    /// Gets or sets a preview of the run output for quick reference.
    /// </summary>
    [JsonPropertyName("outputPreview")]
    public string OutputPreview { get; set; } = "";

    /// <summary>
    /// Gets or sets an error message if the run failed, or null if no error occurred.
    /// </summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>
    /// Gets or sets a detailed summary of the run including intent and actions taken.
    /// </summary>
    [JsonPropertyName("runSummary")]
    public RunSummary? RunSummary { get; set; }

    /// <summary>
    /// Gets the timestamp of the run as a DateTimeOffset.
    /// This is a computed property derived from TimestampUtc and is excluded from JSON serialization.
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset Timestamp => TimestampUtc;

    /// <summary>
    /// Gets the inferred intent of the run, preferring the summary intent over the original prompt.
    /// This is a computed property and is excluded from JSON serialization.
    /// </summary>
    [JsonIgnore]
    public string Intent => RunSummary?.Intent ?? Prompt;
}

/// <summary>
/// Represents a summary of actions taken during an agent run.
/// Captures the intent, actions performed, blockers encountered, and the next recommended step.
/// </summary>
public class RunSummary
{
    /// <summary>
    /// Gets or sets the inferred intent of the run.
    /// </summary>
    [JsonPropertyName("intent")]
    public string Intent { get; set; } = "";

    /// <summary>
    /// Gets or sets the list of actions taken during the run.
    /// </summary>
    [JsonPropertyName("actionsTaken")]
    public List<string> ActionsTaken { get; set; } = new();

    /// <summary>
    /// Gets or sets a description of any blockers encountered during the run.
    /// </summary>
    [JsonPropertyName("blockers")]
    public string Blockers { get; set; } = "";

    /// <summary>
    /// Gets or sets the next best step recommended after the run completed.
    /// </summary>
    [JsonPropertyName("nextBestStep")]
    public string NextBestStep { get; set; } = "";
}

/// <summary>
/// Represents a summary of trends computed from multiple agent runs.
/// Aggregates statistics such as success rates, average durations, and status/outcome distributions.
/// </summary>
public class TrendSummary
{
    /// <summary>
    /// Gets or sets the number of items currently in the trend window.
    /// </summary>
    [JsonPropertyName("windowItems")]
    public int WindowItems { get; set; }

    /// <summary>
    /// Gets or sets the total number of runs included in the trend calculation.
    /// </summary>
    [JsonPropertyName("runCount")]
    public int RunCount { get; set; }

    /// <summary>
    /// Gets or sets the success rate as a decimal value between 0.0 and 1.0.
    /// </summary>
    [JsonPropertyName("successRate")]
    public double SuccessRate { get; set; }

    /// <summary>
    /// Gets or sets the average run duration in milliseconds.
    /// </summary>
    [JsonPropertyName("avgDurationMs")]
    public int AvgDurationMs { get; set; }

    /// <summary>
    /// Gets or sets the average number of tool calls per run.
    /// </summary>
    [JsonPropertyName("avgToolCalls")]
    public double AvgToolCalls { get; set; }

    /// <summary>
    /// Gets or sets a dictionary mapping status values to their occurrence counts.
    /// </summary>
    [JsonPropertyName("statusCounts")]
    public Dictionary<string, int> StatusCounts { get; set; } = new();

    /// <summary>
    /// Gets or sets a dictionary mapping outcome values to their occurrence counts.
    /// </summary>
    [JsonPropertyName("outcomeCounts")]
    public Dictionary<string, int> OutcomeCounts { get; set; } = new();

    /// <summary>
    /// Gets or sets the status of the most recent run.
    /// </summary>
    [JsonPropertyName("lastStatus")]
    public string LastStatus { get; set; } = "";

    /// <summary>
    /// Gets or sets the outcome of the most recent run.
    /// </summary>
    [JsonPropertyName("lastOutcome")]
    public string LastOutcome { get; set; } = "";

    /// <summary>
    /// Gets or sets the model identifier used in the most recent run.
    /// </summary>
    [JsonPropertyName("lastModel")]
    public string LastModel { get; set; } = "";

    /// <summary>
    /// Gets or sets the UTC timestamp of the most recent run, stored as a string.
    /// </summary>
    [JsonPropertyName("lastRunTimestampUtc")]
    public string LastRunTimestampUtc { get; set; } = "";

    /// <summary>
    /// Gets or sets the UTC timestamp when the trend summary was last updated, stored as a string.
    /// </summary>
    [JsonPropertyName("trendLastUpdatedUtc")]
    public string TrendLastUpdatedUtc { get; set; } = "";
}