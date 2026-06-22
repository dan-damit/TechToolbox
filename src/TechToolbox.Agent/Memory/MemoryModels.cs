namespace TechToolbox.Agent.Memory;

using System.Text.Json.Serialization;

public class MemoryPayload
{
    [JsonPropertyName("preferences")]
    public Dictionary<string, object?> Preferences { get; set; } = new();

    [JsonPropertyName("facts")]
    public Dictionary<string, object?> Facts { get; set; } = new();

    [JsonPropertyName("history")]
    public List<RunHistory> History { get; set; } = new();

    [JsonPropertyName("_memoryFormatVersion")]
    public int MemoryFormatVersion { get; set; } = 2;
}

public class RunHistory
{
    [JsonPropertyName("timestampUtc")]
    public DateTimeOffset TimestampUtc { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "";

    [JsonPropertyName("outcome")]
    public string Outcome { get; set; } = "";

    [JsonPropertyName("prompt")]
    public string Prompt { get; set; } = "";

    [JsonPropertyName("model")]
    public string Model { get; set; } = "";

    [JsonPropertyName("durationMs")]
    public int DurationMs { get; set; }

    [JsonPropertyName("maxIterations")]
    public int MaxIterations { get; set; }

    [JsonPropertyName("destructiveConfirmed")]
    public bool DestructiveConfirmed { get; set; }

    [JsonPropertyName("signedFilePolicy")]
    public string SignedFilePolicy { get; set; } = "ignore";

    [JsonPropertyName("autoRetryOnRecursion")]
    public bool AutoRetryOnRecursion { get; set; }

    [JsonPropertyName("toolCalls")]
    public int ToolCalls { get; set; }

    [JsonPropertyName("toolNames")]
    public List<string> ToolNames { get; set; } = new();

    [JsonPropertyName("outputPreview")]
    public string OutputPreview { get; set; } = "";

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("runSummary")]
    public RunSummary? RunSummary { get; set; }

    [JsonIgnore]
    public DateTimeOffset Timestamp => TimestampUtc;

    [JsonIgnore]
    public string Intent => RunSummary?.Intent ?? Prompt;
}

public class RunSummary
{
    [JsonPropertyName("intent")]
    public string Intent { get; set; } = "";

    [JsonPropertyName("actionsTaken")]
    public List<string> ActionsTaken { get; set; } = new();

    [JsonPropertyName("blockers")]
    public string Blockers { get; set; } = "";

    [JsonPropertyName("nextBestStep")]
    public string NextBestStep { get; set; } = "";
}

public class TrendSummary
{
    [JsonPropertyName("windowItems")]
    public int WindowItems { get; set; }

    [JsonPropertyName("runCount")]
    public int RunCount { get; set; }

    [JsonPropertyName("successRate")]
    public double SuccessRate { get; set; }

    [JsonPropertyName("avgDurationMs")]
    public int AvgDurationMs { get; set; }

    [JsonPropertyName("avgToolCalls")]
    public double AvgToolCalls { get; set; }

    [JsonPropertyName("statusCounts")]
    public Dictionary<string, int> StatusCounts { get; set; } = new();

    [JsonPropertyName("outcomeCounts")]
    public Dictionary<string, int> OutcomeCounts { get; set; } = new();

    [JsonPropertyName("lastStatus")]
    public string LastStatus { get; set; } = "";

    [JsonPropertyName("lastOutcome")]
    public string LastOutcome { get; set; } = "";

    [JsonPropertyName("lastModel")]
    public string LastModel { get; set; } = "";

    [JsonPropertyName("lastRunTimestampUtc")]
    public string LastRunTimestampUtc { get; set; } = "";

    [JsonPropertyName("trendLastUpdatedUtc")]
    public string TrendLastUpdatedUtc { get; set; } = "";
}
