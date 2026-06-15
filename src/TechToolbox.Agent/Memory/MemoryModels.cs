namespace TechToolbox.Agent.Memory;

public class MemoryPayload
{
    public Dictionary<string, object?> Preferences { get; set; } = new();
    public Dictionary<string, object?> Facts { get; set; } = new();
    public List<RunHistory> History { get; set; } = new();
}

public class RunHistory
{
    public DateTimeOffset Timestamp { get; set; }

    // Short summary of the user’s intent or the final output
    public string Intent { get; set; } = "";

    // "success", "error", etc.
    public string Status { get; set; } = "";

    // "completed", "blocked", "needs-confirmation", etc.
    public string Outcome { get; set; } = "";

    // Number of tool calls made during the run
    public int ToolCalls { get; set; }

    // Ordered list of tool names used
    public List<string> ToolNames { get; set; } = new();

    // Duration of the run in milliseconds
    public int DurationMs { get; set; }
}
