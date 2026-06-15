using System.Text.Json;

namespace TechToolbox.Agent.Memory;

public class MemoryStore
{
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
        AllowTrailingCommas = true
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
        // Load main memory file
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
                // If corrupted, reset to empty
                Preferences = new();
                Facts = new();
                History = new();
            }
        }

        // Load rolling history file
        if (File.Exists(_historyPath))
        {
            try
            {
                var json = File.ReadAllText(_historyPath);
                var hist = JsonSerializer.Deserialize<List<RunHistory>>(json, _jsonOptions)
                           ?? new List<RunHistory>();

                History = hist;
            }
            catch
            {
                // Ignore corrupted history
            }
        }
    }

    public void Save()
    {
        var payload = new MemoryPayload
        {
            Preferences = Preferences,
            Facts = Facts,
            History = History.TakeLast(8).ToList()
        };

        Directory.CreateDirectory(Path.GetDirectoryName(_basePath)!);
        File.WriteAllText(_basePath, JsonSerializer.Serialize(payload, _jsonOptions));

        Directory.CreateDirectory(Path.GetDirectoryName(_historyPath)!);
        File.WriteAllText(_historyPath, JsonSerializer.Serialize(History, _jsonOptions));
    }

    public void AddHistory(RunHistory entry)
    {
        History.Add(entry);

        // Keep only last 8 entries
        if (History.Count > 8)
            History = History.TakeLast(8).ToList();

        Save();
    }

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
}
