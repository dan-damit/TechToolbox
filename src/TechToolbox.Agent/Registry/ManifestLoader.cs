using System.Text.Json;

namespace TechToolbox.Agent.Registry;

public static class ManifestLoader
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static IReadOnlyDictionary<string, ToolSpec> LoadManifest()
    {
        var manifestPath = Path.Combine(AppContext.BaseDirectory, "manifest.json");

        if (!File.Exists(manifestPath))
            return new Dictionary<string, ToolSpec>();

        try
        {
            var json = File.ReadAllText(manifestPath);
            var dict = JsonSerializer.Deserialize<Dictionary<string, ToolSpec>>(json, _jsonOptions);

            return dict ?? new Dictionary<string, ToolSpec>();
        }
        catch (Exception ex)
        {
            // Fail gracefully — manifest is optional
            return new Dictionary<string, ToolSpec>
            {
                ["__manifest_error__"] = new ToolSpec(
                    Name: "__manifest_error__",
                    Description: $"Manifest failed to load: {ex.Message}",
                    Parameters: new Dictionary<string, ParameterSpec>(),
                    Module: "TechToolbox",
                    Meta: new Dictionary<string, object?>()
                ),
            };
        }
    }
}
