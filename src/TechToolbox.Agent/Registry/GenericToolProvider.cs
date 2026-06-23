namespace TechToolbox.Agent.Registry;

/// <summary>
/// Provides generic built-in tools available to all agent modes:
/// file I/O operations (READ-FILE, WRITE-FILE, LIST-DIRECTORY).
/// These are safe, non-destructive operations suitable for any use case.
/// </summary>
public class GenericToolProvider : IToolProvider
{
    public string ProviderName => "Generic (Built-in File Tools)";

    public IEnumerable<ToolSpec> DiscoverTools()
    {
        return new[]
        {
            new ToolSpec(
                Name: "READ-FILE",
                Description:
                    "Reads text content from a file. Large files may return a structured summary instead of the full body.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative file path."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
            new ToolSpec(
                Name: "LIST-DIRECTORY",
                Description: "Lists directory entries. Folder names end with '/'.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative directory path."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
            new ToolSpec(
                Name: "WRITE-FILE",
                Description: "Writes text to a file, creating parent directories as needed.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative file path."
                    ),
                    ["content"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Text content to write."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };
    }
}
