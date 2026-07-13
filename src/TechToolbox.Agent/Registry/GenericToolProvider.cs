namespace TechToolbox.Agent.Registry;

/// <summary>
/// Provides generic built-in tools available to all agent modes:
/// file I/O operations (READ-FILE, WRITE-FILE, REPLACE-IN-FILE, LIST-DIRECTORY).
/// These are safe, non-destructive operations suitable for any use case.
/// </summary>
public class GenericToolProvider : IToolProvider
{
    /// <summary>
    /// Gets the display name of this tool provider.
    /// </summary>
    public string ProviderName => "Generic (Built-in File Tools)";

    /// <summary>
    /// Discovers and returns all built-in generic tools available in this provider.
    /// These include file I/O operations and URL fetching capabilities.
    /// </summary>
    /// <returns>
    /// An enumerable collection of <see cref="ToolSpec"/> objects representing
    /// each available tool with its name, description, parameters, and metadata.
    /// </returns>
    public IEnumerable<ToolSpec> DiscoverTools()
    {
        return new[]
        {
            new ToolSpec(
                Name: "READ-FILE",
                Description:
                    "Reads text content from a file. Supports optional chunked reads via startLine/endLine/maxLines. Large files may return a structured summary instead of the full body.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative file path."
                    ),
                    ["startLine"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional 1-based first line for chunked reads."
                    ),
                    ["endLine"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional 1-based inclusive end line for chunked reads."
                    ),
                    ["maxLines"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional chunk size when endLine is omitted (default 200, max 1000)."
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
            new ToolSpec(
                Name: "REPLACE-IN-FILE",
                Description:
                    "Performs exact text replacement within an existing file. Prefer this over WRITE-FILE for localized edits in large files.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative file path. File must already exist."
                    ),
                    ["oldText"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Exact existing text to replace."
                    ),
                    ["newText"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Replacement text."
                    ),
                    ["replaceAll"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Boolean",
                        Help: "Optional. When true, replaces all exact matches. Default false requires exactly one match."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
            new ToolSpec(
                Name: "FETCH-URL",
                Description: "Fetches text content from an HTTPS URL only when the host is on the allowlist.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["url"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "HTTPS URL to fetch."
                    ),
                    ["maxChars"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional response text cap. Defaults to 20000, max 200000."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };
    }
}
