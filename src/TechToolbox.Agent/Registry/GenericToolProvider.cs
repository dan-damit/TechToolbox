namespace TechToolbox.Agent.Registry;

/// <summary>
/// Provides generic built-in tools available to all agent modes:
/// file I/O operations (READ-FILE, WRITE-FILE, APPEND-FILE, FINALIZE-FILE-WRITE,
/// REPLACE-IN-FILE, LIST-DIRECTORY).
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
                    "Reads text content from a file. Supports chunked reads, large-file structured summaries, semantic context, header/footer extraction, metadata queries, and streaming reads.",
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
                    ["autoChunk"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Boolean",
                        Help: "Optional. When true, reads the file sequentially in chunks and returns structured chunk metadata."
                    ),
                    ["chunkSize"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional chunk size used by autoChunk and stream modes (default 500 lines)."
                    ),
                    ["semantic"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.String",
                        Help: "Optional regex or keyword to match within the file and return context windows around each match."
                    ),
                    ["contextLines"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional number of lines before and after each semantic match to include (default 40)."
                    ),
                    ["headerLines"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional number of leading lines to return from the file."
                    ),
                    ["footerLines"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional number of trailing lines to return from the file."
                    ),
                    ["stream"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Boolean",
                        Help: "Optional. When true, returns a first chunk plus a nextToken for continued streaming reads."
                    ),
                    ["nextToken"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.String",
                        Help: "Optional continuation token for streamed READ-FILE requests."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
            new ToolSpec(
                Name: "READ-FILE-META",
                Description:
                    "Returns metadata about a file including size, total lines, extension, and whether it exceeds the summary threshold.",
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
            new ToolSpec(
                Name: "APPEND-FILE",
                Description:
                    "Appends text to a file, creating parent directories as needed. Use truncateFirst=true on the first chunk to replace existing content before appending.",
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
                        Help: "Text content to append."
                    ),
                    ["truncateFirst"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Boolean",
                        Help: "Optional. When true, truncates/replaces the file before appending this chunk."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
            new ToolSpec(
                Name: "FINALIZE-FILE-WRITE",
                Description:
                    "Finalizes a chunked APPEND-FILE write for a target path and returns file stats to confirm completion.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["path"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Absolute or relative file path that was written via APPEND-FILE chunks."
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
            new ToolSpec(
                Name: "SEARCH-WEB",
                Description:
                    "Searches the public web API provider for likely sources and returns a compact result set for read-only discovery.",
                Parameters: new Dictionary<string, ParameterSpec>(StringComparer.OrdinalIgnoreCase)
                {
                    ["query"] = new ParameterSpec(
                        Mandatory: true,
                        Type: "System.String",
                        Help: "Search query text."
                    ),
                    ["count"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional result count. Defaults to 5, max 50."
                    ),
                    ["offset"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.Int32",
                        Help: "Optional 0-based result offset."
                    ),
                    ["country"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.String",
                        Help: "Optional country code such as us."
                    ),
                    ["searchLang"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.String",
                        Help: "Optional search language code such as en."
                    ),
                    ["safeSearch"] = new ParameterSpec(
                        Mandatory: false,
                        Type: "System.String",
                        Help: "Optional safe-search level: off, moderate, or strict."
                    ),
                },
                Module: "TechToolbox.Agent.Builtin",
                Meta: new Dictionary<string, object?>()
            ),
        };
    }
}
