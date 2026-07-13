// <copyright file="ManifestLoader.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

using System.Text.Json;

namespace TechToolbox.Agent.Registry;

/// <summary>
/// Provides functionality to load and parse manifest.json files that define available tools and their specifications.
/// The manifest is loaded from the application's base directory and contains mappings of tool names to their metadata.
/// </summary>
public static class ManifestLoader
{
    /// <summary>
    /// JSON serialization options used for deserializing manifest files.
    /// Configures case-insensitive property matching, comment handling, and trailing comma support.
    /// </summary>
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>
    /// Loads the manifest.json file from the application's base directory and deserializes it into a dictionary of tool specifications.
    /// If the manifest file does not exist, returns an empty dictionary.
    /// If the manifest file exists but cannot be parsed, returns a dictionary containing an error entry with details about the failure.
    /// </summary>
    /// <returns>
    /// A read-only dictionary mapping tool names (strings) to their corresponding <see cref="ToolSpec"/> objects.
    /// Returns an empty dictionary if no manifest is found or if parsing fails gracefully.
    /// In case of a parse error, returns a dictionary with a single entry keyed by "__manifest_error__" containing error details.
    /// </returns>
    /// <remarks>
    /// The manifest file is expected to be located at: {AppContext.BaseDirectory}\manifest.json
    /// This method is designed to fail gracefully since the manifest is optional.
    /// Any exceptions during deserialization are caught and reported via the error entry rather than thrown.
    /// </remarks>
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