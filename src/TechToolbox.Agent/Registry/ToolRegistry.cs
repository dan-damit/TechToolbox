using System.Management.Automation;

namespace TechToolbox.Agent.Registry;

public static class ToolRegistry
{
    public static IReadOnlyDictionary<string, ToolSpec> BuildToolRegistry()
    {
        var discovered = DiscoverTools();
        var manifest = ManifestLoader.LoadManifest();

        var registry = new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase);

        // 1. Add discovered tools
        foreach (var tool in discovered)
        {
            registry[tool.Name] = tool;
        }

        // 1b. Add built-in file tools for basic workspace navigation/edit tasks.
        foreach (var tool in GetBuiltInTools())
        {
            registry[tool.Name] = tool;
        }

        // 2. Apply manifest overrides
        foreach (var kv in manifest)
        {
            var name = kv.Key;
            var overrideSpec = kv.Value;

            if (!registry.TryGetValue(name, out var existing))
            {
                // Manifest-only tool
                registry[name] = overrideSpec;
                continue;
            }

            // Merge discovered + manifest
            var merged = existing with
            {
                Description = string.IsNullOrWhiteSpace(overrideSpec.Description)
                    ? existing.Description
                    : overrideSpec.Description,

                Parameters =
                    overrideSpec.Parameters?.Count > 0
                        ? overrideSpec.Parameters
                        : existing.Parameters,

                Module = string.IsNullOrWhiteSpace(overrideSpec.Module)
                    ? existing.Module
                    : overrideSpec.Module,

                Meta = overrideSpec.Meta?.Count > 0 ? overrideSpec.Meta : existing.Meta,
            };

            registry[name] = merged;
        }

        return registry;
    }

    private static IEnumerable<ToolSpec> GetBuiltInTools()
    {
        return new[]
        {
            new ToolSpec(
                Name: "READ-FILE",
                Description: "Reads text content from a file. Large files may return a structured summary instead of the full body.",
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

    private static IEnumerable<ToolSpec> DiscoverTools()
    {
        using var ps = PowerShell.Create();

        var modulePath = ResolveModuleManifestPath();
        if (!string.IsNullOrWhiteSpace(modulePath))
        {
            ps.AddCommand("Import-Module")
                .AddParameter("Name", modulePath)
                .AddParameter("Force")
                .AddParameter("ErrorAction", "Stop");
        }
        else
        {
            ps.AddCommand("Import-Module")
                .AddParameter("Name", "TechToolbox")
                .AddParameter("Force")
                .AddParameter("ErrorAction", "Stop");
        }

        ps.Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException(
                $"Tool discovery failed during module import: {ps.Streams.Error[0]}"
            );

        ps.Commands.Clear();

        ps.AddCommand("Get-Command")
            .AddParameter("Module", "TechToolbox")
            .AddParameter("CommandType", "Function")
            .AddParameter("ErrorAction", "Stop");

        var results = ps.Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Tool discovery failed: {ps.Streams.Error[0]}");

        var list = new List<ToolSpec>();

        foreach (var r in results)
        {
            if (r.BaseObject is not CommandInfo command)
                continue;

            // Skip private/internal helper functions by naming convention.
            if (command.Name.Contains('_', StringComparison.Ordinal))
                continue;

            var parameters = new Dictionary<string, ParameterSpec>(
                StringComparer.OrdinalIgnoreCase
            );
            foreach (var p in command.Parameters.Values)
            {
                var isMandatory = p.Attributes.OfType<ParameterAttribute>().Any(a => a.Mandatory);

                parameters[p.Name] = new ParameterSpec(
                    Mandatory: isMandatory,
                    Type: p.ParameterType?.FullName,
                    Help: null
                );
            }

            list.Add(
                new ToolSpec(
                    Name: command.Name,
                    Description: $"PowerShell tool {command.Name}.",
                    Parameters: parameters,
                    Module: command.ModuleName ?? "TechToolbox",
                    Meta: new Dictionary<string, object?>()
                )
            );
        }

        return list;
    }

    private static string? ResolveModuleManifestPath()
    {
        var envRoot = Environment.GetEnvironmentVariable("TT_ModuleRoot");
        if (!string.IsNullOrWhiteSpace(envRoot))
        {
            var candidate = Path.Combine(envRoot, "TechToolbox.psd1");
            if (File.Exists(candidate))
                return candidate;
        }

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "TechToolbox.psd1");
            if (File.Exists(candidate))
                return candidate;

            dir = dir.Parent;
        }

        return null;
    }
}

public record ToolSpec(
    string Name,
    string Description,
    Dictionary<string, ParameterSpec> Parameters,
    string Module,
    Dictionary<string, object?> Meta
);

public record ParameterSpec(bool Mandatory, string? Type, string? Help);
