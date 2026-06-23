using System.Management.Automation;

namespace TechToolbox.Agent.Registry;

/// <summary>
/// Discovers PowerShell functions from the TechToolbox module.
/// This is the original tool discovery logic, extracted into a provider.
/// </summary>
public class PowerShellToolProvider : IToolProvider
{
    private readonly string? _modulePath;
    private readonly string _moduleName;

    public string ProviderName => "PowerShell (TechToolbox)";

    public PowerShellToolProvider(string? modulePath = null, string moduleName = "TechToolbox")
    {
        _modulePath = modulePath;
        _moduleName = moduleName;
    }

    public IEnumerable<ToolSpec> DiscoverTools()
    {
        using var ps = PowerShell.Create();

        var modulePath = _modulePath ?? ResolveModuleManifestPath();
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
                .AddParameter("Name", _moduleName)
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
            .AddParameter("Module", _moduleName)
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
                    Module: command.ModuleName ?? _moduleName,
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
