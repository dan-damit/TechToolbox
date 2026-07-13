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

    /// <summary>
    /// Gets the display name of this tool provider.
    /// </summary>
    public string ProviderName => "PowerShell (TechToolbox)";

    /// <summary>
    /// Initializes a new instance of the <see cref="PowerShellToolProvider"/> class.
    /// </summary>
    /// <param name="modulePath">Optional explicit path to the module manifest (.psd1). If not provided, the provider will attempt to resolve it automatically.</param>
    /// <param name="moduleName">The name of the PowerShell module to discover tools from. Defaults to "TechToolbox".</param>
    public PowerShellToolProvider(string? modulePath = null, string moduleName = "TechToolbox")
    {
        _modulePath = modulePath;
        _moduleName = moduleName;
    }

    /// <summary>
    /// Discovers all public PowerShell functions from the TechToolbox module and returns them as <see cref="ToolSpec"/> instances.
    /// </summary>
    /// <returns>
    /// An enumerable collection of <see cref="ToolSpec"/> objects representing each discovered PowerShell function.
    /// Private or internal helper functions (those containing underscores in their names) are excluded.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the module import or command discovery fails. The exception message contains details about the failure.
    /// </exception>
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

    /// <summary>
    /// Resolves the path to the TechToolbox module manifest file (TechToolbox.psd1).
    /// </summary>
    /// <returns>
    /// The full path to the module manifest file if found; otherwise, null.
    /// </returns>
    /// <remarks>
    /// Resolution strategy:
    /// <list type="number">
    ///   <item>Check the TT_ModuleRoot environment variable for a candidate path.</item>
    ///   <item>If not found, walk up from the application base directory looking for TechToolbox.psd1.</item>
    /// </list>
    /// </remarks>
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