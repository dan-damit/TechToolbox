using System.Management.Automation;
using TechToolbox.Agent.Agent;

namespace TechToolbox.Agent.Execution;

public static class PowerShellBridge
{
    public static object? RunTool(string toolName, IDictionary<string, object?> args)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            throw new ArgumentException("Tool name must not be empty.", nameof(toolName));

        if (TryRunBuiltInTool(toolName, args, out var builtInResult))
            return builtInResult;

        // Safety check for destructive tools
        Safety.RequireDestructiveConfirmation(toolName, args);

        using var ps = PowerShell.Create();

        // Import the TechToolbox module explicitly
        // (Assumes the module is discoverable via PSModulePath)
        ps.AddCommand("Import-Module")
          .AddParameter("Name", "TechToolbox")
          .AddParameter("ErrorAction", "Stop")
          .Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Failed to import TechToolbox module: {ps.Streams.Error[0]}");

        ps.Commands.Clear();

        // Add the tool command
        ps.AddCommand(toolName);

        // Add parameters
        foreach (var kv in args)
        {
            // Skip internal agent control keys
            if (kv.Key.StartsWith("__", StringComparison.Ordinal))
                continue;

            ps.AddParameter(kv.Key, kv.Value);
        }

        // Execute
        var results = ps.Invoke();

        if (ps.HadErrors)
            throw new InvalidOperationException($"Tool '{toolName}' failed: {ps.Streams.Error[0]}");

        // Normalize output
        if (results is null || results.Count == 0)
            return null;

        if (results.Count == 1)
            return results[0].BaseObject;

        return results.Select(r => r.BaseObject).ToList();
    }

    private static bool TryRunBuiltInTool(string toolName, IDictionary<string, object?> args, out object? result)
    {
        result = null;

        if (toolName.Equals("READ-FILE", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            if (!File.Exists(path))
                throw new FileNotFoundException($"File not found: {path}", path);

            result = File.ReadAllText(path);
            return true;
        }

        if (toolName.Equals("LIST-DIRECTORY", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException($"Directory not found: {path}");

            var entries = Directory
                .EnumerateFileSystemEntries(path)
                .Select(p =>
                {
                    var name = Path.GetFileName(p);
                    return Directory.Exists(p) ? $"{name}/" : name;
                })
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();

            result = entries;
            return true;
        }

        if (toolName.Equals("WRITE-FILE", StringComparison.OrdinalIgnoreCase))
        {
            var path = GetRequiredStringArg(args, "path");
            var content = GetRequiredStringArg(args, "content");

            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(path, content);
            result = "ok";
            return true;
        }

        return false;
    }

    private static string GetRequiredStringArg(IDictionary<string, object?> args, string name)
    {
        var arg = args.FirstOrDefault(kv => string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase));
        var value = arg.Value;

        string? text = value switch
        {
            null => null,
            string s => s,
            System.Text.Json.JsonElement el when el.ValueKind == System.Text.Json.JsonValueKind.String => el.GetString(),
            System.Text.Json.JsonElement el => el.ToString(),
            _ => value.ToString()
        };

        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException($"Missing required parameter '{name}'.", name);

        return text;
    }
}
