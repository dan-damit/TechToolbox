using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TechToolbox.Agent.Memory;

public static class MemoryLearner
{
    private const int MaxPreferenceEntries = 12;
    private const int MaxFactEntries = 12;

    private static readonly Regex[] PreferencePatterns =
    {
        new(
            @"\bprefer\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bdefault\s+to\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bplease\s+use\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\balways\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bavoid\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bdo\s+not\s+(?<value>[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
    };

    private static readonly Regex[] FactPatterns =
    {
        new(
            @"\bmy\s+default\s+model\s+is\s+(?<value>[A-Za-z0-9._:-]{2,80})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\btenant(?:\s+name|\s+id)?\s+is\s+(?<value>[^.!?\r\n]{2,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bmy\s+name\s+is\s+(?<value>[^.!?\r\n]{2,80})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bmy\s+role\s+is\s+(?<value>[^.!?\r\n]{2,80})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
        new(
            @"\bI\s+work\s+in\s+(?<value>[^.!?\r\n]{2,80})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
    };

    public static void LearnFromRun(MemoryStore memory, string prompt, string output)
    {
        ArgumentNullException.ThrowIfNull(memory);

        var changed = false;

        foreach (var preference in ExtractValues(prompt, PreferencePatterns))
        {
            changed |= Upsert(memory.Preferences, "pref", preference, MaxPreferenceEntries);
        }

        foreach (var fact in ExtractValues(prompt, FactPatterns))
        {
            changed |= Upsert(memory.Facts, "fact", fact, MaxFactEntries);
        }

        foreach (var fact in ExtractModelMentions(output))
        {
            changed |= Upsert(memory.Facts, "fact", fact, MaxFactEntries);
        }

        if (changed)
        {
            memory.Save();
        }
    }

    private static IEnumerable<string> ExtractValues(string text, IEnumerable<Regex> patterns)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pattern in patterns)
        {
            foreach (Match match in pattern.Matches(text))
            {
                var value = Sanitize(match.Groups["value"].Value);
                if (!IsUseful(value) || !seen.Add(value))
                {
                    continue;
                }

                yield return value;
            }
        }
    }

    private static IEnumerable<string> ExtractModelMentions(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            yield break;
        }

        var modelRegex = new Regex(
            @"\b(?:model|ollama)\s*[:=]\s*(?<value>[A-Za-z0-9._:-]{2,80})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        );
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in modelRegex.Matches(text))
        {
            var value = Sanitize(match.Groups["value"].Value);
            if (!IsUseful(value) || !seen.Add(value))
            {
                continue;
            }

            yield return value;
        }
    }

    private static bool Upsert(
        Dictionary<string, object?> target,
        string prefix,
        string value,
        int maxEntries
    )
    {
        if (
            target
                .Values.OfType<string>()
                .Any(existing => string.Equals(existing, value, StringComparison.OrdinalIgnoreCase))
        )
        {
            return false;
        }

        var key = BuildKey(prefix, value);
        target[key] = value;

        while (target.Count > maxEntries)
        {
            var oldestKey = target.Keys.First();
            target.Remove(oldestKey);
        }

        return true;
    }

    private static string BuildKey(string prefix, string value)
    {
        var slug = Regex.Replace(value.ToLowerInvariant(), @"[^a-z0-9]+", "-").Trim('-');
        if (slug.Length > 36)
        {
            slug = slug[..36].Trim('-');
        }

        if (string.IsNullOrWhiteSpace(slug))
        {
            slug = "entry";
        }

        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        var hash = Convert.ToHexString(hashBytes)[..8].ToLowerInvariant();
        return $"{prefix}.{slug}.{hash}";
    }

    private static string Sanitize(string value)
    {
        return value
            .Trim()
            .Trim('"', '\'', '.', ',', ';', ':', ')', ']', '}')
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Trim();
    }

    private static bool IsUseful(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 3)
        {
            return false;
        }

        var lowered = value.ToLowerInvariant();
        return lowered is not "it" and not "that" and not "this" and not "them";
    }
}
