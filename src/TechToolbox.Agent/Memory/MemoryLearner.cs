// <copyright file="MemoryLearner.cs" company="TechToolbox">
//     Copyright (c) TechToolbox. All rights reserved.
// </copyright>

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TechToolbox.Agent.Memory;

/// <summary>
/// Provides functionality to learn and persist user preferences and facts from conversation history.
/// Extracts meaningful patterns from prompts and outputs, storing them in a <see cref="MemoryStore"/> for later retrieval.
/// </summary>
public static class MemoryLearner
{
    /// <summary>
    /// The maximum number of preference entries to retain in memory.
    /// </summary>
    private const int MaxPreferenceEntries = 12;

    /// <summary>
    /// The maximum number of fact entries to retain in memory.
    /// </summary>
    private const int MaxFactEntries = 12;

    /// <summary>
    /// Regular expression patterns used to extract user preferences from text.
    /// Each pattern captures a value group that represents a preference statement.
    /// </summary>
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
            @"\b(?<value>do\s+not\s+[^.!?\r\n]{3,120})",
            RegexOptions.IgnoreCase | RegexOptions.Compiled
        ),
    };

    /// <summary>
    /// Regular expression patterns used to extract factual information from text.
    /// Each pattern captures a value group that represents a fact statement.
    /// </summary>
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

    /// <summary>
    /// Learns preferences and facts from a conversation run by analyzing the prompt and output text.
    /// Extracts meaningful patterns using predefined regular expressions and persists them to the provided memory store.
    /// </summary>
    /// <param name="memory">The memory store to update with learned preferences and facts. Cannot be null.</param>
    /// <param name="prompt">The user's prompt text to analyze for preferences and facts.</param>
    /// <param name="output">The system's output text to analyze for additional facts (e.g., model mentions).</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="memory"/> is null.
    /// </exception>
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

    /// <summary>
    /// Extracts values from text using the provided regular expression patterns.
    /// Applies sanitization and deduplication to ensure only unique, useful values are returned.
    /// </summary>
    /// <param name="text">The source text to search for pattern matches. May be null or whitespace-only.</param>
    /// <param name="patterns">An enumerable of regular expression patterns to apply against the text.</param>
    /// <returns>An enumerable of extracted and sanitized string values, deduplicated by case-insensitive comparison.</returns>
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

    /// <summary>
    /// Extracts model-related mentions from text using a pattern that matches "model" or "ollama" followed by a colon or equals sign.
    /// </summary>
    /// <param name="text">The source text to search for model mentions. May be null or whitespace-only.</param>
    /// <returns>An enumerable of extracted model name values, deduplicated by case-insensitive comparison.</returns>
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

    /// <summary>
    /// Inserts a value into the target dictionary if it does not already exist (case-insensitive comparison).
    /// If the dictionary exceeds the maximum entry count, the oldest entry is removed to maintain the limit.
    /// </summary>
    /// <param name="target">The dictionary to update. Values are expected to be strings.</param>
    /// <param name="prefix">A prefix string used when building the dictionary key.</param>
    /// <param name="value">The value to insert into the dictionary.</param>
    /// <param name="maxEntries">The maximum number of entries allowed in the dictionary before eviction occurs.</param>
    /// <returns><c>true</c> if the value was successfully inserted; otherwise, <c>false</c> if it already existed.</returns>
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

    /// <summary>
    /// Builds a unique dictionary key from a prefix and value by creating a slug from the value and appending a SHA256 hash.
    /// The resulting key format is "{prefix}.{slug}.{hash}" where the slug is URL-safe and truncated to 36 characters if necessary.
    /// </summary>
    /// <param name="prefix">The prefix string for the key.</param>
    /// <param name="value">The value to derive the slug from.</param>
    /// <returns>A unique dictionary key in the format "{prefix}.{slug}.{hash}".</returns>
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

    /// <summary>
    /// Sanitizes a string by trimming whitespace and removing trailing punctuation characters.
    /// Replaces carriage returns and line feeds with spaces to produce a single-line value.
    /// </summary>
    /// <param name="value">The raw string value to sanitize.</param>
    /// <returns>The sanitized string with leading/trailing whitespace and specific punctuation removed.</returns>
    private static string Sanitize(string value)
    {
        return value
            .Trim()
            .Trim('"', '\'', '.', ',', ';', ':', ')', ']', '}')
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Trim();
    }

    /// <summary>
    /// Determines whether a value is useful for storage by checking its length and filtering out common stop words.
    /// Values must be at least 3 characters long and not match common unhelpful terms.
    /// </summary>
    /// <param name="value">The string value to evaluate.</param>
    /// <returns><c>true</c> if the value is considered useful; otherwise, <c>false</c>.</returns>
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