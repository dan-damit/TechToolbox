using TechToolbox.Agent.Memory;
using Xunit;

namespace TechToolbox.Agent.Tests;

public class MemoryLearnerTests
{
    [Fact]
    public void LearnFromRun_DeduplicatesNearDuplicatePreferences()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var memory = new MemoryStore(memoryPath);

            MemoryLearner.LearnFromRun(
                memory,
                "Do not summarize your plan before writing.",
                string.Empty
            );
            MemoryLearner.LearnFromRun(
                memory,
                "Do not summarize your plan before editing.",
                string.Empty
            );

            var matching = memory
                .Preferences.Values.OfType<string>()
                .Count(v =>
                    v.Contains(
                        "do not summarize your plan before",
                        StringComparison.OrdinalIgnoreCase
                    )
                );

            Assert.Equal(1, matching);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void LearnFromRun_KeepsDistinctPreferences()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var memory = new MemoryStore(memoryPath);

            MemoryLearner.LearnFromRun(memory, "Do not use tabs.", string.Empty);
            MemoryLearner.LearnFromRun(memory, "Do not use spaces.", string.Empty);

            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                v => string.Equals(v, "Do not use tabs", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                v => string.Equals(v, "Do not use spaces", StringComparison.OrdinalIgnoreCase)
            );
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void LearnFromRun_ExtractsMultiSentencePreferencesAndModelFacts()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var memory = new MemoryStore(memoryPath);

            MemoryLearner.LearnFromRun(
                memory,
                "I like clear markdown bullet lists. I typically prefer short concise answers. My workflow is to inspect the exact file before editing. I use gpt-5.3-codex for coding tasks.",
                "Model: gpt-5.3-codex"
            );

            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                v => v.Contains("clear markdown bullet lists", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.Preferences.Values.OfType<string>(),
                v => v.Contains("short concise answers", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.Facts.Values.OfType<string>(),
                v => v.Contains("gpt-5.3-codex", StringComparison.OrdinalIgnoreCase)
            );
            Assert.Contains(
                memory.MemoryIndex.Keys,
                k => k.Contains("markdown", StringComparison.OrdinalIgnoreCase)
            );
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public void MemoryStore_BuildsHealthSummaryAndIndex()
    {
        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "TechToolbox.Agent.Tests",
            Guid.NewGuid().ToString("N")
        );
        Directory.CreateDirectory(tempRoot);
        var memoryPath = Path.Combine(tempRoot, "memory.json");

        try
        {
            var memory = new MemoryStore(memoryPath);
            memory.SetPreference("pref.concise", "I prefer concise answers.");
            memory.SetFact("fact.model", "gpt-5.3-codex");

            Assert.True(memory.MemoryIndex.ContainsKey("concise"));
            Assert.True(memory.Facts.ContainsKey("memoryHealth"));
            Assert.IsType<MemoryHealthSummary>(memory.Facts["memoryHealth"]);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }
}
