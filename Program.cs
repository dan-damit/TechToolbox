using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TechToolbox.Agent.Core;
using TechToolbox.Agent.Execution;
using TechToolbox.Agent.Llm;
using TechToolbox.Agent.Registry;
using TechToolbox.Agent.Orchestrator;

var tempRoot = Path.Combine(Path.GetTempPath(), "tt-agent-infer-path-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(tempRoot);
var expectedOutputPath = Path.Combine(tempRoot, "about_Test.help.txt");
string? captured = null;
var llm = new FakeLlmClient(new[] {
    "{\"needsTool\":true,\"toolName\":\"WRITE-FILE\",\"toolArgs\":{\"content\":\"updated\"},\"reason\":\"write file\"}",
    "{\"needsTool\":false,\"finalAnswer\":\"Done\",\"reason\":\"done\"}"
});
var tools = new Dictionary<string, Func<string, Task<string>>>(StringComparer.OrdinalIgnoreCase)
{
  ["WRITE-FILE"] = args => {
      captured = args;
      using var doc = System.Text.Json.JsonDocument.Parse(args);
      var path = doc.RootElement.GetProperty("path").GetString() ?? string.Empty;
      var content = doc.RootElement.GetProperty("content").GetString() ?? string.Empty;
      File.WriteAllText(path, content);
      return Task.FromResult("ok");
  }
};
var orchestrator = new AgentOrchestrator(llm, new Dictionary<string, ToolSpec>(StringComparer.OrdinalIgnoreCase), tools, null, "test-model", false, "ignore", 4, false, executionMode: "execute", outputContract: "markdown", qualityProfile: "balanced", thinkingMode: "auto");
var prompt = $"Create help doc\n\nHard requirement:\n- Create the output file at this exact path: {expectedOutputPath}\n- Use WRITE-FILE to create/update the file.\n- Do not return a final answer until WRITE-FILE has succeeded.";
var result = await orchestrator.RunAsync(prompt);
Console.WriteLine("RESULT: " + result.OutputText);
Console.WriteLine("CAPTURED: " + captured);
Console.WriteLine("FILE EXISTS: " + File.Exists(expectedOutputPath));

sealed class FakeLlmClient : LlmClient
{
    private readonly Queue<string> _responses;
    public FakeLlmClient(IEnumerable<string> responses) : base("test") { _responses = new Queue<string>(responses); }
    public override Task<LlmResponse> GenerateDecisionAsync(IReadOnlyList<AgentChatMessage> messages, CancellationToken cancellationToken = default)
      => Task.FromResult(new LlmResponse(_responses.Dequeue(), _responses.Count > 0 ? "" : "", true));
    public override async Task<LlmResponse> GenerateDecisionWithCallbackAsync(IReadOnlyList<AgentChatMessage> messages, Func<string, Task<bool>>? onContentAccumulated = null, CancellationToken cancellationToken = default)
    {
        var next = _responses.Dequeue();
        if (onContentAccumulated is not null)
        {
            var _ = await onContentAccumulated(next);
        }
        return new LlmResponse(next, next, true);
    }
}
