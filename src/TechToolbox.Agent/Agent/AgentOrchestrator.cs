using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

public partial class AgentOrchestrator
{
    private static readonly string[] LineSeparators = ["\r\n", "\n"];
    private static readonly char[] TrimDirectorySeparators =
    [
        Path.DirectorySeparatorChar,
        Path.AltDirectorySeparatorChar,
    ];

    private readonly LlmClient _llm;
    private readonly IReadOnlyDictionary<string, ToolSpec> _registry;
    private readonly Dictionary<string, Func<string, Task<string>>> _tools;
    private readonly MemoryStore? _memory;
    private readonly string _model;
    private readonly bool _destructiveConfirmed;
    private readonly string _signedFilePolicy;
    private readonly int _maxIterations;
    private readonly bool _autoRetry;
    private readonly string? _tracePath;
    private readonly string? _expectedOutputPath;
    private readonly int _recentHistoryItemsInPrompt;
    private readonly object _traceLock = new();

    [GeneratedRegex(@"^\s*(?:#\s*)?\.(?<name>[A-Z][A-Z0-9_-]*)\b")]
    private static partial Regex SectionHeadingRegex();

    [GeneratedRegex(@"^\s*function\s+(?<name>[A-Za-z_][A-Za-z0-9_-]*)\b", RegexOptions.IgnoreCase)]
    private static partial Regex FunctionNameRegex();

    [GeneratedRegex(@"(?im)^\s*-\s*Create\s+the\s+output\s+file\s+at\s+this\s+exact\s+path\s*:\s*(?<path>[A-Za-z]:\\[^\r\n]+)$")]
    private static partial Regex ExpectedOutputPathRegex();

    [GeneratedRegex("(?is)\\b(write|rewrite|update|edit|modify|insert|create)\\b|\\buse\\s+write(?:-|=|\\s*)file\\b|\\bwrite(?:-|=|\\s*)file\\b")]
    private static partial Regex WriteIntentRegex();

    [GeneratedRegex("(?i)(?<path>[A-Za-z]:\\\\[^\\\"'`\\r\\n]*?\\.[A-Za-z0-9]{1,16})\\b")]
    private static partial Regex DirectFilePathRegex();

    [GeneratedRegex("^\\s*(begin|process|end)\\s*\\{", RegexOptions.IgnoreCase)]
    private static partial Regex StructureHintRegex();

    public AgentOrchestrator(
        LlmClient llm,
        IReadOnlyDictionary<string, ToolSpec> registry,
        Dictionary<string, Func<string, Task<string>>> tools,
        MemoryStore? memory,
        string model,
        bool destructiveConfirmed,
        string signedFilePolicy,
        int maxIterations,
        bool autoRetry,
        string? tracePath = null,
        string? expectedOutputPath = null,
        int recentHistoryItemsInPrompt = 2
    )
    {
        _llm = llm;
        _registry = registry;
        _tools = tools;
        _memory = memory;
        _model = model;
        _destructiveConfirmed = destructiveConfirmed;
        _signedFilePolicy = string.IsNullOrWhiteSpace(signedFilePolicy)
            ? "ignore"
            : signedFilePolicy;
        _maxIterations = maxIterations;
        _autoRetry = autoRetry;
        _tracePath = tracePath;
        _expectedOutputPath = expectedOutputPath;
        _recentHistoryItemsInPrompt = Math.Clamp(recentHistoryItemsInPrompt, 0, 20);

        _llm.DiagnosticTrace = msg => Trace($"LlmClient {msg}");
    }

    public AgentResult Run(string prompt) => RunAsync(prompt).GetAwaiter().GetResult();

    public async Task<AgentResult> RunAsync(string prompt)
    {
        prompt ??= string.Empty;
        Trace(
            $"RunAsync start maxIterations={_maxIterations} autoRetry={_autoRetry} recentHistoryItemsInPrompt={_recentHistoryItemsInPrompt} promptLength={prompt.Length}"
        );

        var stopwatch = Stopwatch.StartNew();
        List<string> initialToolNames = [];

        var attempt = await RunLoopAsync(prompt, _maxIterations, initialToolNames)
            .ConfigureAwait(false);
        if (!attempt.ReachedIterationLimit)
        {
            var terminalFailureOutcome = GetTerminalFailureOutcome(attempt.OutputText);
            stopwatch.Stop();
            return FinalizeResult(
                prompt,
                attempt.OutputText,
                initialToolNames,
                stopwatch.ElapsedMilliseconds,
                status: terminalFailureOutcome is null ? "success" : "error",
                outcome: terminalFailureOutcome ?? "completed",
                retriedOnIterationLimit: false,
                retrySucceeded: false,
                initialIterationLimit: _maxIterations,
                retryIterationLimit: null
            );
        }

        if (_autoRetry)
        {
            var retryIterations = Math.Max(
                _maxIterations + 5,
                (int)Math.Ceiling(_maxIterations * 1.5)
            );
            List<string> retryToolNames = [];

            var retryAttempt = await RunLoopAsync(prompt, retryIterations, retryToolNames)
                .ConfigureAwait(false);

            stopwatch.Stop();

            if (!retryAttempt.ReachedIterationLimit)
            {
                var retryFailureOutcome = GetTerminalFailureOutcome(retryAttempt.OutputText);
                return FinalizeResult(
                    prompt,
                    retryAttempt.OutputText,
                    retryToolNames,
                    stopwatch.ElapsedMilliseconds,
                    status: retryFailureOutcome is null ? "success" : "error",
                    outcome: retryFailureOutcome ?? "completed",
                    retriedOnIterationLimit: true,
                    retrySucceeded: retryFailureOutcome is null,
                    initialIterationLimit: _maxIterations,
                    retryIterationLimit: retryIterations
                );
            }

            return FinalizeResult(
                prompt,
                BuildIterationLimitMessage(_maxIterations, retryIterations),
                [],
                stopwatch.ElapsedMilliseconds,
                status: "error",
                outcome: "iteration-limit",
                retriedOnIterationLimit: true,
                retrySucceeded: false,
                initialIterationLimit: _maxIterations,
                retryIterationLimit: retryIterations
            );
        }

        stopwatch.Stop();
        return FinalizeResult(
            prompt,
            BuildIterationLimitMessage(_maxIterations),
            [],
            stopwatch.ElapsedMilliseconds,
            status: "error",
            outcome: "iteration-limit",
            retriedOnIterationLimit: false,
            retrySucceeded: false,
            initialIterationLimit: _maxIterations,
            retryIterationLimit: null
        );
    }

    private async Task<RunLoopResult> RunLoopAsync(
        string prompt,
        int iterationLimit,
        List<string> toolNames
    )
    {
        var messages = PromptBuilder.BuildInitialMessages(
            prompt,
            _registry,
            _memory,
            _recentHistoryItemsInPrompt
        );
        var maxConsecutiveLlmFailures = GetMaxConsecutiveLlmFailures();
        var consecutiveLlmFailures = 0;
        var expectedOutputPath = string.IsNullOrWhiteSpace(_expectedOutputPath)
            ? ExtractExpectedOutputPathFromPrompt(prompt)
            : _expectedOutputPath;
        var requiresWriteFile = !string.IsNullOrWhiteSpace(expectedOutputPath);
        var writeFileCompleted = false;

        if (requiresWriteFile)
        {
            Trace(
                $"RunLoop enforcing WRITE-FILE completion for expected output path: {expectedOutputPath}"
            );
        }

        for (int i = 0; i < iterationLimit; i++)
        {
            Trace($"Iteration {i + 1}/{iterationLimit} start messages={messages.Count}");

            var llmResponse = await _llm.GenerateDecisionAsync(messages).ConfigureAwait(false);
            var raw = (llmResponse.Text ?? "").Trim();

            Trace($"Iteration {i + 1} response length={raw.Length} preview={Preview(raw)}");

            if (string.IsNullOrWhiteSpace(raw) || IsRetryableLlmFailure(raw))
            {
                if (TryApplyReadFileFallback(messages, llmResponse.RawBody, out var fallbackReason))
                {
                    Trace($"Iteration {i + 1} applied READ-FILE fallback: {fallbackReason}");
                    continue;
                }

                consecutiveLlmFailures++;
                Trace($"Iteration {i + 1} consecutive LLM failures={consecutiveLlmFailures}");

                if (consecutiveLlmFailures >= maxConsecutiveLlmFailures)
                {
                    return new RunLoopResult(
                        $"LLM request repeatedly failed ({consecutiveLlmFailures} consecutive attempts). Last error: {raw}",
                        ReachedIterationLimit: false
                    );
                }

                continue;
            }

            messages.Add(new AgentChatMessage { Role = "assistant", Content = raw });

            AgentDecision? decision;
            var decisionValidationError = string.Empty;

            var parsedDecision = JsonHelpers.TryParseDecision(raw, out decision) && decision is not null;
            if (parsedDecision && TryPopulateMissingWriteFilePath(decision!, expectedOutputPath))
            {
                Trace(
                    $"Iteration {i + 1} inferred missing WRITE-FILE path from hard requirement: {expectedOutputPath}"
                );
            }
            if (parsedDecision && !TryValidateDecision(decision!, out decisionValidationError))
            {
                parsedDecision = false;
                Trace(
                    $"Iteration {i + 1} planner decision failed schema validation: {decisionValidationError}"
                );
            }

            if (!parsedDecision)
            {
                Trace($"Iteration {i + 1} invalid planner JSON; issuing repair prompt");

                var invalidResponseForRepair = string.IsNullOrWhiteSpace(decisionValidationError)
                    ? raw
                    : $"{raw}\n\n[SCHEMA_ERROR] {decisionValidationError}";

                messages.Add(PromptBuilder.BuildRepairMessage(invalidResponseForRepair));

                var repairResponse = await _llm.GenerateDecisionAsync(messages)
                    .ConfigureAwait(false);
                var repairedRaw = (repairResponse.Text ?? "").Trim();

                Trace(
                    $"Iteration {i + 1} repair response length={repairedRaw.Length} preview={Preview(repairedRaw)}"
                );

                if (string.IsNullOrWhiteSpace(repairedRaw) || IsRetryableLlmFailure(repairedRaw))
                {
                    if (
                        TryApplyReadFileFallback(
                            messages,
                            repairResponse.RawBody,
                            out var repairFallbackReason
                        )
                    )
                    {
                        Trace(
                            $"Iteration {i + 1} applied READ-FILE fallback after repair failure: {repairFallbackReason}"
                        );
                        continue;
                    }

                    consecutiveLlmFailures++;
                    Trace(
                        $"Iteration {i + 1} consecutive LLM failures after repair={consecutiveLlmFailures}"
                    );

                    if (consecutiveLlmFailures >= maxConsecutiveLlmFailures)
                    {
                        return new RunLoopResult(
                            $"LLM request repeatedly failed ({consecutiveLlmFailures} consecutive attempts). Last error: {repairedRaw}",
                            ReachedIterationLimit: false
                        );
                    }

                    continue;
                }

                messages.Add(new AgentChatMessage { Role = "assistant", Content = repairedRaw });

                var repairedDecisionValid =
                    JsonHelpers.TryParseDecision(repairedRaw, out decision) && decision is not null;
                if (repairedDecisionValid && TryPopulateMissingWriteFilePath(decision!, expectedOutputPath))
                {
                    Trace(
                        $"Iteration {i + 1} inferred missing WRITE-FILE path from hard requirement during repair: {expectedOutputPath}"
                    );
                }
                if (repairedDecisionValid && !TryValidateDecision(decision!, out decisionValidationError))
                {
                    repairedDecisionValid = false;
                    Trace(
                        $"Iteration {i + 1} repaired decision failed schema validation: {decisionValidationError}"
                    );
                }

                if (!repairedDecisionValid)
                {
                    if (
                        JsonHelpers.TryExtractWriteFileDecision(
                            repairedRaw,
                            out var recoveredDecision,
                            out var recoveryReason
                        ) && recoveredDecision is not null
                    )
                    {
                        decision = recoveredDecision;
                        Trace(
                            $"Iteration {i + 1} salvaged malformed WRITE-FILE decision: {recoveryReason}"
                        );
                    }
                    else if (JsonHelpers.LooksLikeWriteFileDecision(repairedRaw))
                    {
                        Trace(
                            $"Iteration {i + 1} malformed WRITE-FILE detected; issuing targeted recovery prompt"
                        );

                        messages.Add(PromptBuilder.BuildWriteFileRecoveryMessage(repairedRaw));

                        var writeFileRecoveryResponse = await _llm.GenerateDecisionAsync(messages)
                            .ConfigureAwait(false);
                        var writeFileRecoveryRaw = (writeFileRecoveryResponse.Text ?? "").Trim();

                        Trace(
                            $"Iteration {i + 1} targeted recovery response length={writeFileRecoveryRaw.Length} preview={Preview(writeFileRecoveryRaw)}"
                        );

                        if (
                            string.IsNullOrWhiteSpace(writeFileRecoveryRaw)
                            || IsRetryableLlmFailure(writeFileRecoveryRaw)
                        )
                        {
                            if (
                                TryApplyReadFileFallback(
                                    messages,
                                    writeFileRecoveryResponse.RawBody,
                                    out var targetedRecoveryFallbackReason
                                )
                            )
                            {
                                Trace(
                                    $"Iteration {i + 1} applied READ-FILE fallback after targeted recovery failure: {targetedRecoveryFallbackReason}"
                                );
                                continue;
                            }

                            consecutiveLlmFailures++;
                            Trace(
                                $"Iteration {i + 1} consecutive LLM failures after targeted recovery={consecutiveLlmFailures}"
                            );

                            if (consecutiveLlmFailures >= maxConsecutiveLlmFailures)
                            {
                                return new RunLoopResult(
                                    $"LLM request repeatedly failed ({consecutiveLlmFailures} consecutive attempts). Last error: {writeFileRecoveryRaw}",
                                    ReachedIterationLimit: false
                                );
                            }

                            continue;
                        }

                        messages.Add(
                            new AgentChatMessage
                            {
                                Role = "assistant",
                                Content = writeFileRecoveryRaw,
                            }
                        );

                        var recoveryDecisionValid =
                            JsonHelpers.TryParseDecision(writeFileRecoveryRaw, out decision)
                            && decision is not null;
                        if (
                            recoveryDecisionValid
                            && TryPopulateMissingWriteFilePath(decision!, expectedOutputPath)
                        )
                        {
                            Trace(
                                $"Iteration {i + 1} inferred missing WRITE-FILE path from hard requirement during targeted recovery: {expectedOutputPath}"
                            );
                        }
                        if (recoveryDecisionValid && !TryValidateDecision(decision!, out decisionValidationError))
                        {
                            recoveryDecisionValid = false;
                            Trace(
                                $"Iteration {i + 1} targeted recovery decision failed schema validation: {decisionValidationError}"
                            );
                        }

                        if (!recoveryDecisionValid)
                        {
                            return new RunLoopResult(
                                $"Agent returned invalid JSON twice. Last response: {repairedRaw}",
                                ReachedIterationLimit: false
                            );
                        }

                        if (
                            decision is null
                            || !decision.NeedsTool
                            || !string.Equals(
                                decision.ToolName,
                                "WRITE-FILE",
                                StringComparison.OrdinalIgnoreCase
                            )
                        )
                        {
                            return new RunLoopResult(
                                $"Agent returned invalid JSON twice. Last response: {repairedRaw}",
                                ReachedIterationLimit: false
                            );
                        }
                    }
                    else
                    {
                        return new RunLoopResult(
                            $"Agent returned invalid JSON twice. Last response: {repairedRaw}",
                            ReachedIterationLimit: false
                        );
                    }
                }
            }

            if (decision is null)
            {
                return new RunLoopResult(
                    "Agent decision was unexpectedly null after parsing/repair.",
                    ReachedIterationLimit: false
                );
            }

            consecutiveLlmFailures = 0;

            if (!decision.NeedsTool)
            {
                if (requiresWriteFile && !writeFileCompleted)
                {
                    var requirementError =
                        $"Required file update step has not completed yet. Use WRITE-FILE or REPLACE-IN-FILE on '{expectedOutputPath}' before returning finalAnswer.";

                    Trace(
                        $"Iteration {i + 1} blocked final answer because WRITE-FILE hard requirement is unmet."
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "FILE-UPDATE",
                            requirementError,
                            succeeded: false
                        )
                    );
                    continue;
                }

                Trace(
                    $"Iteration {i + 1} final answer detected length={decision.FinalAnswer?.Length ?? 0}"
                );
                return new RunLoopResult(
                    decision.FinalAnswer ?? string.Empty,
                    ReachedIterationLimit: false
                );
            }

            var toolName = decision.ToolName ?? string.Empty;

            if (!_tools.TryGetValue(toolName, out var toolFunc))
            {
                Trace($"Iteration {i + 1} tool not found: {toolName}");

                var toolError = $"Tool '{toolName}' was not found.";

                messages.Add(
                    PromptBuilder.BuildToolResultMessage(
                        toolName,
                        toolError,
                        succeeded: false
                    )
                );
                continue;
            }

            toolNames.Add(toolName);

            string jsonArgs;
            try
            {
                jsonArgs = JsonSerializer.Serialize(decision.ToolArgs);
            }
            catch (Exception ex)
            {
                var serializationError = $"Failed to serialize tool args: {ex.Message}";

                messages.Add(
                    PromptBuilder.BuildToolResultMessage(
                        toolName,
                        serializationError,
                        succeeded: false
                    )
                );
                continue;
            }

            Trace($"Iteration {i + 1} executing tool={toolName}");

            string toolResult;
            var toolExecutionSucceeded = true;
            try
            {
                toolResult = await toolFunc(jsonArgs).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                toolExecutionSucceeded = false;
                toolResult = ex.Message;
            }

            if (requiresWriteFile && IsFileUpdateTool(toolName))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out var writePath))
                {
                    toolExecutionSucceeded = false;
                    toolResult = $"{toolName} must include a string path argument.";
                }
                else if (!PathsEqual(writePath, expectedOutputPath!))
                {
                    toolExecutionSucceeded = false;
                    toolResult =
                        $"{toolName} must target expected path '{expectedOutputPath}', but received '{writePath}'.";
                    Trace(
                        $"Iteration {i + 1} rejected file-update path mismatch tool={toolName} expected={expectedOutputPath} actual={writePath}"
                    );
                }
            }

            if (
                toolExecutionSucceeded
                && toolName.Equals("READ-FILE", StringComparison.OrdinalIgnoreCase)
            )
            {
                var compactThreshold = GetReadFilePromptCompactThresholdChars();
                var compactedToolResult = MaybeCompactReadFileResultForPrompt(
                    toolResult,
                    compactThreshold
                );
                if (!string.Equals(compactedToolResult, toolResult, StringComparison.Ordinal))
                {
                    Trace(
                        $"Iteration {i + 1} compacted READ-FILE result for prompt originalLength={toolResult.Length} threshold={compactThreshold} compactLength={compactedToolResult.Length}"
                    );
                    toolResult = compactedToolResult;
                }
            }

            if (
                requiresWriteFile
                && IsFileUpdateTool(toolName)
                && toolExecutionSucceeded
                && !toolResult.StartsWith("Error", StringComparison.OrdinalIgnoreCase)
            )
            {
                if (File.Exists(expectedOutputPath!))
                {
                    writeFileCompleted = true;
                    Trace($"Iteration {i + 1} marked file-update hard requirement as completed via {toolName}.");
                }
                else
                {
                    toolExecutionSucceeded = false;
                    toolResult =
                        $"{toolName} reported success but expected output file does not exist yet at '{expectedOutputPath}'. Retry the file update with the exact path.";
                    Trace(
                        $"Iteration {i + 1} file-update tool returned success but expected file was missing: tool={toolName} path={expectedOutputPath}"
                    );
                }
            }

            var maxToolResultChars = GetMaxToolResultChars();
            var toolResultForPrompt = PrepareToolResultForPrompt(
                toolResult,
                maxToolResultChars,
                out var wasTruncated,
                out var originalLength
            );

            if (wasTruncated)
            {
                Trace(
                    $"Iteration {i + 1} tool result truncated originalLength={originalLength} maxChars={maxToolResultChars}"
                );
            }

            messages.Add(
                PromptBuilder.BuildToolResultMessage(
                    toolName,
                    toolResultForPrompt,
                    toolExecutionSucceeded
                )
            );
        }

        Trace($"RunLoop reached iteration limit={iterationLimit}");
        return new RunLoopResult("Iteration limit reached.", ReachedIterationLimit: true);
    }

    private AgentResult FinalizeResult(
        string prompt,
        string output,
        List<string> toolNames,
        long durationMs,
        string status,
        string outcome,
        bool retriedOnIterationLimit,
        bool retrySucceeded,
        int initialIterationLimit,
        int? retryIterationLimit
    )
    {
        Trace(
            $"FinalizeResult toolCalls={toolNames.Count} durationMs={durationMs} outputLength={output?.Length ?? 0}"
        );

        output ??= "";

        var result = new AgentResult(output)
        {
            ToolNames = toolNames,
            ToolCallCount = toolNames.Count,
            DurationMs = (int)durationMs,
            RetriedOnIterationLimit = retriedOnIterationLimit,
            RetrySucceeded = retrySucceeded,
            InitialIterationLimit = initialIterationLimit,
            RetryIterationLimit = retryIterationLimit,
        };

        _memory?.AddRun(
            new RunHistory
            {
                TimestampUtc = DateTimeOffset.UtcNow,
                Status = status,
                Outcome = outcome,
                Prompt = prompt,
                Model = _model,
                DurationMs = result.DurationMs,
                MaxIterations = _maxIterations,
                DestructiveConfirmed = _destructiveConfirmed,
                SignedFilePolicy = _signedFilePolicy,
                AutoRetryOnRecursion = _autoRetry,
                ToolCalls = result.ToolCallCount,
                ToolNames = toolNames
                    .Select(NormalizeActionName)
                    .Where(t => !string.IsNullOrWhiteSpace(t))
                    .ToList(),
                OutputPreview = Truncate(output, 4000),
                Error = status.Equals("error", StringComparison.OrdinalIgnoreCase)
                    ? Truncate(output, 4000)
                    : null,
                RunSummary = new RunSummary
                {
                    Intent = Truncate(prompt, 220),
                    ActionsTaken = toolNames
                        .Select(NormalizeActionName)
                        .Where(t => !string.IsNullOrWhiteSpace(t))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList(),
                    Blockers = outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
                        ? string.Empty
                        : Truncate(output, 320),
                    NextBestStep = BuildNextBestStep(output, outcome),
                },
            }
        );

        if (_memory is not null)
        {
            MemoryLearner.LearnFromRun(_memory, prompt, output);
        }

        return result;
    }

    private static string BuildIterationLimitMessage(
        int initialIterationLimit,
        int? retryIterationLimit = null
    )
    {
        if (retryIterationLimit.HasValue)
        {
            return $"""
## Agent Iteration Limit Reached

The agent stopped because it reached its internal reasoning/tool-call limit before a final stop condition.

- initial iteration_limit used: {initialIterationLimit}
- retry iteration_limit used: {retryIterationLimit.Value}
- max_iterations requested: {initialIterationLimit}
- auto-retry attempts: 1

Next best action:
- Retry with a narrower prompt or a higher --max-iterations value.
- If this repeats, inspect tool outputs for loops or missing termination cues.
""";
        }

        return $"""
## Agent Iteration Limit Reached

The agent stopped because it reached its internal reasoning/tool-call limit before a final stop condition.

- iteration_limit used: {initialIterationLimit}
- max_iterations requested: {initialIterationLimit}

Next best action:
- Retry with a narrower prompt or a higher --max-iterations value.
- If this repeats, inspect tool outputs for loops or missing termination cues.
""";
    }

    private void Trace(string message)
    {
        if (string.IsNullOrWhiteSpace(_tracePath))
            return;

        try
        {
            var line = $"[{DateTime.UtcNow:O}] {message}{Environment.NewLine}";
            lock (_traceLock)
            {
                var dir = Path.GetDirectoryName(_tracePath);
                if (!string.IsNullOrWhiteSpace(dir))
                    Directory.CreateDirectory(dir);

                File.AppendAllText(_tracePath, line);
            }
        }
        catch
        {
            // Diagnostic tracing must never break orchestration.
        }
    }

    private static string Preview(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "(empty)";

        var normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return normalized.Length <= 120 ? normalized : normalized[..120];
    }

    private static bool IsRetryableLlmFailure(string text)
    {
        return text.StartsWith("LLM request timed out", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM response read timed out", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM request failed", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM error:", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM returned empty content", StringComparison.OrdinalIgnoreCase)
            || text.StartsWith("LLM response parse failed", StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetTerminalFailureOutcome(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return null;

        if (output.StartsWith("Agent returned invalid JSON twice.", StringComparison.OrdinalIgnoreCase))
            return "invalid-json";

        if (output.StartsWith("LLM request repeatedly failed", StringComparison.OrdinalIgnoreCase))
            return "llm-failure";

        if (output.StartsWith("Error:", StringComparison.OrdinalIgnoreCase))
            return "runtime-error";

        return null;
    }

    private static int GetMaxConsecutiveLlmFailures()
    {
        const int defaultFailures = 2;
        const int minFailures = 1;
        const int maxFailures = 10;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_MAX_CONSEC_LLM_FAILURES");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minFailures, maxFailures);

        return defaultFailures;
    }

    private static int GetMaxToolResultChars()
    {
        const int defaultChars = 12000;
        const int minChars = 500;
        const int maxChars = 200_000;

        var raw = Environment.GetEnvironmentVariable("TT_AGENT_MAX_TOOL_RESULT_CHARS");
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minChars, maxChars);

        return defaultChars;
    }

    private static int GetReadFilePromptCompactThresholdChars()
    {
        const int defaultChars = 6000;
        const int minChars = 1000;
        const int maxChars = 50000;

        var raw = Environment.GetEnvironmentVariable(
            "TT_AGENT_READ_FILE_PROMPT_COMPACT_THRESHOLD_CHARS"
        );
        if (int.TryParse(raw, out var parsed))
            return Math.Clamp(parsed, minChars, maxChars);

        return defaultChars;
    }

    private static string PrepareToolResultForPrompt(
        string? toolResult,
        int maxChars,
        out bool wasTruncated,
        out int originalLength
    )
    {
        var text = toolResult ?? "null";
        originalLength = text.Length;

        if (text.Length <= maxChars)
        {
            wasTruncated = false;
            return text;
        }

        wasTruncated = true;
        var head = text[..maxChars];
        return $"{head}\n\n[TRUNCATED_TOOL_RESULT original_length={text.Length} shown={maxChars}]";
    }

    private static string NormalizeActionName(string toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            return string.Empty;

        return toolName.Trim().ToLowerInvariant().Replace('-', '_').Replace(' ', '_');
    }

    private static string BuildNextBestStep(string output, string outcome)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
                ? string.Empty
                : "Review the run output and resolve the blocker before retrying.";
        }

        var lines = output
            .Split(LineSeparators, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line));

        foreach (var line in lines)
        {
            if (
                line.StartsWith("Next best action", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("Next step", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("What Is Required", StringComparison.OrdinalIgnoreCase)
            )
            {
                return Truncate(line, 220);
            }
        }

        return outcome.Equals("completed", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : "Retry after addressing the error details captured in outputPreview.";
    }

    private static string Truncate(string value, int maxChars)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var normalized = value.Trim();
        return normalized.Length <= maxChars ? normalized : normalized[..maxChars] + "...";
    }

    private static bool TryApplyReadFileFallback(
        List<AgentChatMessage> messages,
        string? rawBody,
        out string reason
    )
    {
        reason = string.Empty;

        if (messages.Count == 0)
            return false;

        var lastMessage = messages[^1];
        if (!string.Equals(lastMessage.Role, "user", StringComparison.OrdinalIgnoreCase))
            return false;

        if (
            !TryExtractToolResult(
                lastMessage.Content,
                out var toolName,
                out var toolResult,
                out var status
            )
        )
            return false;

        if (!string.Equals(toolName, "READ-FILE", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
            return false;

        if (toolResult.Contains("READ_FILE_FALLBACK_COMPACT_VIEW", StringComparison.Ordinal))
            return false;

        var compactResult = BuildReadFileFallbackCompactView(toolResult, rawBody);
        if (string.Equals(compactResult, toolResult, StringComparison.Ordinal))
            return false;

        messages[^1] = PromptBuilder.BuildToolResultMessage(
            toolName,
            compactResult,
            succeeded: true
        );
        reason =
            $"replaced READ-FILE raw content with compact fallback view length={compactResult.Length}";
        return true;
    }

    private static string? ExtractExpectedOutputPathFromPrompt(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return null;

        var match = ExpectedOutputPathRegex().Match(prompt);

        if (match.Success)
        {
            var explicitPath = NormalizeDetectedPath(match.Groups["path"].Value);
            if (!string.IsNullOrWhiteSpace(explicitPath))
                return explicitPath;
        }

        if (!WriteIntentRegex().IsMatch(prompt))
            return null;

        var directPathMatches = DirectFilePathRegex().Matches(prompt);
        if (directPathMatches.Count == 0)
            return null;

        for (var i = directPathMatches.Count - 1; i >= 0; i--)
        {
            var candidate = NormalizeDetectedPath(directPathMatches[i].Groups["path"].Value);
            if (!string.IsNullOrWhiteSpace(candidate))
                return candidate;
        }

        return null;
    }

    private static string? NormalizeDetectedPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        var trimmed = path.Trim().TrimEnd('.', ',', ';', ':', ')', ']', '}');
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static bool TryGetToolArgString(
        IDictionary<string, object?> args,
        string key,
        out string value
    )
    {
        value = string.Empty;
        if (args is null)
            return false;

        var match = args.FirstOrDefault(kv =>
            string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)
        );
        if (string.IsNullOrWhiteSpace(match.Key))
            return false;

        value = match.Value switch
        {
            null => string.Empty,
            string s => s,
            JsonElement el when el.ValueKind == JsonValueKind.String => el.GetString()
                ?? string.Empty,
            JsonElement el => el.ToString(),
            _ => match.Value?.ToString() ?? string.Empty,
        };

        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryPopulateMissingWriteFilePath(
        AgentDecision decision,
        string? expectedOutputPath
    )
    {
        if (decision is null)
            return false;

        if (!decision.NeedsTool)
            return false;

        if (!IsFileUpdateTool(decision.ToolName))
            return false;

        if (string.IsNullOrWhiteSpace(expectedOutputPath))
            return false;

        if (decision.ToolArgs is null)
        {
            decision.ToolArgs = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        }

        if (TryGetToolArgString(decision.ToolArgs, "path", out _))
            return false;

        decision.ToolArgs["path"] = expectedOutputPath;
        return true;
    }

    private static bool TryValidateDecision(AgentDecision decision, out string error)
    {
        error = string.Empty;

        if (decision is null)
        {
            error = "decision is null";
            return false;
        }

        if (decision.NeedsTool)
        {
            if (string.IsNullOrWhiteSpace(decision.ToolName))
            {
                error = "needsTool=true requires non-empty toolName";
                return false;
            }

            if (decision.ToolArgs is null)
            {
                error = "needsTool=true requires toolArgs object";
                return false;
            }

            if (string.Equals(decision.ToolName, "WRITE-FILE", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    error = "WRITE-FILE requires non-empty string toolArgs.path";
                    return false;
                }

                if (!TryGetToolArgString(decision.ToolArgs, "content", out _))
                {
                    error = "WRITE-FILE requires non-empty string toolArgs.content";
                    return false;
                }
            }

            if (string.Equals(decision.ToolName, "REPLACE-IN-FILE", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    error = "REPLACE-IN-FILE requires non-empty string toolArgs.path";
                    return false;
                }

                if (!TryGetToolArgString(decision.ToolArgs, "oldText", out _))
                {
                    error = "REPLACE-IN-FILE requires non-empty string toolArgs.oldText";
                    return false;
                }

                if (!TryGetToolArgString(decision.ToolArgs, "newText", out _))
                {
                    error = "REPLACE-IN-FILE requires non-empty string toolArgs.newText";
                    return false;
                }
            }

            return true;
        }

        if (string.IsNullOrWhiteSpace(decision.FinalAnswer))
        {
            error = "needsTool=false requires non-empty finalAnswer";
            return false;
        }

        return true;
    }

    private static bool PathsEqual(string left, string right)
    {
        try
        {
            var fullLeft = Path.GetFullPath(left)
                .TrimEnd(TrimDirectorySeparators);
            var fullRight = Path.GetFullPath(right)
                .TrimEnd(TrimDirectorySeparators);

            return string.Equals(fullLeft, fullRight, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return string.Equals(left?.Trim(), right?.Trim(), StringComparison.OrdinalIgnoreCase);
        }
    }

    private static bool IsFileUpdateTool(string? toolName)
    {
        return string.Equals(toolName, "WRITE-FILE", StringComparison.OrdinalIgnoreCase)
            || string.Equals(toolName, "REPLACE-IN-FILE", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryExtractToolResult(
        string content,
        out string toolName,
        out string toolResult,
        out string status
    )
    {
        toolName = string.Empty;
        toolResult = string.Empty;
        status = string.Empty;

        if (string.IsNullOrWhiteSpace(content))
            return false;

        var toolLine = content
            .Split('\n')
            .FirstOrDefault(line => line.StartsWith("Tool:", StringComparison.OrdinalIgnoreCase));
        var statusLine = content
            .Split('\n')
            .FirstOrDefault(line => line.StartsWith("Status:", StringComparison.OrdinalIgnoreCase));
        var beginMarker = "BEGIN_TOOL_RESULT";
        var endMarker = "END_TOOL_RESULT";
        var beginIndex = content.IndexOf(beginMarker, StringComparison.Ordinal);
        var endIndex = content.IndexOf(endMarker, StringComparison.Ordinal);

        if (toolLine is null || statusLine is null || beginIndex < 0 || endIndex <= beginIndex)
            return false;

        toolName = toolLine["Tool:".Length..].Trim();
        status = statusLine["Status:".Length..].Trim();

        var resultStart = beginIndex + beginMarker.Length;
        toolResult = content[resultStart..endIndex].Trim();
        return !string.IsNullOrWhiteSpace(toolName);
    }

    private static string BuildReadFileFallbackCompactView(string toolResult, string? rawBody)
    {
        var normalized = toolResult.Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = normalized.Split('\n');
        var sections = lines
            .Select(line => SectionHeadingRegex().Match(line))
            .Where(match => match.Success)
            .Select(match => match.Groups["name"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var functions = lines
            .Select(line => FunctionNameRegex().Match(line))
            .Where(match => match.Success)
            .Select(match => match.Groups["name"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var paramBlock = ExtractParamBlock(lines, 18);
        var structureHints = lines
            .Where(line =>
                StructureHintRegex().IsMatch(line)
            )
            .Select(line => line.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var excerpt = BuildCompactExcerpt(lines, 40, 3200);
        var diagnostics = ExtractBodyDiagnostics(rawBody);

        var sb = new StringBuilder();
        sb.AppendLine("READ_FILE_FALLBACK_COMPACT_VIEW");
        sb.AppendLine(
            "Reason: previous LLM response returned empty content after the full READ-FILE result."
        );
        sb.AppendLine($"OriginalLength: {toolResult.Length}");
        sb.AppendLine($"LineCount: {lines.Length}");
        if (!string.IsNullOrWhiteSpace(diagnostics))
            sb.AppendLine($"PriorEmptyContentDiagnostics: {diagnostics}");
        sb.AppendLine(
            $"Functions: {(functions.Length == 0 ? "(none detected)" : string.Join(", ", functions))}"
        );
        sb.AppendLine(
            $"HelpSections: {(sections.Length == 0 ? "(none detected)" : string.Join(", ", sections))}"
        );
        sb.AppendLine(
            $"StructureHints: {(structureHints.Length == 0 ? "(none detected)" : string.Join(", ", structureHints))}"
        );
        sb.AppendLine();
        sb.AppendLine("ParameterExcerpt:");
        sb.AppendLine(string.IsNullOrWhiteSpace(paramBlock) ? "(none detected)" : paramBlock);
        sb.AppendLine();
        sb.AppendLine("ContentExcerpt:");
        sb.Append(excerpt);
        return sb.ToString().TrimEnd();
    }

    private static string ExtractParamBlock(string[] lines, int maxLines)
    {
        var startIndex = Array.FindIndex(
            lines,
            line => line.Contains("param(", StringComparison.OrdinalIgnoreCase)
        );
        if (startIndex < 0)
            return string.Empty;

        List<string> collected = [];
        var balance = 0;

        for (int i = startIndex; i < lines.Length && collected.Count < maxLines; i++)
        {
            var line = lines[i];
            collected.Add(line);
            balance += line.Count(ch => ch == '(');
            balance -= line.Count(ch => ch == ')');

            if (i > startIndex && balance <= 0)
                break;
        }

        return string.Join(Environment.NewLine, collected).Trim();
    }

    private static string BuildCompactExcerpt(string[] lines, int maxLines, int maxChars)
    {
        const int maxLineChars = 180;

        var selected = lines
            .Take(maxLines)
            .Select(line =>
                line.Length <= maxLineChars ? line : line[..maxLineChars] + " [LINE_TRUNCATED]"
            )
            .ToArray();

        var text = string.Join(Environment.NewLine, selected).Trim();
        if (text.Length <= maxChars)
            return text;

        return text[..maxChars] + Environment.NewLine + "[COMPACT_EXCERPT_TRUNCATED]";
    }

    private static string ExtractBodyDiagnostics(string? rawBody)
    {
        if (string.IsNullOrWhiteSpace(rawBody))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(rawBody);
            var root = doc.RootElement;
            List<string> fields = [];

            if (
                root.TryGetProperty("done_reason", out var doneReason)
                && doneReason.ValueKind == JsonValueKind.String
            )
                    fields.Add($"done_reason={doneReason.GetString()}");

            if (
                root.TryGetProperty("eval_count", out var evalCount)
                && evalCount.ValueKind == JsonValueKind.Number
            )
                fields.Add($"eval_count={evalCount.GetInt32()}");

            if (
                root.TryGetProperty("message", out var message)
                && message.ValueKind == JsonValueKind.Object
            )
            {
                if (
                    message.TryGetProperty("thinking", out var thinking)
                    && thinking.ValueKind == JsonValueKind.String
                )
                    fields.Add($"thinking_length={thinking.GetString()?.Length ?? 0}");
            }

            return fields.Count == 0 ? Preview(rawBody) : string.Join(", ", fields);
        }
        catch
        {
            return Preview(rawBody);
        }
    }

    private static string MaybeCompactReadFileResultForPrompt(string toolResult, int thresholdChars)
    {
        if (string.IsNullOrWhiteSpace(toolResult))
            return toolResult;

        if (toolResult.Length <= thresholdChars)
            return toolResult;

        var trimmed = toolResult.TrimStart();
        if (
            trimmed.StartsWith('{')
            && trimmed.Contains("\"kind\":\"file-summary\"", StringComparison.OrdinalIgnoreCase)
        )
        {
            return toolResult;
        }

        if (!LooksLikePowerShellScript(toolResult))
            return toolResult;

        return BuildReadFileFallbackCompactView(toolResult, rawBody: null);
    }

    private static bool LooksLikePowerShellScript(string text)
    {
        var normalized = text.Replace("\r\n", "\n");
        return normalized.Contains("function ", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("[CmdletBinding()]", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("param(", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(
                "# SIG # Begin signature block",
                StringComparison.OrdinalIgnoreCase
            );
    }
}

public record RunLoopResult(string OutputText, bool ReachedIterationLimit);

public class AgentResult(string output)
{
    public string OutputText { get; } = output;
    public List<string> ToolNames { get; set; } = new();
    public int ToolCallCount { get; set; }
    public int DurationMs { get; set; }
    public bool RetriedOnIterationLimit { get; set; }
    public bool RetrySucceeded { get; set; }
    public int InitialIterationLimit { get; set; }
    public int? RetryIterationLimit { get; set; }
}
