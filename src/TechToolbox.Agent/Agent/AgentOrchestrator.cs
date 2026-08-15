using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechToolbox.Agent.Memory;
using TechToolbox.Agent.Registry;

namespace TechToolbox.Agent.Agent;

/// <summary>
/// Orchestrates agent execution by managing LLM interactions, tool invocations, and iteration control.
/// </summary>
public partial class AgentOrchestrator
{
    private const int MaxClarificationCyclesBeforeBoundedProbe = 2;
    private static readonly string[] LineSeparators = ["\r\n", "\n"];
    private static readonly string[] InvestigationTerms =
    [
        "investigate",
        "troubleshoot",
        "diagnose",
        "issue",
        "problem",
        "error",
        "failure",
        "debug",
        "check why",
    ];
    private static readonly char[] TrimDirectorySeparators =
    [
        Path.DirectorySeparatorChar,
        Path.AltDirectorySeparatorChar,
    ];

    private readonly ILlmClient _llm;
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
    private readonly string _executionMode;
    private readonly string _outputContract;
    private readonly string _qualityProfile;
    private readonly string _thinkingMode;
    private readonly HeuristicScoringEngine _heuristicScoringEngine = new();
    private readonly int _promptPreflightScore;
    private readonly int _promptPreflightWarningCount;
    private readonly int _promptPreflightCriticalCount;
    private readonly object _traceLock = new();

    [GeneratedRegex(@"^\s*(?:#\s*)?\.(?<name>[A-Z][A-Z0-9_-]*)\b")]
    private static partial Regex SectionHeadingRegex();

    [GeneratedRegex(@"^\s*function\s+(?<name>[A-Za-z_][A-Za-z0-9_-]*)\b", RegexOptions.IgnoreCase)]
    private static partial Regex FunctionNameRegex();

    [GeneratedRegex(@"(?im)^\s*-\s*Create\s+the\s+output\s+file\s+at\s+this\s+exact\s+path\s*:\s*(?<path>[A-Za-z]:\\[^\r\n]+)$")]
    private static partial Regex ExpectedOutputPathRegex();

    [GeneratedRegex("(?is)\\b(write|rewrite|update|edit|modify|insert|create)\\b|\\buse\\s+write(?:-|=|\\s*)file\\b|\\bwrite(?:-|=|\\s*)file\\b")]
    private static partial Regex WriteIntentRegex();

    [GeneratedRegex("(?i)(?<path>[A-Za-z]:\\\\[^\\\"'`\\r\\n]*\\.[A-Za-z0-9]{1,16})(?=\\s|$|[)\\],;:])")]
    private static partial Regex DirectFilePathRegex();
    [GeneratedRegex("(?i)\\bservice\\s+(?<name>[A-Za-z0-9_.-]+)\\b")]
    private static partial Regex ServiceHintRegex();
    [GeneratedRegex("(?i)https?://[^\\s)\\],;]+")]
    private static partial Regex UrlHintRegex();

    [GeneratedRegex("^\\s*(begin|process|end)\\s*\\{", RegexOptions.IgnoreCase)]
    private static partial Regex StructureHintRegex();

    /// <summary>
    /// Initializes a new instance of the <see cref="AgentOrchestrator"/> class.
    /// </summary>
    /// <param name="llm">The LLM client used to generate agent decisions.</param>
    /// <param name="registry">The registered tool specifications available to the agent.</param>
    /// <param name="tools">The executable tool callbacks keyed by tool name.</param>
    /// <param name="memory">The optional memory store used for prompt history and learning.</param>
    /// <param name="model">The model identifier associated with the current run.</param>
    /// <param name="destructiveConfirmed">Indicates whether destructive operations have been explicitly confirmed.</param>
    /// <param name="signedFilePolicy">The signed-file handling policy applied during file operations.</param>
    /// <param name="maxIterations">The maximum number of planner/tool iterations allowed per run attempt.</param>
    /// <param name="autoRetry">Indicates whether the orchestrator should retry automatically after hitting the iteration limit.</param>
    /// <param name="tracePath">The optional file path used to write diagnostic trace output.</param>
    /// <param name="expectedOutputPath">The optional required output path that file-update tools must target.</param>
    /// <param name="recentHistoryItemsInPrompt">The number of recent history items to include in the initial prompt.</param>
    /// <param name="executionMode">Execution mode: execute, plan, analyze, or chat.</param>
    /// <param name="outputContract">Output contract: markdown, plain-text, or json.</param>
    /// <param name="qualityProfile">Quality profile: precise, balanced, or creative.</param>
    /// <param name="thinkingMode">Thinking mode: auto, on, or off.</param>
    /// <param name="promptPreflightScore">Prompt preflight score (0..100).</param>
    /// <param name="promptPreflightWarningCount">Prompt preflight warning count.</param>
    /// <param name="promptPreflightCriticalCount">Prompt preflight critical issue count.</param>
    public AgentOrchestrator(
        ILlmClient llm,
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
        int recentHistoryItemsInPrompt = 2,
        string executionMode = "chat",
        string outputContract = "markdown",
        string qualityProfile = "balanced",
        string thinkingMode = "auto",
        int promptPreflightScore = 0,
        int promptPreflightWarningCount = 0,
        int promptPreflightCriticalCount = 0
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
        _executionMode = NormalizeExecutionMode(executionMode);
        _outputContract = NormalizeOutputContract(outputContract);
        _qualityProfile = NormalizeQualityProfile(qualityProfile);
        _thinkingMode = thinkingMode;
        _promptPreflightScore = Math.Clamp(promptPreflightScore, 0, 100);
        _promptPreflightWarningCount = Math.Max(0, promptPreflightWarningCount);
        _promptPreflightCriticalCount = Math.Max(0, promptPreflightCriticalCount);

        _llm.DiagnosticTrace = msg => Trace($"LlmClient {msg}");
    }

    /// <summary>
    /// Runs the agent synchronously for the supplied prompt.
    /// </summary>
    /// <param name="prompt">The user prompt to process.</param>
    /// <returns>An <see cref="AgentResult"/> that contains the final output and execution metadata.</returns>
    public AgentResult Run(string prompt) => RunAsync(prompt).GetAwaiter().GetResult();

    /// <summary>
    /// Runs the agent asynchronously for the supplied prompt.
    /// </summary>
    /// <param name="prompt">The user prompt to process.</param>
    /// <returns>A task that resolves to an <see cref="AgentResult"/> containing the final output and execution metadata.</returns>
    public async Task<AgentResult> RunAsync(string prompt)
    {
        prompt ??= string.Empty;
        Trace(
            $"RunAsync start maxIterations={_maxIterations} autoRetry={_autoRetry} recentHistoryItemsInPrompt={_recentHistoryItemsInPrompt} executionMode={_executionMode} outputContract={_outputContract} qualityProfile={_qualityProfile} promptPreflightScore={_promptPreflightScore} warnings={_promptPreflightWarningCount} critical={_promptPreflightCriticalCount} promptLength={prompt.Length}"
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
                BuildIterationLimitMessage(
                    _maxIterations,
                    retryIterations,
                    retryAttempt.ProgressCheckpoint
                ),
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
            BuildIterationLimitMessage(_maxIterations, checkpoint: attempt.ProgressCheckpoint),
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
            _recentHistoryItemsInPrompt,
            _executionMode,
            _outputContract,
            _thinkingMode
        );
        var maxConsecutiveLlmFailures = GetMaxConsecutiveLlmFailures();
        var consecutiveLlmFailures = 0;
        var clarificationCycles = 0;
        var recentToolFailures = new List<string>();
        string? lastFailureTargetHint = null;
        var expectedOutputPath = string.IsNullOrWhiteSpace(_expectedOutputPath)
            ? ExtractExpectedOutputPathFromPrompt(prompt)
            : _expectedOutputPath;
        var requiresWriteFile = !string.IsNullOrWhiteSpace(expectedOutputPath);
        var writeFileCompleted = false;
        var writeFinalizeRequired = false;
        ChatTurnPlan? chatTurnPlan = null;
        var preflightRisk = _heuristicScoringEngine.EvaluatePreflightRisk(
            prompt,
            new PreflightSignalSnapshot(
                _promptPreflightScore,
                _promptPreflightWarningCount,
                _promptPreflightCriticalCount
            ),
            _memory?.History
        );

        Trace(
            $"RunLoop preflight riskScore={preflightRisk.RiskScore:F2} thresholdAdjustment={preflightRisk.ClarificationThresholdAdjustment:F2} predictiveFailureLikely={preflightRisk.PredictiveFailureLikely} factors={string.Join(" | ", preflightRisk.RiskFactors)}"
        );

        if (requiresWriteFile)
        {
            Trace(
                $"RunLoop enforcing WRITE-FILE completion for expected output path: {expectedOutputPath}"
            );
        }

        for (int i = 0; i < iterationLimit; i++)
        {
            if (string.Equals(_executionMode, "chat", StringComparison.OrdinalIgnoreCase))
            {
                chatTurnPlan = ChatModeOrchestration.BuildTurnPlan(
                    prompt,
                    _memory,
                    messages,
                    toolNames,
                    recentToolFailures,
                    _promptPreflightScore,
                    _promptPreflightWarningCount,
                    _promptPreflightCriticalCount
                );
                UpsertChatOrchestrationContext(messages, chatTurnPlan);
            }

            Trace($"Iteration {i + 1}/{iterationLimit} start messages={messages.Count}");

            // Create incremental validator and call LLM with streaming
            var validator = CreateIncrementalDecisionValidator(expectedOutputPath, i + 1, out var foundValidDecision);
            var llmResponse = await _llm.GenerateDecisionWithCallbackAsync(messages, validator)
                .ConfigureAwait(false);
            var raw = (llmResponse.Text ?? "").Trim();

            Trace(
                $"Iteration {i + 1} response length={raw.Length} stoppedEarly={!llmResponse.Success} preview={Preview(raw)}"
            );

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
                if (TryHandleIncompleteProgressDecision(messages, decision!, i + 1, out var handledValidationError))
                {
                    Trace(
                        $"Iteration {i + 1} redirected schema-invalid progress update back into the loop: {handledValidationError}"
                    );
                    continue;
                }

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

                // Use incremental validator for repair response as well
                var repairValidator = CreateIncrementalDecisionValidator(
                    expectedOutputPath,
                    i + 1,
                    out var repairFoundValidDecision
                );
                var repairResponse = await _llm.GenerateDecisionWithCallbackAsync(messages, repairValidator)
                    .ConfigureAwait(false);
                var repairedRaw = (repairResponse.Text ?? "").Trim();

                Trace(
                    $"Iteration {i + 1} repair response length={repairedRaw.Length} stoppedEarly={!repairResponse.Success} preview={Preview(repairedRaw)}"
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
                    if (TryHandleIncompleteProgressDecision(messages, decision!, i + 1, out var handledValidationError))
                    {
                        Trace(
                            $"Iteration {i + 1} redirected repaired schema-invalid progress update back into the loop: {handledValidationError}"
                        );
                        continue;
                    }

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

                        // Use incremental validator for write file recovery as well
                        var recoveryValidator = CreateIncrementalDecisionValidator(
                            expectedOutputPath,
                            i + 1,
                            out var recoveryFoundValidDecision
                        );
                        var writeFileRecoveryResponse = await _llm.GenerateDecisionWithCallbackAsync(
                            messages,
                            recoveryValidator
                        ).ConfigureAwait(false);
                        var writeFileRecoveryRaw = (writeFileRecoveryResponse.Text ?? "").Trim();

                        Trace(
                            $"Iteration {i + 1} targeted recovery response length={writeFileRecoveryRaw.Length} stoppedEarly={!writeFileRecoveryResponse.Success} preview={Preview(writeFileRecoveryRaw)}"
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

            var currentTargetHint = ExtractDecisionTargetHint(decision, prompt);
            var hasNewConcreteTargetHint = !string.IsNullOrWhiteSpace(currentTargetHint)
                && !string.Equals(
                    currentTargetHint,
                    lastFailureTargetHint,
                    StringComparison.OrdinalIgnoreCase
                );

            if (hasNewConcreteTargetHint && recentToolFailures.Count > 0)
            {
                // Clear stale failure pressure when the user/model provides a new concrete target.
                recentToolFailures.Clear();
                Trace(
                    $"Iteration {i + 1} reset recent tool failure penalties due to new concrete target hint: {currentTargetHint}"
                );
            }

            var heuristicEvaluation = _heuristicScoringEngine.Evaluate(
                prompt,
                decision,
                recentToolFailures,
                lastSuccessfulTool: _memory?.History.LastOrDefault()?.ToolNames.LastOrDefault(),
                lastSuccessfulTargetHint: _memory?.History.LastOrDefault()?.RunSummary?.Intent,
                clarificationCycles: clarificationCycles,
                hasNewConcreteTargetHint: hasNewConcreteTargetHint,
                preflightRisk: preflightRisk
            );

            if (decision.NeedsTool && heuristicEvaluation.NeedsClarification)
            {
                if (
                    IsInvestigationPrompt(prompt)
                    && IsLowRiskExploratoryTool(decision.ToolName)
                    && clarificationCycles < MaxClarificationCyclesBeforeBoundedProbe
                )
                {
                    clarificationCycles++;
                    Trace(
                        $"Iteration {i + 1} heuristic clarification cycle={clarificationCycles} confidence={heuristicEvaluation.Confidence:F2} tool={decision.ToolName}"
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "HEURISTIC-CLARIFICATION",
                            heuristicEvaluation.ClarificationMessage,
                            succeeded: false
                        )
                    );
                    continue;
                }

                if (
                    IsInvestigationPrompt(prompt)
                    && IsLowRiskExploratoryTool(decision.ToolName)
                    && clarificationCycles >= MaxClarificationCyclesBeforeBoundedProbe
                )
                {
                    Trace(
                        $"Iteration {i + 1} forcing bounded exploratory step after {clarificationCycles} clarification cycles confidence={heuristicEvaluation.Confidence:F2} tool={decision.ToolName}"
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "HEURISTIC-BOUND-PROBE",
                            "Proceeding with a bounded exploratory step due to repeated clarification cycles. Keep scope narrow and use conservative assumptions.",
                            succeeded: false
                        )
                    );
                }
                else
                {
                    Trace(
                        $"Iteration {i + 1} heuristic clarification triggered confidence={heuristicEvaluation.Confidence:F2} tool={decision.ToolName}"
                    );
                    return new RunLoopResult(
                        heuristicEvaluation.ClarificationMessage,
                        ReachedIterationLimit: false
                    );
                }

                Trace(
                    $"Iteration {i + 1} bypassed clarification return and continued with bounded exploratory execution."
                );
            }

            if (!decision.NeedsTool)
            {
                if (requiresWriteFile && !writeFileCompleted)
                {
                    var requirementError =
                        $"Required file update step has not completed yet. Use WRITE-FILE, APPEND-FILE, or REPLACE-IN-FILE on '{expectedOutputPath}' before returning finalAnswer.";

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

                if (requiresWriteFile && writeFinalizeRequired)
                {
                    var finalizeError =
                        $"Chunked APPEND-FILE write is not finalized yet. Call FINALIZE-FILE-WRITE on '{expectedOutputPath}' before returning finalAnswer.";

                    Trace(
                        $"Iteration {i + 1} blocked final answer because FINALIZE-FILE-WRITE is required after APPEND-FILE."
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "FINALIZE-FILE-WRITE",
                            finalizeError,
                            succeeded: false
                        )
                    );
                    continue;
                }

                if (LooksLikeIncompleteFinalAnswer(decision.FinalAnswer))
                {
                    const string incompleteFinalAnswerError =
                        "Final answer indicates the task is still in progress. Do not return a progress update as finalAnswer; continue with the next required tool call or return a completed result only after all requested work is done.";

                    Trace(
                        $"Iteration {i + 1} blocked final answer because it self-reported incomplete work."
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "FINAL-ANSWER",
                            incompleteFinalAnswerError,
                            succeeded: false
                        )
                    );
                    continue;
                }

                if (!ValidateFinalAnswerContract(decision.FinalAnswer, _outputContract, out var contractError))
                {
                    Trace(
                        $"Iteration {i + 1} blocked final answer because output contract '{_outputContract}' was not met: {contractError}"
                    );
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "OUTPUT-CONTRACT",
                            contractError,
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

            if (string.Equals(_executionMode, "chat", StringComparison.OrdinalIgnoreCase) && chatTurnPlan is not null)
            {
                if (decision.NeedsTool)
                {
                    if (chatTurnPlan.CompassAction == ConversationCompassAction.Escalate)
                    {
                        Trace(
                            $"Iteration {i + 1} blocked tool call due to chat compass escalation."
                        );
                        return new RunLoopResult(
                            "This request looks high-risk. Before I run tools, please confirm the exact safe objective and constraints you want me to follow.",
                            ReachedIterationLimit: false
                        );
                    }

                    if (chatTurnPlan.CompassAction == ConversationCompassAction.Challenge)
                    {
                        Trace(
                            $"Iteration {i + 1} challenged tool call due to chat compass challenge action."
                        );
                        return new RunLoopResult(
                            "Before I act, can we tighten scope? Please provide one concrete target and one success criterion so I can avoid guesswork.",
                            ReachedIterationLimit: false
                        );
                    }

                    if (chatTurnPlan.CompassAction == ConversationCompassAction.Clarify)
                    {
                        Trace(
                            $"Iteration {i + 1} requested clarification because chat compass action is Clarify."
                        );
                        return new RunLoopResult(
                            "Do you want me to analyze this, plan something, or execute something?",
                            ReachedIterationLimit: false
                        );
                    }
                }

                var hesitation = chatTurnPlan.Hesitation;
                if (hesitation.Level == ToolHesitationLevel.High)
                {
                    var clarification = string.IsNullOrWhiteSpace(hesitation.ClarificationPrompt)
                        ? "Before I run tools, should I focus on analysis, planning, or a concrete execution step?"
                        : hesitation.ClarificationPrompt;

                    Trace(
                        $"Iteration {i + 1} blocked tool call due to high chat hesitation score={hesitation.Score}."
                    );
                    return new RunLoopResult(
                        clarification,
                        ReachedIterationLimit: false
                    );
                }

                if (hesitation.Level == ToolHesitationLevel.Medium)
                {
                    if (ShouldClarifyForMediumHesitation(prompt, decision))
                    {
                        var nudge = string.IsNullOrWhiteSpace(hesitation.ClarificationPrompt)
                            ? "I can run a quick lookup now, but do you want a short explanation first?"
                            : hesitation.ClarificationPrompt;

                        Trace(
                            $"Iteration {i + 1} requested clarification due to medium chat hesitation score={hesitation.Score}."
                        );
                        return new RunLoopResult(
                            nudge,
                            ReachedIterationLimit: false
                        );
                    }

                    Trace(
                        $"Iteration {i + 1} allowed tool call despite medium hesitation because target appears concrete."
                    );
                }
            }

            var toolName = decision.ToolName ?? string.Empty;

            if (!string.Equals(_executionMode, "execute", StringComparison.OrdinalIgnoreCase))
            {
                var isAllowedChatTool = string.Equals(_executionMode, "chat", StringComparison.OrdinalIgnoreCase)
                    && (string.Equals(toolName, "SEARCH-WEB", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(toolName, "FETCH-URL", StringComparison.OrdinalIgnoreCase));

                if (!isAllowedChatTool)
                {
                    var modeBlockError =
                        string.Equals(_executionMode, "chat", StringComparison.OrdinalIgnoreCase)
                            ? "Execution mode 'chat' does not allow tool calls except for SEARCH-WEB and FETCH-URL. Return needsTool=false with a clarification question or conceptual answer instead of guessing."
                            : $"Execution mode '{_executionMode}' does not allow tool calls. Return needsTool=false with a complete {(string.Equals(_executionMode, "plan", StringComparison.OrdinalIgnoreCase) ? "numbered plan" : "analysis")}.";
                    Trace($"Iteration {i + 1} blocked tool call because execution mode is {_executionMode} and tool is {toolName}.");
                    messages.Add(
                        PromptBuilder.BuildToolResultMessage(
                            "MODE-GUARD",
                            modeBlockError,
                            succeeded: false
                        )
                    );
                    continue;
                }
            }


            if (!_tools.TryGetValue(toolName, out var toolFunc))
            {
                Trace($"Iteration {i + 1} tool not found: {toolName}");

                if (ShouldReturnAmbiguityClarification(prompt, decision))
                {
                    return new RunLoopResult(
                        "I need clarification before selecting the next action. Please provide exactly one value for the primary target (for example a file path, URL, service name, or query).",
                        ReachedIterationLimit: false
                    );
                }

                if (heuristicEvaluation.NeedsClarification)
                {
                    Trace(
                        $"Iteration {i + 1} returned clarification because requested tool '{toolName}' is unavailable and prompt remains ambiguous."
                    );
                    return new RunLoopResult(
                        heuristicEvaluation.ClarificationMessage,
                        ReachedIterationLimit: false
                    );
                }

                recentToolFailures.Add(toolName);
                lastFailureTargetHint = currentTargetHint;

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
            var isFileUpdateTool = IsFileUpdateTool(toolName);
            var isFinalizeTool = IsFileWriteFinalizeTool(toolName);

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
                recentToolFailures.Add(toolName);
                lastFailureTargetHint = currentTargetHint;
            }

            if (requiresWriteFile && (isFileUpdateTool || isFinalizeTool))
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

            if (toolExecutionSucceeded)
            {
                clarificationCycles = 0;
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
                && isFileUpdateTool
                && toolExecutionSucceeded
                && !toolResult.StartsWith("Error", StringComparison.OrdinalIgnoreCase)
            )
            {
                if (File.Exists(expectedOutputPath!))
                {
                    writeFileCompleted = true;
                    if (string.Equals(toolName, "APPEND-FILE", StringComparison.OrdinalIgnoreCase))
                    {
                        writeFinalizeRequired = true;
                        Trace($"Iteration {i + 1} marked file-update as completed via APPEND-FILE and now requires FINALIZE-FILE-WRITE.");
                    }
                    else
                    {
                        writeFinalizeRequired = false;
                        Trace($"Iteration {i + 1} marked file-update hard requirement as completed via {toolName}.");
                    }
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

            if (
                requiresWriteFile
                && isFinalizeTool
                && toolExecutionSucceeded
                && !toolResult.StartsWith("Error", StringComparison.OrdinalIgnoreCase)
            )
            {
                if (!writeFileCompleted)
                {
                    toolExecutionSucceeded = false;
                    toolResult =
                        "FINALIZE-FILE-WRITE cannot run before a successful file update. Use WRITE-FILE/APPEND-FILE/REPLACE-IN-FILE first.";
                }
                else if (!File.Exists(expectedOutputPath!))
                {
                    toolExecutionSucceeded = false;
                    toolResult =
                        $"FINALIZE-FILE-WRITE reported success but expected output file does not exist at '{expectedOutputPath}'.";
                }
                else
                {
                    writeFinalizeRequired = false;
                    Trace($"Iteration {i + 1} marked chunked file-update finalize requirement as completed.");
                }
            }

            if (!toolExecutionSucceeded)
            {
                recentToolFailures.Add(toolName);
                lastFailureTargetHint = currentTargetHint;
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

        var progressCheckpoint = BuildProgressCheckpoint(
            toolNames,
            recentToolFailures,
            lastFailureTargetHint,
            iterationLimit
        );
        Trace($"RunLoop reached iteration limit={iterationLimit}");
        return new RunLoopResult(
            "Iteration limit reached.",
            ReachedIterationLimit: true,
            ProgressCheckpoint: progressCheckpoint
        );
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
                ExecutionMode = _executionMode,
                OutputContract = _outputContract,
                QualityProfile = _qualityProfile,
                PromptPreflightScore = _promptPreflightScore,
                PromptPreflightWarningCount = _promptPreflightWarningCount,
                PromptPreflightCriticalCount = _promptPreflightCriticalCount,
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
        int? retryIterationLimit = null,
        string? checkpoint = null
    )
    {
        var checkpointBlock = string.IsNullOrWhiteSpace(checkpoint)
            ? string.Empty
            : $"{Environment.NewLine}Progress checkpoint:{Environment.NewLine}{checkpoint.Trim()}{Environment.NewLine}";

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

{checkpointBlock}
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

{checkpointBlock}
""";
    }

    private static void UpsertChatOrchestrationContext(
        List<AgentChatMessage> messages,
        ChatTurnPlan plan
    )
    {
        var context = PromptBuilder.BuildChatOrchestrationMessage(plan);
        const string contextPrefix = "CHAT_ORCHESTRATION_CONTEXT";

        for (var i = messages.Count - 1; i >= 0; i--)
        {
            var msg = messages[i];
            if (!string.Equals(msg.Role, "system", StringComparison.OrdinalIgnoreCase))
                continue;

            if (msg.Content.StartsWith(contextPrefix, StringComparison.Ordinal))
            {
                messages[i] = context;
                return;
            }
        }

        messages.Insert(1, context);
    }

    private static string BuildProgressCheckpoint(
        IReadOnlyList<string> attemptedTools,
        IReadOnlyList<string> recentToolFailures,
        string? lastFailureTargetHint,
        int iterationLimit
    )
    {
        var attempted = attemptedTools.Count == 0
            ? "none"
            : string.Join(" -> ", attemptedTools.TakeLast(8));
        var failures = recentToolFailures.Count == 0
            ? "none"
            : string.Join(", ", recentToolFailures.TakeLast(5).Distinct(StringComparer.OrdinalIgnoreCase));
        var blocker = string.IsNullOrWhiteSpace(lastFailureTargetHint)
            ? "no specific target hint captured"
            : lastFailureTargetHint;

        return $"""
- attempted: {attempted}
- blocked by: {failures}
- blocker target hint: {blocker}
- next step: narrow the target and retry with a focused prompt or higher iteration budget (current limit: {iterationLimit}).
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

    private static bool LooksLikeIncompleteFinalAnswer(string? output)
    {
        if (string.IsNullOrWhiteSpace(output))
            return false;

        var normalized = output.Trim().ToLowerInvariant();
        return normalized.Contains("let me continue", StringComparison.Ordinal)
            || normalized.Contains("now i need to", StringComparison.Ordinal)
            || normalized.Contains("next i need to", StringComparison.Ordinal)
            || normalized.Contains("still need to", StringComparison.Ordinal)
            || normalized.Contains("i need to continue", StringComparison.Ordinal)
            || (normalized.Contains("need to", StringComparison.Ordinal)
                && (
                    normalized.Contains("add ", StringComparison.Ordinal)
                    || normalized.Contains("update ", StringComparison.Ordinal)
                    || normalized.Contains("edit ", StringComparison.Ordinal)
                    || normalized.Contains("write ", StringComparison.Ordinal)
                    || normalized.Contains("modify ", StringComparison.Ordinal)
                    || normalized.Contains("finish ", StringComparison.Ordinal)
                    || normalized.Contains("complete ", StringComparison.Ordinal)
                    || normalized.Contains("document", StringComparison.Ordinal)
                    || normalized.Contains("fix ", StringComparison.Ordinal)
                    || normalized.Contains("replace ", StringComparison.Ordinal)
                    || normalized.Contains("create ", StringComparison.Ordinal)
                ))
            || normalized.Contains("continue with those edits", StringComparison.Ordinal)
            || normalized.Contains("continue with the edits", StringComparison.Ordinal)
            || normalized.Contains("continue with those changes", StringComparison.Ordinal)
            || normalized.Contains("continue with the changes", StringComparison.Ordinal);
    }

    private static bool TryHandleIncompleteProgressDecision(
        List<AgentChatMessage> messages,
        AgentDecision decision,
        int iterationNumber,
        out string handledValidationError
    )
    {
        handledValidationError = string.Empty;

        if (decision.NeedsTool)
            return false;

        if (!string.IsNullOrWhiteSpace(decision.FinalAnswer))
            return false;

        if (!LooksLikeIncompleteFinalAnswer(decision.Reason))
            return false;

        handledValidationError = "needsTool=false requires non-empty finalAnswer";
        var progressError =
            "Your previous response indicates progress but not completion. If more work is required, set needsTool=true and choose the next tool call. Use needsTool=false only when the task is fully complete and finalAnswer is non-empty.";

        messages.Add(
            PromptBuilder.BuildToolResultMessage(
                "FINAL-ANSWER",
                progressError,
                succeeded: false
            )
        );
        return true;
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

    private static string BuildReadFileModeGuidance(string toolResult, string? rawBody)
    {
        if (string.IsNullOrWhiteSpace(toolResult))
            return string.Empty;

        var normalized = toolResult.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
            return string.Empty;

        var isSummary = normalized.Contains("\"kind\":\"file-summary\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"auto-chunk\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"semantic-chunk\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"header-footer\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"stream\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"file-meta\"", StringComparison.OrdinalIgnoreCase);

        if (!isSummary)
            return string.Empty;

        var pathHint = TryExtractPathHint(normalized, rawBody);
        var filePath = string.IsNullOrWhiteSpace(pathHint) ? "the target file" : pathHint;

        if (normalized.Contains("\"kind\":\"file-summary\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"kind\":\"file-meta\"", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\"isLarge\":true", StringComparison.OrdinalIgnoreCase))
        {
            return $"Use READ-FILE-META for {filePath}, then prefer READ-FILE autoChunk=true chunkSize=500 for large files. If the goal is symbol lookup, use READ-FILE semantic=\"target\" contextLines=40. For structure-only reads, use READ-FILE headerLines=200 footerLines=200. For very large files, use READ-FILE stream=true chunkSize=500 with nextToken continuation.";
        }

        if (normalized.Contains("\"kind\":\"semantic-chunk\"", StringComparison.OrdinalIgnoreCase))
        {
            return $"Use READ-FILE semantic=\"oldText\" contextLines=40 for targeted symbol lookup in {filePath}. This is safer than a full-file scan and keeps the context focused.";
        }

        if (normalized.Contains("\"kind\":\"header-footer\"", StringComparison.OrdinalIgnoreCase))
        {
            return $"Use READ-FILE headerLines=200 footerLines=200 for structure-only inspection of {filePath}; this preserves file shape without pulling the whole file body.";
        }

        if (normalized.Contains("\"kind\":\"stream\"", StringComparison.OrdinalIgnoreCase))
        {
            return $"Continue READ-FILE streaming for {filePath} using nextToken until the target context is complete.";
        }

        return $"Use READ-FILE-META for {filePath} and select the right mode: autoChunk for large files, semantic for symbol lookup, header/footer for structure, or stream for very large files.";
    }

    private static string? TryExtractPathHint(string toolResult, string? rawBody)
    {
        if (string.IsNullOrWhiteSpace(toolResult))
            return null;

        var pathMatches = Regex.Matches(toolResult, "\"path\"\\s*:\\s*\"(?<path>[^\"]+)\"");
        foreach (Match match in pathMatches)
        {
            var candidate = match.Groups["path"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(candidate))
                return candidate;
        }

        if (!string.IsNullOrWhiteSpace(rawBody))
        {
            var fallbackMatch = DirectFilePathRegex().Match(rawBody);
            if (fallbackMatch.Success)
                return NormalizeDetectedPath(fallbackMatch.Groups["path"].Value);
        }

        return null;
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

    private static bool IsInvestigationPrompt(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return false;

        foreach (var term in InvestigationTerms)
        {
            if (prompt.Contains(term, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsLowRiskExploratoryTool(string? toolName)
    {
        if (string.IsNullOrWhiteSpace(toolName))
        {
            return false;
        }

        return toolName.Equals("READ-FILE", StringComparison.OrdinalIgnoreCase)
            || toolName.Equals("LIST-DIRECTORY", StringComparison.OrdinalIgnoreCase)
            || toolName.Equals("SEARCH-WEB", StringComparison.OrdinalIgnoreCase)
            || toolName.Equals("FETCH-URL", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldReturnAmbiguityClarification(string prompt, AgentDecision decision)
    {
        if (string.IsNullOrWhiteSpace(prompt) || decision is null)
            return false;

        var normalized = prompt.Trim().ToLowerInvariant();
        var isShortAmbiguous = normalized.Length <= 40
            && (normalized.Contains("help", StringComparison.Ordinal)
                || normalized.Contains("this", StringComparison.Ordinal)
                || normalized.Contains("that", StringComparison.Ordinal));

        if (!isShortAmbiguous)
            return false;

        if (decision.ToolArgs is null || decision.ToolArgs.Count == 0)
            return true;

        return !TryGetToolArgString(decision.ToolArgs, "path", out _)
            && !TryGetToolArgString(decision.ToolArgs, "url", out _)
            && !TryGetToolArgString(decision.ToolArgs, "query", out _)
            && !TryGetToolArgString(decision.ToolArgs, "target", out _);
    }

    private static bool ShouldClarifyForMediumHesitation(string prompt, AgentDecision decision)
    {
        if (decision is null)
            return true;

        if (decision.ToolArgs is not null)
        {
            if (TryGetToolArgString(decision.ToolArgs, "url", out var urlArg) && !string.IsNullOrWhiteSpace(urlArg))
                return false;

            if (TryGetToolArgString(decision.ToolArgs, "query", out var queryArg) && !string.IsNullOrWhiteSpace(queryArg))
                return false;

            if (TryGetToolArgString(decision.ToolArgs, "target", out var targetArg) && !string.IsNullOrWhiteSpace(targetArg))
                return false;

            if (TryGetToolArgString(decision.ToolArgs, "path", out var pathArg) && !string.IsNullOrWhiteSpace(pathArg))
                return false;
        }

        if (!string.IsNullOrWhiteSpace(prompt))
        {
            if (UrlHintRegex().IsMatch(prompt))
                return false;

            var normalized = prompt.Trim().ToLowerInvariant();
            var hasWebTargetWords =
                normalized.Contains("website", StringComparison.Ordinal)
                || normalized.Contains("domain", StringComparison.Ordinal)
                || normalized.Contains("url", StringComparison.Ordinal)
                || normalized.Contains("weather.gov", StringComparison.Ordinal);
            var hasFactualOrSearchIntent =
                normalized.Contains("weather", StringComparison.Ordinal)
                || normalized.Contains("current", StringComparison.Ordinal)
                || normalized.Contains("latest", StringComparison.Ordinal)
                || normalized.Contains("today", StringComparison.Ordinal)
                || normalized.Contains("now", StringComparison.Ordinal)
                || normalized.Contains("search", StringComparison.Ordinal)
                || normalized.Contains("fetch", StringComparison.Ordinal)
                || normalized.Contains("look up", StringComparison.Ordinal)
                || normalized.Contains("lookup", StringComparison.Ordinal);

            if (hasWebTargetWords && hasFactualOrSearchIntent)
                return false;

            if (normalized.Length <= 35)
                return true;
        }

        return true;
    }

    private static string? ExtractDecisionTargetHint(AgentDecision decision, string prompt)
    {
        if (decision?.ToolArgs is not null)
        {
            var preferredKeys = new[] { "path", "service", "target", "url", "file", "query" };
            foreach (var key in preferredKeys)
            {
                if (TryGetToolArgString(decision.ToolArgs, key, out var value))
                {
                    return NormalizeDetectedPath(value) ?? value.Trim();
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(prompt))
        {
            var pathMatch = DirectFilePathRegex().Match(prompt);
            if (pathMatch.Success)
            {
                return NormalizeDetectedPath(pathMatch.Groups["path"].Value);
            }

            var serviceMatch = ServiceHintRegex().Match(prompt);
            if (serviceMatch.Success)
            {
                var service = serviceMatch.Groups["name"].Value.Trim();
                if (!string.IsNullOrWhiteSpace(service))
                {
                    return service;
                }
            }

            var urlMatch = UrlHintRegex().Match(prompt);
            if (urlMatch.Success)
            {
                return urlMatch.Value.Trim();
            }
        }

        return null;
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

        if (!IsFileUpdateTool(decision.ToolName) && !IsFileWriteFinalizeTool(decision.ToolName))
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

    /// <summary>
    /// Creates a callback for incremental decision validation during streaming.
    /// Parses and validates decisions as content accumulates, enabling early stop when a valid decision is found.
    /// </summary>
    /// <param name="expectedOutputPath">Optional expected file path for WRITE-FILE operations.</param>
    /// <param name="iterationNumber">Current iteration number for tracing.</param>
    /// <param name="foundValidDecision">Output: true if a valid decision was found during streaming.</param>
    /// <returns>An async callback that returns true when a valid decision is discovered.</returns>
    private Func<string, Task<bool>> CreateIncrementalDecisionValidator(
        string? expectedOutputPath,
        int iterationNumber,
        out bool foundValidDecision
    )
    {
        foundValidDecision = false;

        return async (accumulatedContent) =>
        {
            // Try to parse the accumulated content as a decision
            if (!JsonHelpers.TryParseDecision(accumulatedContent, out var decision) || decision is null)
            {
                // Not yet a valid JSON decision, continue streaming
                return false;
            }

            // Attempt to populate missing write file path if needed
            if (TryPopulateMissingWriteFilePath(decision, expectedOutputPath))
            {
                Trace(
                    $"Iteration {iterationNumber} inferred missing WRITE-FILE path from hard requirement during streaming: {expectedOutputPath}"
                );
            }

            // Validate the decision schema
            if (!TryValidateDecision(decision, out var validationError))
            {
                Trace(
                    $"Iteration {iterationNumber} streaming decision failed schema validation: {validationError}"
                );
                // Schema invalid, but might improve as more content streams in, so continue
                return false;
            }

            // Only stop early for tool decisions. For final answers (needsTool=false),
            // continue streaming until model completion to avoid truncating content.
            if (!decision.NeedsTool)
            {
                return false;
            }

            // Found a valid decision!
            Trace($"Iteration {iterationNumber} found valid decision during streaming; stopping early");
            await Task.CompletedTask;
            return true;
        };
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

            if (string.Equals(decision.ToolName, "APPEND-FILE", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    error = "APPEND-FILE requires non-empty string toolArgs.path";
                    return false;
                }

                if (!TryGetToolArgString(decision.ToolArgs, "content", out _))
                {
                    error = "APPEND-FILE requires non-empty string toolArgs.content";
                    return false;
                }
            }

            if (string.Equals(decision.ToolName, "FINALIZE-FILE-WRITE", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    error = "FINALIZE-FILE-WRITE requires non-empty string toolArgs.path";
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

            if (string.Equals(decision.ToolName, "READ-FILE", StringComparison.OrdinalIgnoreCase))
            {
                if (TryGetToolArgString(decision.ToolArgs, "path", out var pathValue))
                {
                    if (string.IsNullOrWhiteSpace(pathValue))
                    {
                        error = "READ-FILE path must be a non-empty string when specified.";
                        return false;
                    }
                }

                var supportedReadModes = new[]
                {
                    "startLine",
                    "endLine",
                    "maxLines",
                    "autoChunk",
                    "chunkSize",
                    "semantic",
                    "contextLines",
                    "headerLines",
                    "footerLines",
                    "stream",
                    "nextToken",
                    "path",
                };

                var hasSupportedMode = decision.ToolArgs.Keys.Any(key =>
                    supportedReadModes.Contains(key, StringComparer.OrdinalIgnoreCase)
                );

                if (!hasSupportedMode && !TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    // Preserve compatibility with existing minimal READ-FILE tool calls while
                    // still accepting the expanded large-file modes introduced in the advanced bridge.
                    return true;
                }
            }

            if (string.Equals(decision.ToolName, "READ-FILE-META", StringComparison.OrdinalIgnoreCase))
            {
                if (!TryGetToolArgString(decision.ToolArgs, "path", out _))
                {
                    error = "READ-FILE-META requires non-empty string toolArgs.path";
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
            || string.Equals(toolName, "APPEND-FILE", StringComparison.OrdinalIgnoreCase)
            || string.Equals(toolName, "REPLACE-IN-FILE", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsFileWriteFinalizeTool(string? toolName)
    {
        return string.Equals(toolName, "FINALIZE-FILE-WRITE", StringComparison.OrdinalIgnoreCase);
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

    private static bool ValidateFinalAnswerContract(
        string? finalAnswer,
        string outputContract,
        out string error
    )
    {
        error = string.Empty;
        var answer = finalAnswer ?? string.Empty;

        if (string.Equals(outputContract, "json", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(answer))
            {
                error = "Output contract 'json' requires non-empty valid JSON text in finalAnswer.";
                return false;
            }

            try
            {
                using var doc = JsonDocument.Parse(answer);
                if (
                    doc.RootElement.ValueKind != JsonValueKind.Object
                    && doc.RootElement.ValueKind != JsonValueKind.Array
                )
                {
                    error =
                        "Output contract 'json' requires finalAnswer to be a JSON object or array.";
                    return false;
                }

                return true;
            }
            catch
            {
                error =
                    "Output contract 'json' requires finalAnswer to be valid JSON text (object or array).";
                return false;
            }
        }

        if (string.Equals(outputContract, "plain-text", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(answer))
                return true;

            var normalized = answer.Replace("\r\n", "\n");
            if (
                normalized.Contains("```", StringComparison.Ordinal)
                || normalized.Contains("~~~", StringComparison.Ordinal)
                || Regex.IsMatch(normalized, @"(?m)^\s*#{1,6}\s+")
                || Regex.IsMatch(normalized, @"(?m)^\s*[-*+]\s+")
                || Regex.IsMatch(normalized, @"(?m)^\s*\d+\.\s+")
            )
            {
                error =
                    "Output contract 'plain-text' forbids markdown headings, lists, and code fences.";
                return false;
            }

            return true;
        }

        return true;
    }

    private static string NormalizeExecutionMode(string? executionMode)
    {
        if (string.IsNullOrWhiteSpace(executionMode))
            return "chat";

        return executionMode.Trim().ToLowerInvariant() switch
        {
            "analyze" => "analyze",
            "plan" => "plan",
            "chat" => "chat",
            "execute" => "execute",
            _ => "chat",
        };
    }

    private static string NormalizeOutputContract(string? outputContract)
    {
        if (string.IsNullOrWhiteSpace(outputContract))
            return "markdown";

        return outputContract.Trim().ToLowerInvariant() switch
        {
            "json" => "json",
            "plain-text" => "plain-text",
            _ => "markdown",
        };
    }

    private static string NormalizeQualityProfile(string? qualityProfile)
    {
        if (string.IsNullOrWhiteSpace(qualityProfile))
            return "balanced";

        return qualityProfile.Trim().ToLowerInvariant() switch
        {
            "precise" => "precise",
            "creative" => "creative",
            _ => "balanced",
        };
    }
}

/// <summary>
/// Represents the outcome of an internal run-loop execution.
/// </summary>
/// <param name="OutputText">The output text produced by the run loop.</param>
/// <param name="ReachedIterationLimit"><see langword="true"/> when the run loop stopped because it exhausted the iteration budget; otherwise, <see langword="false"/>.</param>
public record RunLoopResult(string OutputText, bool ReachedIterationLimit, string ProgressCheckpoint = "");

/// <summary>
/// Represents the final outcome of an agent run, including output, tool usage, and retry metadata.
/// </summary>
/// <param name="output">The final output text produced by the agent run.</param>
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
