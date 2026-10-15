# TechToolbox Agent Architecture Breakdown

- Scope
  - This document is a source-grounded overview of the implementation under `src/TechToolbox.Agent`.
  - It describes the major layers, responsibilities, execution flow, safety boundaries, and extension points visible in the project structure and core implementation.
  - It is an architecture overview, not a claim that every implementation detail or runtime deployment setting is captured here.

- High-level architecture
  - Public entry point and composition root
    - `Core/AgentCore.cs` exposes synchronous and asynchronous agent run methods.
    - It converts parameter-based calls into `AgentConfiguration` instances for compatibility and composition.
    - It coordinates MCP initialization, tool discovery, tool wrapping, optional memory initialization, LLM client creation, orchestration, optional two-stage execution, and result metadata.
  - Configuration and policy
    - `Configuration/AgentConfiguration.cs` centralizes model, provider, execution mode, output contract, quality, reasoning, runtime profile, resilience, tool, memory, search, shell, and safety settings.
    - `Configuration/AgentMode.cs` and `Configuration/AgentModeDetector.cs` define and detect operating modes.
    - `Configuration/McpConfiguration.cs` and `Configuration/McpOAuthConfiguration.cs` hold MCP and OAuth-related settings.
  - Prompt construction
    - `Prompting/PromptBuilder.cs` and its partial files assemble system and goal context.
    - `Prompting/PromptPolicy.cs` and `Prompting/PromptSections.cs` define prompt policy and reusable prompt sections.
  - LLM abstraction
    - `Llm/ILlmClient.cs` defines the client contract.
    - `Llm/LlmClient.cs` provides shared client behavior.
    - `Llm/OpenAiCompatibleLlmClient.cs` supports OpenAI-compatible transports.
    - `Llm/LlmClientFactory.cs` constructs the provider client and resolves runtime-profile model settings.
  - Orchestration
    - `Orchestrator/AgentOrchestrator.cs` and its partial files implement the model/tool decision loop, validation, retries, budgets, cancellation, finalization, and related routing behavior.
  - Tool registry and providers
    - `Registry/IToolProvider.cs` defines the provider abstraction.
    - `Registry/ToolRegistry.cs` builds the discovered tool specification registry.
    - Generic, external, PowerShell, and MCP providers supply tool definitions through provider-specific implementations.
  - Tool execution
    - `Execution/IToolExecutor.cs` defines execution contracts.
    - `Execution/PowerShellToolExecutor.cs` handles PowerShell-backed tools.
    - `Execution/McpToolExecutor.cs` handles MCP-backed tools.
    - `Tools/ToolWrapper.cs` converts registered tool specifications into callable wrappers and applies execution-related policy inputs.
  - MCP subsystem
    - `Mcp/IMcpClient.cs`, `Mcp/McpBootstrap.cs`, and `Mcp/McpLifecycle.cs` cover client setup and lifecycle.
    - `Mcp/McpIdentity.cs` and `Mcp/McpIdentityRegistry.cs` represent server identities.
    - `Mcp/McpAuthChallenge.cs`, `Mcp/McpOAuth.cs`, `Mcp/McpOAuthFactory.cs`, and `Mcp/McpOAuthSessionManager.cs` cover OAuth challenge, creation, and session-management concerns.
    - `Mcp/McpRedaction.cs` provides MCP-specific redaction behavior.
  - Memory and heuristics
    - `Memory/MemoryStore.cs`, `Memory/MemoryModels.cs`, and `Memory/MemoryLearner.cs` provide optional persistent run-history and learning support.
    - `Heuristics/HeuristicScoringEngine.cs`, `HeuristicRoutingPipeline.cs`, `HeuristicCostModel.cs`, `PatternEvidenceMatcher.cs`, and `SessionReinforcement.cs` support evidence-based routing and scoring behavior.
  - Verification
    - `Tests/` contains coverage for core execution, orchestration, tools, reliability, memory, MCP, OAuth integration, and routing.

- Primary request-to-result flow
  - A caller invokes `AgentCore.RunAgent` or `AgentCore.RunAgentAsync`.
  - Input validation rejects an empty prompt or null configuration.
  - Parameter-based overloads map individual arguments into `AgentConfiguration`.
  - Optional runtime-profile and resilience JSON payloads are parsed with defaults used when payloads are absent or invalid.
  - MCP configuration is validated before provider discovery and client creation.
  - `McpBootstrap.InitializeAsync` creates the MCP runtime when configured.
  - Configured tool providers are combined with MCP providers.
  - `ToolRegistry.BuildToolRegistry` creates the tool specification map.
  - Meta-tools are filtered unless `AllowMetaTools` is enabled.
  - Chat mode restricts the registry to the configured web-discovery tools exposed by the active registry and provider set.
  - Empty non-chat registries terminate with an explicit discovery error.
  - `ToolWrapper.BuildTools` creates executable tool delegates and receives safety, fetch-host, search, shell-allowlist, and executor settings.
  - An optional `MemoryStore` is initialized when `MemoryPath` is configured.
  - `LlmClientFactory` creates the LLM client.
  - `AgentOrchestrator` receives the client, registry, tool delegates, memory, model, safety settings, iteration limits, output settings, prompt-preflight data, and complete configuration.
  - The orchestrator runs the prompt/tool loop and returns an `AgentResult`.
  - Optional metadata includes provider, model, execution settings, used tools, tool-call count, duration, retry information, fallback information, and iteration-limit status.
  - MCP resources are disposed through the asynchronous MCP runtime lifetime.

- Execution modes
  - `execute`
    - Supports the full configured tool workflow.
    - May use the optional two-stage planner/executor flow when enabled for the applicable provider and policy.
  - `plan`
    - Produces planning-oriented output rather than performing the normal execution workflow.
  - `analyze`
    - Provides analysis behavior controlled by the orchestrator and prompt policy.
  - Output contracts include `markdown`, `plain-text`, and `json`.

- Optional two-stage resilience flow
  - The two-stage path is enabled only when the configured resilience policy enables it, the provider is Ollama, and the execution mode is `execute`.
  - A planning configuration changes the execution mode to `plan`, reduces the planning iteration budget, and selects the configured reasoning profile when available.
  - The planning prompt requests numbered steps, assumptions, and stop criteria.
  - A terminal or empty planning result causes a fallback to the normal single-stage execution.
  - Otherwise, the original task is executed with the planning result supplied as guidance.
  - The execution stage is instructed to verify each step with current tools and system/file state.

- Configuration model
  - Provider and model controls
    - Provider identifiers include Ollama, OpenAI, OpenAI-compatible, and Azure OpenAI.
    - Endpoint, deployment, and API-version properties support provider-specific transport configuration.
    - `Model` may identify a concrete model or participate in automatic routing.
  - Runtime profiles
    - Named profiles define provider, model, context budget, output budget, sampling values, and descriptions.
    - The configuration distinguishes default, reasoning, coding, and fallback profile names.
    - Resolved profile limits and diagnostics are retained on the configuration for downstream use and metadata.
  - Reasoning and quality
    - Quality profiles are `precise`, `balanced`, and `creative`.
    - Thinking modes are `auto`, `on`, and `off`.
    - Reasoning effort supports `low`, `medium`, `high`, and `xhigh` when applicable.
    - Prompt preflight score, warning count, and critical count are passed into orchestration.
  - Runtime limits
    - Maximum iterations are configurable.
    - The orchestrator run deadline is clamped by configuration resolution to 300 through 1800 seconds.
    - The documented default max-iteration fallback is 50 when configuration cannot provide a positive value.
  - Memory and diagnostics
    - `MemoryPath` enables persistent memory.
    - Recent history injection is configurable.
    - Diagnostic traces and expected output paths can be supplied.
    - `ReturnMetadata` enables structured output containing result text and run metadata.

- Tool architecture
  - Tool discovery is provider-based rather than hard-coded solely in the orchestrator.
  - `McpBootstrap` discovers tools dynamically from configured MCP servers and applies server-level safety filters before registration.
  - `McpToolProvider` supplies tools exposed by initialized MCP servers.
  - Legacy compatibility/provider-bridge discovery adapters were removed; MCP provider composition is now the primary tool discovery path.
  - `ExternalToolProvider` supports external tool definitions.
  - `McpToolSchemaTranslator` adapts MCP schemas into the internal tool model.
  - `ToolPolicy` provides policy controls around tool availability and execution boundaries.

- Execution and safety boundaries
  - PowerShell execution is separated behind `PowerShellToolExecutor` and bridge implementations.
  - `Execution/PowerShellBridge.cs` and its partial files handle compatibility execution paths and argument normalization when a provider surface still routes through that layer.
  - `Execution/ExecutionSecurity.cs`, `Execution/AdvancedHardening.cs`, and `Execution/ExecutionArchitecture.cs` represent execution-security and hardening concerns.
  - `Execution/AsyncExecution.cs` and `Execution/Reliability.cs` support bounded asynchronous execution and reliability behavior.
  - Shell-capable tool surfaces remain subject to executable allowlists, working-directory authorization, timeout bounds, and output caps when the provider exposes them.
  - Fetch operations are controlled by an allowed-host list; an empty list blocks external fetch requests.
  - Destructive operations require the configured confirmation state.
  - Signed-file behavior is controlled by `ignore`, `warn`, or `require` policy values.
  - Meta-tools are disabled by default to prevent recursive orchestration and nested assistant loops.
  - Expected output-path configuration can constrain where `WRITE-FILE` is permitted to write.

- Orchestrator responsibilities
  - `AgentOrchestrator` is split into focused partial files rather than one monolithic implementation.
  - Run-loop files cover iteration, control flow, tool flow, tool execution, post-processing, helpers, and decision repair.
  - Supporting files cover reasoning, prompt heuristics, path inference, finalization, decision validation, resilience, state, utilities, and weather routing.
  - `RunBudget` and `OrchestratorStateModel` represent run limits and state tracking.
  - Tool-loop guards protect against repeated or non-progressing calls.
  - Decision validation handles structured model decisions and repair behavior.
  - Finalization normalizes and returns the selected output contract.
  - Resilience features include retry tiers, fallback behavior, iteration-limit handling, strict runtime-mode budgets, cancellation budgets, and terminal-failure detection.
  - The project README highlights runtime safeguards such as strict budgeting and Markdown heading de-duplication.

- Prompt and policy pipeline
  - Prompt sections separate system instructions, goal context, policy material, and other reusable context.
  - Prompt policy establishes behavioral constraints and output expectations.
  - Prompt builders incorporate configuration and runtime context into the LLM request.
  - Heuristic scoring and routing can use prompt complexity and evidence patterns to inform model or profile selection.
  - Memory can contribute recent run-history context when enabled.

- MCP and OAuth architecture
  - MCP is modeled as an independent subsystem rather than as an LLM provider setting.
  - MCP configuration is validated before provider discovery and client construction.
  - Bootstrap produces MCP providers and, when available, an MCP executor.
  - The tool-wrapper layer can compose MCP execution with the PowerShell executor through `McpCompositeToolExecutor`.
  - MCP lifecycle management is asynchronous and owned by the core run path.
  - OAuth-related classes separate identity, authentication challenge, OAuth construction, and session management responsibilities.
  - Redaction is represented explicitly in the MCP layer for handling sensitive protocol data.
  - The project contains dedicated MCP configuration, lifecycle, redaction, and OAuth integration tests.

- Observability and UI integration
  - `Execution/Observability.cs` and `Execution/OrchestratorObservability.cs` provide execution and orchestration observability components.
  - UI observability safety is separated in `UI/ObservabilitySafety.cs`.
  - UI contracts and view models are separated from runtime services.
  - `UI/PowerShellUiRuntimeService.cs` integrates UI execution with the runtime.
  - `UI/StateConcurrency.cs` addresses UI state concurrency.
  - `UI/Accessibility.cs` and the accessibility tests provide UI accessibility coverage.
  - The project README documents stdout parsing fallback that preserves embedded answer Markdown while filtering runtime status noise.

- Extension points
  - Add or replace an LLM transport through `ILlmClient` and the client factory.
  - Add tool sources through `IToolProvider` and register them in configuration.
  - Add execution backends through `IToolExecutor`.
  - Add or modify provider-backed PowerShell execution surfaces through the bridge/provider layers.
  - Add MCP server integrations through MCP configuration, identity, bootstrap, provider, and executor components.
  - Add routing or evidence behavior through the heuristics pipeline and scoring components.
  - Add mode-specific prompting through prompt sections, policy, and builder components.
  - Extend UI behavior through the UI contracts, view models, and runtime service boundaries.

- Test coverage map
  - Core and orchestration tests cover agent execution, state models, chat-mode orchestration, cancellation, budgets, retries, and final behavior.
  - LLM tests cover clients and transport behavior.
  - Tool tests cover wrappers, policies, provider integration boundaries, and reliability.
  - MCP tests cover configuration, lifecycle, schema registry, redaction, and OAuth integration.
  - Heuristic and memory tests cover scoring, routing evidence, and learning behavior.
  - UI tests cover foundation contracts, preflight, state concurrency, accessibility, and observability safety.
  - Weather routing tests cover the specialized weather path.

- Operational summary
  - The architecture is a layered, provider-driven agent runtime.
  - `AgentCore` composes configuration, providers, executors, memory, LLM transport, and orchestration.
  - `AgentOrchestrator` owns the iterative decision process and resilience controls.
  - Registries and providers decouple tool discovery from execution.
  - Separate executors isolate PowerShell, MCP, and external-process concerns.
  - Configuration and policy objects make safety, routing, runtime budgets, output contracts, and resilience explicit.
  - Tests are organized around the major boundaries, including MCP/OAuth and UI integration.

---

Tech agent completed.
## Summary

In this code, `allowedPathRoots` is an authorization boundary for write tools, not a blanket grant of filesystem write access. The policy checks that every supplied target path resolves within a configured root. It does not itself perform the write or override operating-system permissions.

The core logic is in `src/TechToolbox.Agent/Registry/ToolPolicy.cs`; the orchestrator calls it from `AgentOrchestrator.ToolPolicy.cs`, and destructive approvals are enforced again by the tool execution layer.

## Write-tool policies

`BuildPolicies()` registers these write-capable tools as mutations with `MutationType.Update` and `EnforcePath: true`:

- `mcp.filesystem.write_file` and `mcp.filesystem.append_file`: require `path` and `content`. Their allowed arguments include `createDirectories`, `createIfMissing`, `dryRun`, `encoding`, `lineEnding`, and `truncateFirst`.
- `mcp.filesystem.replace_in_file`: requires `path`, `oldText`, and `newText`; accepts `replaceAll`, `dryRun`, and `expectedReplacements` as well.
- `mcp.filesystem.edit_file`: requires `path` and `edits`; accepts `dryRun` as well.

All four policies have `RequiresAuthorization: true`, `RequiresConfirmation: false`, a 16,000-character argument limit, and a 20-second policy timeout. The explicit approval behavior comes from their destructive-tool classification and approval-token checks, not the `RequiresConfirmation` property.

## Authorization sequence

1. **The orchestrator builds the request.** `TryAuthorizeToolPolicy()` parses the tool arguments, determines destructive status with `Safety.IsDestructive(toolName)`, resolves workspace context from configured trusted roots, and supplies `_allowedPathRoots` to `ToolPolicyRegistry.Authorize()`.
2. **The write operation is classified as destructive.** `Safety.IsDestructive()` explicitly lists the filesystem write, append, replace, and edit tools (and their uppercase aliases). The orchestrator may ask its host approval callback for approval when no token is present; if approved, it mints a token and injects it into the arguments.
3. **The policy validates the request.** `Authorize()` rejects unknown tools, unexpected or missing arguments, oversized arguments, disallowed execution modes, missing required workspace authorization context, and invalid paths. For destructive requests, it first validates the supplied approval token without consuming it.
4. **Path containment is checked.** Since each write policy has `EnforcePath: true`, `ValidatePaths()` extracts the path arguments and rejects the request if there is no usable candidate path, no configured root, or any candidate falls outside all roots. A rejection is returned as `PATH_NOT_ALLOWED`.
5. **The orchestrator rechecks before execution.** `ExecuteToolAsync()` checks authorization before proceeding and again immediately before handing arguments to the tool executor. For `replace_in_file`, it also rechecks before its file preflight. That preflight reads the target and requires an existing file and an exact `oldText` match; without `replaceAll`, multiple matches block execution.
6. **The execution layer consumes destructive approval.** The MCP executor validates the token with `consumeToken: true` before invoking the remote tool. The wrapper also consumes it for delegate-based execution. The tests cover replay rejection after token consumption. Thus, in the normal orchestrator flow, authorization checks can validate the token before execution, while the executor consumes it for the actual call.

## Exact path boundary behavior

`TrustedPathRoots.Canonicalize()` trims and fully resolves configured roots, deduplicates and sorts them using platform-appropriate case comparison, and rejects invalid roots and roots that traverse reparse points. `IsCandidateAllowed()` fully resolves each candidate against `Environment.CurrentDirectory` (the code comment says this matches the filesystem executor's base for relative arguments). It then allows an exact root match or a path whose next character after the root is a directory separator. This separator check prevents a sibling such as `C:\repo-other` from matching a root of `C:\repo`.

Candidate paths are also rejected for certain invalid or unsafe forms, including NUL characters, non-fully-qualified rooted paths, and reparse-point traversal. A candidate need not already exist to pass this policy check: the code checks reparse points when paths exist but does not require the target file or directory to exist. Whether parent directories are created is governed separately by the tool's execution behavior and its creation arguments.

The configured roots, rather than `WorkspaceRoot` or the candidate path itself, determine containment. Tests explicitly cover multiple roots, traversal, missing trusted roots, symlink/reparse-point traversal, and a candidate outside the configured root. They also show that an empty `content` string is accepted by the policy for `write_file`.

## What authorization does not guarantee

- A path under an allowed root passes this policy check; that alone does not guarantee the host process or remote filesystem can write there.
- The policy does not establish that directories exist or that creation flags are enabled.
- `ToolPolicyRegistry.Authorize()` validates destructive tokens without consuming them. Consumption is an execution-layer check, so calling the registry method alone is not equivalent to running the complete orchestrated tool flow.
- `AgentOrchestrator.ToolPolicy.cs` has an observe-mode bypass for a tool with no registered policy. That is separate from the registered write-tool policies described above; enforce mode is intended to reject missing policy coverage.

## Bottom line

A write is authorized by the application when the tool has a registered
path-enforcing mutation policy, its arguments pass validation, every target
resolves within one of the configured `allowedPathRoots`, and the destructive
approval token passes the checks required by the execution path. Actual success
still depends on the executor and underlying filesystem permissions.
