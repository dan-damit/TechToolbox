# TechAgent architecture breakdown (source-grounded current snapshot)

This document is a current, source-grounded summary of the implementation under `src/TechToolbox.Agent` as reflected in the repository code inspected for this review. It is intentionally scoped to what is evidenced in the code and avoids treating deployment assumptions, host wiring, or UI runtime behavior as guaranteed project features unless they appear in the inspected implementation.

## Scope and method

This is an architecture overview, not an exhaustive map of every runtime deployment setting or every possible provider configuration. The current implementation indicates a layered design in which:

- `AgentCore` composes the runtime,
- configuration objects encode policy, routing, and runtime limits,
- tool providers and registries separate discovery from execution,
- the orchestrator owns the iterative decision loop,
- MCP and PowerShell execution are separated behind provider-specific executors,
- memory and retrieval are optional context sources,
- safety and authorization are enforced through policy and execution-time checks.

Where evidence is incomplete or runtime-specific, the text below states that explicitly.

## High-level architecture

### Composition root and orchestration entry

The observed composition path starts in `AgentCore`. Current code shows it constructing runtime configuration, validating inputs, resolving optional memory, choosing retrieval providers, creating the LLM client, and then handing the assembled runtime to `AgentOrchestrator` for the run loop.

The source also shows `AgentCore` handling several runtime concerns that are relevant to architecture:

- parameter-based overloads are converted into `AgentConfiguration`,
- runtime-profile and resilience JSON payloads are parsed with defaults when absent or invalid,
- MCP configuration is validated before provider discovery,
- tool providers are combined, including MCP-backed providers,
- optional memory is initialized when `MemoryPath` is configured,
- the LLM client is created through `LlmClientFactory`,
- `AgentOrchestrator` is invoked with tool registry, LLM client, memory, safety settings, iteration limits, and output settings.

This suggests a single composition root with a clear dependency boundary, rather than a monolithic orchestration implementation.

### Configuration and policy model

`AgentConfiguration` is the central runtime object. The current code exposes configuration for:

- model/provider selection,
- execution mode and output contract,
- quality and reasoning behavior,
- runtime profiles,
- resilience and retry behavior,
- tool provider registration,
- memory and retrieval settings,
- fetch and path authorization boundaries,
- shell execution policy,
- safety and signed-file settings.

`AgentMode.cs` and `AgentModeDetector.cs` define mode semantics, while `McpConfiguration` and `McpOAuthConfiguration` hold MCP and OAuth-specific settings. The architecture therefore treats policy as explicit configuration rather than hidden behavior in the orchestrator.

### Prompt construction and prompt policy

The prompt pipeline is split into reusable prompt sections, prompt policies, and builders. The code indicates a structured separation between:

- system instructions,
- goal/context payloads,
- policy and safety framing,
- retrieval evidence,
- memory/history context,
- tool instructions and output expectations.

This is consistent with a design where the LLM call is not a raw dump of the task but a policy-shaped, bounded prompt.

### LLM abstraction and provider selection

The LLM layer is separated behind `ILlmClient` and `LlmClientFactory`. The current source shows factory logic that:

- normalizes provider aliases,
- checks supported providers and model capabilities,
- chooses runtime profiles for the prompt,
- creates provider-specific clients, including OpenAI-compatible transport handling,
- rejects unsupported provider/model combinations.

The code suggests that provider selection and runtime-profile selection are explicit concerns, rather than hidden within the orchestrator.

## Primary request-to-result flow

The current observed flow is:

1. Caller invokes `AgentCore.RunAgent` / `RunAgentAsync`.
2. Input validation rejects empty prompts or invalid configuration.
3. Parameter overloads map to `AgentConfiguration`.
4. Retrieval, resilience, and runtime-profile defaults are resolved.
5. MCP configuration validation occurs before tool discovery.
6. `McpBootstrap.InitializeAsync` creates the MCP runtime when configured.
7. Tool providers are discovered and composed.
8. `ToolRegistry.BuildToolRegistry` produces the tool specification registry.
9. Meta-tools are filtered unless allowed by configuration.
10. `ToolWrapper.BuildTools` creates callable delegates with execution policy inputs.
11. An optional `MemoryStore` is initialized if configured.
12. `LlmClientFactory` creates the LLM client.
13. `AgentOrchestrator` executes the iteration loop and returns an `AgentResult`.
14. MCP resources are disposed through the runtime lifecyle.

The design is therefore composition-first and policy-aware. A request is not just “prompt the model”; it is assembled from configuration, tool registry, memory, safety state, and active providers before the decision loop begins.

## Execution modes

The current source indicates these primary execution modes:

- `execute`: the normal tool-enabled run path.
- `plan`: a planning-oriented path that produces a plan rather than normal execution behavior.
- `analyze`: analysis-oriented execution under orchestrator and prompt policy.
- output contracts include Markdown, plain text, and JSON.

The implementation also includes a two-stage planner/executor path, but the code indicates this is gated by provider and resilience settings rather than universally active. The current source shows that the planner path is enabled only when the configured resilience policy allows it, the provider is Ollama, and execution mode is `execute`.

## Configuration model

The architecture is driven by explicit configuration objects rather than scattered ad hoc state.

### Provider and model controls

The code supports provider identifiers including Ollama, OpenAI, OpenAI-compatible, and Azure OpenAI. Endpoint, deployment, API version, and model selection are all represented in configuration and resolved through the client factory.

### Runtime profiles

The runtime profile model distinguishes default, reasoning, coding, and other profiles. The code also includes logic that resolves profile-limited values and retains the effective profile information for downstream use.

### Safety and policy controls

The current implementation exposes policy settings for:

- allowed fetch hosts,
- allowed path roots,
- destructive-tool confirmation,
- signed-file handling,
- shell allowlists,
- working-directory constraints,
- output-path restrictions,
- confirm/authorize gates for destructive operations.

This is a meaningful part of the architecture and should be treated as a first-class design boundary, not a secondary concern.

## Tool architecture

The current architecture separates tool discovery and execution.

### Providers and registry

The code shows `IToolProvider` and `ToolRegistry`. The observed model is provider-driven rather than hard-coded within the orchestrator. MCP bootstrap discovers server tools and registers provider-backed tool definitions. Generic, external, PowerShell, and MCP providers all participate through the provider abstraction.

The architecture therefore separates:

- what a tool is (`ToolRegistry` / tool schema),
- where it comes from (provider/discovery layer),
- how it executes (`IToolExecutor`),
- how it is authorized and constrained (policy layer).

### Execution backends

The execution layer currently includes distinct handling for PowerShell and MCP tool execution. The source shows dedicated executors and bridging behavior, with policy checks being applied before the actual tool call. The architecture is therefore not a single “generic shell runner”; it is a layered execution model with provider-specific execution semantics.

### Security and authorization boundaries

The code is specifically concerned with path authorization, destructive-tool classification, confirmation, and execution enforcement. The current implementation treats write tools as mutation operations that require path validation and approval under configured authorization conditions. The architecture is explicit that authorization is not the same as raw filesystem permission; it is an application-level gate layered above the underlying OS and executor behavior.

## Retrieval, memory, heuristics, and LLM routing

The current source shows retrieval as a separate context-preparation layer. `AgentCore` can resolve a retrieval provider based on configuration and pass it to the orchestrator. The retrieval boundary enforces timeouts, cancellation handling, payload caps, and normalization before content reaches the prompt.

The implementation indicates the following design intent:

- retrieval is separate from transport,
- retrieval content is untrusted evidence and not policy,
- provider selection is explicit,
- payloads are bounded,
- provider status and candidate counts are tracked in metadata.

`MemoryStore` is optional and persists structured memory state, history, and indexed entries. The code indicates bounded history windows, persistence safeguards, and privacy-aware handling. The architecture treats memory as contextual evidence that can influence prompting, but not as a higher-authority source than current user intent or verified current tool results.

`HeuristicScoringEngine` and the routing pipeline are advisory. The current implementation makes clear that safety gates, authorization checks, and execution policy outrank heuristics and routing recommendations. `LlmClientFactory` also includes prompt-complexity heuristics and runtime-profile selection, further separating “how to route or choose a model” from “whether execution is allowed.”

This is an important architectural boundary: heuristics influence decisions, but they do not replace safety or authorization.

## MCP and OAuth architecture

The project treats MCP as a first-class subsystem, not merely an LLM setting. Current code and tests cover:

- MCP configuration,
- bootstrap and lifecycle,
- tool discovery and schema translation,
- server identities,
- OAuth challenge/session handling,
- redaction behaviors,
- executor composition.

The architecture separates MCP identity, auth challenge generation, session management, and tool execution. This is a materially different design from a simple “tool names in configuration” model.

One important caution: the implementation appears to be more mature in MCP/tool policy than in UI/runtime host integration. The inspected code evidence supports MCP and orchestration behavior clearly; it does not make equivalent claims about broader deployment or host UI surfaces unless those code paths are actually present.

## Observability and UI/runtime concerns

The code shows observability components for execution traces, redaction, and bounded event reporting. Observability is treated as metadata and diagnostics, not as a permission boundary. The current implementation additionally includes retry, iteration-limit, and status metadata in the result structure.

The inspected `src/TechToolbox.Agent` tree does not show a distinct UI runtime layer comparable to the agent runtime itself. The source evidence supports:

- console iteration signals,
- execution and orchestrator observability,
- redacted trace behavior,
- metadata reporting.

It does not support a broad claim that the project owns GUI, accessibility, or host UI runtime behavior beyond the code actually present.

## Extension points

The current implementation suggests a few natural extension seams:

- Add or replace an LLM provider through `ILlmClient` and the factory.
- Add new tool sources via `IToolProvider` and register them in the runtime configuration.
- Add new execution backends through `IToolExecutor`.
- Add new MCP integrations through MCP bootstrap, schema translation, lifecycle, and auth configuration.
- Extend retrieval through `IRetrievalContextProvider` and bounded retrieval-context logic.
- Extend memory and learning through `MemoryStore` and `MemoryLearner` while preserving provenance and privacy boundaries.
- Extend heuristics and routing behavior without allowing them to override safety or authorization.

These extension points are structurally visible in the code, but the exact host integration points for runtime deployment remain outside the inspected source.

## Test coverage map

The repository includes tests covering major boundaries. Based on the current source tree, these are the most relevant categories:

- composition and orchestration: `AgentCoreTests`, `AgentOrchestratorTests`, `OrchestratorStateModelTests`
- cancellation, scheduling, retries, and hardening: orchestration reliability and hardening tests
- prompt and retrieval: prompt policy and retrieval provider tests
- MCP and OAuth: lifecycle, configuration, redaction, schema, and OAuth integration tests
- memory and heuristics: memory and scoring tests
- LLM client behavior: LLM transport/client tests
- safety and policy: tool-policy and authorization tests

This indicates broad boundary coverage, but it does not prove complete coverage for every deployment environment or every provider variant.

## Operational summary

The current implementation reflects a layered agent runtime with a clear separation of responsibilities:

- `AgentCore` composes configuration, providers, LLM client, memory, and orchestration state.
- `AgentOrchestrator` owns the bounded iterative decision loop and tool policy checks.
- tool discovery and execution are separated from policy and authorization.
- MCP is a first-class subsystem with its own lifecycle and auth concerns.
- retrieval and memory are optional context sources rather than execution authority.
- heuristics are advisory and never a substitute for safety gates and policy enforcement.

The strongest evidence in the current code points to a provider-driven, policy-aware runtime with explicit safety boundaries. The weakest area in the code evidence is broad host/UI/runtime assumptions, which should be treated cautiously unless directly confirmed by the inspected implementation.

## Bottom line

The current code supports a defensible architectural description of a layered, provider-driven agent runtime with explicit configuration, tool policy, retrieval, memory, and MCP boundaries. It does not support a blanket claim that every deployment, host integration, or UI concern is implemented in this project unless that behavior is directly visible in the inspected source.
