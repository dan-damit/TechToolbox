## Qwen2.5-7B with RAG and a Recommendation LoRA Adapter

### Architecture

- Qwen/Qwen2.5-7B-Instruct remains the reasoning core. It interprets the request, applies its learned language and reasoning capability, and produces the response.
- Retrieval-augmented generation is designed to supply bounded, source-grounded context at prompt construction time. The repository defines retrieval, indexing, query/reranking, context-packing, and prompt-composition contracts; retrieved material is explicitly untrusted evidence and cannot override policy or safety instructions. Empty, disabled, failed, or timed-out retrieval contributes no context.
- A small LoRA adapter changes task behavior without replacing the base model. The recommendation micro-pass examples focus on recommendation-domain decisions and orchestration behavior, such as tool selection, response contracts, observed-data grounding, and handling blockers. This complements retrieval: the adapter guides how to respond, while retrieved context supplies facts that should not be memorized in the adapter.

### Project workflow and evidence

- Dataset builder scripts generate localized recommendation micro-pass examples. The pass-2 builder creates deterministic user/assistant message examples for cases including authorization stops, a single timeout retry, rate limiting, partial or empty results, and mixed outcomes.
- The training artifacts include separate recommendation micro train and validation JSONL files. The LoRA training workflow accepts these files, validates their records, and supports dry-run checks; its driver exposes explicit limits for epochs, sequence length, batch/accumulation, learning rate, and adapter rank. The project guidance calls for a bounded, behavior-focused run rather than factual memorization.
- Evaluation is against generated decision-pack artifacts, not a general measure of raw language-model quality. In `ModelTraining/decision_eval_report_extended_recommendation_micro_pass3.json`, the same Qwen2.5-7B base scored 3 overall passes out of 24; the pass-3 adapter scored 5 out of 24. Both had 24/24 JSON-valid and schema-valid outputs. This is a modest, task-pack-specific improvement, not evidence that every behavior improved or that the combined RAG-plus-adapter runtime achieved that score.

### Why combine them

A plain 7B model must rely on its stored training knowledge and generic learned behavior. That leaves it without newly retrieved project context and without the recommendation-specific behavior tuning represented by the adapter examples. RAG can ground an answer in relevant, current source material; LoRA can make the model more consistent in applying recommendation-domain patterns and instruction/decision rules. Together, these address different limitations while retaining the smaller base model as the reasoning engine. This can improve relevance and reduce unsupported claims when retrieval supplies good evidence, but neither retrieval quality nor a pass-pack score guarantees zero hallucinations or universal instruction-following gains.

### Implementation status and qualification

The repository contains substantial RAG contracts, pipeline components, prompt integration seams, and deterministic tests, but the project overview states retrieval is disabled by default. The retrieval configuration is contract-only and does not itself execute retrieval. Therefore, describe grounding and fresh context as the architecture's intended benefit, not as a demonstrated live RAG-plus-LoRA evaluation result. The reported 3-to-5 pass change is adapter evaluation evidence; retrieval quality is a separate gate and the supplied report does not establish a measured combined-stack gain.

### Conclusion

RAG supplies bounded external evidence while the recommendation micro-pass LoRA adapts response behavior, allowing Qwen2.5-7B to act more like a domain-specialized, grounded system without requiring a much larger base model. The project artifacts show a small improvement on the evaluated decision pack; the combined benefit remains conditional on enabling and validating retrieval in the runtime.

---

## Short answer

Yes — in this codebase they are separate settings, so they can both be active at the same time, but they are used for different jobs.

- The main LLM model is resolved from `-Model` / `settings.agent.model` in `Invoke-TechAgent.ps1:878-926`.
- Retrieval is a separate config object, with its own `Enabled` and `Model` fields, in `AgentRetrievalConfiguration.cs:7-18`.

## What wins for the actual answer model?

`-Model` is the effective generation model when supplied. The script does:

- `$resolvedModel = $Model`
- then only falls back to config if `-Model` is empty

That behavior is in `Invoke-TechAgent.ps1:900-926`.

So if you call:

- `-Model qwen3.8:27b`

then the run’s main model is `qwen3.8:27b` for the agent response generation.

## What does retrieval use?

Retrieval is checked separately in the orchestrator before the prompt is built:

- it evaluates `_retrievalConfiguration.Enabled`
- then calls `RetrieveAsync(...)`
- and injects the retrieved context into the prompt

See `AgentOrchestrator.RunLoop.cs:11-31`.

The retrieval config explicitly says the model is separate from the provider/model used for the main LLM:

> “Provider endpoints, credentials, and transport options belong to LLM configuration instead.”  
> from `AgentRetrievalConfiguration.cs:1-8`

## So in your example

If:

- retrieval is enabled with a local 7b custom retrieval model
- and the call site passes `-Model qwen3.8:27b`

then:

- the retrieval path may use the local 7b retrieval model for retrieval context
- the agent’s actual generation still uses `qwen3.8:27b`

So the answer is: yes, both can participate, but they are not competing for the same slot — they are used in different phases.
