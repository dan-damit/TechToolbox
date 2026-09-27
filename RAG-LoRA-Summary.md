## Qwen2.5-7B: RAG and Recommendation LoRA

### Architecture

- **Reasoning core:** `Qwen/Qwen2.5-7B-Instruct` remains the base model that interprets requests and generates responses.
- **RAG for context:** The repository integrates retrieval into prompt preparation. Its configured local-memory and ripgrep backends can provide bounded workspace or memory context to ground a response in relevant source material, rather than relying only on facts encoded in model weights. RAG supplies evidence; it does not replace the model's reasoning or guarantee that retrieved evidence is complete or current.
- **LoRA for behavior:** A small adapter tunes how the base model handles recommendation micro-pass decisions. It complements retrieval: the adapter shapes task behavior, while retrieved context supplies case-specific facts.

### Training and evaluation evidence

- Recommendation micro-pass dataset builders generate localized examples, including scenarios such as authorization stops, timeout retries, rate limits, partial or empty results, and mixed outcomes. The repository contains separate train and validation JSONL artifacts: `recommendation-micro-train_split.jsonl` and `recommendation-micro-validation_split.jsonl`.
- `Train-QwenLoRA.ps1` takes those JSONL inputs and exposes bounded training controls. Its defaults include 2 epochs, sequence length 2048, batch size 2 with gradient accumulation 8, learning rate `1e-4`, and LoRA rank 16; it also supports a dry run. This is a behavior-focused adapter workflow, not a process for replacing or retraining the 7B base model.
- The generated decision-pack evaluation compares base and adapter behavior on 24 cases. In `decision_eval_report_extended_recommendation_micro_pass3.json`, overall passes increased from **3/24** for the base to **5/24** for the pass-3 adapter. Both produced **24/24 JSON-valid and schema-valid** outputs. This is a modest, pack-specific result, not a general model-quality score.

### Why the combination helps

A plain 7B model has neither newly retrieved project context nor this recommendation-specific behavior tuning. With retrieval enabled and a concrete provider configured, RAG can make responses more relevant to available evidence and reduce reliance on unsupported recollection. The localized LoRA examples can improve consistency in applying recommendation-domain instructions and decision patterns. These mechanisms address different limitations while retaining the smaller model as the reasoning core; they do not establish zero hallucinations or universal gains.

### Status and conclusion

The repository documents retrieval configuration under `settings.agent.retrieval`, and the runtime calls retrieval when enabled. Retrieval must be enabled and have a concrete provider; the orchestrator rejects an enabled configuration without one. The cited 3-to-5 pass comparison measures the adapter on a generated decision pack, not a live combined RAG-plus-LoRA run, so it does not quantify an additional RAG gain.

In conclusion, RAG plus recommendation LoRA can make Qwen2.5-7B behave more like a domain-specialized, grounded, and higher-performing system without requiring a much larger base model; the measured pass improvement is adapter-specific, and the combined runtime benefit depends on configured and validated retrieval.
