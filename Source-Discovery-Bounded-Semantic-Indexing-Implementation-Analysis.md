
## Cross-cutting security requirements

- Fail closed: missing or invalid scope means no file ingestion.
- Authorize at use: re-check on open/read; enumeration checks alone are insufficient.
- Use component-aware path containment with correct filesystem semantics.
- Use least privilege: where practical, the process account can read only intended roots.
- Treat file content as untrusted. Retrieval safety is downstream defense, not a substitute for source authorization.
- Bound every stage: traversal, reads, parsing, chunks, embedding concurrency, queues, writes, retries, and checkpoint state.
- Do not confuse document metadata or claimed source type with authorization.
- Sanitize diagnostics and avoid raw content/path leakage.
- Revalidate checkpointed paths against current policy.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Prefix check authorizes a sibling | Canonicalize and compare path components; test sibling-prefix cases. |
| Link escapes root | Skip links initially, or resolve and reauthorize targets with cycle/race safeguards. |
| Root is too broad | Require reviewed explicit roots, quotas, dry-run inventory, and least privilege. |
| Enumeration/materialization exhausts memory | Enforce quotas while walking and use bounded queues; account for writer full-input materialization. |
| Checkpoint bypasses new policy | Treat it as a hint and revalidate paths against current roots. |
| Partial scan deletes valid records | Apply tombstones only after a complete authoritative scan. |
| File changes between check and read | Reauthorize on open and use handle-based protections where possible; document residual risk. |
| Logs/metadata disclose content or paths | Minimize/sanitize metadata; avoid raw text; apply access and retention controls. |
| Config appears protective but is unwired | Verify every setting's runtime effect and test it end to end. |

## Recommended delivery order

1. Complete Phase 0 and approve scope/security contract.
2. Implement validated root configuration and authorization tests.
3. Implement bounded deterministic discovery and secure reads in dry-run/inventory mode.
4. Add provenance, extraction, and bounded chunking.
5. Connect embedding and bounded writes; address writer full-input materialization before large runs.
6. Add checkpointing and deletion semantics after defining success boundaries.
7. Complete security, quota, and failure-injection tests; roll out with narrow scope.

This order proves the filesystem boundary before content flows into embeddings and persistent storage.

## Definition of completion

The implementation is complete when roots and quotas are explicit and validated; discovery and file opening cannot escape those roots; every downstream document carries validated provenance; all stages have enforceable work bounds; partial failures and checkpoints cannot widen scope or trigger incorrect deletions; and automated tests demonstrate both authorized ingestion and denial of out-of-scope content. Existing writer and vector-store limits contribute to capacity control but do not, on their own, meet this definition.
