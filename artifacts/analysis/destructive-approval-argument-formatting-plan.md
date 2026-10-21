# Destructive Approval Argument Formatting: Analysis and Implementation Plan

## Goal

Improve the console preview shown when a destructive action is awaiting approval. Keep the file path and other high-value context visible, while showing more of the available arguments in a readable, bounded, and privacy-conscious format. This is an analysis and implementation plan; no source code changes are proposed as part of this document.

## Current implementation

The approval console formatting is in `Public/AI/Invoke-TechAgent.ps1`, in the `$processAgentStdOutLine` script block that handles the `__TT_APPROVAL_REQUEST__:` prefix.

The current flow:

1. Parses the request JSON and extracts `toolName` and `arguments`.
2. Renders argument values as strings, then truncates each displayed value to 150 characters.
3. Excludes keys ranked as sensitive (including token, API key, secret, and password patterns) and replaces other sensitive values with `<redacted>` when applicable.
4. Treats known large/noisy fields such as `content`, `edits`, `patch`, `diff`, `body`, `script`, `payload`, `json`, and `data` as omitted. Values over twice the per-value limit are also treated as noisy.
5. Sorts remaining descriptors by key priority: path-like keys first, then operational keys, then other keys. It selects at most five non-noisy fields and reports a count of omitted fields.
6. Prints the tool name, an `Arguments:` section, and the approval prompt. A parse failure logs a warning and may show a truncated raw payload.

The current five-field cap and noisy-field omission are likely why useful context beyond the path is absent. Some non-sensitive arguments can also be omitted simply because they rank below the selected fields. The formatter is inline in the script and is used when processing child stdout during both the normal asynchronous read loop and the final drain.

A repository search for the approval-specific symbols found matches in this script only. That search is not a complete test inventory, so related coverage should be confirmed before implementation.

## Recommended behavior

### 1. Show a bounded, useful argument summary

- Keep paths and destinations prominent, but include a larger configurable or clearly named maximum number of argument entries instead of the current fixed limit of five.
- Consider showing all safe scalar arguments up to a total display budget, rather than dropping safe fields solely because they are beyond a small count limit.
- Keep explicit omitted-field counts and make clear when content is omitted or truncated. Do not imply that the preview displays every argument when it does not.
- Preserve deterministic ordering: path/target fields first, then operation/action/mode/command and other meaningful parameters, then remaining safe fields. Use a stable key-name tie-breaker.

### 2. Render values by shape and risk

- Scalars: show quoted or clearly delimited values; escape newlines, tabs, and terminal control characters so one argument cannot spoof extra console lines or headings.
- Arrays and objects: show a compact, bounded summary (for example, item/property counts and a short preview), with total length or truncation indicators where available.
- Large content fields: indicate that the field exists and show an approximate size or item count instead of silently omitting it. Do not print full file contents, scripts, patches, or payloads in the approval prompt.
- Continue to enforce per-value and overall output limits to avoid overwhelming the console.

### 3. Preserve redaction and approval semantics

- Keep sensitive-key detection and redaction in the formatting path. Review nested object/array handling so secrets are not exposed just because they are inside a container.
- Never include approval tokens, credentials, API keys, passwords, or secret values in the preview or raw-payload fallback.
- Do not change the authorization decision, approval cache behavior, request parsing contract, or the rule that approval is explicit and single-use. Formatting must remain informational only.
- Reconsider whether displaying a raw serialized payload on parse failure is safe. Prefer a generic parse-failure summary or a sanitized, bounded representation rather than dumping raw JSON that could contain secrets or control characters.

### 4. Improve presentation

Use clear labels and line wrapping that make the tool and arguments easy to scan. Example only:

```text
=== Destructive Action Approval Required ===
Tool: mcp.filesystem.edit_file
Arguments:
  - path: "C:\\work\\settings.json"
  - operation: "replace"
  - edits: [omitted; 2 entries, 1,240 chars]
  - createIfMissing: false
  - encoding: "utf-8"
  ... 2 additional safe argument(s) omitted by display limit
```

The example is illustrative, not a claim about the exact request schema. Keep the existing approval instructions and denial-by-default behavior intact.

## Implementation plan

1. **Confirm contract and coverage.** Inspect the approval request DTO/serialization and existing PowerShell tests or test conventions. Identify real argument shapes and whether values arrive as `PSCustomObject`, arrays, or primitives.
2. **Set display requirements.** Agree on a maximum number of entries, maximum characters per entry, total preview budget, handling for nested values, and the exact redaction policy. Prefer named constants near the current preview-limit settings.
3. **Refine rendering helpers.** Extend the existing raw-value renderer and truncator, or add small focused helpers, to safely render scalars, arrays, and objects. Escape console control characters, cap recursion/depth and output size, and preserve type/size cues when truncating.
4. **Adjust descriptor selection.** Retain priority ordering and sensitive-key filtering. Include more safe fields within a total budget and summarize omitted noisy/large fields instead of losing all context about them. Avoid making a count limit the only reason a useful argument disappears.
5. **Harden fallback handling.** Ensure parse-failure output cannot reveal raw secrets or inject misleading console lines. Keep diagnostic logging appropriately bounded and avoid logging full sensitive payloads.
6. **Keep output behavior consistent.** The same formatter should be called from both stdout processing paths. Keep approval/denial prompts and decision processing unchanged.
7. **Add tests.** Cover path-first ordering, more than five safe fields, key-based and nested secret redaction, long strings, large payloads, arrays/objects, null and boolean values, empty arguments, malformed JSON, control-character escaping, total-budget enforcement, and deterministic output. Add a regression test that formatting does not alter the approval decision.
8. **Validate in the repository.** Run the relevant PowerShell lint/tests and any existing integration tests for approval request handling. Manually inspect representative console output in interactive and redirected/non-interactive modes. Confirm that the approval prompt still denies by default when interactive approval is unavailable.

## Risks and safeguards

- **Secret leakage:** nested values and malformed-payload fallback are the highest-risk paths. Test redaction before expanding displayed data.
- **Console spoofing:** escape newlines and terminal control characters in keys and values.
- **Unbounded output:** enforce both per-value and total-preview limits, including for deeply nested structures.
- **Misleading approval:** label the output as a preview and explicitly identify omitted content/fields; do not imply that summaries are full representations.
- **Scope creep:** keep changes limited to the presentation of the pending approval request. Do not alter execution, authorization, or safety policy.

## Validation checklist

- Path/file location remains visible and prioritized.
- More relevant safe arguments are shown than under the current five-entry cap.
- Secrets remain redacted, including inside nested values.
- Large content is summarized without dumping its contents.
- Output is bounded, stable, and resistant to multiline/control-character injection.
- Omitted fields and truncated values are clearly disclosed.
- Parse-error handling does not print an unsanitized payload.
- Approval decision and denial behavior are unchanged.
- Both stdout handling paths use identical formatting.
