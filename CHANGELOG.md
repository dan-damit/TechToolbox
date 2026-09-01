# CHANGELOG.md

# TechToolbox Changelog  
All notable changes to this project will be documented in this file.  
This project follows the **Milestone‑Driven Semantic Versioning** model described in `VERSIONING.md`.

---

## [0.5.0] — 2026‑06‑10  
### **Milestone: AI & Metadata Integration**

This release marks a major architectural evolution of TechToolbox.  
The framework now includes a full AI‑assisted development pipeline, deep metadata export, and a stabilized loader/config system. This milestone establishes TechToolbox as a true operator framework rather than a collection of scripts.

### **Added**
- **AI Agent Bridge**
  - `Invoke-TechAgent` orchestrates structured AI workflows.
  - `Invoke-CodeAssistant` and `Invoke-CodeAssistantFolder` provide local AI‑assisted code analysis.
  - `Invoke-CodeAssistantWrapper` standardizes AI task execution patterns.
  - New packaged `TechToolbox.Agent` C# runtime for agent orchestration.
  - New `AI/Tasks/` library of standardized prompt templates for common tasks.

- **Full Metadata Export System**
  - `Export-ToolboxFunctions` now exports:
    - Function names, aliases, and categories  
    - Parameter metadata (types, mandatory flags, defaults, aliases, allowed values)  
    - Full help text (synopsis, description, examples, notes)  
    - Safety classification flags  
    - Module version and source context  
  - Output is structured JSON for AI consumption.

- **Documentation Enhancements**
  - New `commands.md` catalog with categorized command listings.
  - New `VERSIONING.md` defining the Milestone‑Driven SemVer model.
  - Updated README with architecture diagrams, quick start, and developer guide.

### **Improved**
- **Loader Architecture**
  - More deterministic bootstrap sequence.
  - Cleaner separation between module root and operational home.
  - Improved path token resolution (`%TT_ModuleRoot%`, `%TT_Home%`, `%TT_LogsRoot%`, `%TT_ExportsRoot%`).
  - Private helpers load earlier and more predictably.

- **Configuration System**
  - Deep merge between `config.json` and `config.secrets.json`.
  - Environment variable overrides (`TT_ConfigSecretsPath`, `TT_DisableConfigSecretsMerge`).
  - More stable caching and lazy initialization.

- **Logging Subsystem**
  - Lazy initialization on first log call.
  - Respect for config‑driven log levels and file formats.
  - Cleaner console output.

- **Developer Experience**
  - Standardized function template.
  - Improved ScriptAnalyzer compatibility.
  - Better WhatIf support across destructive commands.

- **Alias Updates (deprecated)**
  - Added documentation for `ITA` (the `Invoke-TechAgent` convenience wrapper in the module).
  - Fixed `ITA` argument forwarding so `-ConfirmDestructive` and other forwarded options bind as named parameters instead of being treated as positional model input.

### **Fixed**
- Path token inconsistencies in certain subsystems.
- Occasional loader re‑entry issues during module import.
- Minor help text formatting issues in several commands.
- Edge cases in config merge when secrets file is missing or malformed.

---

## [0.4.x] — Pre‑Milestone Evolution  
*(Summarized for historical context)*

### **Highlights**
- Initial loader and config system.
- Early Active Directory, Exchange Online, and Purview tooling.
- Browser cleanup and diagnostics suite.
- Worker patterns and remote execution helpers.
- First iteration of AI‑assisted workflows.
- Rapid iteration and patch‑level improvements leading up to the 0.5.0 milestone.

---

## [Unreleased]  
Latest completed enhancements:

### **Condensed Release Notes (2026-08-28)**

#### **Highlights**
- Refined TechAgent model routing: fast/default remains `phi4:14b`, while deep reasoning and coding-specialist paths now use `qwen3.8:27b`.
- Removed deprecated vision runtime profile (`vision_support` / `medgemma1.5:4b`) and repointed fallback profile to `main_reasoning`.
- Strengthened expected output path inference for script-authoring prompts, including name+directory phrasing such as "name the script file ..." and "output the file in directory ...".
- Improved run-log clarity with richer markdown diagnostics:
  - Added `## Preflight` section between prompt and output.
  - Expanded `## Postflight` with status, response length, known-failure-prefix detection, expected-output existence, and reason.
  - Added explicit recovered-success reporting (`SuccessRecovered`) when known orchestrator failure text appears but required output artifacts exist.
- Reduced postflight false positives by suppressing clarification/inability warnings when completion evidence is present (for example result headers, created-file lines, or complete PowerShell code blocks).

#### **Quality Outcome**
- TechAgent markdown logs now provide clearer operator signals for true failures vs recovered successes vs quality warnings.

### **TechAgent Runtime Reliability & Model Defaults (2026-08-26)**

#### **Improved**
- Switched TechAgent default local runtime model from `phi4-reasoning:14b` to `phi4:14b` across:
  - `Config/config.json` runtime profiles (`main_reasoning`)
  - `Public/AI/Invoke-TechAgent.ps1`
  - `Private/AI/Invoke-LocalLLM.ps1`
  - installation/help/readme examples
- Stabilized weather execution flows to reduce non-progress loops:
  - Added execute-mode weather concrete-target recognition so weather+location prompts are accepted as actionable targets.
  - Added repeated-NOAA-call forced-finalization fallback that converts successful NOAA payloads into final markdown output instead of exhausting iteration budget.

#### **Fixed**
- Hardened agent decision parsing for malformed mixed-prose model replies by:
  - extracting schema-valid JSON decision objects from embedded content
  - reducing oversized repair-prompt echo snippets that amplified invalid-JSON loops
- Reduced weather-run failures where repeated successful `GET-NOAA-FORECAST` calls previously ended with iteration-limit responses.

#### **Tests**
- Added/updated regression coverage for:
  - mixed-prose JSON decision recovery
  - weather prompt target recognition
  - repeated NOAA-call loop handling and forced finalization behavior

### **Added**
- Expanded `AI\Tasks\Templates` with a multi-scenario task template library, including:
  - C# XML docs, refactor, and bug-fix templates
  - PowerShell comment-help, about-help, refactor, bug-fix, and help-authoring templates
  - CI workflow bug-fix, release/versioning change, docs markdown generation, test authoring, security review, and scenario-analysis templates
- Added `AI\Tasks\Use-TaskTemplate.ps1` helper workflow with support for:
  - listing templates
  - category filtering (`-Category`)
  - interactive picking (`-Pick`)
  - template preview (`-Show`)
  - template open in editor (`-Open`)
  - shorthand template resolution with or without `.txt`
- Added public command `Use-TechAgentTaskTemplate` as a thin wrapper over the task-template helper so template workflows are available immediately after module import.

### **Improved**
- Standardized prompt template structure and placeholder vocabulary across the template library for consistent authoring and easier reuse.
- Updated `Invoke-TechAgent` default prompt source configuration to `AI\Tasks\CurrentTask.txt` when no `-Prompt` or `-PromptFile` is supplied.
- Hardened `AI\Tasks\Use-TaskTemplate.ps1` path resolution to derive task/template paths from module root for portability.

### **Removed**
- Removed obsolete legacy AI commands from the module:
  - `Invoke-CodeAssistant`
  - `Invoke-CodeAssistantFolder`
  - `Invoke-CodeAssistantWrapper`
- Recommended replacement workflow: `Invoke-TechAgent`.

### **Fixed**
- Agent orchestration reliability:
  - blocked premature completion when a model returns a progress-style `finalAnswer` that indicates work is still in progress
  - recovered from schema-invalid progress updates (`needsTool=false` with empty `finalAnswer` and coherent progress `reason`) by steering the loop forward instead of surfacing misleading invalid-JSON terminal failures
  - added regression coverage for both failure patterns in `src\TechToolbox.Agent\Tests\AgentOrchestratorTests.cs`
  - added READ-FILE loop guards for repeated identical calls and repeated non-progress evidence patterns across varying READ-FILE argument shapes
  - added fail-fast termination path for repeated non-progress READ-FILE loops to prevent iteration-budget exhaustion
  - added/updated regression coverage for fail-fast READ-FILE loop-guard behavior in `src\TechToolbox.Agent\Tests\AgentOrchestratorTests.cs`
- Removed the `ITA` wrapper from module exports. Operators now call `Invoke-TechAgent` directly as the single agent entry point.
- Refactored TechToolbox home initialization to default runtime data paths to module root and removed first-import home staging/copy behavior. Runtime folders (`LogsAndExports/Logs`, `LogsAndExports/Exports`) are now ensured in-place unless `TT_Home` is explicitly set.

### **Documentation**
- Updated `Public\AI\README.md` with:
  - default `Invoke-TechAgent` prompt-source behavior
  - `Use-TechAgentTaskTemplate` command usage and workflow
- Updated top-level `README.md` to reflect template-driven TechAgent prompt staging.
- Updated `COMMANDS.md` to include `Use-TechAgentTaskTemplate` in AI-assisted workflows.

### **0.6.0 — GUI & Operator Experience Refresh**
### **Milestone: Windows Operator Desktop**

This release focuses on making TechToolbox easier to operate as a day-to-day Windows automation platform rather than a command-only toolkit. The goal is to improve the human-facing workflow around diagnostics, exports, AI-assisted automation, and repeated operator tasks.

### **Added**
- Native Windows desktop experience for common operator workflows.
- Unified dashboard and orchestration surfaces for task execution.
- Better visibility into logs, exports, diagnostics, and AI activity.

### **Improved**
- Simplified UX for launching and monitoring common workflows.
- Better operator feedback during diagnostics and export tasks.
- More cohesive experience across AI-assisted execution and system operations.

### **0.7.0 — Worker & Remoting Enhancements**
- Unified worker orchestration.
- Credential flow improvements.
- Remote execution reliability upgrades.

---
