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

- **Alias Updates**
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

### **Fixed**
- Agent orchestration reliability:
  - blocked premature completion when a model returns a progress-style `finalAnswer` that indicates work is still in progress
  - recovered from schema-invalid progress updates (`needsTool=false` with empty `finalAnswer` and coherent progress `reason`) by steering the loop forward instead of surfacing misleading invalid-JSON terminal failures
  - added regression coverage for both failure patterns in `src\TechToolbox.Agent.Tests\AgentOrchestratorTests.cs`
- Removed the `ITA` wrapper from module exports. Operators now call `Invoke-TechAgent` directly as the single agent entry point.
- Refactored TechToolbox home initialization to default runtime data paths to module root and removed first-import home staging/copy behavior. Runtime folders (`LogsAndExports/Logs`, `LogsAndExports/Exports`) are now ensured in-place unless `TT_Home` is explicitly set.

### **Documentation**
- Updated `Public\AI\README.md` with:
  - default `Invoke-TechAgent` prompt-source behavior
  - `Use-TechAgentTaskTemplate` command usage and workflow
- Updated top-level `README.md` to reflect template-driven TechAgent prompt staging.
- Updated `COMMANDS.md` to include `Use-TechAgentTaskTemplate` in AI-assisted workflows.

### **0.6.0 — Cross‑Platform Stabilization**
- Path normalization across Windows/macOS/Linux.
- Worker compatibility improvements.
- Enhanced environment detection.

### **0.7.0 — Worker & Remoting Enhancements**
- Unified worker orchestration.
- Credential flow improvements.
- Remote execution reliability upgrades.

---
