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
  - New `AI/Agent/` subsystem for Python bridge and agent tooling.

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
Changes planned for upcoming milestones:

### **Alias Updates**
- Added documentation for `ITA` (the `Invoke-TechAgent` convenience wrapper in the module).
- Fixed `ITA` argument forwarding so `-ConfirmDestructive` and other forwarded options bind as named parameters instead of being treated as positional model input.

### **0.6.0 — Cross‑Platform Stabilization**
- Path normalization across Windows/macOS/Linux.
- Worker compatibility improvements.
- Enhanced environment detection.

### **0.7.0 — Worker & Remoting Enhancements**
- Unified worker orchestration.
- Credential flow improvements.
- Remote execution reliability upgrades.

---
