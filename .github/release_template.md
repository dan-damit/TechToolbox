# 🚀 TechToolbox v0.5.0
### AI & Metadata Milestone
---
## Summary  
This milestone marks TechToolbox’s evolution from a powerful admin toolkit into a **operator‑grade automation framework**, introducing AI‑assisted workflows, deep metadata export, and a hardened loader/config architecture. 
**v0.5.0 establishes the foundation for scalable automation, AI integration, and future cross‑platform support.**

---

## 📌 Release Highlights

### **AI Agent Bridge**
- Introduced `Invoke-TechAgent` for structured, agent-driven automation workflows  
- Established the packaged C# TechToolbox agent runtime for local orchestration
- Expanded the agent runtime into multiple modes so it can cover a wider range of tasks:
  - `TechToolbox` for module-native automation and safe system actions
  - `Assistant` for general chat, Q&A, writing help, and email drafting
  - `CodingAgent` for code analysis, debugging, and refactoring
  - `Custom` for user-defined workflows and specialized tool sets
- Added a configuration-driven agent entrypoint so mode selection, tool providers, and runtime behavior can be changed without altering the core orchestrator

### **Full Metadata Export System**

Enables full introspection of the module for AI agents, documentation tooling, and automation pipelines.

- `Export-ToolboxFunctions` now exports:
  - Function names, aliases, categories  
  - Parameter metadata (types, defaults, mandatory flags, aliases, allowed values)  
  - Full help text (synopsis, description, examples, notes)  
  - Safety classification flags  
  - Module version and source context  
- Output is structured JSON designed for AI consumption and tooling integration.

### **Documentation Enhancements**
- Added `VERSIONING.md` defining the Milestone‑Driven SemVer model.  
- Updated `commands.md` with a full categorized command catalog.  
- Expanded architecture overview, quick start, and developer guide.

---

## 🛠 Improvements

### **Loader Architecture**
- Deterministic and repeatable bootstrap sequence  
- Clear separation between module root and operational home  
- Improved path token resolution:
  - `%TT_ModuleRoot%`
  - `%TT_Home%`
  - `%TT_LogsRoot%`
  - `%TT_ExportsRoot%`
- Private helpers load earlier and more predictably

### **Configuration System**
- Deep merge between `config.json` and `config.secrets.json`.  
- Environment variable overrides (`TT_ConfigSecretsPath`, `TT_DisableConfigSecretsMerge`).  
- More stable caching and lazy initialization.
- Added agent mode configuration so the same runtime can be used for TechToolbox automation, general assistant tasks, and coding-focused workflows.

### **Logging Subsystem**
- Lazy initialization on first log call.  
- Respect for config‑driven log levels and file formats.  
- Cleaner, more consistent console output.

### **Developer Experience**
- Standardized function template.  
- Improved ScriptAnalyzer compatibility.  
- Better WhatIf support across destructive commands.
- Preserved backward compatibility so existing TechToolbox agent entrypoints continue to behave the same while newer modes are added on top.

---

## 🐛 Fixes
- Resolved path token inconsistencies in several subsystems.  
- Fixed loader re‑entry issues during module import.  
- Corrected help text formatting in multiple commands.  
- Improved config merge behavior when secrets file is missing or malformed.

---

## 📁 Updated Documentation
- Updated README with architecture diagrams and quick start.  
- Added `VERSIONING.md` and milestone roadmap.  
- Updated developer & contributor guide.  
- Expanded command catalog.

---

## 🔧 Breaking Changes  
None in this release.
This milestone stabilizes core architecture ahead of future API guarantees.

---

## 📦 Installation  
```powershell
Install-Module TechToolbox -Scope CurrentUser
Import-Module TechToolbox
```

---

## 🗺 Roadmap  
### **Next Milestone: v0.6.0 — Cross‑Platform Stabilization**
- Path normalization across Windows/macOS/Linux  
- Worker compatibility improvements  
- Enhanced environment detection  

---

## ❤️ Contributors  
- Dan Damit  
- Copilot (AI engineering assistant)
- Local AI Agent (AI‑assisted code analysis and documentation)
