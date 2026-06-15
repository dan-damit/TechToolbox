# 🚀 TechToolbox v0.5.0 — *AI & Metadata Milestone*

## 📌 Summary  
This milestone marks a major evolution of TechToolbox from a powerful admin toolkit into a **true operator framework** with AI‑assisted development, deep metadata export, and a hardened loader/config architecture.  
Version **0.5.0** establishes the foundation for future cross‑platform stability, worker orchestration improvements, and a path toward a 1.0 release.

---

## ✨ New Features

### **AI Agent Bridge**
- Introduced `Invoke-TechAgent` for structured, agent‑driven automation workflows.  
- Added `Invoke-CodeAssistant` and `Invoke-CodeAssistantFolder` for local AI‑assisted code analysis.  
- Added `Invoke-CodeAssistantWrapper` to standardize AI task execution patterns.  
- New C# local agent runtime under `src/TechToolbox.Agent/`.

### **Full Metadata Export System**
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
- More deterministic bootstrap sequence.  
- Cleaner separation between module root and operational home.  
- Improved path token resolution (`%TT_ModuleRoot%`, `%TT_Home%`, `%TT_LogsRoot%`, `%TT_ExportsRoot%`).  
- Private helpers load earlier and more predictably.

### **Configuration System**
- Deep merge between `config.json` and `config.secrets.json`.  
- Environment variable overrides (`TT_ConfigSecretsPath`, `TT_DisableConfigSecretsMerge`).  
- More stable caching and lazy initialization.

### **Logging Subsystem**
- Lazy initialization on first log call.  
- Respect for config‑driven log levels and file formats.  
- Cleaner, more consistent console output.

### **Developer Experience**
- Standardized function template.  
- Improved ScriptAnalyzer compatibility.  
- Better WhatIf support across destructive commands.

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
TechToolbox remains pre‑1.0, but this milestone stabilizes core architecture and prepares for future API guarantees.

---

## 📦 Installation  
```powershell
Import-Module .\TechToolbox.psd1 -Force
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
