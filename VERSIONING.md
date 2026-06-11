# VERSIONING.md (Ready to Paste)

## TechToolbox Versioning Policy

TechToolbox uses a **Milestone‑Driven Semantic Versioning** model:

```
MAJOR.MINOR.PATCH
```

This hybrid approach provides the predictability of SemVer while aligning MINOR releases with major architectural or subsystem milestones.

---

## 1. Version Number Structure

### **MAJOR**
Incremented when:
- Breaking changes are introduced  
- A subsystem is redesigned in a way that requires user adaptation  
- The framework reaches a new stability tier (e.g., 1.0.0)

### **MINOR**
Incremented when:
- A new subsystem or major feature set is added  
- Significant architectural improvements are introduced  
- The module reaches a defined milestone (see Milestones section)

### **PATCH**
Incremented when:
- Bug fixes are made  
- Internal improvements occur without changing behavior  
- Documentation or metadata updates occur  
- Non-breaking enhancements are added

---

## 2. Current Version

**TechToolbox v0.5.0 — “AI & Metadata Milestone”**

This release marks:
- Introduction of the AI agent bridge  
- Full metadata export via `Export-ToolboxFunctions`  
- Enhanced loader and config architecture  
- Stabilized path token system  
- Improved developer experience and documentation  

---

## 3. Milestone Roadmap

The following MINOR versions represent planned architectural milestones:

### **0.6.0 — Cross‑Platform Stabilization**
- PowerShell 7+ parity across Windows, macOS, Linux  
- Path token normalization  
- Worker compatibility improvements  

### **0.7.0 — Worker & Remoting Enhancements**
- Unified worker orchestration  
- Improved remote execution patterns  
- Credential flow refinements  

### **0.8.0 — Diagnostics & Health Suite Expansion**
- System trust diagnostics  
- Battery, uptime, and event log improvements  
- Snapshot v2  

### **0.9.0 — Config & Secrets v2**
- Stronger schema validation  
- Environment‑aware config layers  
- Secrets provider abstraction  

### **1.0.0 — Stable Operator Framework**
- API stability guarantee  
- Full documentation  
- Production‑ready lifecycle  

---

## 4. Release Process

### **Patch Releases (x.x.PATCH)**
- Released as needed  
- No breaking changes  
- No new subsystems  

### **Minor Releases (x.MINOR.0)**
- Released when a milestone is completed  
- May include new commands, subsystems, or architecture  
- No breaking changes  

### **Major Releases (MAJOR.0.0)**
- Reserved for breaking changes or stability guarantees  

---

## 5. Tagging & Changelog

Each release must include:

### **Git Tag**
```
vMAJOR.MINOR.PATCH
```

### **Changelog Entry**
Documented in `CHANGELOG.md` with:
- Summary of changes  
- New features  
- Fixes  
- Breaking changes (if any)  

---

## 6. Pre‑1.0 Stability Notes

While TechToolbox is < 1.0:
- Breaking changes may occur between MINOR versions  
- API stability is not yet guaranteed  
- Rapid iteration is expected  

---

## 7. Philosophy

TechToolbox evolves quickly.  
This versioning model ensures:

- **Clarity** for contributors  
- **Predictability** for users  
- **Freedom** for rapid development  
- **Narrative structure** for the project’s growth  

---
