# **TechToolbox AI Code Analysis Commands**
These commands provide **local, offline PowerShell code analysis** using a locally‑hosted LLM.  
They are designed specifically for **Dan’s personal workstation** and are **not intended for cloud use, shared environments, or production systems**.

The goal is to provide fast, private, technician‑grade code review with:
 
- signature‑safe preprocessing  
- Markdown report generation  
- folder‑level automation  
- zero cloud dependency  

All analysis is performed **entirely on the local machine**.

---

## **Available Commands**

### ### `Invoke-CodeAssistant`
Core analysis engine.  
Takes raw code text and a filename, streams analysis to the console, and generates a Markdown report in:

```
C:\TechToolbox\CodeAnalysis
```

Used internally by all other AI commands.

---

### ### `Invoke-CodeAssistantFolder`
Analyzes **every `.ps1` file** in a folder (recursively).

**Usage:**
```powershell
Invoke-CodeAssistantFolder -Path C:\TechToolbox\Public
```

For each file, it:

- streams analysis  
- generates a Markdown report  
- names the report after the script  

Ideal for reviewing entire modules.

---

### ### `Invoke-CodeAssistantWrapper`
Simple wrapper script to simplify the CLI inputs for the user

**Usage:**
```powershell
Invoke-CodeAssistantWrapper .\Path\to\your\script
```

---

## **Local‑Only Design**
These commands are intentionally built for **local analysis only**:

- They rely on a **local LLM** (Ollama or equivalent).  
- No code is sent to cloud services.  
- No external API calls are made.  
- All artifacts are stored locally.  
- All processing happens on Dan’s personal rig.

This ensures:

- privacy  
- speed  
- offline capability  
- predictable behavior  

---

## **Signature‑Safe Preprocessing**
Before analysis, scripts are automatically cleaned of:

- Authenticode signature blocks  
- PEM certificates  
- RSA keys  
- PKCS7 blobs  

This prevents the model from misinterpreting cryptographic data as code.

---

## **Output Location**
All analysis reports are saved to:

```
C:\TechToolbox\CodeAnalysis
```

Each file is named:

```
Analysis-<ScriptName>-<Timestamp>.md
```

---

## **Intended Use**
These tools are meant for:

- personal development  
- code review  
- refactoring  
- learning  
- module cleanup  
- exploratory analysis  

They are **not** intended for:

- production pipelines  
- CI/CD  
- shared environments  
- cloud execution  
