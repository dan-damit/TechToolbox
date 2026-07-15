# Task Templates

This folder contains reusable prompt templates for common TechAgent workflows.

Usage:
- Copy the template that best matches the task.
- Replace all placeholder values such as `<PRIMARY_INPUT_FILE>` and `<TASK_DETAILS>`.
- Paste the result into `AI/Tasks/CurrentTask.txt` or pass it directly to `Invoke-TechAgent`.

Current templates:
- `CSharp-XmlDocs-InPlace.txt`: update XML documentation comments in an existing C# file.
- `CSharp-Refactor-InPlace.txt`: refactor an existing C# file without changing intended behavior.
- `CSharp-BugFix-InPlace.txt`: fix a specific C# bug in place with focused validation.
- `PowerShell-CommentHelp-InPlace.txt`: update comment-based help in an existing PowerShell script or function file.
- `PowerShell-AboutHelp-NewFile.txt`: generate a new `about_*.help.txt` file for PowerShell help.
- `PowerShell-Refactor-InPlace.txt`: refactor an existing PowerShell script or function file without changing intended behavior.
- `PowerShell-BugFix-InPlace.txt`: fix a specific PowerShell bug in place with focused validation.
- `Tests-AddOrUpdate.txt`: add or update tests for a specific file, behavior, or regression.
- `Docs-Markdown-NewFile.txt`: generate a new markdown document at an exact output path.
- `Release-Versioning-Change.txt`: make a focused release, versioning, packaging, or publishing change.
- `CI-Workflow-BugFix.txt`: diagnose and fix a failing CI or GitHub Actions workflow.
- `PowerShell-HelpAuthoring-Review.txt`: review a PowerShell command and produce or improve help guidance.
- `Security-Review-Targeted.txt`: perform a targeted security review for a file, feature, or workflow.
- `General-BestPractices-Question.txt`: ask for best-practice guidance for a specific technology or scenario.
- `General-CodeReview.txt`: review an existing file for bugs, risks, regressions, and missing tests.
- `General-Scenario-Analysis.txt`: analyze a design, incident, or operational scenario and recommend an approach.

Helper script:
- `..\Use-TaskTemplate.ps1`: lists available templates, shows or opens them, and copies a chosen template into `AI/Tasks/CurrentTask.txt` or another destination.

Guidelines:
- Use absolute paths when the agent must write to or validate a specific file.
- Keep the hard requirement block when file output is mandatory.
- Prefer the language-native documentation style for the target file.
- For PowerShell scripts, prefer comment-based help rather than C# XML documentation terms.
- For refactor templates, define the intended invariant clearly so the agent does not broaden scope.
- For bug-fix templates, include the failing behavior, error text, or reproduction when available.
- For test templates, specify the target test project or test file when you already know it.

Standard template shape:
- `Primary input file:` or `Primary input files:` when the task is grounded in specific files.
- `Additional context:` when repo, environment, or scenario context matters.
- `Task:` for the main request.
- One optional detail section such as `Task details:`, `Bug details:`, `Requested outcome:`, or `Question:`.
- `Output file:` only when the task must create a new file.
- `Requirements:` for constraints, validation, and stop conditions.

Standard placeholders:
- `<PRIMARY_INPUT_FILE>`: one source file.
- `<PRIMARY_INPUT_FILES>`: multiple source files or inputs.
- `<OUTPUT_FILE>`: exact file path to create or update as the final artifact.
- `<TASK_DETAILS>`: general task-specific detail block.
- `<BUG_DESCRIPTION>`: failing behavior, reproduction, or error text.
- `<REFACTOR_GOAL>`: the specific refactor objective.
- `<TEST_BEHAVIOR>`: the behavior or regression the tests should cover.
- `<DOCUMENT_TOPIC>`: the markdown or help topic to produce.
- `<QUESTION_TOPIC>`: the best-practices question to answer.
- `<HELP_GOAL>`: the requested PowerShell help authoring or review outcome.
- `<REPO_CONTEXT>`: optional repository, environment, or operational context.
- `<REVIEW_SCOPE>`: the scope of a targeted review.
- `<SCENARIO_DESCRIPTION>`: the scenario to analyze.

Quick start:
- List templates: `./AI/Tasks/Use-TaskTemplate.ps1 -List`
- List templates in one category: `./AI/Tasks/Use-TaskTemplate.ps1 -List -Category PowerShell`
- Pick a template interactively and copy it into the current task file: `./AI/Tasks/Use-TaskTemplate.ps1 -Pick`
- Pick a template interactively from one category: `./AI/Tasks/Use-TaskTemplate.ps1 -Pick -Category CSharp`
- Pick a template interactively and show it first: `./AI/Tasks/Use-TaskTemplate.ps1 -Pick -Show`
- Show a template: `./AI/Tasks/Use-TaskTemplate.ps1 -Template CSharp-BugFix-InPlace -Show`
- Open a template: `./AI/Tasks/Use-TaskTemplate.ps1 -Template PowerShell-BugFix-InPlace -Open`
- Copy one into the current task file: `./AI/Tasks/Use-TaskTemplate.ps1 -Template CSharp-BugFix-InPlace.txt`
- Copy to another destination: `./AI/Tasks/Use-TaskTemplate.ps1 -Template General-CodeReview.txt -Destination <PATH>`

Available categories:
- `CSharp`
- `PowerShell`
- `General`
- `Docs`
- `Tests`
- `Release`
- `CI`
- `Security`
