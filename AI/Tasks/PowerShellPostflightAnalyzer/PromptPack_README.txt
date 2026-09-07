PowerShell Parser Postflight Analyzer - Prompt Pack

Purpose:
This prompt pack provides a safe phased implementation path for POWERSHELL-PARSER.

Use order:
1) Initial_OverviewPrompt.txt
2) PowerShellParser_Phase02_ManifestRegistryValidation_Implementation.txt
3) PowerShellParser_Phase03_ParserAdapterDiagnostics_Implementation.txt
4) PowerShellParser_Phase04_AstAndCommandDiscovery_Implementation.txt
5) PowerShellParser_Phase05_PolicyEngineProfiles_Implementation.txt
6) PowerShellParser_Phase06_PostflightIntegration_Implementation.txt

Strict companion files:
- Each phase has a matching _Strict.txt file.
- Feed the strict file as a second input to keep scope bounded and fail closed.

Recommended execution pattern:
- Run one phase at a time.
- Require build plus targeted tests before moving to next phase.
- Stop on failed validation and fix only phase-owned surfaces.

Completion criteria:
- All phase acceptance criteria pass.
- Tool remains static-only with no PowerShell execution path.
- Optional/required integration behavior is deterministic and tested.
