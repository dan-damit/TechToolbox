# TechShell Winget Release Guide

This guide adds a separate, PowerShell-friendly release path for the Windows Shell app without changing the PowerShell Gallery module flow.

## Scope

- Module distribution: PowerShell Gallery (`TechToolbox` module)
- Shell app distribution: Winget (`TechToolbox.TechShell`)

## Prerequisites

- Signed Shell installer artifact (recommended: MSIX)
- Public HTTPS download URL for each release asset
- `winget` available locally for validation
- Repository root open in PowerShell

## Recommended repo layout

Create and maintain manifests under:

- `packaging/winget/TechToolbox.TechShell/<version>/TechToolbox.TechShell.yaml`
- `packaging/winget/TechToolbox.TechShell/<version>/TechToolbox.TechShell.installer.yaml`
- `packaging/winget/TechToolbox.TechShell/<version>/TechToolbox.TechShell.locale.en-US.yaml`

Example version folder:

- `packaging/winget/TechToolbox.TechShell/0.6.1/`

## Generate hash and manifest files directly

Use the helper script after you have the final installer file:

```powershell
pwsh -NoProfile -File .\Config\New-WingetManifestData.ps1 `
  -InstallerPath .\Out\TechShell\TechShell.msix `
  -PackageVersion 0.6.1 `
  -InstallerUrl "https://github.com/dan-damit/TechToolbox/releases/download/v0.6.1/TechShell.msix" `
  -WriteManifestFiles
```

This returns:

- `Metadata` object including `InstallerSha256`
- YAML content for the three manifests
- `ManifestFiles` output containing the exact paths written under `packaging/winget`

You can still run in preview mode (no file writes) by omitting `-WriteManifestFiles`.

## Validate manifest files (CI/local)

Run:

```powershell
pwsh -NoProfile -File .\Config\Test-WingetManifest.ps1 `
  -PackageVersion 0.6.1
```

Behavior:

- Verifies required file structure exists
- Checks `InstallerUrl` is HTTPS
- Checks `InstallerSha256` format
- Runs `winget validate --manifest` when `winget` is available
- Fails with non-zero exit when validation errors are found

## Release checklist

1. Build and sign Shell installer asset (MSIX preferred).
2. Upload installer to GitHub Release for the matching tag.
3. Run `New-WingetManifestData.ps1 -WriteManifestFiles` to compute SHA256 and write the three manifest files.
4. Review manifest content and commit.
5. Run `Test-WingetManifest.ps1 -PackageVersion <version>` and fix any failures.
6. Submit or update the Winget package source (community manifest repo or internal source).
7. Verify install on a clean machine:

```powershell
winget install TechToolbox.TechShell
```

8. Keep PSGallery release flow unchanged for the PowerShell module.

## Notes for this repository

- Current module publish workflow intentionally excludes `src` from PSGallery package content.
- Keep Shell app release artifacts separate from module packaging.
- Continue using `Config/Build.ps1` to build Shell in Release while skipping Shell publish in module pipeline.
- Initial scaffold exists at `packaging/winget/TechToolbox.TechShell/1.3.3/` with placeholder SHA/URL values; replace them by running `New-WingetManifestData.ps1` against the real installer.
