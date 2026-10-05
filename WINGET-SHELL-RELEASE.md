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
- GitHub Actions secrets for release signing:
  - `TECHSHELL_CODE_SIGNING_THUMBPRINT`
  - `TECHTOOLBOX_SUBMODULES_PAT` (token with read access to `dan-damit/TechShell` and `dan-damit/TechToolbox.Agent` for submodule checkout)
- GitHub Actions secrets for winget-pkgs submission:
  - `WINGET_PKGS_PAT` (token with access to your `winget-pkgs` fork)
  - `WINGET_PKGS_FORK` (for example `yourname/winget-pkgs`)
  - `WINGET_PKGS_FORK_OWNER` (for example `yourname`)

- GitHub Actions repository variable to enable submission job:
  - `ENABLE_WINGET_SUBMISSION`
  - Set to `false` during local/private testing (default behavior when unset)
  - Set to `true` when you are ready to open automated PRs to `microsoft/winget-pkgs`

The workflow can be manually controlled through the `submit_winget_pr` input on workflow dispatch. If you want a hard approval gate, add an environment gate to the submission job in your local workflow configuration.

The release workflow resolves a signing certificate before building the MSIX using an HSM/provider-backed key available in the Windows certificate store.

Important:

- A public certificate (`.cer`) alone is not enough for signing.
- `TECHSHELL_CODE_SIGNING_THUMBPRINT` must be set to the certificate thumbprint exposed by your signing provider.
- Run the release job on a Windows runner where the provider software is installed and the certificate/private-key provider is available in the Windows certificate store.
- Set repository variable `TECHSHELL_RELEASE_RUNNER` to your self-hosted Windows runner label so the workflow runs in your Certum-capable environment.
- The workflow now fails fast unless it is running on a self-hosted Windows runner and `TECHSHELL_RELEASE_RUNNER` is set.
- Self-signed or otherwise non-public-trust signing certificates are blocked by the build/signing preflight checks.

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

## Build + manifest helper (recommended)

Use the dedicated helper to publish the TechShell MSIX, stage a stable installer filename,
and generate/validate winget manifests in one pass:

```powershell
pwsh -NoProfile -File .\Config\Build-TechShellWinget.ps1 `
  -PackageVersion 0.6.1 `
  -RuntimeIdentifier win-x64
```

If you need to override the TechShell package version, pass `-Version` (or `-PackageVersion`) to the bundle script or use the dedicated TechShell release switch:

```powershell
pwsh -NoProfile -File .\Config\Build.ps1 -ReleaseTechShell -Version 1.3.11
```

Use `-ReleaseTechToolbox` for the PSGallery/module release path, `-ReleaseTechAgent` for the runtime/agent release lane, and `-ReleaseTechShell` for the standalone shell package lane. Do not combine more than one release route in the same invocation.

Notes:

- This script keeps TechShell packaging independent from PSGallery module publishing.
- It writes outputs under `Out\TechShell\<version>\<runtime>\`.
- It also stages `Register-TechShellExplorerIntegration.ps1` beside the `.msix` so the shell context-menu helper ships with the release bundle.
- Use `-SkipManifestWrite` to dry-run metadata generation only.
- Use `-SkipManifestValidation` to bypass local validation temporarily.

After install, run the one-click installer helper:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Install-TechShellExplorerIntegration.ps1 -AutoDetect
```

This automatically locates the installed TechShell executable and registers the Explorer context-menu integration without replacing File Explorer.

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

## Automated winget-pkgs submission (new)

The `techshell-winget-release.yml` workflow now includes a second job that can create a PR to `microsoft/winget-pkgs` automatically after a successful build/sign/upload.

Behavior:

- Tag push (`v*`): submission job runs automatically after release build.
- Manual dispatch: you can toggle submission with `submit_winget_pr` input.

Note: the submission job runs only when `ENABLE_WINGET_SUBMISSION` is set to `true`.

What it does:

1. Downloads the generated winget manifest artifact.
2. Clones your `winget-pkgs` fork.
3. Copies manifests into `manifests/t/TechToolbox/TechShell/<version>/`.
4. Creates/pushes a branch and opens a PR to `microsoft/winget-pkgs`.

## Notes for this repository

- Current module publish workflow intentionally excludes `src` from PSGallery package content.
- Keep Shell app release artifacts separate from module packaging.
- Continue using `Config/Build.ps1` to build Shell in Release while skipping Shell publish in module pipeline.
- Initial scaffold exists at `packaging/winget/TechToolbox.TechShell/1.3.3/` with placeholder SHA/URL values; replace them by running `New-WingetManifestData.ps1` against the real installer.
