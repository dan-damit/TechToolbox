# TechToolbox Updatable Help

This guide describes how to produce and publish Updatable Help artifacts so users can run:

```powershell
Update-Help -Module TechToolbox
```

## Prerequisites

- PowerShell 7+
- Windows (CAB generation uses `makecab.exe`)
- A static site that serves the `HelpInfo` XML and CAB files at the URL configured in `HelpInfoURI` in `TechToolbox.psd1`

Current `HelpInfoURI`:

- `https://dan-damit.github.io/TechToolbox-Docs/`

## Build the feed artifacts

Run from repository root:

```powershell
pwsh -NoProfile -File .\Config\Build-UpdatableHelp.ps1 -Clean
```

Default behavior:

- Reads manifest metadata from `TechToolbox.psd1`
- Uses `ModuleVersion` as the help version (normalized to `major.minor.build.revision`)
- Uses `HelpInfoURI` as `HelpContentURI` in HelpInfo XML
- Packages all `*.help.txt` files from `en-US`

Outputs:

- `Out\UpdatableHelp\en-US\TechToolbox_<GUID>_HelpInfo.xml`
- `Out\UpdatableHelp\en-US\TechToolbox_<GUID>_en-US_HelpContent.cab`

## Include command external help (optional)

If you also maintain MAML XML command help files (`*-help.xml`), include them in the CAB:

```powershell
pwsh -NoProfile -File .\Config\Build-UpdatableHelp.ps1 -Clean -ExternalHelpPath .\HelpXml\en-US
```

## Publish

Upload both generated files from `Out\UpdatableHelp\en-US` to the static root at your `HelpInfoURI`.

Because `HelpContentURI` is set to the same root URL, `Update-Help` expects both files to be discoverable there.

## Validate after publish

On a clean machine (or after reinstalling the module):

```powershell
Update-Help -Module TechToolbox -Force -Verbose
Get-Help about_Clear-BrowserProfileData
```

## Release checklist

1. Update help source files in `en-US` (and external XML help if used).
2. Bump module version in `TechToolbox.psd1`.
3. Rebuild help artifacts with `Build-UpdatableHelp.ps1`.
4. Publish generated XML and CAB to `HelpInfoURI` root.
5. Validate `Update-Help -Module TechToolbox` and spot-check about topics.
