# Invoke-PAWConfigValidation.ps1 - Configuration and Environment Checks

## Overview

`Invoke-PAWConfigValidation.ps1` checks the installed PAWDeploy configuration and reports on paths, templates, VHDX files, the PowerShell environment, and script versions. It is a diagnostic tool: it reports findings but does not repair configuration or provision or remove virtual machines.

## Checks performed

Startup is logged to `%TEMP%\PAWDeploy\Invoke-PAWConfigValidation.log`.

- Reads `Config\Config.json` below the parent installation folder and resolves relative configured paths against the folder containing that file.
- Checks configured VM, installation, VHD, baseline, template, and log paths.
- Lists JSON templates and reports whether each template parses.
- Lists `.vhdx` files in the configured VHD folder and tests read access.
- Reports the solution version. Community and Enterprise are separate build outputs; no edition marker or runtime edition detection is used.
- Checks for PowerShell 5.1 and attempts to import the `PAWUtility` module.
- Reports detected versions of the installed scripts:
  - Both editions: `New-PAWVM.ps1`, `PAWDeployUI.ps1`, both configuration/template editors (UI and CLI), `Import-PAWVHDX.ps1`, `PAWVHDXImportUI.ps1`, application tools, and `PAWMenu.ps1`.
  - WIM conversion (`Convert-PAWWIM2VHD.ps1`) and VM removal (`Remove-PAWVM.ps1`) command-line tools are checked in both editions.
  - Enterprise-only graphical tools are checked when installed: `PAWRemoveVMUI.ps1` and `PAWWIM2VHDUI.ps1`.

## Usage

Run the script from the installed PAWDeploy folder:

```powershell
.\Tools\Invoke-PAWConfigValidation.ps1
```

The script has no command-line parameters. Review its color-coded console report for missing paths, invalid templates, inaccessible VHDX files, or unavailable scripts and modules.

## Logging and requirements

- Windows PowerShell 5.1 is required.
- `Config\Config.json` and the `Functions\PAWUtility` helper used to enumerate templates must be available below the parent installation folder in the expected installation layout.
- The validation report is written to the PowerShell console; no separate log file is created.
- A missing `Config.json` or required template helper stops execution with an error.

This script performs checks only; a reported problem must be corrected using the relevant configuration or installation tools.

## Related documentation

- [Config.json.md](Config.json.md) - Configuration settings and template layout
- [Invoke-PAWConfigurationSettings.md](Invoke-PAWConfigurationSettings.md) - Editing configuration from the command line
- [Invoke-PAWTemplateSettings.md](Invoke-PAWTemplateSettings.md) - Editing templates from the command line
- [PAWConfigEditorUI.md](PAWConfigEditorUI.md) - Editing configuration settings
- [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md) - Editing deployment templates
- [Install-PAWDeploy.md](Install-PAWDeploy.md) - Installing the solution
