# PAWDeploy

PAWDeploy helps organizations deploy repeatable Privileged Access Workstations
(PAWs) as Hyper-V virtual machines for sensitive administrative work, separate
from everyday activities such as browsing and email. Templates make deployments
easier to repeat and reduce manual configuration differences. Follow
[Getting started](GettingStarted.md) to deploy a test PAW.

A deployed VM alone does not guarantee security: protect and maintain the host,
reference image, accounts, network access and policies, and test the result
against your organization's requirements.

Deployment supports template-controlled guest ASR Block rules (`ASR` True/False,
`-SkipASR` to override True and opt out) and
template/CLI/UI-selected Windows Defender Application Control XML from
`Resources\WDACPolicies` (`-SkipWDAC` to opt out). Enterprise includes
**Import WDAC Policy**; both editions include the logged CLI importer.
WDAC retains XML Audit/Enforced mode and activates at the next VM boot.
See [security deployment requirements](Docs/New-PAWVM.md#asr-and-windows-defender-application-control).

The toolkit version is recorded in `Config\Config.json`. Module versions are
tracked independently. Existing release archives retain their original versions.

## Overview

PAWDeploy automates the deployment and removal of Privileged Access Workstations (PAWs) as Hyper-V virtual machines. Each PAW VM is provisioned from a VHDX template image, configured with unattended setup and security settings, with optional security baselines and domain join. The implementation is driven by a central JSON configuration file and JSON template files stored alongside it.

New to PAWDeploy? Start with [GettingStarted.md](GettingStarted.md) for host requirements, Hyper-V and network preparation, reference image preparation, template and application configuration, and testing.

## Editions

PAWDeploy is built in two editions (using `Build\Invoke-Build.ps1` in the source repository):

| Component | Community | Enterprise |
|---|---|---|
| `Install-PAWDeploy.ps1`, `Config.json`, templates, `Resources` | Yes | Yes |
| `New-PAWVM.ps1`, `PAWDeployUI.ps1` | Yes | Yes |
| `Invoke-PAWConfigurationSettings.ps1`, `Invoke-PAWTemplateSettings.ps1` | Yes | Yes |
| `Import-PAWTemplate.ps1`, `Export-PAWTemplate.ps1` | CLI | CLI and Template Editor Import/Export tab |
| `Invoke-PAWConfigValidation.ps1` | Yes | Yes |
| Application Manager CLI/UI, bundles and application preparation | Yes | Yes |
| `Import-PAWOSBaseline.ps1`, `Import-PAWEdgeBaseline.ps1`, `Import-PAWLGPO.ps1` | CLI | CLI and three import menu buttons |
| `PAWMenu.ps1` | New PAW, Configuration, Templates, Applications/Bundles and PowerShell | Full menu |
| `PAWHelpUI.ps1` | Yes | Yes |
| `PAWConfigEditorUI.ps1` | Yes | Yes |
| `Remove-PAWVM.ps1`, `Convert-PAWWIM2VHD.ps1` (command line) | Yes | Yes |
| `PAWRemoveVMUI.ps1`, `PAWWIM2VHDUI.ps1` (graphical) | - | Yes |

## Major Components

### Install-PAWDeploy.ps1
Installs the solution to a target host by copying the PAWDeploy content tree to the selected install path. Host-side resources are grouped directly under `PAWDeploy\Resources`: application catalog, bundles, downloads, application payloads, custom scripts, security baselines, and WDAC policies. VM destinations such as `C:\PAWFiles` remain unchanged.

### Config.json
The central configuration file is [PAWDeploy/Config/Config.json](Config/Config.json). It stores environment defaults such as OrgName, FullName, VMFolder, InstallFolder, VHDFolder, SecurityBaseLineFolder, and LogFilesFolder. Deployment templates are individual `.json` files directly in [PAWDeploy/Config](Config), alongside `Config.json`, without a Templates subfolder or configurable template path. Template readers exclude `Config.json`.

Tool logs use the current user's `%TEMP%\PAWDeploy` folder regardless of legacy
`LogFilesFolder` values. Deployment logging starts before template loading and
resource preflight. Existing logs are not moved or deleted.

After installation, the same layout is `<InstallPath>\Config\Config.json` and
`<InstallPath>\Config\<TemplateName>.json`. The installer migrates older root-level
configuration and template folders during upgrades, preserving user files and
stopping on destination conflicts.

Installation shortcuts are stored in `<InstallPath>\ShortCuts`. Upgrades rename
the old `shortscut` folder (conflicting folders must be resolved first) and move
existing tool shortcuts from the installation root to that folder. Shortcuts
created by the installer use the PowerShell installation running the installer.

GUI and command-line tools are in [PAWDeploy/Tools](Tools).
Both menu source scripts and `New-PAWVM.ps1` are in the PAWDeploy root.
Menus launch GUI scripts from `Tools`, using the installation root as the
working directory.

All UI windows, including both menus and the help reader, use a fixed outer size of
1344 x 756 pixels (70% of each dimension on a 1920 x 1080 display) and open centered on the screen. Saved per-tool window sizes
and positions are ignored so the windows align; other saved tool settings remain
unchanged. The configuration editor separates Configuration, Templates and Import/Export into
tabs and presents all template settings in a scrolling grid. VM removal supports
vertical and horizontal list scrolling. Menu-launched tools use a hidden PowerShell
host and open at the menu's exact position, including on secondary monitors.
After Build, the deployment GUI hands off to a classic PowerShell console with
the same width and half the height, aligned with the menu/form's bottom edge.
An explicit console host keeps it out of Windows Terminal tabs.
Window titles use `PAWDeploy Toolkit - <version> - <script filename>`.
All main GUI windows have a top ribbon displaying the script name without `.ps1`.
All toolkit windows and custom dialogs use the ribbon's dark green background
(`#153132`) with light captions. Layout panels and tabs share that background;
input fields and lists use a softer gray-green (`#294546`), with darker read-only
and document surfaces (`#203C3D`) and light text. Selections use `#416B6D`;
orange validation accents are retained. Windows-managed file pickers and message
boxes use the OS theme.
Menu-launched tools use the horizontal toolkit logo on the left and **Help** /
**Close** on the right. Help opens the tool's local guide in the documentation
reader; the reader's own Help button selects its guide without opening another window.
Both menus retain the centered background image and footer actions, with the
horizontal toolkit logo at the top right and the white Community or Enterprise Truesec logo
at the bottom left. The tool name remains at the top left.
All GUI windows use the toolkit App-Icon. The four toolkit PNGs are maintained in
`Resources` and copied to `<InstallPath>\Assets\img` during installation, including
upgrades. Release packages include them in `PAWDeploy\Assets\img`.

### New-PAWVM.ps1
The core headless deployment engine. It reads the selected template from the JSON template collection, resolves paths from Config.json, creates the VM, injects unattend configuration into the VHDX, starts the OS, waits for it to become ready, then hardens the VM with BitLocker, Virtualization-Based Security, Credential Guard, and optional Microsoft Security Baselines. It supports both domain-joined and workgroup deployments.

### PAWDeployUI.ps1
A Windows Forms front-end for `New-PAWVM.ps1`. It loads templates from the configured template folder and allows operators to select a template, review the settings, and deploy a PAW VM without using the command line.

### PAWConfigEditorUI.ps1
A Windows Forms editor that reads and writes `Config.json` and manages the template JSON files in the configured template folder. It exposes the main settings, supports browsing for folders, applies template dropdowns for values like VMSwitch, TimeZoneName, locale settings, scripts, VHD files, and baseline folders, and prevents duplicate template names.

### Invoke-PAWConfigurationSettings.ps1
A command-line tool to view and edit the settings in `Config.json`. Each setting is a named, validated parameter, so settings can be changed in scripts or remote sessions without the graphical editor. Supports `-WhatIf` and `-Confirm`.

### Invoke-PAWTemplateSettings.ps1
A command-line template editor. It lists, shows, creates, clones, edits, and removes the template JSON files beside `Config.json`, validates every value, and writes files in the same format as `PAWConfigEditorUI.ps1`. Supports `-WhatIf` and `-Confirm`.

### PAWWIM2VHDUI.ps1
A Windows Forms GUI front-end for `Convert-PAWWIM2VHD.ps1`. It validates the conversion inputs, provides browse dialogs for source and destination paths, previews commands, and launches image conversion in a new PowerShell window.

### Convert-PAWWIM2VHD.ps1
Converts a Windows image (WIM) into a bootable VHDX that can be used as the PAW reference image.

### Invoke-PAWConfigValidation.ps1
Diagnostic tool that checks `Config.json` paths, templates, VHDX files, the PowerShell environment, and the versions of the installed scripts. Community and Enterprise are separate build outputs, without an edition marker file.

### Invoke-PAWApplicationDownload.ps1
Prepares applications selected by an Application Manager bundle. WinGet saves the
installer and manifest, PSGallery saves modules, and Local apps use installers in
`Resources\ApplicationDownloads\Local\<Name>`. Generated install metadata uses the persistent
catalog Settings. New-PAWVM runs preparation automatically using its resolved
bundle plan; verified existing cache can be used offline.

### Invoke-PAWApplicationSettings.ps1
A name-based convenience editor backed by the Application Manager CLI and its
canonical catalog. It supports list/show/new/clone/edit/remove and
`-WhatIf`/`-Confirm`. Use the manager for WinGet discovery, bundles and transfer.

### PAWMenu.ps1
A Windows Forms launcher for the UI tools. The Community edition ships `PAWMenuCommunity.ps1` as `PAWMenu.ps1`, with **New PAW**, **Configuration**, **Templates**, **Applications/Bundles** and **PowerShell Prompt**.
Both menus open an administrator console using the same PowerShell installation as the menu, in the installation
root, importing `PAWUtility` and displaying `PAWDeploy Toolkit - <menu version>` in green.

### Baseline and LGPO imports
`Import-PAWOSBaseline.ps1` and `Import-PAWEdgeBaseline.ps1` import separate Microsoft
baseline ZIPs into `Resources\SecurityBaselines\<OS folder>\OS` or `Edge`.
`Import-PAWLGPO.ps1` imports LGPO.exe into every imported baseline's
`Scripts\Tools` directory. Import OS/Edge first, then LGPO. Existing content
requires `-Replace`; three Enterprise-menu buttons provide replacement confirmation.
See [the import guide](Docs/Import-PAWSecurityBaseline.md).

### Import-PAWRunScript.ps1
Imports one or more `.ps1` files into `Resources\CustomScripts`, with
explicit `-Replace` for existing names. Enterprise offers **Import Run Scripts**.
New PAW lists only filenames in this directory; scripts are staged/run independently
of applications and Copy Folder. See [SampleScripts](Docs/SampleScripts.md).

### Template import/export

`Tools\Import-PAWTemplate.ps1` imports one or more template JSON files with format
and setting-value validation. `Tools\Export-PAWTemplate.ps1` exports saved templates
by name to separate JSON files. Both log normally and require `-Replace` for
conflicting names/files. Import rejects format errors but preserves invalid setting
values, warning/logging all corrections so templates can be repaired in the editor.
The Template Editor's separate **Import/Export** tab
runs these scripts with explicit replacement approval.
See [format rules and examples](Docs/PAWConfigEditorUI.md#importexport-tab).

### PAWHelpUI.ps1
A local documentation reader available through **Help** in both menus. Lists all
Markdown guides in `Docs` and displays headings, emphasis, lists, tables and code
in a scrollable window, without executing document content or using the internet.

### Invoke-PAWInstallApplications.ps1
Runs inside the VM (started by `New-PAWVM.ps1`) and installs the enabled applications in `Applications.json` from the WinGet download cache (or the Local folder), using the per-application install files, then copies the enabled PowerShell modules.

### PAWRemoveVMUI.ps1
A Windows Forms GUI for removing existing Hyper-V VMs. It lists VMs on the host and allows operators to select one or more for deletion, including the VM, attached virtual hard disks, and the configuration folder.

### Remove-PAWVM.ps1
The headless equivalent of `PAWRemoveVMUI.ps1`. It accepts one or more VM names and removes each VM along with any attached virtual hard disks and configuration folder. It supports `-WhatIf`, `-Confirm`, and `-Force` for safe scripted use.

## Shared modules and helpers

The codebase now uses dedicated shared modules under [PAWDeploy/Functions](Functions) to centralize reusable logic and UI behavior:

- [PAWDeploy/Functions/PAWUtility](Functions/PAWUtility) contains path resolution, config parsing, logging, and deployment helpers.
- [PAWDeploy/Functions/PAWUIUtility](Functions/PAWUIUtility) contains Windows Forms helper functions and template editor utilities.

This refactor reduces duplication across the deployment and editor scripts and makes the project easier to validate with Pester tests.

## Documentation

- [Commandline Samples](Docs/CommandlineSamples.md) - End-to-end PowerShell walkthrough from image and resource preparation to deploying a PAW, including Community Edition.

Window titles show the executing script filename and its declared version, for
both GUI tools and command-line tools (including the deployment engine).

`Build\Invoke-Build.ps1` creates a Community and Enterprise ZIP archive under
`Releases\<Edition>`. It stages each package outside the repository, sets the
edition (`$script:PAWEdition`) in every packaged GUI/menu, creates the ZIP and
removes the staging folders. Only ZIP archives remain in `Releases`; existing
archives are never overwritten. Validation builds use temporary folders.

The release version is `Solution.Version` in `PAWDeploy\Config\Config.json`.
Each build records a fingerprint of the packaged sources in the current user's
local application data, outside the repository. When that version is already
released and the sources have changed (or no fingerprint exists), Invoke-Build.ps1
increments the last version part in Config.json (for example `2.0.0.1` to
`2.0.0.2`) and builds the new version. Unchanged sources produce no new package.
Changes only to tests, logs or imported baselines do not create a new version.

To force a new release even when sources are unchanged, run
`.\Build\Invoke-Build.ps1 -Force`. If the configured version is already released,
the revision is incremented to the next free version and both Config.json version
fields are updated automatically. Existing releases are never overwritten.
If the configured version has not yet been released, it is built as configured.

Run `.\Build\Test-PAWRelease.ps1` to test the latest release installers manually.
It selects the highest ZIP version separately for Enterprise and Community,
extracts each into its own `%TEMP%\PAWDeploy-ReleaseValidation-*` folder, and
opens two elevated Windows PowerShell windows that remain open after installation.
The targets are `C:\PAWEnterprise` and `C:\PAWcommunity` (override with
`-PathToEnterprise`/`-PathToCommunity`); `-ImageLocation`, `-VMLocation` and
`-Theme` are also configurable and default to `C:\PAWImages`, `C:\Data\VMs`
and `Dark`.
Each window first deletes its destination folder and all its content, so every
test is a clean installation, and deletes its extracted files afterwards, also
when the installation fails. Only the destination folders and release ZIPs remain.
Extracted folders left by earlier validations (for example a closed window) are
listed before extraction and deleted if you answer `y`; answer no if another
validation is still running.
Use `-WhatIf` to preview without extracting, deleting or launching installers.

PAWUIUtility loads logos, the menu background, icons and the window icon directly
from `PAWDeploy\Assets\img` using `Get-PAWImage` and `Get-PAWWindowIcon`. GUI scripts
contain no image data.

UI colors are loaded from `PAWDeploy\Assets\Themes`. Installation automatically
detects the Windows apps appearance and stores the result as `Dark` or `Light`;
use `Install-PAWDeploy.ps1 -Theme System|Dark|Light` to select automatic
detection or override the theme. Omitting `-Theme` also detects Windows appearance
during upgrades; Tab completion suggests `Dark` and `Light`. Additional theme JSON files can be added without
editing UI scripts.

GUI and command-line tools are in `PAWDeploy\Tools`. `New-PAWVM.ps1`,
`PAWMenu.ps1` and `PAWMenuCommunity.ps1` are in the PAWDeploy root.
Run the installed menu with `.\PAWMenu.ps1`. Run tools from the installation
folder using `.\Tools\<ScriptName>.ps1`; they resolve Config, Functions and
Resources against that installation folder. `C:\PAWFiles` is a guest-side path.

### Application Manager

Use **Applications / Bundles** in either menu or
`.\Tools\PAWApplicationManagerUI.ps1`. The UI calls
`Invoke-PAWApplicationManager.ps1`, backed by the `PAWApplicationManager` module.
Applications have individual catalog JSON files; bundles select ordered app IDs.
Templates assign a bundle, and New PAW/`-ApplicationBundle` can override it for one
build. The former maintained Applications.json list is replaced without migration.
See [Application Manager](Docs/ApplicationManager.md) for CLI examples,
WinGet prerequisites and import/export.

The folder [PAWDeploy/Docs](Docs) contains operational documentation for setup, deployment, image preparation, removal, hardening, and post-deployment scripting.

### Documentation Index

- [PAWConfigEditorUI.md](Docs/PAWConfigEditorUI.md) - Graphical editor for `Config.json` and template JSON files.
- [Invoke-PAWConfigurationSettings.md](Docs/Invoke-PAWConfigurationSettings.md) - Command-line viewer and editor for `Config.json` settings.
- [Invoke-PAWTemplateSettings.md](Docs/Invoke-PAWTemplateSettings.md) - Command-line template editor: list, show, create, clone, edit, and remove templates.
- [PAWUtility.md](Docs/PAWUtility.md) - Core deployment and infrastructure helper module for PAW automation.
- [PAWUIUtility.md](Docs/PAWUIUtility.md) - Shared Windows Forms and UI helper module for the PAW management tools.
- [Config.json.md](Docs/Config.json.md) - Reference document for the current JSON-based configuration model and the legacy XML migration notes.
- [Invoke-PAWInstallApplications.md](Docs/Invoke-PAWInstallApplications.md) - Installing the applications in `Applications.json` inside the PAW from the WinGet download cache.
- [ApplicationManager.md](Docs/ApplicationManager.md) - Application catalog, bundles, CLI/UI and transfer.
- [Invoke-PAWApplicationDownload.md](Docs/Invoke-PAWApplicationDownload.md) - Preparation of bundle-selected applications.
- [Invoke-PAWApplicationSettings.md](Docs/Invoke-PAWApplicationSettings.md) - Convenience catalog editor.
- `PAWWIM2VHDUI.md` - Graphical tool for building and launching WIM-to-VHD(X) conversions (Enterprise only).
- [PAWMenu.md](Docs/PAWMenu.md) - Enterprise edition GUI launcher.
- [PAWMenuCommunity.md](Docs/PAWMenuCommunity.md) - Community menu source and its packaged launcher behavior.
- [PAWHelpUI.md](Docs/PAWHelpUI.md) - Local documentation reader available from both menus.
- [Invoke-PAWConfigValidation.md](Docs/Invoke-PAWConfigValidation.md) - Configuration and environment diagnostics.

### Install-PAWDeploy.md
Explains how to install and update the solution safely, including logging behavior, validation checks, and upgrade considerations.

### Convert-PAWWIM2VHD.md
Covers converting a WIM image into a bootable VHDX template, including disk layout choices, parameter reference, multiple usage scenarios, and validation steps.

### Config.json.md
Documents the current `Config.json` structure, the related template folder model, and the migration context from the older XML-based configuration layout.

### PAWConfigEditorUI.md
Explains the graphical editor for `Config.json`, including folder browsing, template selection, save behavior, validation rules, dropdown population, and logging.

### New-PAWVM.md
Documents the command-line deployment engine in detail: prerequisites, deployment sequence, parameters, examples, logging, and post-run checks.

### PAWDeployUI.md
Provides end-user documentation for the graphical deployment tool, including field-by-field guidance and validation behavior.

### PAWRemoveVMUI.md
Provides end-user documentation for the graphical VM removal tool, including multi-select usage, safety notes, and verification checks.

### Invoke-PAWInstallApplications.md
Describes the PAW application lifecycle scripts and the package definition model used during deployment.

### Remove-PAWVM.md
Documents headless VM removal via PowerShell with safe usage patterns (`-WhatIf`, `-Confirm`, `-Force`) and operational verification.

### SampleScripts.md
Explains how sample scripts are used as post-deployment examples and how they are associated with templates.

### SecurityBaselines.md
Explains how to add Microsoft security baselines to PAW images, required folder layout (`OS` and `Edge`), configuration updates, and verification guidance.

## Recent changes reflected in this repo

The current codebase includes:

- migration from XML-centric configuration to JSON-based configuration in `Config.json`
- Template definition files (`*.json`) in Config instead of inline template XML blocks
- UI-driven editing for the main configuration values and template metadata
- shared `PAWUtility` and `PAWUIUtility` modules for common logic and UI helpers
- richer template editor dropdowns for VHD files, scripts, time zones, locale values, security baselines, and Hyper-V switches
- stricter duplicate-name handling and state persistence for the editor UI

These changes are reflected in the current scripts and should be treated as the canonical behavior for future modifications.
