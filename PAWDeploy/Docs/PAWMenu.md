# PAWMenu.ps1 - Enterprise GUI Launcher

## Overview

`PAWMenu.ps1` is the Enterprise edition's Windows Forms launcher for the PAWDeploy tools. It provides a central menu for opening the deployment UI, VM removal UI, configuration editor, and WIM-to-VHDX conversion UI.

Each menu action starts its corresponding script from `Tools` in a separate,
hidden process using the same PowerShell installation as the menu. The tool opens directly over the menu on the same
monitor. The menu displays **Opening...** centered in the header until it detects the tool window,
ignores additional tool launches during that wait, and reports a startup error
if the process exits before opening a window. The log records how long it took
to detect the window.

Startup and tool launches are logged to `%TEMP%\PAWDeploy\PAWMenu.log`.

The installed background image stretches across the entire client area in both
themes, without a ribbon. The window size is unchanged. The tool name at the top
left, horizontal toolkit logo at the top right and white Enterprise Truesec logo at
the bottom left are overlays. The bottom logo remains 20 pixels from the edges.
Action buttons retain their two-column positions, and Logs, Help and
Close are grouped at the bottom right.
The left column contains New PAW, Configuration, Templates,
Convert WIM 2 VHDX, Applications / Bundles, Remove PAW and
PowerShell Prompt, in that order.
All Import actions are in the right column: OS Baseline, Edge Baseline, LGPO,
Run Scripts, WDAC Policy and VHDX.
**Edit ASR Rules** opens the [ASR rule editor](PAWASREditorUI.md).
**Logs** opens the [log viewer](PAWLogsUI.md) in both editions.
**Help** remains in the footer;
**Close** remains at the bottom right. The window uses the toolkit App-Icon.
The title is `PAWDeploy Toolkit - <version> - PAWMenu.ps1 - <script folder>`.

**Import OS Baseline**, **Import Edge Baseline** and **Import LGPO** each open
one ZIP picker. OS/Edge asks for an OS folder; LGPO applies to all imported
baselines, installing `Scripts\Tools\LGPO.exe`. Import baselines before LGPO.
Replacement is unchecked by default and requires confirmation.
The same [three CLI import tools](Import-PAWSecurityBaseline.md) can be run independently.

**Import Run Scripts** on the left selects multiple `.ps1` files for configured
Resources\CustomScripts. Existing filenames require explicit replacement approval.
No imported script is run. See [SampleScripts](SampleScripts.md).

**Import WDAC Policy** selects multiple XML files and invokes
`Tools\Import-PAWWDACPolicy.ps1`. The importer validates the Windows Code Integrity
schema, requires explicit permission to replace existing filenames, and logs
results/errors. Import never installs or activates policy.
See [ASR/WDAC](New-PAWVM.md#asr-and-windows-defender-application-control).

**Import VHDX** selects one or more `.vhdx` files and copies them into the
configured `VHDFolder` from `Config.json`. Existing files require explicit
replacement approval. The same operation is available from
[Import-PAWVHDX.md](Import-PAWVHDX.md).

**PowerShell Prompt**, on the left below **Remove PAW**, opens an
administrator console using the menu's PowerShell installation (UAC approval may be required).
It starts in the PAWDeploy installation root, imports `PAWUtility` and
`PAWApplicationManager`, and prints
`PAWDeploy Toolkit - <menu version>` in green. The console remains open for commands.
Launch failures appear in an error dialog; startup/import failures appear in the console.
The console overlays the menu's lower half at its current screen position, with
the same width and half the height. An explicit classic console host prevents
Windows Terminal tab placement. After successful import it also prints
`PAWUtility module loaded.` and `PAWApplicationManager module loaded.` in green.

## Requirements

- Windows with Windows PowerShell 5.1 or PowerShell 7.
- The PAWDeploy UI scripts installed in the `Tools` subfolder.

## Usage

Run the script from the installed PAWDeploy folder:

```powershell
.\PAWMenu.ps1
```

The menu has no command-line parameters. Select a tool to open it, or select **Close** to exit.
Select **Help** to open the documentation reader, which lists all Markdown guides
in `Docs`. It uses the same 1344 x 756 window size and menu position.

## Related documentation

- [PAWDeployUI.md](PAWDeployUI.md) - PAW VM deployment UI
- [PAWRemoveVMUI.md](PAWRemoveVMUI.md) - VM removal UI
- [PAWConfigEditorUI.md](PAWConfigEditorUI.md) - Configuration editor
- [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md) - Template editor
- [Import-PAWVHDX.md](Import-PAWVHDX.md) - Import VHDX files
- [PAWWIM2VHDUI.md](PAWWIM2VHDUI.md) - WIM-to-VHDX conversion UI
- [PAWHelpUI.md](PAWHelpUI.md) - Local documentation reader
