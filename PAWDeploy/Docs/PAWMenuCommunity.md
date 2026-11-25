# PAWMenuCommunity.ps1 - Community Edition Menu

## Overview

Startup and tool launches are logged to `%TEMP%\PAWDeploy\PAWMenuCommunity.log`,
including when this edition is installed as `PAWMenu.ps1`.

`PAWMenuCommunity.ps1` is the source script for the Community edition's Windows Forms launcher. The build process installs it as `PAWMenu.ps1`, so run the installed name from the PAWDeploy folder:

```powershell
.\PAWMenu.ps1
```

The Community menu provides **New PAW**, **Configuration**, **Templates**,
**Applications/Bundles** and **PowerShell Prompt**. **Logs**, **Help** and
**Close** remain available; other menu buttons are not shown.

**PowerShell Prompt** is enabled on the left below **Applications/Bundles**.
It opens an administrator console using the menu's PowerShell installation (UAC approval may be required)
in the PAWDeploy installation root, imports `PAWUtility` and
`PAWApplicationManager`, and prints
`PAWDeploy Toolkit - <menu version>` in green. The console remains open for commands.
Launch failures appear in an error dialog; startup/import failures appear in the console.
The console overlays the menu's lower half at its current screen position, with
the same width and half the height. An explicit classic console host prevents
Windows Terminal tab placement. After successful import it also prints
`PAWUtility module loaded.` and `PAWApplicationManager module loaded.` in green.

When enabled, a menu action opens its corresponding UI from `Tools` in a separate,
hidden process using the same PowerShell installation as the menu. The menu displays **Opening...** centered in the header until it detects
the tool window and reports a startup error if the process exits early.
The tool opens at the menu's exact position on the
same monitor.

The installed background image stretches across the entire client area in both
themes, without a ribbon. The window size and two-column action layout are unchanged.
The tool name at the top left, horizontal toolkit logo at the top right, and
DeploymentBunny and white Community Truesec logos at the bottom left are overlays,
with transparent backgrounds and 20-pixel side margins.
Help and Close are
grouped at the bottom right.
The left column contains New PAW, Configuration, Templates,
Applications/Bundles and PowerShell Prompt. **Logs**, **Help** and **Close**
are grouped in the footer. Both editors also have command-line alternatives.
All windows use the
toolkit App-Icon. **Help** opens the documentation reader and lists all Markdown
guides in `Docs`; **Close** is at the bottom right. Help is available in both
editions and uses the same 1344 x 756 window size.

Titles use `PAWDeploy Toolkit - <version> - <script filename> - <script folder>`. In an installed
Community package the filename is `PAWMenu.ps1`.

## Requirements

- Windows with Windows PowerShell 5.1 or PowerShell 7.
- The Community edition of PAWDeploy installed.

The menu has no command-line parameters.

## Related documentation

- [Commandline Samples](CommandlineSamples.md) - Prepare resources and deploy a PAW from PowerShell in Community Edition.

- [PAWMenu.md](PAWMenu.md) - Enterprise edition launcher
- [PAWDeployUI.md](PAWDeployUI.md) - PAW VM deployment UI
- [Install-PAWDeploy.md](Install-PAWDeploy.md) - Installing the solution
- [PAWHelpUI.md](PAWHelpUI.md) - Local documentation reader
