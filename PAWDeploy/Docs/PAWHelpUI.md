# PAWHelpUI.ps1 - Documentation Reader

## Overview

Select **Help** in either PAWDeploy menu to browse all Markdown files in the
installed `Docs` folder. Choose a filename on the left to read it on the right.
The reader formats headings, emphasis, lists, tables and fenced code blocks.
Document content is never executed, links are displayed as text, and no internet
connection is required.

Startup, opened guides and reading errors are logged to
`%TEMP%\PAWDeploy\PAWHelpUI.log`.

The reader uses the same fixed 1344 x 756 window size as the other tools. Menu
launches hide the PowerShell host and place the reader directly over the menu.
The title is `PAWDeploy Toolkit - <version> - PAWHelpUI.ps1 - <script folder>`.
The title bar uses the same toolkit icon as the menu and other graphical tools.

## Usage

Requires Windows PowerShell 5.1 and the installed PAWDeploy modules.
From the installation root:

```powershell
.\Tools\PAWHelpUI.ps1
.\Tools\PAWHelpUI.ps1 -Document PAWDeployUI.md
```

`-Document` accepts an existing Markdown filename in `Docs`, not an external path.
The default guide is `PAWMenu.md`. Optional `-WindowX` and `-WindowY` parameters
position the window; without both, a direct launch opens centered.

The top ribbon displays the horizontal toolkit logo and the script name.
**Help** on the right selects this reader's guide in the current window;
**Close** exits. The document pane supports scrolling.

## Related documentation

- [PAWMenu.md](PAWMenu.md) - Enterprise launcher
- [PAWMenuCommunity.md](PAWMenuCommunity.md) - Community launcher
