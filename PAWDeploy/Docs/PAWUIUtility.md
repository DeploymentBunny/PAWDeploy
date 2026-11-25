# PAWUIUtility module

## Purpose

`PAWUIUtility` contains the shared UI helper functions used by the Windows Forms tools in PAWDeploy. It centralizes form styling, dialog helpers, template editor behavior, and saved UI state persistence so the GUI scripts do not each need to duplicate the same code.

## Typical responsibilities

- Windows Forms button, label, textbox, and styling helpers
- Segoe UI typography for toolkit-owned controls and dialogs
- browse dialogs for file/folder selection
- error display behavior for UI scripts
- template editor dropdown population and editor state management
- UI state save/load for per-user settings
- External theme loading and system appearance selection through `Get-PAWUiPalette` and `Set-PAWUiTheme`
- graphics from `PAWDeploy\Assets\img` through `Get-PAWImage` and `Get-PAWWindowIcon`
- main-window branding and Help/Close placement through `Add-PAWUiRibbon`
- themed windows and layout through `Set-PAWUiTheme` (`Set-PAWUiDarkBackground` remains as a compatibility wrapper)
- character width conversion helpers
- classic deployment-console positioning with `Set-PAWConsoleWindow`
- elevated interactive console startup with `Start-PAWElevatedPowerShell`, shared by both menus
- Application Manager forms through `Show-PAWApplicationManager`; all application
  and bundle operations call `Invoke-PAWApplicationManager.ps1`, not storage APIs

See [Application Manager](ApplicationManager.md) for the CLI/module/UI boundaries.

The elevated launcher accepts screen-pixel `X`, `Y`, `Width` and `Height` and
uses the classic console host with `Set-PAWConsoleWindow`. Menus pass their current
lower-half bounds. Successful startup prints the toolkit version and confirms
that PAWUtility was loaded, both in green.

## Graphics

`Get-PAWImage` loads a file from `PAWDeploy\Assets\img` and returns an independent
`System.Drawing.Bitmap`; callers own and dispose the returned image. The optional
`-MaximumWidth` scales large images down proportionally. `Get-PAWWindowIcon`
converts `PAW-Deployment-Toolkit-App-Icon.png` to an owned 32-pixel window icon.
Callers dispose the icon when the window closes. The images are shipped as files
rather than embedded in the module. Repository runs can resolve the original PNGs
from the root `Resources` folder; installed assets take precedence.

`Add-PAWUiRibbon -Form $form -ScriptPath $PSCommandPath -CloseButton $close`
reserves the top 64 client pixels for the horizontal logo, script name and actions.
All six editor/tool ribbons share this height and fill the form's client width.
Their left logo is 48 pixels high with equal 8-pixel top and left margins and preserves
its aspect ratio; the title is vertically centered beside it without overlapping.
The displayed artwork trims
the image's top and bottom background margins; the original file is unchanged.
Menus have no ribbon.
It reparents the existing Close button so its save/close handlers are retained.
Help launches the matching local guide at the caller's screen position, using a
hidden host. `-HelpAction` supplies in-reader navigation instead.
`-Menu` places the tool name directly on the form at the top left. The horizontal
toolkit logo appears at the top right; `-Edition Community` or `-Edition Enterprise`
selects the corresponding white Truesec logo at the bottom left. These controls overlay the
full-window menu background, not a ribbon.
The ribbon uses friendly headings for PAW Menu, PAW Deploy, PAW Application
Manager, PAW Configuration Editor, PAW Remove and PAW WIM-2-VHDx.
Help routing still uses the script filename.
The ribbon disposes its own logo and heading font with the form.

The ribbon applies `Set-PAWUiTheme -Control $form` to the current control tree.
All PAWDeploy-owned colors are loaded from JSON files under
`PAWDeploy\Assets\Themes`; the current graphite palette is `Dark.json` and
`Light.json` defines the light palette. Themes provide semantic colors for
backgrounds, panels, fields, borders, read-only surfaces, selections, text and
accents, with an optional `BackgroundImage` asset name for menu branding. Custom
theme files can be added there without changing UI scripts, as long as they
provide the same color properties.

Both built-in themes use the same menu background image, stretched to fill the
client area. The legacy optional `MenuRibbon` palette property is retained for
compatibility but is not displayed by menus. Tool ribbons use `Background`.

Buttons visibly change background on hover and press in both built-in themes,
including accent actions. `ButtonHover`, `ButtonPressed`, `AccentHover` and
`AccentPressed` customize these states in theme JSON. Older custom themes without
these optional properties retain their previous Field/Border/Accent state colors.
Both `Set-PAWThemedButton` and recursive `Set-PAWUiTheme` apply these states;
disabled buttons keep their standard disabled behavior.

Text buttons use a shared 200 x 30-pixel size and Segoe UI 11 bold, with Help,
Close and small icon buttons retaining their dedicated sizes. All secondary
buttons and accent buttons have a one-pixel white border in Dark and a one-pixel
black border in Light (`ButtonBorder` in theme JSON), including Browse, Help,
Close and small icon buttons; other Dark
palette colors are unchanged. Tab headers use Segoe UI 12 bold and 200 x 40-pixel
click targets in every themed UI.

The selected name is stored as `Settings.Configuration.UITheme` in `Config\Config.json`.
Older installations without that setting can still read `Settings\UITheme.json`.
`System` reads the Windows
apps appearance preference (`AppsUseLightTheme`) whenever a UI starts, falling
back to Dark only when Windows does not expose that preference. An explicit theme
name selects its matching JSON file. `Get-PAWUiPalette` loads that theme and
`Set-PAWUiTheme` applies it to forms, grids, inputs, buttons and toolkit-owned
dialogs. Windows-managed file pickers and message boxes retain the OS theme.
Tool windows and dialogs use one background color across forms, panels, groups,
tab pages and caption surfaces, matching WIM-2-VHDx. Input fields, content lists,
buttons and validation highlights retain their semantic colors. PAW Menu keeps
its background image and panel colors, without a ribbon.
Unused tab-strip and ListView header areas are also painted with theme colors,
including the space after the last tab or column.
Use `Install-PAWDeploy.ps1 -Theme Dark`, `-Theme Light` or `-Theme System` to
choose the installed setting.

## Module location

- [PAWDeploy/Functions/PAWUIUtility](../Functions/PAWUIUtility)
- [PAWDeploy/Functions/PAWUIUtility/PAWUIUtility.psd1](../Functions/PAWUIUtility/PAWUIUtility.psd1)
- [PAWDeploy/Functions/PAWUIUtility/PAWUIUtility.psm1](../Functions/PAWUIUtility/PAWUIUtility.psm1)

## Design intent

This module is intended to hold the GUI and interaction logic. It is used by the editor and UI front-end scripts, including configuration editing and VM removal or deployment forms.

## Common examples

- `$Form.Icon = Get-PAWWindowIcon`
- `$PictureBox.Image = Get-PAWImage -Name Logo -Edition Enterprise`
- `$Form.BackgroundImage = Get-PAWImage -Name Background`
- `Select-PAWFolderPath`
- `Select-PAWFilePath`
- `Show-PAWUiError`
- `Save-PAWUiState`
- `Import-PAWUiState`
- `Set-PAWConsoleWindow -X 100 -Y 400 -Width 1344 -Height 378`
- `Add-PAWTemplateSettingsEditorDropDowns`

## Function naming and migration

Version 0.0.10 standardizes all functions to `Verb-PAW...`, without compatibility
aliases. Existing external callers must use the new names, for example
`New-UiButton` becomes `New-PAWUiButton`, `Select-FolderPath` becomes
`Select-PAWFolderPath`, and `Get-SharedPawLogo` becomes `Get-PAWImage -Name Logo`.
The old `Invoke-TSxPAWDeploy...` helpers are now `Invoke-PAWDeploy...`;
`Invoke-TSxCopyPAWCMD` is `Invoke-PAWCopyDeploymentCommand`.
Parameters and behavior are unchanged. See the
[core module migration notes](PAWUtility.md#function-naming-and-migration).

Keeping these helpers here makes the UI tools easier to maintain and keeps the operational utility module focused on system and deployment logic.
