# PAW Configuration Editor UI

`PAWConfigEditorUI.ps1` is the Windows Forms editor for `Config.json`. Template
files are managed separately in [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md).

The editor allows you to update organization information, Hyper-V VM storage,
the installation and VHD folders, the security baseline folder, and the UI
theme. Configuration changes are saved only to Config.json. The legacy
`Settings.HyperV.VMLocation` property is removed in favour of `VMFolder`.

The editor provides small, underlined **Browse** links immediately to the left
of the VM, VHD and security-baseline folder fields. Select **Dark** or **Light**
under **UI Theme**, then click **Save**. Changing
the theme affects newly opened toolkit windows; restart the current application
for it to use the new theme.

The main window is 1344 x 756 pixels and opens at the menu's position when
launched from the menu without showing a PowerShell console.

Run from the PAWDeploy installation root:

```powershell
.\Tools\PAWConfigEditorUI.ps1
.\Tools\PAWConfigEditorUI.ps1 -ConfigPath 'C:\PAWDeploy\Config\Config.json'
```

The command-line equivalent is
[Invoke-PAWConfigurationSettings.md](Invoke-PAWConfigurationSettings.md).

Configuration mode logs to `%TEMP%\PAWDeploy\PAWConfigEditorUI.log`; Template
mode logs to `%TEMP%\PAWDeploy\PAWTemplateEditorUI.log`. Both paths are fixed
under the current user's TEMP folder.
