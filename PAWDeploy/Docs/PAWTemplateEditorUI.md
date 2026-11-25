# PAW Template Editor UI

`PAWTemplateEditorUI.ps1` is the graphical editor for deployment templates.
It manages template JSON files beside `Config.json`; it does not edit the
configuration settings. The command-line equivalent is
[Invoke-PAWTemplateSettings.md](Invoke-PAWTemplateSettings.md).

Run from the PAWDeploy installation root:

```powershell
.\Tools\PAWTemplateEditorUI.ps1
.\Tools\PAWTemplateEditorUI.ps1 -ConfigPath 'D:\PAWDeploy\Config\Config.json'
```

The editor supports selecting, creating, cloning, editing, removing, importing
and exporting templates. Template values are saved to each template's JSON
file; saving a template does not modify `Config.json`.

The editor shares the underlying UI implementation with the configuration
editor but opens only the Templates and Import/Export tabs. Its command-line
operations are provided by `Tools\Invoke-PAWTemplateSettings.ps1`,
`Tools\Import-PAWTemplate.ps1` and `Tools\Export-PAWTemplate.ps1`.
