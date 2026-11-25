# Invoke-PAWConfigurationSettings.ps1 - Command-Line Config.json Editor

## Overview

`Invoke-PAWConfigurationSettings.ps1` views and edits the settings in `Config.json` from the command line. It is the command-line alternative to [PAW Configuration Editor](PAWConfigEditorUI.md) and is useful for unattended setup, remote sessions, or changing a single value quickly. Both the CLI and UI are included in Community and Enterprise editions.

Only the settings you supply are changed. All other settings, including the `Solution` and `SolutionVersion` metadata, are preserved. Templates are not edited by this script; use [Invoke-PAWTemplateSettings.ps1](Invoke-PAWTemplateSettings.md) or [PAW Template Editor](PAWTemplateEditorUI.md).

## Usage

Display the current settings:

```powershell
.\Tools\Invoke-PAWConfigurationSettings.ps1
```

Update one or more settings:

```powershell
.\Tools\Invoke-PAWConfigurationSettings.ps1 -OrgName 'Contoso' -FullName 'Contoso Ltd'
```

Update several settings with splatting and display the result:

```powershell
$params = @{
    VMFolder = 'D:\VMs'
    NoCPU    = 4
    Memory   = 8192
    DiskMode = 'Diff'
}
.\Tools\Invoke-PAWConfigurationSettings.ps1 @params -Show
```

Preview a change without writing the file:

```powershell
.\Tools\Invoke-PAWConfigurationSettings.ps1 -TimeZoneName 'W. Europe Standard Time' -UserLocale 'sv-SE' -WhatIf
```

Edit a config file in another location:

```powershell
.\Tools\Invoke-PAWConfigurationSettings.ps1 -ConfigPath 'D:\PAWDeploy\Config\Config.json' -LogFilesFolder '%TEMP%\PAWDeploy'
```

## Parameters

| Parameter | Config.json setting | Allowed values |
|---|---|---|
| `-ConfigPath` | - | Path to `Config.json`. Default: `Config\Config.json` below the parent installation folder. |
| `-Show` | - | Display all settings (after any update). |
| `-PassThru` | - | Return all settings as objects (`Section`, `Setting`, `Value`) after the update. |
| `-OrgName` | `CustomerData.OrgName` | Any non-empty text |
| `-FullName` | `CustomerData.FullName` | Any non-empty text |
| `-VMFolder` | `HyperV.VMFolder` | Absolute folder path |
| `-VMGen` | `HyperV.VMGen` | `1` or `2` |
| `-NoCPU` | `HyperV.NoCPU` | Whole number 1-1024 |
| `-Memory` | `HyperV.Memory` | Memory in MB, 512 or higher |
| `-DynamicMem` | `HyperV.DynamicMem` | `True` or `False` |
| `-DiskMode` | `HyperV.DiskMode` | `Diff` or `Copy` |
| `-DomainOrWorkGroup` | `OperatingSystemConfiguration.DomainOrWorkGroup` | `DOMAIN` or `WORKGROUP` |
| `-TimeZoneName` | `OperatingSystemConfiguration.TimeZoneName` | Windows time zone ID (`Get-TimeZone -ListAvailable`) |
| `-InputLocale` | `OperatingSystemConfiguration.InputLocale` | Culture name (`sv-SE`) or keyboard identifier (`041d:0000041d`) |
| `-SystemLocale` | `OperatingSystemConfiguration.SystemLocale` | Culture name, for example `en-US` |
| `-UILanguage` | `OperatingSystemConfiguration.UILanguage` | Culture name, for example `en-US` |
| `-UserLocale` | `OperatingSystemConfiguration.UserLocale` | Culture name, for example `sv-SE` |
| `-InstallFolder` | `Configuration.InstallFolder` | Absolute folder path |
| `-VHDFolder` | `Configuration.VHDFolder` | Absolute folder path |
| `-SecurityBaseLineFolder` | `Configuration.SecurityBaseLineFolder` | Absolute folder path |
| `-LogFilesFolder` | `Configuration.LogFilesFolder` | `%TEMP%\PAWDeploy` or its expanded current-user path; the log folder is fixed |

## Validation behavior

- All values are validated before anything is written. If one value is invalid, no changes are saved.
- Time zone and culture names are stored with their canonical casing, for example `w. europe standard time` is saved as `W. Europe Standard Time`.
- Folder paths must be absolute. Trailing backslashes are removed. A warning is shown if a folder does not exist yet, but the value is still saved.
- When `-VMFolder` is set, the legacy `HyperV.VMLocation` property is removed, matching the graphical editor.
- If the requested values already match the file, nothing is written.

## Logging and requirements

- Windows PowerShell 5.1 is required.
- The `Functions\PAWUtility` module must be available beside the script.
- Each changed setting is logged with its old and new value to `%TEMP%\PAWDeploy\Invoke-PAWConfigurationSettings.log`. The log folder is created if needed and cannot be overridden by configuration.
- The file is saved as UTF-8 JSON, the same format used by `PAWConfigEditorUI.ps1` and `Install-PAWDeploy.ps1`.

## Related documentation

- [Config.json.md](Config.json.md) - Configuration settings and template layout
- [PAWConfigEditorUI.md](PAWConfigEditorUI.md) - Graphical editor for settings
- [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md) - Graphical editor for templates
- [Invoke-PAWConfigValidation.md](Invoke-PAWConfigValidation.md) - Validating the configuration after changes
- [Install-PAWDeploy.md](Install-PAWDeploy.md) - Setting install, image, and VM locations during installation
