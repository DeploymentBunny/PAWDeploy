# Invoke-PAWTemplateSettings.ps1 - Command-Line Template Editor

See [Commandline Samples](CommandlineSamples.md) for a complete example that imports resources and uses them in a new deployment template.

## Overview

`Invoke-PAWTemplateSettings.ps1` manages PAWDeploy deployment templates from the command line. Templates are the JSON files beside `Config\Config.json` below the parent installation folder; each file describes one type of PAW. The script is the command-line alternative to [PAW Template Editor](PAWTemplateEditorUI.md) and writes template files in the same format. Both the CLI and UI are included in Community and Enterprise editions.

| Action | What it does |
|---|---|
| `-List` (default) | Lists all templates with their VHDX file, domain/workgroup mode, switch, and file name. |
| `-Show` | Displays every setting of one template. |
| `-New` | Creates a new template. Settings you do not specify use the defaults from `Config.json`. |
| `-Clone` | Copies an existing template to a new name, optionally changing settings in the copy. |
| `-Edit` | Changes settings of an existing template and optionally renames it with `-NewName`. |
| `-Remove` | Deletes a template file. Prompts for confirmation unless `-Force` is used. |

Deployments select templates by name, so template names must be unique (case-insensitive).

Template names complete with Tab for `-Show`, `-Clone`, `-Edit`, and `-Remove`. Names with spaces are quoted automatically. Completion uses the template folder configured in the `Config\Config.json` below the parent installation folder.

### Tab completion of setting values

Setting values also complete with Tab, using the same choices as the template grid in [PAWTemplateEditorUI.ps1](PAWTemplateEditorUI.md):

| Parameter | Suggested values |
|---|---|
| `-VMGen`, `-DynamicMem`, `-DiskMode`, `-Shielded`, `-BitLocker`, `-ASR`, `-Application`, `-ApplySecurityBaseline`, `-DomainOrWorkGroup` | The allowed values |
| `-NoCPU` | 2-8 |
| `-Memory` | 2048-65535 MB in 1024 MB steps |
| `-TimeZoneName` | Windows time zone IDs |
| `-InputLocale`, `-SystemLocale`, `-UILanguage`, `-UserLocale` | Culture names, for example `sv-SE` |
| `-VHDFile` | `.vhdx` files in the configured `VHDFolder` |
| `-RunScript` | `NA` and `.ps1` files in `Resources\CustomScripts` |
| `-WDACPolicyFile` | `NA` and XML filenames directly in `Resources\WDACPolicies` |
| `-SecurityBaselineLocation` | Folders in the configured `SecurityBaseLineFolder` |
| `-VMSwitch` | Hyper-V virtual switches |

Values that start with the typed text are offered first. If none do, values that contain the text are offered, so `-TimeZoneName Europe<Tab>` finds `W. Europe Standard Time`. Folders are read from the `Config\Config.json` below the parent installation folder. `-VMSwitch` completion requires Hyper-V and an elevated session (or membership in Hyper-V Administrators). The first `-VMSwitch` completion in a session can take several seconds while the Hyper-V module loads.

The suggestions are only a convenience. Every value is still validated, and values outside the suggestions (for example a larger `-Memory` value or a keyboard identifier for `-InputLocale`) are accepted when valid.

## Usage

Set ASR like the other template security flags:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 x64 PAW for WORKGROUP ON' -ASR False
```

`-ASR True` is the new-template default. Deployment `-SkipASR` overrides True;
False always skips configuration. Older templates without ASR remain enabled.

Select a WDAC policy for a saved template (`NA` or an empty value selects none):

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 x64 PAW for WORKGROUP ON' -WDACPolicyFile 'PAW.xml'
```

The field is optional for older templates. The template editor checks the
filename format; [policy import/deployment](New-PAWVM.md#asr-and-windows-defender-application-control)
validates XML. Audit/Enforced options are preserved and activation is next boot.

List all templates:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1
```

Show all settings of a template:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Show -Name 'Windows 11 x64 PAW for WORKGROUP ON'
```

Create a new domain-joined template:

```powershell
$params = @{
    New               = $true
    Name              = 'Windows 11 T0 PAW for CORP'
    VHDFile           = 'W1124H2VPAW.vhdx'
    VMSwitch          = 'CorpSwitch'
    DomainOrWorkGroup = 'DOMAIN'
    DNSDomain         = 'corp.contoso.com'
    MachineObjectOU   = 'OU=PAW,OU=Tier0,DC=corp,DC=contoso,DC=com'
    NameSuffix        = 'T0'
}
.\Tools\Invoke-PAWTemplateSettings.ps1 @params
```

Clone a template and change settings in the copy:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Clone -Name 'Windows 11 T0 PAW for CORP' -NewName 'Windows 11 T1 PAW for CORP' -NameSuffix 'T1' -VLanID 20
```

If `-NewName` is omitted, the clone is named `<Name> - Clone`.

Edit a template, previewing the change first:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 T1 PAW for CORP' -Memory 8192 -NoCPU 4 -WhatIf
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 T1 PAW for CORP' -Memory 8192 -NoCPU 4
```

Rename a template:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 T1 PAW for CORP' -NewName 'Windows 11 Tier 1 PAW'
```

Remove a template:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Remove -Name 'Windows 11 Tier 1 PAW'
.\Tools\Invoke-PAWTemplateSettings.ps1 -Remove -Name 'Windows 11 Tier 1 PAW' -Force
```

Set custom or additional settings with a hashtable:

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 T0 PAW for CORP' -Setting @{ VMNotes = 'Tier 0 admin workstation' }
```

## Parameters

### Actions and general parameters

| Parameter | Description |
|---|---|
| `-List`, `-Show`, `-New`, `-Clone`, `-Edit`, `-Remove` | The action to perform. Only one can be used. `-List` is the default. |
| `-Name` | Template name. Required for every action except `-List`. Press Tab to complete existing template names for `-Show`, `-Clone`, `-Edit`, and `-Remove`. |
| `-NewName` | New template name for `-Clone` (default `<Name> - Clone`) or `-Edit` (rename). |
| `-Force` | Remove without prompting. |
| `-PassThru` | Returns the created or updated template as an object. |
| `-Setting` | Hashtable of settings. Standard settings are validated; unknown settings are stored as-is with a warning. |

### Template settings

Template settings can be used with `-New`, `-Clone`, and `-Edit`.

| Parameter | Allowed values | Default for `-New` |
|---|---|---|
| `-VMNotes` | Any text | Template name |
| `-VMGen` | `2` (required for vTPM, BitLocker, and Shielded VMs) | `Config.json` HyperV value or `2` |
| `-NoCPU` | 1-240 | `Config.json` HyperV value or `2` |
| `-Memory` | MB, 2048 or higher | `Config.json` HyperV value or `3072` |
| `-DynamicMem` | `True` or `False` | `Config.json` HyperV value or `False` |
| `-DiskMode` | `Diff` or `Copy` | `Config.json` HyperV value or `Diff` |
| `-Shielded` | `True` or `False` | `True` |
| `-BitLocker` | `True` or `False` | `True` |
| `-ASR` | `True` or `False` | `True` |
| `-Application` | `True` or `False` | `True` |
| `-ApplicationBundle` | Bundle GUID, or `NA` to skip | `cbade470-64cc-4628-9536-b58e3ca3be8d` |
| `-ApplySecurityBaseline` | `True` or `False` | `False` |
| `-VHDFile` | File name in `VHDFolder`, or full path | empty (must be set before deploying) |
| `-RunScript` | Script name in `Resources\CustomScripts`, or `NA` to skip | `NA` |
| `-WDACPolicyFile` | XML filename in `Resources\WDACPolicies`, or `NA` to skip | unset (no policy) |
| `-SecurityBaselineLocation` | Folder name in `SecurityBaseLineFolder`, or full path | empty |
| `-TimeZoneName` | Windows time zone ID (`Get-TimeZone -ListAvailable`) | `Config.json` value or `W. Europe Standard Time` |
| `-InputLocale` | Culture name (`sv-SE`) or keyboard identifier (`041d:0000041d`) | `Config.json` value or `en-US` |
| `-SystemLocale`, `-UILanguage`, `-UserLocale` | Culture name, for example `en-US` | `Config.json` value or `en-US` |
| `-DomainOrWorkGroup` | `DOMAIN` or `WORKGROUP` | `Config.json` value or `WORKGROUP` |
| `-DNSDomain` | DNS domain name, or `NA` | `NA` |
| `-MachineObjectOU` | OU distinguished name, or `NA` | `NA` |
| `-NamePrefix`, `-NameSuffix` | Letters, digits, and hyphens | `PAW` / empty |
| `-VLanID` | 0-4094 (0 = no VLAN) | `0` |
| `-VMSwitch` | Hyper-V switch name | empty (must be set before deploying) |
| `-ProductKey` | Empty, or `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` | empty |

## Validation behavior

- All values are validated before anything is written. If one value is invalid, nothing is saved.
- Values are stored with canonical casing, for example `w. europe standard time` becomes `W. Europe Standard Time` and `domain` becomes `DOMAIN`.
- Warnings are shown, but the template is still saved, when:
  - the `VHDFile`, `RunScript`, or `SecurityBaselineLocation` cannot be found,
  - the `VMSwitch` does not exist or cannot be queried (`Get-VMSwitch` requires an elevated session),
  - a `DOMAIN` template has no `DNSDomain` or `MachineObjectOU`,
  - a template has no `VHDFile` or `VMSwitch`.
- New and cloned templates are saved as `<Template name>.json`. Characters that are not valid in file names are replaced with `_`, and a number is added if the file already exists.
- Renaming a template with `-Edit -NewName` changes the `Name` inside the file but keeps the file name, the same as the graphical editor.
- Settings are written in the standard order, followed by any custom settings. Invalid JSON files in the template folder are skipped with a warning.

## Logging and requirements

- Windows PowerShell 5.1 is required.
- The `Functions\PAWUtility` module must be available beside the script.
- Every create, clone, edit, and remove is logged to `%TEMP%\PAWDeploy\Invoke-PAWTemplateSettings.log`, including old and new values for edits.

## Related documentation

- [Config.json.md](Config.json.md) - Template fields and configuration layout
- [Invoke-PAWConfigurationSettings.md](Invoke-PAWConfigurationSettings.md) - Command-line editor for `Config.json` settings
- [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md) - Graphical editor for templates
- [New-PAWVM.md](New-PAWVM.md) - Deploying a PAW from a template
- [SecurityBaselines.md](SecurityBaselines.md) - Preparing security baseline folders
- [SampleScripts.md](SampleScripts.md) - Post-deployment scripts used by `RunScript`
