# Config.json

## What Is It?

`Config.json` is the active configuration file used by the current PAWDeploy implementation. It defines the environment defaults and the path roots needed to build PAW VMs, while template-specific values live as JSON files beside it in Config.

The file uses JSON syntax and contains root `Solution` and `Settings` objects. It is edited with the PAW Configuration Editor UI or command-line tool, but it can also be reviewed and adjusted directly in a text editor. Templates have their own UI and command-line editors.

> The current scripts read `Config.json` and separate JSON files in the same Config folder; XML configuration files are not used by these consumers.

---

## Why Is It Needed?

PAWDeploy supports deploying different PAW profiles for different purposes: Tier 0, Tier 1, or workgroup-based administrative workstations. Instead of hard-coding these details into the scripts, the environment-specific values are kept in `Config.json`, with each template stored as a dedicated JSON file in the template folder.

This means:

- the scripts do not have to be edited for a new customer or environment
- multiple templates can coexist and be selected at runtime
- path configuration and deployment defaults are centralized in one location
- template data can be managed separately from settings in the PAW Template Editor

---

## File Location

After installation, the active config file is located at:

```text
C:\PAWDeploy\Config\Config.json
```

(Or on whichever drive and path you chose during installation.) Template JSON
files are directly beside it in `Config`, with no Templates subfolder.
`Config.json` is reserved for settings and is never loaded as a template.

---

## Structure Overview

The active `Config.json` contains `Solution` metadata and a top-level `Settings` object. The current file is structured as follows:

```json
{
  "Solution": { "Name": "PAWDeploy", "Version": "2.0.0.1" },
  "Settings": {
    "SolutionVersion": { "Major": 2, "Minor": "0", "Build": 0, "Revision": 1 },
    "CustomerData": { "OrgName": "Corp", "FullName": "Corp" },
    "HyperV": {
      "VMFolder": "C:\\VMs",
      "VMGen": "2",
      "NoCPU": "2",
      "Memory": "3072",
      "DynamicMem": "False",
      "DiskMode": "Diff"
    },
    "OperatingSystemConfiguration": {
      "DomainOrWorkGroup": "WORKGROUP",
      "TimeZoneName": "Pacific Standard Time",
      "InputLocale": "en-US",
      "SystemLocale": "en-US",
      "UILanguage": "en-US",
      "UserLocale": "en-US"
    },
    "Configuration": {
      "InstallFolder": "C:\\PAWDeploy",
      "VHDFolder": "C:\\PAWDeploy\\VHDFolder",
      "SecurityBaseLineFolder": "C:\\PAWDeploy\\Resources\\SecurityBaselines",
      "LogFilesFolder": "%TEMP%\\PAWDeploy"
    }
  }
}
```

`Solution.Name`/`Solution.Version` and `Settings.SolutionVersion` are package/version metadata. `Settings.HyperV` values provide VM defaults and template values take precedence where supported. Relative folder settings are resolved against the folder containing `Config.json`. Templates always use that same folder; obsolete `TemplateFolder`/`TemplatesFolder` settings are ignored and removed by installation or editor saves. Logs always use the current user's LocalAppData folder.

## Section 1 - CustomerData

This section identifies the organisation and is used during unattended setup.

```json
"CustomerData": {
  "OrgName": "Contoso",
  "FullName": "Contoso Ltd"
}
```

| Setting | Description | Example |
|---|---|---|
| `OrgName` | Short name of the organisation. | `Contoso` |
| `FullName` | Full legal name of the organisation. | `Contoso Ltd` |

---

## Section 2 - HyperV

This section defines the Hyper-V-specific defaults used when a VM is created.

```json
"HyperV": {
  "VMFolder": "C:\\Data\\VMs",
  "VMGen": "2",
  "NoCPU": "2",
  "Memory": "3072",
  "DynamicMem": "False",
  "DiskMode": "Diff"
}
```

| Setting | Description | Example |
|---|---|---|
| `VMFolder` | Folder where VM configuration folders are created. Must exist on the host. | `C:\Data\VMs` |
| `VMGen` | Hyper-V generation; accepted values are `1` or `2`. | `2` |
| `NoCPU` | Positive number of virtual processors. | `2` |
| `Memory` | Positive VM memory amount in MB. | `3072` |
| `DynamicMem` | Whether dynamic memory is enabled. | `True` or `False` |
| `DiskMode` | How the base disk is created for the VM. | `Diff` or `Copy` |

---

### OperatingSystemConfiguration

These values are fallbacks when the selected template does not supply a locale or domain/workgroup value.

| Setting | Description |
|---|---|
| `DomainOrWorkGroup` | Default join mode, typically `WORKGROUP` or `Domain`. |
| `TimeZoneName` | Windows time zone identifier. |
| `InputLocale`, `SystemLocale`, `UILanguage`, `UserLocale` | Keyboard, system, display, and regional locale defaults. |

---

## Section 3 - Configuration

This section defines the root folders used by PAWDeploy.

```json
"Configuration": {
  "InstallFolder": "C:\\PAWDeploy",
  "VHDFolder": "C:\\PAWDeploy\\VHDFolder",
  "SecurityBaseLineFolder": "C:\\PAWDeploy\\Resources\\SecurityBaselines",
  "LogFilesFolder": "%TEMP%\\PAWDeploy"
}
```

| Setting | Description | Example |
|---|---|---|
| `InstallFolder` | Root folder where PAWDeploy is installed. | `C:\PAWDeploy` |
| `VHDFolder` | Root folder containing VHD/VHDX source files. | `C:\PAWDeploy\VHDFolder` |
| `SecurityBaseLineFolder` | Root folder containing security baseline folders. | `C:\PAWDeploy\Resources\SecurityBaselines` |
| `LogFilesFolder` | Fixed folder for script logs. Existing custom values are ignored by the logging helpers. | `%TEMP%\PAWDeploy` |

---

## Section 4 - Templates

Templates are separate JSON files beside `Config.json`; they are not embedded in it. The deployment engine can select any valid template file. `PAWDeployUI.ps1` hides a template only when its optional `Active` property is `false` (a missing `Active` property is treated as active).

The default folder is `<InstallPath>\Config`. Templates share this folder with
`Config.json`; all readers exclude that reserved file. Creating a template named
`Config` uses a non-conflicting filename such as `Config (2).json`.

A representative template uses fields such as:

```json
{
  "Name": "Windows 11 x64 PAW for WORKGROUP ON",
  "Active": true,
  "VMNotes": "Windows 11 x64 PAW for WORKGROUP",
  "VMGen": "2",
  "NoCPU": "2",
  "Memory": "3072",
  "DynamicMem": "False",
  "DiskMode": "Diff",
  "Shielded": "True",
  "BitLocker": "True",
  "Application": "True",
  "ApplySecurityBaseline": "True",
  "VHDFile": "W1124H2VPAW.vhdx",
  "RunScript": "CustomScripts\\Sample1.ps1",
  "SecurityBaselineLocation": "Windows11_24H2",
  "TimeZoneName": "W. Europe Standard Time",
  "InputLocale": "sv-SE",
  "SystemLocale": "sv-SE",
  "UILanguage": "sv-SE",
  "UserLocale": "sv-SE",
  "DomainOrWorkGroup": "WorkGroup",
  "DNSDomain": "NA",
  "MachineObjectOU": "NA",
  "NamePrefix": "PAW",
  "NameSuffix": "WOG",
  "VLanID": "0",
  "VMSwitch": "Default Switch",
  "ProductKey": ""
}
```

| Template setting | Description |
|---|---|
| `Name` | Display/selection name. When omitted, the JSON filename (without extension) is used. |
| `Active` | UI visibility flag; `false` hides the entry, while missing is treated as active. |
| `VMNotes`, `VMGen`, `NoCPU`, `Memory`, `DynamicMem` | VM metadata and hardware settings. Numeric and boolean values are commonly stored as strings. |
| `DiskMode` | `Diff` or `Copy`; overrides `Settings.HyperV.DiskMode`. |
| `Shielded` / `Shielding` | Controls the Shielded VM policy; `-SkipShielding` overrides it. |
| `BitLocker` | `False` disables guest disk encryption; `-SkipDiskEncryption` also disables it. |
| `Application` | `False` disables the application-install path; `-SkipApplication` also disables it. |
| `ApplySecurityBaseline` | `True` enables application of staged baselines; `False` leaves the files unapplied. |
| `VHDFile` | Source VHDX. A filename resolves under `Settings.Configuration.VHDFolder`; rooted paths are used as given, and relative paths containing a folder resolve from the Config.json folder. |
| `RunScript` | Post-deployment script value; command-line `-RunScript` can override it and `-SkipRunScript` skips it. |
| `ExtraFolder` | Optional UI template value passed as `-ExtraFolder`; when omitted, no additional folder is copied. |
| `SecurityBaselineLocation` | Baseline folder/path. Relative values resolve under `SecurityBaseLineFolder`; a non-empty value enables baseline staging unless `-SkipSecurityBaseLine` is set. `ApplySecurityBaseline` must also be `True` to apply the files in the guest. |
| `TimeZoneName`, `InputLocale`, `SystemLocale`, `UILanguage`, `UserLocale` | Windows locale and regional settings. |
| `DomainOrWorkGroup`, `DNSDomain`, `MachineObjectOU` | Domain/workgroup mode and domain join settings. |
| `NamePrefix`, `NameSuffix` | Inputs for generated VM names. |
| `VLanID` | Template VLAN ID (`0`–`4095`). |
| `VMSwitch` | Template default switch name; the value must match an available Hyper-V switch. |
| `ProductKey` | Optional product key value. |
| `ExpansionScript` | UI fallback for the Run Command field when `RunScript` is empty. |

`ApplySecurityBaseline` controls whether copied baseline files are applied in the guest. Set it to `True` to apply baselines; the files are staged when `SecurityBaselineLocation` is non-empty and `-SkipSecurityBaseLine` is not supplied.

---

## Recommended workflow

1. Set environment paths and defaults under `Settings` in `Config.json`.
2. Ensure Config contains the JSON templates used for deployment and the UI.
3. Use the template/configuration tools to add, clone, or update templates and paths.
4. Check that source VHDX and baseline paths resolve on the host.
5. Save the configuration and validate the JSON before deployment.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| No templates found | Config contains no valid template JSON files | Add template files beside `Config.json`; configuration itself is not a template. |
| No templates are shown in the GUI | Folder is empty, JSON is invalid, or every template has `Active = false` | Add a valid JSON template or enable one by setting `Active` to `true` (or omit `Active`). |
| VHD file not found | `VHDFolder` or template `VHDFile` does not resolve to a file | Check the configured folder and the template's filename/path. |
| Security baseline is not applied | `SecurityBaseLineFolder` or `SecurityBaselineLocation` is incorrect, or baseline is skipped | Check both paths and ensure `-SkipSecurityBaseLine` is not supplied. |
| The editor cannot save | Invalid JSON or duplicate/invalid template data | Correct the JSON and resolve duplicate template names in the editor. |

## Related Documents

- [PAWConfigEditorUI.md](PAWConfigEditorUI.md)
- [PAWTemplateEditorUI.md](PAWTemplateEditorUI.md)
- [Import-PAWVHDX.md](Import-PAWVHDX.md)
- [New-PAWVM.md](New-PAWVM.md)
- [PAWDeployUI.md](PAWDeployUI.md)
- [Install-PAWDeploy.md](Install-PAWDeploy.md)
