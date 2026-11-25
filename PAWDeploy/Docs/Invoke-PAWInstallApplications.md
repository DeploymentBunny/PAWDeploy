# Invoke-PAWInstallApplications.ps1 - Install Applications in the PAW

## What Is It?

`Invoke-PAWInstallApplications.ps1` installs the resolved application selection in
the generated guest `Applications.json`. WinGet, Classic and modules use staged
resources. Windows components use the configured offline source, or explicitly
allow OS servicing to acquire resources online when Source is empty.

The application workflow has two stages:

1. **Download stage (host)** - `Invoke-PAWApplicationDownload.ps1` downloads the latest version of each enabled application with WinGet, together with its WinGet manifest (the install instructions, including the silent switches). PowerShell modules are downloaded from the PowerShell Gallery. Local applications (`Source` `Local`) are not downloaded; their installer is placed in `Resources\ApplicationDownloads\Local\<Name>`. See [Invoke-PAWApplicationDownload.md](Invoke-PAWApplicationDownload.md).
2. **Install stage (VM)** - `Invoke-PAWInstallApplications.ps1` runs inside the VM through PowerShell Direct and installs each application silently from the cache.

The VM does not need internet for fully staged applications or Windows components
with matching offline media. Components configured with an empty Source may
require access to Windows servicing sources.

Before running a WinGet installer, the script verifies the copied file's SHA256
against `PAWApplication.json`. Mismatch, missing/invalid hash or inconsistent
installer metadata prevents execution and reports the application, file and
corrective action; mismatches include expected and actual hashes. Download again
on the host with `Invoke-PAWApplicationDownload.ps1 -Name '<Name>' -Force` and
restage the application. The deployment engine reports the application failure
and continues with other applications, marking the PAW as incompletely configured.
Already-installed applications are skipped without executing their cache.
Local installers and PSGallery modules retain their existing behavior. This check
verifies integrity since download, not publisher authenticity.

The installer is stored at `Resources\Applications\Invoke-PAWInstallApplications.ps1`
on the host. `New-PAWVM.ps1` selectively stages only the chosen applications'
metadata, cache files and payloads, plus the shared `PAWUtility` module, to the
following guest paths independently of **Copy Folder**:

```text
C:\PAWFiles\AppInstall\Invoke-PAWInstallApplications.ps1
C:\PAWFiles\AppInstall\Applications.json   the application list
C:\PAWFiles\AppInstall\Applications\
    <Application name>.json      install file (Settings and Installer)
C:\PAWFiles\AppInstall\Downloads\
    WinGet\<Application name>\   installer, WinGet manifest, PAWApplication.json
    Modules\<Module>\<Version>\  PowerShell modules
C:\PAWFiles\AppInstall\Local\
    <Application name>\          installer of a Local application
C:\PAWFiles\AppInstall\Packages\
    <ApplicationId>\             Classic and manually supplied offline resources
C:\PAWFiles\Functions\PAWUtility\
```

---

## How New-PAWVM.ps1 Uses It

Application handling is enabled when the template `Application` setting is not
`False` and `-SkipApplication` is not used. Application definitions and resources always come from fixed folders below
`Resources`; `-ExtraFolder` does not select the application source.

1. **Before the VM is created**, `New-PAWVM.ps1` runs `Invoke-PAWApplicationDownload.ps1` against `Resources\ApplicationCatalog` and `Resources\ApplicationDownloads`. Missing installers or download errors warn and appear in the final report; an existing cache can still be staged. `-WhatIf` skips downloads.
2. **While the image is mounted**, only selected AppInstall content and PAWUtility are staged at the paths above. Unrelated existing destination content is refused rather than overwritten. Staging failure warns and prevents application installation.
3. **After security configuration and RunScript**, the host uses its frozen bundle
   plan and invokes `Invoke-PAWInstallApplications.ps1 -Name <application>` in the
   VM in bundle order, including modules, Classic applications and components.
   Output is logged with the application name.
4. Microsoft Security Baselines are attempted after the applications.

If an installation fails, deployment logs/reports the package name and reason
and continues to the next package and later optional stages.

---

## Typed Classic applications and Windows components

Schema 2 Classic definitions use a package-relative executable/script,
arguments, working directory, timeout and explicit success exit codes.
A Path detection rule skips an existing installation and verifies completion.
Scripts run in the guest; the host never evaluates the command. Configure
silent/no-restart arguments yourself. No reboot is triggered by the reserved
RestartRequired metadata.

Windows components use the guest's native Capability, OptionalFeature or
ServerFeature cmdlets, detect existing state and verify enabled/installed state.
Client/server compatibility and component names are checked on that guest.
Offline sources must match the target OS build, architecture and language.
Use LimitAccess with a local source for capabilities/optional features to prevent
Windows Update access. ServerFeature does not support LimitAccess.

See [Application Manager](ApplicationManager.md#application-types) for the full
configuration contract and offline RSAT example.

## How an Application Is Installed

For each WinGet and Local application, the script:

1. Reads the install file `AppInstall\Applications\<Name>.json` (see [Install Files](#install-files)) and checks that the installer exists in `Downloads\WinGet\<Name>` (WinGet) or `Local\<Name>` (Local).
2. Checks whether the application is already installed, and skips it if so:
   - If `Settings.InstallCheckPaths` is set, the application is installed when one of the paths exists.
   - Otherwise, if `Installer.ProductCode` is set, the application is installed when that product code is registered under the 64-bit or 32-bit Uninstall registry key.
3. Builds the install command from the installer type (`Get-PAWWinGetInstallCommand` in the `PAWUtility` module):

| Installer type | How it is installed |
|---|---|
| `msi`, `wix` | `msiexec.exe /i "<installer>" <silent> <custom> <MsiProperties>` |
| `burn`, `inno`, `nullsoft`, `exe` | Runs the installer with `<silent> <custom>` |
| `msix`, `appx` | `Add-AppxProvisionedPackage -Online -SkipLicense` |
| `zip` with nested `portable` | Extracts the files to `DestinationPath` (default `%ProgramFiles%\<Name>`) and checks that the `NestedInstallerFiles` exist |
| `zip` with another nested type | Extracts the archive and runs the nested installer from `NestedInstallerFiles` |
| `portable` | Copies the file to `DestinationPath` |

The silent switches are taken from, in this order:

1. `Settings.SilentArguments`
2. `Installer.SilentArguments`, which the download stage takes from `InstallerSwitches.Silent` in the WinGet manifest, or from the WinGet default for the installer type: `/quiet /norestart` for `msi`, `wix` and `burn`, `/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART` for `inno`, and `/S` for `nullsoft`

`Installer.CustomArguments` (from the manifest) and `Settings.CustomArguments` are added after the silent switches. An `exe` installer without silent switches fails with a message to set `SilentArguments` in `Settings`.

4. Runs the installer and checks the exit code against `Installer.SuccessExitCodes`. The download stage builds them from `0`, `InstallerSuccessCodes` in the manifest, and `ExpectedReturnCodes` with the response `alreadyInstalled`, `rebootRequiredToFinish` or `rebootInitiated`. For `msi`, `wix` and `burn`, `1641` and `3010` are also success codes. A restart required by an installer (`Installer.RebootExitCodes`) is logged; the PAW is restarted later in the deployment.
5. If `Settings.PostInstallKillProcess` is set, the script waits for those processes to start after the installer, stops them, and then waits for the installer to exit. Use it for installers that start the application at the end of the installation.

---

## How Modules Are Installed

With `-ModulesOnly` (or when no `-Name` is used), the enabled `PSGallery` applications are installed:

Schema 2 modules additionally select an exact version or Latest, local versus
PSGallery origin and the destination runtime. PowerShell 7 modules use the
PowerShell 7 module directory and require that runtime in the guest. Place the
PowerShell 7 application earlier in the bundle when it must be installed first.
The following legacy defaults still apply to schema 1 module definitions:

1. For each module, the latest version in `Downloads\Modules\<Module>` is selected, and the `RequiredModules` in its manifest are added (recursively).
2. Each module version is copied to `%ProgramFiles%\WindowsPowerShell\Modules\<Module>\<Version>`. Versions that already exist are skipped.
3. The script checks that each module is listed by `Get-Module -ListAvailable`.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-CacheRoot` | String | `<script folder>\Downloads` (`C:\PAWFiles\AppInstall\Downloads` in the PAW) | Root folder of the download cache. |
| `-ApplicationsPath` | String | `<CacheRoot>\..\Applications.json` (`C:\PAWFiles\AppInstall\Applications.json`) | Application list. |
| `-Name` | String | All enabled applications | Install only this application. Alias: `-PackageName`. |
| `-ModulesOnly` | Switch | Off | Install only the enabled PowerShell modules. Cannot be combined with `-Name`. |

Without `-Name` and `-ModulesOnly`, the script installs every enabled application and then the enabled modules.

---

## Install Files

`Applications.json` only lists which applications are wanted; `InstallEnabled` (`true` or `false`) controls whether an application is installed. See [Invoke-PAWApplicationDownload.md](Invoke-PAWApplicationDownload.md#applicationsjson).

How a WinGet or Local application is installed is kept in its own install file, `<PAWFiles>\AppInstall\Applications\<Name>.json`. `Invoke-PAWApplicationDownload.ps1` creates or updates it on every download. The file has two sections:

- **`Settings`** - edited by you and never overwritten by the download. Missing settings are added with empty values.
- **`Installer`** - written from the WinGet manifest on every download. Do not edit it.

`Settings`:

| Setting | Description |
|---|---|
| `InstallCheckPaths` | Files or folders that show the application is already installed. Environment variables such as `%ProgramFiles%` are expanded in the PAW. |
| `SilentArguments` | Replaces the silent switches from the WinGet manifest. |
| `CustomArguments` | Extra arguments added after the silent switches. |
| `MsiProperties` | MSI/WiX only. Properties added to the `msiexec` command line. |
| `PostInstallKillProcess` | Process names to stop after the installer starts them. |
| `DestinationPath` | Zip/portable only. Folder for the files. Default `%ProgramFiles%\<Name>`. |

`Installer`:

| Property | Description |
|---|---|
| `Version` | Downloaded version |
| `InstallerType`, `NestedInstallerType`, `NestedInstallerFiles` | Installer technology, and for a zip, what is inside it |
| `InstallerFile`, `ManifestFile` | File names in `Downloads\WinGet\<Name>` |
| `ProductCode` | Used to detect an existing installation when `InstallCheckPaths` is empty |
| `SilentArguments`, `SilentSource` | Silent switches and where they come from (`WinGet manifest` or `WinGet default for <type>`) |
| `CustomArguments` | `InstallerSwitches.Custom` from the manifest |
| `SuccessExitCodes`, `RebootExitCodes` | Exit codes treated as success, and the ones that mean a restart is required |

Example (`PowerShell 7.json`):

```json
{
  "Name": "PowerShell 7",
  "Source": "WinGet",
  "Id": "Microsoft.PowerShell",
  "Settings": {
    "InstallCheckPaths": [ "%ProgramFiles%\\PowerShell\\7\\pwsh.exe" ],
    "SilentArguments": "",
    "CustomArguments": "",
    "MsiProperties": [ "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1", "ENABLE_PSREMOTING=1", "REGISTER_MANIFEST=1" ],
    "PostInstallKillProcess": [],
    "DestinationPath": ""
  },
  "Installer": {
    "Version": "7.6.7.0",
    "InstallerType": "wix",
    "NestedInstallerType": "",
    "NestedInstallerFiles": [],
    "InstallerFile": "PowerShell_7.6.7.0_Machine_X64_wix_en-US.msi",
    "ManifestFile": "PowerShell_7.6.7.0_Machine_X64_wix_en-US.yaml",
    "ProductCode": "{B6950B97-25F0-4EB3-9FC8-DB5D085645DE}",
    "SilentArguments": "/quiet /norestart",
    "SilentSource": "WinGet manifest",
    "CustomArguments": "",
    "SuccessExitCodes": [ 0, 1638, 1641, 3010 ],
    "RebootExitCodes": [ 1641, 3010 ]
  }
}
```

PAWDeploy ships install files with `Settings` for the default applications. Upgrades with `Install-PAWDeploy.ps1` do not overwrite existing install files.

---

## Examples

Run these inside a PAW, as administrator, after the `PAWFiles` folder has been copied to `C:\PAWFiles`.

```powershell
# Install every enabled application and module
C:\PAWFiles\AppInstall\Invoke-PAWInstallApplications.ps1

# Install one application
C:\PAWFiles\AppInstall\Invoke-PAWInstallApplications.ps1 -Name '7-Zip'

# Install only the PowerShell modules
C:\PAWFiles\AppInstall\Invoke-PAWInstallApplications.ps1 -ModulesOnly
```

To add an application, add it to `Applications.json` and download it with `Invoke-PAWApplicationDownload.ps1` (see [Add an application](Invoke-PAWApplicationDownload.md#add-an-application)). The download creates its install file; edit `Settings` in it if needed. The next deployment installs it.

---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `Applications.json not found` | The resolved application snapshot is missing from the guest AppInstall folder. | Verify that application staging completed successfully and that `C:\PAWFiles\AppInstall\Applications.json` exists. |
| `Install file not found` or `has no Installer information` | The application was added or enabled after the last download | Run `Invoke-PAWApplicationDownload.ps1 -Name '<Name>'`. |
| `Installer not found` | The download cache does not match the install file | Run `Invoke-PAWApplicationDownload.ps1 -Name '<Name>' -Force`. |
| `Failed to install <Name>. Installer exit code: <code>` | The installer failed | Check the exit code against `Installer.SuccessExitCodes` in the install file. Set `SilentArguments` or `CustomArguments` in `Settings` if the manifest switches do not work for this installer. |
| `No silent install switches` | An `exe` installer has no silent switches in its manifest | Set `SilentArguments` in `Settings` in the install file. |
| An application is skipped as already installed | A `Settings.InstallCheckPaths` path exists, or `Installer.ProductCode` is registered | Check the paths in the install file. |
| The installer hangs after the application opens | The installer started the application and waits for it | Add the process name to `Settings.PostInstallKillProcess`. |
| `Module <Name> is still not available after copying from cache` | The module destination is not in `$env:PSModulePath` | Check `%ProgramFiles%\WindowsPowerShell\Modules` and the `[Modules]` lines in the deployment log. |

---

## Related Documents

- [Invoke-PAWApplicationDownload.md](Invoke-PAWApplicationDownload.md) - `Applications.json` and the download stage
- [Invoke-PAWApplicationSettings.md](Invoke-PAWApplicationSettings.md) - command-line editor for `Applications.json`
- [New-PAWVM.md](New-PAWVM.md) - deployment workflow
- [PAWUtility.md](PAWUtility.md) - `Get-PAWApplicationInstallFile`, `Get-PAWWinGetInstallCommand` and the other application helpers
