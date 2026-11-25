et.-# Application Manager

## Architecture

See [Commandline Samples](CommandlineSamples.md) for an end-to-end example that imports one application, creates a bundle and assigns it to a deployment template.

`PAWApplicationManager` owns application definitions, bundles, validation and
portable JSON import/export. `Tools\Invoke-PAWApplicationManager.ps1` is the
command-line entry point. `Tools\PAWApplicationManagerUI.ps1` opens the Windows
Forms manager; its GUI helpers live in `PAWUIUtility` and invoke the **same CLI
script** for every data operation. No console-text parsing or separate GUI
business logic is used.

Both editions include the manager. Open **Applications / Bundles** in the menu
or run:

```powershell
.\Tools\PAWApplicationManagerUI.ps1
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ListApplications
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ListBundles
```

The menu's PowerShell console also loads `PAWApplicationManager`, providing
`Get-PAWApplication`, `Get-PAWApplicationBundle`, `Get-PAWCachedApplication`,
`New-PAWApplicationBundle` and `Add-PAWApplicationToBundle`. See the pipeline
and installation-order examples in [Commandline Samples](CommandlineSamples.md#create-an-application-bundle).
`Get-PAWCachedApplication` reports folders with local files, including
unmatched folders; it does not verify that those files are complete or usable.
`Remove-PAWApplication` blocks removal while any bundle references the
application. `Remove-PAWApplicationBundle` blocks template assignments.
`Remove-PAWApplicationFromBundle` removes assignments without deleting the
applications or changing the remaining order.
`Remove-PAWCachedApplication` removes the selected cache or package folder,
including manually supplied files, without removing catalog definitions.
`Export-PAWApplication` and `Export-PAWApplicationBundle` produce portable
packages compatible with the matching import commands. Application export
filenames include the application name and ID, for example `7-Zip--<id>.json`;
characters invalid in filenames are replaced with underscores. Both commands use
the existing `Export-PAWApplicationPackage` format. `Export-PAWCachedApplication`
and `Import-PAWCachedApplication` transfer complete cache folders separately,
including orphaned and manual files, without creating catalog entries. Restoring
with `-Replace` replaces the entire existing cache folder.
Use `-WhatIf` to preview. The older `Remove-PAWManagedApplication` retains its
previous behavior of removing an application from its bundles.

The manager opens at 1344 x 756 pixels with the same minimum size as the other
main PAWDeploy windows. Applications and Bundles each have a single row of
compact action buttons.

## Storage

Application storage is fixed under the installation's `Resources` folder and is
independent of Copy Folder:

```text
Resources\
  ApplicationCatalog\<SafeName>--<ApplicationId>.json  Persistent application definitions and Settings
  ApplicationBundles\<BundleId>.json                    Ordered references to application IDs
  ApplicationDownloads\WinGet\<Name>\                   Installer, manifest and recorded SHA256
  ApplicationDownloads\Modules\                         PSGallery modules
  ApplicationDownloads\Local\<Name>\                    Operator-provided local installers
  Applications\InstallFiles\<Name>.json                 Generated install metadata
  Applications\Packages\<ApplicationId>\                Classic and offline application payloads
  Applications\Invoke-PAWInstallApplications.ps1        Guest installer entry point
  CustomScripts\                                         Imported deployment scripts
```

The former maintained `Applications.json` list is replaced, not migrated.
The shipped nine applications are individual catalog definitions referenced by
`Default`. `Applications.json` is now generated **inside the staged guest
payload only**, recording the resolved bundle and application list for that build.
Changing an override never rewrites the host catalog or template.

New applications use schema 2 with a type-specific Configuration:

```json
{
  "SchemaVersion": 2,
  "ApplicationId": "0fb0bced-b99c-4330-b62e-9ebd3c918d23",
  "Type": "WinGet",
  "Enabled": true,
  "RestartRequired": false,
  "Definition": {
    "Name": "7-Zip",
    "Type": "WinGet",
    "InstallEnabled": true,
    "Configuration": {
      "Id": "7zip.7zip",
      "Architecture": "x64",
      "Scope": "Machine",
      "InstallerType": "NA"
    }
  },
  "Settings": {
    "InstallCheckPaths": ["%ProgramFiles%\\7-Zip\\7z.exe"]
  }
}
```

ApplicationId and BundleId are non-empty GUIDs in standard hyphenated format.
Creation generates them automatically when omitted; replacement requires an ID.
Catalog filenames use a sanitized display name followed by `--` and the stable
ApplicationId, for example `7-Zip--0fb0bced-b99c-4330-b62e-9ebd3c918d23.json`.
The name makes files easy to identify in Explorer; the GUID remains the identity
used by bundles, imports and deployment. Older `<ApplicationId>.json` catalog
files remain readable until migrated.
Import/export preserve IDs and bundle references. Names and WinGet package IDs
are separate from these internal identities. Legacy IDs are not accepted:
the repository files/references are converted, but installed copies are not migrated.
IDs and display names are immutable
in the editor. Create a separate definition to change identity; names also
identify cache/install files. Duplicate names or normalized cache filenames
are rejected.

Schema 1 WinGet/PSGallery/Local definitions remain readable. Schema 2 separates
common identity/state from type-specific settings rather than requiring irrelevant
WinGet fields for Windows components or scripts. `Settings` supports `InstallCheckPaths`, `SilentArguments`,
`CustomArguments`, `MsiProperties`, `PostInstallKillProcess` and `DestinationPath`.
Edit these in the catalog, not generated installation metadata. Environment
variables remain unexpanded until installation in the guest.

`RestartRequired` is a top-level JSON boolean, defaulting to `false` when absent.
It is saved and preserved by import/export, shown as **Restart Required** in the
application list, and offered as a checkbox during WinGet creation. Edit it in
the application definition JSON for existing apps. CLI WinGet creation accepts
`-RestartRequired $true`. This is future-facing metadata only: it is not passed
to the installer and does not change reboot behavior, execution order or batching.

## Create and edit applications

WinGet discovery requires the structured `Microsoft.WinGet.Client` PowerShell
module (`Install-Module Microsoft.WinGet.Client`). Downloading continues to use
the existing WinGet CLI; these are separate prerequisites.
Only WinGet discovery requires Microsoft.WinGet.Client. The manager can open and
manage modules, Classic applications and Windows components without it. If WinGet
discovery is unavailable, its action reports this installation command:

```powershell
Install-Module Microsoft.WinGet.Client -Scope CurrentUser -Repository PSGallery
```

Retry WinGet discovery after installation. Headless catalog, bundle and
deployment operations do not require WinGet discovery; the CLI exposes the
same optional dependency check with `-Action TestPrerequisites`.
When launched from PAWMenu, startup errors are centered on the menu's screen,
including layouts with negative monitor coordinates.
The startup error text is read-only but selectable: mark the installation
command and press Ctrl+C, or use Ctrl+A followed by Ctrl+C to copy all details.

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Search -Query '7-Zip'
.\Tools\Invoke-PAWApplicationManager.ps1 -Action NewWinGet `
    -Id Notepad++.Notepad++ -Architecture x64 -Scope Machine
```

Creation resolves one exact package identity, saves a definition, and does not
download or execute its installer. Architecture, scope and installer type are
explicit operator choices; `NA` lets WinGet choose at download time.
The generated GUID is independent of `Notepad++.Notepad++`, which remains the
WinGet ID. The display name remains `Notepad++`. GUI lists show names first.

For other types, obtain an unsaved typed seed, configure it and save:

```powershell
$app = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type PowerShellModule -Name 'Active Directory tools'
$app.Definition.Configuration.Id = 'Example.Module'
$app.Definition.Configuration.Version = '1.2.3'
$saved = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication -InputObject $app
.\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication -InputObject $saved -Replace
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Disable -ApplicationId $saved.ApplicationId
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Enable -ApplicationId $saved.ApplicationId
```

Global `Enabled=false` removes the app from every resolved bundle.
`Enabled` controls downloading; `InstallEnabled` controls guest installation.
A disabled app cannot be re-enabled by a bundle or download name filter.
Build preparation downloads only enabled members of the template's assigned
bundle (or the explicit build override). Standalone precaching without a bundle
downloads every enabled catalog application, including unassigned applications.
The former `DownloadEnabled` property is removed from the definition schema;
explicit catalog conversion also removes it from older WinGet/module definitions.

## Application types

| Type | Configuration |
|---|---|
| `WinGet` | `Id`, `Architecture`, `Scope`, `InstallerType`; uses existing manifest/cache installation |
| `PowerShellModule` | `Id`, `Version` (`Latest` or exact numeric version), `Runtime` (`WindowsPowerShell` or `PowerShell7`), `Origin` (`PSGallery` or `Local`) |
| `Classic` | `FolderPath`, `Executable`, `Arguments`, `WorkingDirectory`, `SuccessExitCodes` (integer array), `TimeoutSeconds`, optional `Detection` (`Kind=PowerShell`, `ScriptPath`) |
| `WindowsComponent` | `Kind` (`Capability`, `OptionalFeature`, `ServerFeature`), `Names` (array), `Source` (package-relative folder or empty for online), `LimitAccess` (boolean) |

Use **New** to select a type in the GUI. Configuration is validated
through the same CLI used by automation. Existing definitions retain their GUIDs
and bundle assignments.
The type picker uses Segoe UI 10-point text and padded rows so all four choices
are easy to read without scrolling.
Assign uses the same typography, text-sized padded rows and outer margins for
both bundle and template lists.
Application field dialogs show field names on the left and inputs on the same row
in an aligned right-hand column. Folder and detection-file Browse/Clear buttons
sit below their inputs.
The toolbar uses the shared 200 x 30-pixel button size and wraps onto a second
row when needed. On the Applications tab, New is the leftmost button and uses the
shared orange accent; Refresh follows it. The Bundles tab likewise starts with
an orange New bundle button, followed by Refresh.
WinGet creation is available through New rather than a separate
New WinGet toolbar button. Catalog conversion is available through the CLI only;
the Convert catalog toolbar button has been removed.
New WindowsComponent drafts have no component names selected; enter the actual
capability/feature names before saving. RSAT is an example, not a default.
For `Kind=Capability`, Names also accepts `*` and `?` wildcards, such as `RSAT*`.
Patterns are resolved with `Get-WindowsCapability -Online -Name <pattern>` in
the guest, never on the build host. Overlapping matches are installed only once;
a pattern with no matches fails before any capability installation begins.
`OptionalFeature` and `ServerFeature` still require explicit names.
The Source field is read-only: **Browse...** selects a folder whose contents are
copied (including subfolders and hidden files) to `Packages\<ApplicationId>\Source`
when saving. The definition stores `Source`, not the original host path, so the
files follow the application during export and deployment. Cancelling leaves
the catalog and payload unchanged. Replacing a source replaces its files; a
failed definition write restores the previous source. **Clear** selects online
installation (also turn off LimitAccess); existing cached files are retained.

The equivalent CLI save uses `-SourceFolder` with
`$app.Definition.Configuration.Source = 'Source'`. The selected folder must be
non-empty and must not overlap the destination or contain the application store.
No component installation runs on the build host.

### Classic applications

**FolderPath / Browse...** selects a source folder, not an installer file.
On save, its contents (including subfolders and hidden files) are copied to
`Resources\Applications\Packages\<ApplicationId>`, then selectively staged into
`C:\PAWFiles\AppInstall\Packages` for the deployment.
The saved `FolderPath` is `.` (relative to that package), never the original host
path. For CLI saves, set `Configuration.FolderPath = '.'` and supply
`-SourceFolder 'C:\Media\MyApplication'`. The folder must exist, contain files and
not overlap the destination or contain the store. Replacing the folder replaces
its contents; a failed definition write restores the previous payload.

**Executable** is what runs: for example `cmd.exe`, `Install.exe`,
`msiexec.exe`, a PowerShell script, another command on the guest's PATH, or an
absolute guest executable path. Package-relative executables are resolved from
FolderPath before searching PATH. **Arguments** contains only the switches.
Use `%App%` (case-insensitive) to reference the copied folder, for example:

```text
Executable: msiexec.exe
Arguments:  /i "%App%\install.msi" /qn /norestart
```

Quote paths that may contain spaces. `%App%` and environment variables are
expanded in Executable and Arguments inside the PAW, not on the build host.
WorkingDirectory defaults to `.` and is relative to FolderPath; relative paths
cannot traverse outside their root. Commands are started as processes, not
evaluated as PowerShell expressions. Set silent/no-restart arguments yourself.
RestartRequired remains metadata-only.

**DetectionScript / Browse...** selects an optional `.ps1` file inside the
selected FolderPath (or the copied application folder when editing). For example,
selecting `Checks\Detect.ps1` stores `%App%\Checks\Detect.ps1`, not a host path.
The file is copied and exported with the rest of the application. Files outside
the application folder, traversal paths and missing detection files are rejected.
**Clear** disables detection.

The script must output exactly one Boolean: `$true` means installed (skip),
`$false` means not installed (run the command). Example contents of `Detect.ps1`:

```powershell
Test-Path -LiteralPath "$env:ProgramFiles\Vendor\Application.exe"
```

The script file runs only in the guest; `$App` contains the copied folder path,
and `$PSScriptRoot` refers to the detection script's directory.
When provided, detection is checked again after a successful installer exit and
must then return `$true`. Script errors and non-Boolean/multiple results fail
explicitly. Leave it empty to let the application handle existing installations;
only the exit code is checked. JSON/CLI definitions can omit `Detection`, set it
to `null`, or use `@{ Kind = 'PowerShell'; ScriptPath = '%App%\Checks\Detect.ps1' }`.

Existing Classic definitions using `FilePath` and `Kind=Path` detection remain
supported without automatic conversion and open in the JSON editor. Earlier
inline `Detection.Script` definitions also retain their behavior in the JSON editor.

For a local PowerShell module, place versioned module directories and dependencies
under `Packages\<ApplicationId>\<Module>\<Version>\<Module>.psd1`.
Choose the target PowerShell runtime explicitly.

Offline RSAT uses `WindowsComponent` with `Kind=Capability`, a copied local FoD
repository and `LimitAccess=true`; see the [offline RSAT example](#rsat-tools---offline-windowscomponent).
Optional features use their own OS names and
matching feature source media. `ServerFeature` is Windows Server-only and does
not support `LimitAccess`; unsupported combinations fail explicitly. Component
availability is checked against the guest OS, never inferred from the build host.
Host preflight validates payload resources, not component availability in an
unbooted target OS. Guest compatibility errors therefore surface during the
installation stage and are reported as application failures.

## Application examples

Run the CLI examples from the PAWDeploy installation root. They create catalog
definitions; they do not install applications on the build host. The Classic
example also copies its source folder when saving. If an application with the
same name already exists, edit it instead of creating another definition.

### Advanced IP Scanner - WinGet

In **Applications**, click **New**, select **WinGet Application**, search for
`Advanced IP Scanner`, and select the exact package ID
`Famatech.AdvancedIPScanner`.

| Field | Value |
|---|---|
| Name | `Advanced IP Scanner` |
| Architecture | `x86` |
| Scope | `Machine` |
| InstallerType | `NA` |
| Restart Required | Unchecked |

The [published WinGet manifest](https://github.com/microsoft/winget-pkgs/tree/master/manifests/f/Famatech/AdvancedIPScanner)
provides an x86 installer, which can also run on a 64-bit Windows PAW. Do not
select x64 just because the guest OS is x64; choose an architecture supplied by
the package.

Equivalent CLI:

```powershell
$ipScanner = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewWinGet `
    -Id Famatech.AdvancedIPScanner -Name 'Advanced IP Scanner' `
    -Architecture x86 -Scope Machine -InstallerType NA
```

WinGet discovery requires Microsoft.WinGet.Client as described above. The
installer and its metadata are downloaded during application preparation.

### Az.Accounts - PowerShell Module

Click **New**, select **PowerShell Module**, and enter:

| Field | Value |
|---|---|
| Name | `Az.Accounts` |
| Id | `Az.Accounts` |
| Version | `Latest` |
| Runtime | `WindowsPowerShell` |
| Origin | `PSGallery` |

Equivalent CLI:

```powershell
$moduleDraft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type PowerShellModule -Name 'Az.Accounts'
$moduleDraft.Definition.Configuration.Id = 'Az.Accounts'
$moduleDraft.Definition.Configuration.Version = 'Latest'
$moduleDraft.Definition.Configuration.Runtime = 'WindowsPowerShell'
$moduleDraft.Definition.Configuration.Origin = 'PSGallery'
$azAccounts = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $moduleDraft
```

[Az.Accounts on PowerShell Gallery](https://www.powershellgallery.com/packages/Az.Accounts)
supports Windows PowerShell 5.1. Preparation downloads the module and required
dependencies, and deployment copies them into the guest's Windows PowerShell
module directory. To target PowerShell 7 instead, choose `PowerShell7` and ensure
that runtime is already installed in the guest. Use an exact tested module
version instead of `Latest` when a fixed version is required. Installing the
module does not authenticate to Azure or create an account connection.

### Adobe Acrobat Reader - Classic

Obtain an Adobe Reader **offline installer**, not a web downloader. In this
example its filename is renamed to `ReaderSetup.exe`. Keep any accompanying
installation files in the same source folder:

```text
C:\Media\AcrobatReader\
  ReaderSetup.exe
  Detection\
    Detect.ps1
```

Click **New**, select **Classic Application**, and use:

| Field | Value |
|---|---|
| Name | `Adobe Acrobat Reader` |
| FolderPath | Browse to `C:\Media\AcrobatReader` |
| Executable | `%App%\ReaderSetup.exe` |
| Arguments | `/sAll /rs /msi /qn /norestart EULA_ACCEPT=YES` |
| WorkingDirectory | `.` |
| TimeoutSeconds | `1800` |
| SuccessExitCodes | `0, 3010` |
| DetectionScript | Browse to `Detection\Detect.ps1` inside the selected folder |

These [Adobe bootstrapper switches](https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/cmdline.html)
request silent installation and suppress restart; the switches after `/msi` are
passed to Windows Installer. Use `EULA_ACCEPT=YES` only when authorized to accept
Adobe's license terms. Confirm the switches against the offline package you use.

For a current 64-bit Reader package, example contents of `Detection\Detect.ps1`:

```powershell
return (Test-Path -LiteralPath "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe" -PathType Leaf)
```

Adjust detection to your installer and required version. This simple executable
check also matches the full Acrobat product; use a product/version-specific
check if that distinction matters. Older or 32-bit Reader packages may use
`Acrobat Reader DC\Reader\AcroRd32.exe` under Program Files or Program Files (x86).
The file must return exactly one Boolean, without extra output.

Equivalent CLI, after preparing the folder and detection file:

```powershell
$readerDraft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type Classic -Name 'Adobe Acrobat Reader'
$readerDraft.Definition.Configuration.FolderPath = '.'
$readerDraft.Definition.Configuration.Executable = '%App%\ReaderSetup.exe'
$readerDraft.Definition.Configuration.Arguments = '/sAll /rs /msi /qn /norestart EULA_ACCEPT=YES'
$readerDraft.Definition.Configuration.WorkingDirectory = '.'
$readerDraft.Definition.Configuration.TimeoutSeconds = 1800
$readerDraft.Definition.Configuration.SuccessExitCodes = @(0, 3010)
$readerDraft.Definition.Configuration.Detection = [pscustomobject]@{
    Kind = 'PowerShell'
    ScriptPath = '%App%\Detection\Detect.ps1'
}
$reader = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $readerDraft -SourceFolder 'C:\Media\AcrobatReader'
```

Saving copies the entire source folder to `Packages\<ApplicationId>` and stores
`FolderPath = '.'` and the relative detection path, never the original host path.
`%App%` resolves to that copied folder in the guest. Detection is optional:
leave the GUI field empty, or set `Configuration.Detection = $null`, to let the
installer handle existing installations itself.

### RSAT tools - offline WindowsComponent

This example installs Active Directory, Group Policy, DNS and DHCP management
tools on a Windows 11 x64 Pro or Enterprise PAW without downloading components
from Windows Update. RSAT is a Windows capability, not a WinGet package or
PowerShell Gallery module.

#### Prepare the offline source

1. Obtain Microsoft's **Windows 11 Languages and Optional Features ISO** for
   the target Windows release and architecture before deploying the offline PAW.
   For example, a Windows 11 24H2 x64 guest needs matching 24H2 x64 media.
   The regular Windows installation ISO's `sources\sxs` folder is not the RSAT
   FoD repository.
2. Extract the complete `LanguagesAndOptionalFeatures` repository to, for
   example, `C:\Media\Windows11-FoD\LanguagesAndOptionalFeatures`.
   Preserve all repository metadata, subfolders, dependency packages and
   language satellites. Do not select only the CAB files whose names contain
   RSAT: Active Directory tools also depend on Server Manager tools.
3. Use that folder as the application's **Source**. Application Manager copies
   its contents into `Packages\<ApplicationId>\Source`, so the guest does not
   need the original host folder, mounted ISO or a network share.

For a smaller source, create a supported repository using DISM `/Export-Source`
rather than manually collecting CAB files. See Microsoft's
[Features on Demand guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11)
for repository requirements and
[RSAT capability names and dependencies](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11#remote-server-administration-tools-rsat).

#### Add the application

In **Applications**, click **New**, select **WindowsComponent**, and enter:

| Field | Value |
| --- | --- |
| Name | `RSAT Tools - Offline` |
| Kind | `Capability` |
| Names | `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0, Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0, Rsat.Dns.Tools~~~~0.0.1.0, Rsat.DHCP.Tools~~~~0.0.1.0` |
| Source | **Browse...** to `C:\Media\Windows11-FoD\LanguagesAndOptionalFeatures` |
| LimitAccess | `True` (checked) |

`LimitAccess = true` prevents DISM from contacting Windows Update. If a required
package is missing from the local repository, installation fails instead of
falling back to a download. Do not **Clear** Source or turn off LimitAccess for
this offline application.

The equivalent CLI creation, run from the PAWDeploy installation folder, is:

```powershell
$rsatDraft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type WindowsComponent -Name 'RSAT Tools - Offline'
$rsatDraft.Definition.Configuration.Kind = 'Capability'
$rsatDraft.Definition.Configuration.Names = @(
    'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
    'Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0'
    'Rsat.Dns.Tools~~~~0.0.1.0'
    'Rsat.DHCP.Tools~~~~0.0.1.0'
)
$rsatDraft.Definition.Configuration.Source = 'Source'
$rsatDraft.Definition.Configuration.LimitAccess = $true
$rsat = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $rsatDraft `
    -SourceFolder 'C:\Media\Windows11-FoD\LanguagesAndOptionalFeatures'
```

Saving only packages the source; installation runs inside the guest during
deployment. Already installed capabilities are skipped. The runtime uses
`Add-WindowsCapability -Online -Source <copied-source> -LimitAccess`:
**`-Online` means the running guest OS, not an Internet connection.**
Add or remove explicit capability names to select other RSAT tools; do not use
wildcards for optional features or server features.

To install **all available RSAT capabilities**, set the GUI **Names** field to
`RSAT*`, or replace the CLI Names assignment above with:

```powershell
$rsatDraft.Definition.Configuration.Names = @('RSAT*')
```

The guest expands `RSAT*` using `Get-WindowsCapability -Online -Name RSAT*`
and installs each matching capability by its full name, skipping installed ones.
Keep the complete matching FoD repository and `LimitAccess = true` for offline
installation; wildcard selection does not download missing source packages.

After saving each example, select the application and click **Assign** to add
it to a bundle. On **Bundles**, assign that bundle to a deployment template.
Creating an application alone does not add it to a template's deployment plan.

## Explicit catalog conversion

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ConvertCatalog
```

Conversion validates first, backs up `ApplicationCatalog` and `ApplicationBundles`
under `Resources\Backups\Schema2-...`, verifies backup hashes and converts
WinGet/PSGallery definitions to schema 2 while renaming legacy GUID-only catalog
files to the readable name-plus-GUID format. Application IDs, state, Settings
and bundle references remain unchanged. Failure restores original files. No conversion runs automatically
when opening the manager. Legacy Local installers remain supported; conversion
reports them for manual Classic configuration because a reliable command and
detection rule cannot be inferred. The obsolete DownloadEnabled field is cleaned
from these retained schema 1 Local definitions as part of the backed-up operation.
No files in other installations are changed.

## Bundles and template assignment

On **Applications**, select an application and click **Assign** to choose an
existing bundle. The application is appended to that bundle's installation order;
existing members and other bundles are retained. Assigning an existing member
shows an informational message and does not add a duplicate. Cancel leaves all
bundles unchanged. Create a bundle first if none exist.

On **Bundles**, **Assign** continues to link the selected bundle to a template.

```powershell
$bundle = [pscustomobject]@{
    SchemaVersion = 1
    Name = 'Azure administrators'
    Applications = @(
        '3af78a0c-aef4-4a8b-a39a-f5d3d7288787'
        '7ea6957c-51d3-4346-9178-e5317c6480af'
        'e452f3e3-25e1-4d4f-af55-3bd2d5ef61ce'
        'd50ad50b-c250-49ef-a8c9-6a6a32a31eaa'
    )
}
$savedBundle = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveBundle -InputObject $bundle
.\Tools\Invoke-PAWApplicationManager.ps1 -Action AssignBundle `
    -BundleId $savedBundle.BundleId -TemplateName 'Windows 11 x64 PAW for WORKGROUP ON'
```

Bundles contain ordered application IDs, not copied definitions. The order of
the `Applications` array is the installation order: the first application is
installed first. Nested bundles are not supported.

Bundle names must be unique, ignoring case and surrounding whitespace. Creating,
renaming or importing a bundle with another bundle's name fails, even with
`-Replace`; replacing the same bundle by ID is supported. Bundles that already
share a name remain available by ID. Rename or remove the extras before saving
a bundle with that name. Check template assignments before removing a bundle;
an assigned bundle cannot be removed. Concurrent bundle writes are prevented;
if the bundle write lock is in use, retry the operation.

When saving a bundle, repeated application IDs are reported and skipped; other
applications are still saved in order. When reading an older bundle containing
duplicates, the manager warns and returns only the first occurrence of each
ID. The file is unchanged until the returned bundle is saved with `-Replace`.
Imported packages with duplicate bundle references remain invalid.

In the GUI, **Bundles > New bundle** or **Edit** opens the bundle editor:

- **Available applications** lists catalog applications that are not in the
  bundle.
- **Installation order** lists bundle members numbered `1.`, `2.`, ... from
  top to bottom, which is the order they are installed in.
- **Add >** (or double-click in Available) appends the selected application to
  the end of the order. **< Remove** (or double-click in Installation order)
  returns it to Available.
- **Move up** and **Move down** change the position of the selected application;
  numbering is updated immediately.
- IDs that no longer exist in the catalog are shown as
  `Missing application (<id>)` and are kept until removed.
- **Save bundle** stores the order exactly as displayed.
Template editing exposes `ApplicationBundle` in CLI and GUI.
Application and bundle lists omit internal GUID columns; IDs remain attached to
the selected objects for CLI operations. **Assign** opens a list of
existing templates from the installation's Config folder (excluding Config.json),
retrieved through `-Action ListTemplates`. Select a template and confirm to
assign the selected bundle, or cancel without saving.
The application list's **Assigned** column shows all bundle names referencing
the application. **Assigned Templates** in the bundle list shows all template
names referencing that bundle, including application-disabled templates. Empty
assignments display **Not assigned**. Refresh and successful data operations
reload these relationships through the CLI's `ListAssignments` action; global
disable does not remove a stored bundle membership.

In New PAW, **Template default** uses the template's assigned bundle. Select
another bundle to override it for one build. Build and Copy CMD use the same
selection:

```powershell
.\New-PAWVM.ps1 -Template 'My template' -ApplicationBundle $savedBundle.BundleId
.\Tools\Invoke-PAWApplicationDownload.ps1 -ApplicationBundle $savedBundle.BundleId
```

`SkipApplication`, template `Application=False` or `ApplicationBundle=NA` skips
applications entirely.
Otherwise an explicit override wins over the template. Missing bundles and
dangling references block preflight; there is no silent fallback to all apps.
The initial resolved plan is reused for preparation, final preflight, staged
selection and host-initiated guest installation. Typed deployments execute in
bundle order, including modules and OS components.

## Import, export and deletion

Exports are portable **JSON packages**, containing the complete definition and
Settings. A bundle export includes every referenced app, including disabled apps.
Schema 2 transfer packages also embed Classic/local-module/offline-component
payload files as base64 with SHA256 checks; these are portable JSON, not ZIP.
Online WinGet/PSGallery caches are not exported. Do not put credentials in
definitions, scripts or payload files.

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ExportApplication `
    -ApplicationId 0fb0bced-b99c-4330-b62e-9ebd3c918d23 -Path .\7Zip-package.json
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ExportBundle `
    -BundleId cbade470-64cc-4628-9536-b58e3ca3be8d -Path .\Default-package.json
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Import -Path .\Default-package.json
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Import -Path .\Default-package.json -Replace
.\Tools\Invoke-PAWApplicationManager.ps1 -Action RemoveApplication -ApplicationId $saved.ApplicationId
.\Tools\Invoke-PAWApplicationManager.ps1 -Action RemoveBundle -BundleId $savedBundle.BundleId
```

Import validates all definitions/references/conflicts before writing; replacing
existing IDs requires `-Replace`. Writes are atomic per file, with rollback if
a multi-file import fails. Payload paths, duplicate names, base64 and hashes are
validated before writing. Payload directory replacement removes stale files;
rollback restores the old directory if a later definition write fails.
Reparse points and paths escaping the package are rejected. App deletion also
removes the application from every bundle, preserving remaining member order.
Bundles remain valid when empty, and their template assignments are unchanged.
If a bundle update or catalog deletion fails, bundle changes are rolled back and
the error is reported. `-WhatIf` changes neither catalog nor bundles.
Bundle deletion is still blocked while assigned to a template. Cache and
installers are retained. Mutating operations support `-WhatIf`/`-Confirm`;
CLI deletion also prompts unless explicitly confirmed or `-Force` is supplied.
Actions and errors are logged to `%TEMP%\PAWDeploy\PAWApplicationManager.log`.
