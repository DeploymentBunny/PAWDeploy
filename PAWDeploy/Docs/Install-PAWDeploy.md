# Install-PAWDeploy.ps1

## What Is It?

`Install-PAWDeploy.ps1` is the setup and upgrade script for the PAWDeploy solution. You run it to copy PAWDeploy content from the source location (for example, a USB drive or network share) to the machine that will deploy Privileged Access Workstations (PAWs).

Think of it as the installer — before you can deploy any PAW virtual machines, this script must be run to put everything in the right place on the target machine.

---

## Why Is It Needed?

The PAWDeploy solution consists of scripts, configuration files, templates, and virtual machine images. These files must be copied to paths where the host can read and write them.

Running this script:

- Copies the `PAWDeploy` folder (scripts, configuration, and baseline folder structure) to the install path.
- Installs and refreshes `README.md` and `GettingStarted.md` from beside the
  installer into the install root, alongside `Docs`, on new installs and upgrades.
  Their relative links are adjusted for the installed layout.
- Creates **PAW Enterprise Toolkit** or **PAW Community Toolkit** in the all-users
  Start menu with shortcuts to the menu and every UI in the selected edition.
  `-SkipShortCut` skips this and the installation-folder shortcut creation.
- New or refreshed PowerShell shortcuts use `-NoProfile` so user profiles do
  not affect toolkit startup.
- Excludes Git metadata from the source and removes empty shipped `.gitkeep`
  placeholders from existing installations. Non-empty placeholders and paths
  under links are retained with a warning; existing Git repositories are not deleted.
  `-WhatIf` previews placeholder removal.
- Groups host-side content directly under `<Path>\Resources`: `ApplicationCatalog`,
  `ApplicationBundles`, `ApplicationDownloads`, `Applications`, `CustomScripts`,
  `SecurityBaselines`, and `WDACPolicies`. VM-side paths such as `C:\PAWFiles` and
  `C:\SECBL` are unchanged.
- Installs the four `PAW-Deployment-Toolkit-*.png` branding images and both
  edition logos into
  `<Path>\Assets\img`, refreshing them during upgrades. Repository installs read
  root `Resources`; release installs read the packaged `PAWDeploy\Assets\img`.
- Copies `Resources\WDACPolicies` in both editions and preserves existing
  imported policy filenames during upgrades; new filenames are still copied.
- Creates the default or custom image destination folder and updates configured image paths; it does **not** copy `.vhdx` files.
- Optionally sets the Hyper-V VM storage folder in `Config.json` with `-VMLocation`.
- Saves the selected UI theme as `Settings.Configuration.UITheme` in `Config\Config.json`. The default and
  `-Theme System` detect the Windows apps appearance setting and save the result
  as `Dark` or `Light`; explicit `-Theme Dark` and `-Theme Light` pin those
  palettes. Additional theme names resolve to JSON files in `Assets\Themes`.
- Validates that the chosen locations are on valid drives and writable.
- Detects an **upgrade** when `-Path` contains `Config\Config.json` or the older root-level `Config.json`.
- Preserves existing configuration/templates in `Config`, application definitions
  in `Resources\ApplicationCatalog`, bundles in `Resources\ApplicationBundles`,
  download caches, install metadata and payloads under `Resources`, and `.vhdx`
  files during upgrades. No resource-layout migration is performed.
- Migrates root-level `Config.json` and content from legacy `TemplateFolder` / `Templates` directly into `Config`, without a Templates subfolder. External configured templates are copied, leaving their originals unchanged. Destination conflicts stop migration before any configuration or templates are moved.
- Removes the seven retired template/log-folder helper files from an existing installation after copying the updated modules. Preview with `-WhatIf` retains those files.
- Updates `Config.json` install/image references automatically on new installs.
- After a successful install or upgrade, changes the current PowerShell location to the install path.

---

## Before You Start

Make sure the following conditions are met:

1. You are running PowerShell **as an elevated local Administrator**. This is
   required for every operation, including `-WhatIf`, `-SkipShortCut` and
   `-SelfTest`.
   - Right-click on the PowerShell icon and select **Run as Administrator**.
2. The source files (the folder containing `Install-PAWDeploy.ps1`) are accessible — for example, already copied from a USB drive or mounted network share.
3. The install and image paths are on valid drives and the parent locations are writable.
4. Make sure the selected image destination has enough free space for the `.vhdx` template images. The installer creates the destination folder but does not copy image files; place the required `.vhdx` files there separately.


---

## How to Run It

Open PowerShell **as Administrator** and navigate to the folder that contains `Install-PAWDeploy.ps1`.

```powershell
cd C:\Source\TSPAWDeploy
```

Then run the script with `-Path`, specifying the folder where `PAWDeploy` should be installed.

### Basic syntax

```powershell
$params = @{
   Path = '<InstallFolderPath>'
}

.\Install-PAWDeploy.ps1 @params
```

### Parameters

| Parameter | Type | Default / requirement | Description |
|---|---|---|---|
| `-Path` | String | No default; required unless `-SelfTest` is used | Install or uninstall path. Its drive must exist and its parent folder must be writable. |
| `-ImageLocation` | String | No default; new install uses `<Path>\VHDFolder`; upgrade keeps the existing value unless supplied | Image destination folder. The installer creates the destination if needed and updates `Settings.Configuration.VHDFolder` when appropriate; it does not copy `.vhdx` files. |
| `-VMLocation` | String | No default; omitted preserves the configured value | Sets `Settings.HyperV.VMFolder`. The destination drive and writable parent must exist. |
| `-Theme` | String | Automatically detects Windows appearance on both install and upgrade | Overrides the detected theme. Tab completes `Dark` and `Light`; also accepts `System` or a custom theme filename from `Assets\Themes`. |
| `-Force` | Switch | Off | Skips upgrade confirmation. With `-Uninstall`, prompts separately before removing protected image folders under `-Path`. |
| `-Uninstall` | Switch | Off | Removes installation contents at `-Path`, preserving image folders located under that path. Cannot be combined with `-ImageLocation`, `-VMLocation` or `-Theme`. |
| `-SelfTest` | Switch | Off | Runs the built-in JSON path-update self-test and exits; `-Path` is ignored. |
| `-SkipShortCut` | Switch | Off | Skips creation of Start menu and installation-folder shortcuts. |

The script also supports the common advanced parameters `-WhatIf`, `-Confirm`, and `-Verbose`.

Start menu shortcuts use the all-users Programs folder and point to the UI scripts
shipped in the selected edition. Existing shortcuts with different targets are
not overwritten; resolve a conflict before rerunning the installer. On upgrade,
matching shortcuts in the former `PAW Toolkit` folder are removed after the new
shortcuts are created; unrelated contents are preserved. Start menu shortcuts are
not removed automatically by uninstall.

Tool shortcuts are also created in `<Path>\ShortCuts`; GUI targets are in `<Path>\Tools`
and the menu target is `<Path>\PAWMenu.ps1`. On upgrades, existing tool shortcuts in the install root are moved
to this folder, even with `-SkipShortCut` (which skips creation only). Conflicting
copies stop the upgrade with an error. `-WhatIf` leaves shortcuts and folders
unchanged. VM connection shortcuts keep their existing separate location.

GUI scripts and command-line tools are installed in `<Path>\Tools`;
`New-PAWVM.ps1` and menus are at `<Path>`. Updates remove obsolete Tools menu copies
after installing their root replacements. Updates replace
legacy root-level tools with the packaged Tools copies and recreate tool
shortcuts with the new targets unless `-SkipShortCut` is supplied. If using
`-SkipShortCut`, existing shortcut targets must be updated separately.

By default, the script creates and uses:

| Folder | Contents |
|---|---|
| `<Path>` | `New-PAWVM.ps1`, edition-specific menu and installation subfolders |
| `<Path>\Config` | `Config.json` and all template JSON files directly in the same folder |
| `<Path>\Settings\UITheme.json` | Legacy UI theme selection, read only when Config.json has no UITheme setting |
| `<Path>\Assets\Themes` | External JSON theme palettes (`Dark.json`, `Light.json`, and custom themes) |
| `<Path>\Tools` | Command-line tools and Windows Forms UI scripts |
| `<Path>\Resources\ApplicationCatalog` | Application definitions |
| `<Path>\Resources\ApplicationBundles` | Application bundles |
| `<Path>\Resources\ApplicationDownloads` | Downloaded installers, module cache, and manually supplied local installers |
| `<Path>\Resources\Applications` | Application installer, install metadata, and application payloads |
| `<Path>\Resources\CustomScripts` | Imported deployment scripts |
| `<Path>\Resources\SecurityBaselines` | Host security baseline content |
| `<Path>\Resources\WDACPolicies` | WDAC XML policies |
| `<Path>\ShortCuts` | Installation shortcuts for the PAWDeploy tools; upgrades rename legacy `shortscut`, refusing conflicts if both folders exist |
| `<Path>\VHDFolder` | Image destination folder for `.vhdx` files (created by the installer; images are not copied) |

---

## Examples

### New install to C:\PAWDeploy

This uses the default image destination `<Path>\VHDFolder`. The installer creates the folder and updates the configured VHD paths; place the `.vhdx` files there separately.

```powershell
$params = @{
   Path = 'C:\PAWDeploy'
}

.\Install-PAWDeploy.ps1 @params
```

### Install with custom image location

To configure a different image destination, set `-ImageLocation`. The installer creates that folder and rebases configured VHD paths, but does not copy the `.vhdx` files.

```powershell
$params = @{
   Path          = 'D:\Tools\PAWDeploy'
   ImageLocation = 'E:\PAWImages'
}

.\Install-PAWDeploy.ps1 @params
```

### Set the Hyper-V VM storage location

Use optional `-VMLocation` to set `Settings.HyperV.VMFolder` in the installed `Config.json`. The value must be on a valid drive with a writable parent folder. If omitted, a new install keeps the configured default and an upgrade preserves the existing setting.

```powershell
$params = @{
   Path       = 'D:\Tools\PAWDeploy'
   VMLocation = 'E:\VirtualMachines'
}

.\Install-PAWDeploy.ps1 @params
```

### Select a UI theme

New installations automatically detect the Windows apps appearance setting and
save the result as `Dark` or `Light`. Use `-Theme Dark` or `-Theme Light` to pin
the theme for this installation; `-Theme System` performs the same detection.
Upgrades also detect Windows appearance when `-Theme` is omitted, replacing any
previous selection. Tab completion after `-Theme` suggests `Dark` and `Light`.

```powershell
.\Install-PAWDeploy.ps1 -Path 'C:\PAWDeploy' -Theme Dark
```

### Preview what will happen without making any changes

Use `-WhatIf` to preview directory creation, file copies, configuration updates, and shortcut creation without changing the target. Neither the install folder nor the image destination folder is created, including an explicit `-ImageLocation`. Write-access probes are skipped; path and drive validation still run, but write access is only tested on an actual run. The installer does not create a log file.

```powershell
$params = @{
   Path   = 'C:\PAWDeploy'
   WhatIf = $true
}

.\Install-PAWDeploy.ps1 @params
```

### See detailed progress as the install runs

Use `-Verbose` to see each file as it is copied.

```powershell
$params = @{
   Path    = 'C:\PAWDeploy'
   Verbose = $true
}

.\Install-PAWDeploy.ps1 @params
```

---

## What Happens When You Run It

1. The script validates that `-Path` (and `-ImageLocation` / `-VMLocation`, when set) are on existing drives and writable.
2. If neither `Config\Config.json` nor legacy `Config.json` exists at `-Path`, it performs a **new install**:
   - Copies the `PAWDeploy` source tree.
   - Creates the image destination folder and updates `Config.json` paths to your selected install and image locations, plus `Settings.HyperV.VMFolder` when `-VMLocation` is supplied.
3. If `-Path` already contains either configuration layout, it performs an **upgrade**:
   - Migrates older configuration and templates to `Config`, retaining relative path meanings and user values. Empty legacy template folders are removed.
   - Overwrites solution files while preserving existing files in `Config`,
     application `Catalog`, `Bundles`, generated installation metadata and `.vhdx`
     files. No conversion of legacy application lists is performed.
   - Keeps existing customer values; templates are migrated into `<Path>\Config`, then obsolete template-folder properties are removed. Supplying an installer option overrides its corresponding setting.
4. Progress and results are displayed in the PowerShell console. The installer does not create a log file.

---

## Re-running the Script (Updating PAWDeploy)

If a newer version of the PAWDeploy solution is provided, you can safely re-run the script against the same install path. It will:

- Update the files in the `PAWDeploy` source tree, including scripts and baseline folder structure.
- Preserve existing `Config.json` settings on upgrades unless a corresponding installer option is supplied. `-VMLocation` updates `Settings.HyperV.VMFolder` when provided.
- Leave existing `.vhdx` files untouched; the installer does not copy or relocate the VM template images.

---

## Output

Review the progress and results in the PowerShell console. The installer does not write a separate log file.

---

## Troubleshooting

| Problem | What to check |
|---|---|
| *"Access is denied"* | Make sure you are running PowerShell as Administrator. |
| *"... is not on a valid drive"* | Verify the drive letter exists and is available on this host. |
| *"... parent path ... does not exist"* | Create the parent folder first, or choose a different `-Path`, `-ImageLocation`, or `-VMLocation`. |
| *"Unable to write to Path"* | Verify permissions on the selected location and run PowerShell as Administrator. |
| *"Source folder not found, skipping"* | The source `PAWDeploy` folder is missing. Make sure the solution was extracted before running the installer. The installer does not require or copy a separate `PAWImages` source folder. |
| Script does not start | Execution policy may be blocking the script. Run `Set-ExecutionPolicy RemoteSigned -Scope Process` in the same PowerShell window, then try again. |

---

## Quick Validation Checklist

After running the installer, verify the following:

1. Install folder exists at your selected `-Path`.
2. Image destination folder exists at `-ImageLocation` or `<Path>\VHDFolder`, and the required `.vhdx` files have been placed there separately.
3. `Config.json` contains the configured VM storage path at `Settings.HyperV.VMFolder`; if `-VMLocation` was supplied, confirm it matches the requested path.
4. On upgrades, existing `.vhdx` files were preserved.
5. On new installs, `Config.json` references match your chosen install/image paths and, if supplied, VM storage path.
6. The console output contains no unexpected errors, and `Config.json` specifies `%TEMP%\PAWDeploy` for `LogFilesFolder`.
