# Convert-PAWWIM2VHD.ps1

See [Commandline Samples](CommandlineSamples.md) for how conversion and VHDX import fit into a complete PAW deployment.

## What Is It?

`Convert-PAWWIM2VHD.ps1` converts a Windows installation image (a `.wim` file) into a bootable virtual hard disk (`.vhd` or `.vhdx`). The resulting `.vhd` or `.vhdx` file can be used as a template image when deploying PAW virtual machines.

In simple terms: a `.wim` file is like a compressed snapshot of a fully configured Windows installation. This script takes that snapshot, creates a blank virtual disk, copies Windows onto it, and sets it up so it can boot — producing a ready-to-use template that PAWDeploy can spin up into a new virtual machine.

---

## Why Is It Needed?

PAWDeploy creates each PAW virtual machine from a template `.vhdx` image. Before deploying, the image must exist in the configured `VHDFolder` (the example configuration uses `C:\PAWDeploy\VHDFolder`).

If you have a `.wim` file (for example, exported from a reference machine, obtained from a deployment solution, or extracted from a Windows ISO), this script turns it into a bootable virtual disk for use as a template.

> **Edition:** The command-line converter is included in both editions. The graphical converter is Enterprise only.

You would typically run this script:

- When setting up PAWDeploy for the first time and no `.vhdx` template yet exists.
- When a new Windows image is available and you want to update the template with a newer version.
- When you want to create a second template for a different PAW configuration (for example, a Tier 0 and a Tier 1 image).

> **Note:** If a `.vhdx` template was already provided to you as part of the PAWDeploy package, you do not need to run this script — it has already been done for you.

---

## Before You Start

Make sure the following conditions are met:

1. You are running PowerShell as an **elevated local Administrator**, including
   when using `-WhatIf`.
   - Right-click on the PowerShell icon and select **Run as Administrator**.
2. You have a valid `.wim` source file available, and you know its full path.
3. You know which index inside the `.wim` file contains the Windows edition you want.
   - A `.wim` file can contain multiple editions (for example, Pro and Enterprise). Use index `1` if you are unsure — you can check available indexes with the command shown in the [Finding the Correct Index](#finding-the-correct-index) section below.
4. You have enough free disk space at the destination.
   - The default virtual disk size is 120 GB (`120000 MB`). For an expandable disk, actual disk usage will be much smaller initially and grow as needed.
5. The destination folder exists before running the script.

---

## Disk Layout — Which One to Choose?

The `-Disklayout` parameter is required and controls how the virtual disk is partitioned and configured for booting. If you are unsure, use **UEFI** — it is the correct choice for all modern PAW deployments on Generation 2 Hyper-V virtual machines.

| Value | When to use |
|---|---|
| `UEFI` | **Recommended.** Modern hardware and Generation 2 Hyper-V VMs. Uses GPT partitioning. |
| `BIOS` | Legacy hardware or Generation 1 Hyper-V VMs. Uses MBR partitioning. |
| `COMBO` | Special case: needs to support both BIOS and UEFI boot from the same disk. Uses MBR with a FAT32 boot partition. |

---

## Parameters Reference

| Parameter | Type | Required | Default | Accepted values / constraints | Description |
|---|---|---|---|---|---|
| `-Sourcefile` | `[string]` | Yes | — | Non-empty path | Path to the source `.wim` file. |
| `-DestinationFile` | `[string]` | Yes | — | Non-empty path; destination folder must already exist | Path for the output `.vhd` or `.vhdx` file. |
| `-Disklayout` | `[string]` | Yes | — | `BIOS`, `UEFI`, `COMBO` | Partition and boot layout. |
| `-Index` | `[int]` | No | `1` | `1`–`999` | WIM image index to apply. |
| `-SizeInMB` | `[int]` | No | `120000` | `1024`–`4194304` | Virtual disk size in MB. |
| `-VHDType` | `[string]` | No | `EXPANDABLE` | `EXPANDABLE`, `FIXED` | Virtual disk allocation type. |
| `-Force` | `[switch]` | No | Off | — | Allows replacement of an existing destination; deletion honors ShouldProcess. |
| `-RemoveOldVHD` | `[switch]` | No | Off | Legacy compatibility only | Does not authorize replacement; use `-Force`. |
| `-WhatIf` | `[switch]` | No | Off | — | Previews conversion without creating, deleting, mounting, formatting, or writing anything, including logs. |
| `-Confirm` | `[switch]` | No | Off | — | Requests confirmation for conversion and, with an existing destination, its deletion. |
| `-SXSFolderCopy` | `[switch]` | No | Off | — | Copies the SxS source folder into the mounted image under `Sources\SXS`. |
| `-PathtoSXSFolder` | `[string]` | No | None | Non-empty path when supplied | SxS source folder; required when `-Features` is used and needed for `-SXSFolderCopy`. |
| `-PathtoExtraFolder` | `[string]` | No | None | Non-empty path when supplied | Folder copied into the mounted image under `Tools`. |
| `-PathtoPackagesFolder` | `[string]` | No | None | Non-empty path when supplied | Folder containing `.cab` packages to inject. |
| `-Features` | `[string[]]` | No | None | One or more feature names | Optional Windows features to enable; requires an existing `-PathtoSXSFolder`. |
| `-OSVersion` | `[string]` | No | None | `w7`, `w2k8r2` | Legacy image handling mode. |
| `-DISMExe` | `[string]` | No | `dism.exe` | Any non-empty command name or path | DISM executable used for feature enablement. |

> **Safety:** The script supports `-WhatIf` and `-Confirm` (ConfirmImpact: Medium). Conversion approval covers disk creation, mounting, partitioning, formatting, image application, boot configuration, optional content, and logs. `-WhatIf` returns before importing helpers or resolving/creating the log folder, so it makes no changes. If the destination exists, the script throws unless `-Force` is specified; `-RemoveOldVHD` alone no longer permits replacement. `-Force` does not bypass `-WhatIf` or `-Confirm`, and deletion has its own ShouldProcess check. Declining either approval aborts conversion. Structured entries are written to `%TEMP%\PAWDeploy\Convert-PAWWIM2VHD.log`. The log folder is created if needed; configuration cannot override it.


## How to Run It

Open PowerShell **as Administrator** and navigate to the PAWDeploy folder.

```powershell
cd C:\PAWDeploy\PAWDeploy
```

Then run the script with the required parameters.

---

## Examples

### Typical use — create a UEFI template image

This is the most common scenario. Takes a `.wim` file and produces a 120 GB expandable `.vhdx` ready for use as a PAWDeploy template.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx'
    Disklayout      = 'UEFI'
    Index           = 1
    SizeInMB        = 120000
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

---

### Create a larger image (150 GB)

If the PAW workload requires more disk space, increase `-SizeInMB`.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx'
    Disklayout      = 'UEFI'
    Index           = 1
    SizeInMB        = 153600
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

> 153600 MB = 150 GB. To calculate: multiply the number of GB you want by 1024.

---

### Replace an existing image

If `C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx` already exists and you want to rebuild it from a newer `.wim`, add `-Force`.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx'
    Disklayout      = 'UEFI'
    Index           = 1
    SizeInMB        = 120000
    Force           = $true
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

> **Warning:** `-Force` permits permanently deleting the existing `.vhdx` before creating the new one. Make sure no VMs are currently using that image as a parent disk before running this.

---

### Preview or confirm conversion

Using the replacement parameters above, preview safely or request confirmation:

```powershell
.\Tools\Convert-PAWWIM2VHD.ps1 @params -WhatIf
.\Tools\Convert-PAWWIM2VHD.ps1 @params -Confirm
```

The destination folder must already exist even for a preview. An existing destination still requires `-Force`.

---

### Apply a specific image index from a multi-edition WIM

If the `.wim` contains multiple Windows editions, specify which one to use with `-Index`.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\Windows11.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W11Enterprise.vhdx'
    Disklayout      = 'UEFI'
    Index           = 3
    SizeInMB        = 120000
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

---

### Create a fixed-size disk

A fixed-size disk allocates all space immediately. This can improve performance in some environments at the cost of using more storage up front.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW-Fixed.vhdx'
    Disklayout      = 'UEFI'
    Index           = 1
    SizeInMB        = 120000
    VHDType         = 'FIXED'
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

---

### Inject an extra tools folder into the image

If you want a folder of tools or scripts to be available inside the VM at `C:\Tools`, use `-PathtoExtraFolder`.

```powershell
$params = @{
    Sourcefile        = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile   = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx'
    Disklayout        = 'UEFI'
    Index             = 1
    SizeInMB          = 120000
    PathtoExtraFolder = 'C:\PAWDeploy\Resources\CustomScripts'
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

---

### Enable optional Windows features during image creation

Use `-Features` together with `-PathtoSXSFolder` to enable Windows optional features (such as `.NET Framework 3.5`) at image creation time, without needing internet access later.

```powershell
$params = @{
    Sourcefile      = 'C:\Images\W1124H2VPAW.wim'
    DestinationFile = 'C:\PAWDeploy\VHDFolder\W1124H2VPAW.vhdx'
    Disklayout      = 'UEFI'
    Index           = 1
    SizeInMB        = 120000
    Features        = @('NetFx3')
    PathtoSXSFolder = 'D:\Sources\SxS'
}

.\Tools\Convert-PAWWIM2VHD.ps1 @params
```

---

## Finding the Correct Index

A `.wim` file can contain more than one Windows edition. To list all available editions and their index numbers, run the following command in PowerShell (requires elevation):

```powershell
Get-WindowsImage -ImagePath "C:\Images\W1124H2VPAW.wim"
```

Example output:

```
ImageIndex       : 1
ImageName        : Windows 11 Enterprise
ImageDescription : Windows 11 Enterprise
ImageSize        : 18,345,123,456 bytes

ImageIndex       : 2
ImageName        : Windows 11 Pro
ImageDescription : Windows 11 Pro
ImageSize        : 17,982,654,321 bytes
```

Use the `ImageIndex` number of the edition you want with the `-Index` parameter. For PAW deployments, **Windows 11 Enterprise** is typically the correct choice.

---

## What Happens When You Run It

1. A new, blank virtual disk (`.vhd` or `.vhdx`) is created at the path you specified.
2. The virtual disk is partitioned and formatted according to the `-Disklayout` you chose.
3. Windows is extracted from the `.wim` file and written onto the virtual disk.
4. Boot configuration files are written so the virtual disk can start Windows when used as a VM.
5. If you specified `-PathtoExtraFolder`, that folder is copied into the image under `\Tools`.
6. If you specified `-SXSFolderCopy`, the SxS folder is copied into the image under `Sources\SXS`.
7. If you specified `-PathtoPackagesFolder`, `.cab` update packages in that folder are injected.
8. If you specified `-Features`, those Windows optional features are enabled inside the image.
9. The virtual disk is safely unmounted and the output file is ready to use.


This process typically takes **10–30 minutes** depending on the size of the Windows image and the speed of the disk.

---
## Troubleshooting

| Problem | What to check |
|---|---|
| *"Unable to access \<path\>"* | The `-Sourcefile` path is wrong or the `.wim` file does not exist. Double-check the path. |
| *"Destination ... already exists. Specify -Force to replace it."* | Use a different output path or explicitly add `-Force` to permit replacement. `-RemoveOldVHD` alone is insufficient. |
| *"-Features requires -PathtoSXSFolder"* | You specified `-Features` but forgot to also specify `-PathtoSXSFolder`. Both are required together. |
| *Access denied errors* | Make sure you are running PowerShell as Administrator. |
| Script does not start | Execution policy may be blocking the script. Run `Set-ExecutionPolicy RemoteSigned -Scope Process` in the same PowerShell window, then try again. |
| The resulting `.vhdx` does not boot | Make sure `-Disklayout` matches the VM generation: use `UEFI` for Generation 2 VMs, `BIOS` for Generation 1. |
| Conversion takes a very long time | This is normal for large images. A 20 GB WIM file applied to a spinning hard disk can take 30+ minutes. Running from an SSD is significantly faster. |

---

## Quick Validation Checklist

After conversion finishes, verify the following:

1. The output `.vhd` or `.vhdx` file exists at `-DestinationFile`.
2. The file timestamp matches your latest conversion run.
3. The virtual disk can be attached to a test VM with the matching VM generation.
4. The VM can boot to Windows setup/desktop successfully.
5. The template JSON in Config points to this file through its `VHDFile` property. Filename-only values resolve under `VHDFolder`; relative subpaths resolve from the folder containing `Config.json`.
