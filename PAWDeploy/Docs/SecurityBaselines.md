# How to Add a Security Baseline to a PAW Image

## What Is a Security Baseline?

A **security baseline** is a Microsoft-recommended collection of security settings for Windows and Microsoft Edge.

These settings are designed to make a system more secure by turning on safer defaults and reducing unnecessary risk. In simple terms, a baseline is a pre-approved package of security rules that helps you lock down a PAW in a consistent way.

In PAWDeploy, the security baseline is stored in a folder structure that PAWDeploy can copy into the virtual machine and apply during deployment.

---

## Why Is It Needed?

A Privileged Access Workstation (PAW) is meant to be a hardened, trusted administrative machine. Because it is used for sensitive administrative work, it must be configured more carefully than a normal desktop.

Without a security baseline:

- important security settings may be missed
- two PAWs may end up configured differently
- support and auditing become harder
- the machine may not meet your organisation's security standard

Using a Microsoft security baseline helps by:

- applying a consistent set of recommended settings
- reducing manual configuration work
- making each deployed PAW more predictable and easier to support
- aligning the PAW more closely with Microsoft's hardening guidance

---

## How PAWDeploy Uses the Security Baseline

Deployment baseline copy/application failures are warnings, not deployment aborts.
OS and Edge are attempted independently, with script stdout/stderr recorded in
the host deployment log. The final report lists failures and reasons; completion
does not imply full hardening when any requested baseline failed. Imported files
are not executed by the ZIP import tool; this behavior concerns VM deployment.

PAWDeploy expects the baseline files to be stored in a dedicated folder.

The repository includes only the empty Windows11_24H2 and Windows11_25H2
OS/Edge directory structure, preserved with `.gitkeep` files. Microsoft baseline
packages are not bundled; obtain them separately from Microsoft before using
baseline deployment. Imported files under `PAWDeploy/Resources/SecurityBaselines`
are ignored by Git. Use the [ZIP import tool](Import-PAWSecurityBaseline.md)
or **Import OS Baseline** / **Import Edge Baseline** in the Enterprise menu.
After baseline imports, use **Import LGPO** (CLI `Import-PAWLGPO.ps1`) with the
separate Microsoft LGPO ZIP. It installs `LGPO.exe` into **every imported**
OS/Edge baseline's `Scripts\Tools` directory across all OS folders.
An empty directory or `.gitkeep` is not an installed baseline.

For the current Windows 11 example in this repository, that folder is:

```text
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2
```

Inside that folder, PAWDeploy expects this structure:

```text
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2
├── OS
└── Edge
```

Meaning:

- the **Windows operating system baseline** files go into `OS`
- the **Microsoft Edge baseline** files go into `Edge`

PAWDeploy resolves the template JSON `SecurityBaselineLocation` value against `Settings.Configuration.SecurityBaseLineFolder` in `Config.json` when the value is relative. Rooted paths are also accepted. The current Config.json default is `C:\PAWDeploy\Resources\SecurityBaselines`.

---

## The Required Folder Structure

For Windows 11 24H2, use this structure:

```text
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\OS
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\Edge
```

The repository includes empty `OS` and `Edge` placeholder folders for `Windows11_24H2` and `Windows11_25H2` under `PAWDeploy\Resources\SecurityBaselines`. It does not include Microsoft baseline package files; populate these folders before deploying with baselines enabled.

### What Goes Where

| Folder | What to put in it |
|---|---|
| `OS` | The extracted Windows baseline, including `Scripts\Baseline-LocalInstall.ps1` directly under this folder |
| `Edge` | The extracted Edge baseline, including `Scripts\Baseline-LocalInstall.ps1` directly under this folder |

---

## Where to Get the Baseline Files

Download the security baseline packages from **Microsoft**.

You need two things:

1. the **Windows operating system security baseline** for the OS version you are deploying
2. the **Microsoft Edge security baseline**

After downloading them:

- unzip the **operating system baseline** into the `OS` folder
- unzip the **Edge baseline** into the `Edge` folder

For example, for the current Windows 11 24H2 structure:

- unzip the Windows baseline into `C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\OS`
- unzip the Edge baseline into `C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\Edge`

> Keep the files from Microsoft grouped cleanly. Do not mix OS baseline files and Edge baseline files in the same folder.

---

## Step-by-Step: Add a Windows 11 24H2 Baseline

### Option 1 — Recommended for most customers: use File Explorer

This is the easiest method for customers with little IT experience.

1. Download the **Windows 11 security baseline** from Microsoft.
2. Download the **Microsoft Edge security baseline** from Microsoft.
3. Open File Explorer.
4. Go to:

```text
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2
```

5. Open the `OS` folder.
6. Extract the **Windows operating system baseline** files into that `OS` folder.
7. Go back and open the `Edge` folder.
8. Extract the **Edge baseline** files into that `Edge` folder.
9. Confirm the files are present in both places.
10. Check the template JSON file in Config and its baseline fields:

```json
{
  "SecurityBaselineLocation": "Windows11_24H2",
  "ApplySecurityBaseline": "True"
}
```

After that, PAWDeploy can use the baseline during deployment.

---

### Option 2 — PowerShell method with splatting

If you prefer a repeatable script-based setup, you can create the folders and unzip the downloaded files with PowerShell.

#### Step 1 — Make sure the folders exist

```powershell
$osFolderParams = @{
    Path      = 'C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\OS'
    ItemType  = 'Directory'
    Force     = $true
}

New-Item @osFolderParams

$edgeFolderParams = @{
    Path      = 'C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\Edge'
    ItemType  = 'Directory'
    Force     = $true
}

New-Item @edgeFolderParams
```

#### Step 2 — Extract the Windows baseline into `OS`

This example assumes you already downloaded the ZIP file to `C:\Downloads`.

```powershell
$expandWindowsParams = @{
    Path            = 'C:\Downloads\Windows-11-24H2-Security-Baseline.zip'
    DestinationPath = 'C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\OS'
    Force           = $true
}

Expand-Archive @expandWindowsParams
```

#### Step 3 — Extract the Edge baseline into `Edge`

```powershell
$expandEdgeParams = @{
    Path            = 'C:\Downloads\Microsoft-Edge-Security-Baseline.zip'
    DestinationPath = 'C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2\Edge'
    Force           = $true
}

Expand-Archive @expandEdgeParams
```

---

## How to Tell PAWDeploy to Use the Baseline

The baseline root is configured in `Config.json` at `Settings.Configuration.SecurityBaseLineFolder` (the helper also accepts the legacy `SecurityBaselineFolder` spelling). The default is `C:\PAWDeploy\Resources\SecurityBaselines`, and baseline folders are under `PAWDeploy\Resources\SecurityBaselines`, not `PAWFiles`.

Each template JSON file that should use the baseline must contain:

```json
{
  "SecurityBaselineLocation": "Windows11_24H2",
  "ApplySecurityBaseline": "True"
}
```

### What These Settings Mean

| Setting | Meaning |
|---|---|
| `SecurityBaselineLocation` | The selected baseline folder containing the `OS` and `Edge` subfolders |
| `ApplySecurityBaseline` | Whether PAWDeploy should apply the baseline during deployment |

If `ApplySecurityBaseline` is not the string `"True"`, the baseline is not applied, although the selected folder may still be copied into the image. A blank `SecurityBaselineLocation` or `-SkipSecurityBaseLine` skips both copying and application.

---

## Example: Template JSON for Windows 11 24H2

```json
{
  "SecurityBaselineLocation": "Windows11_24H2",
  "ApplySecurityBaseline": "True"
}
```

The relative value resolves under `Settings.Configuration.SecurityBaseLineFolder` to:

```text
C:\PAWDeploy\Resources\SecurityBaselines\Windows11_24H2
```

---

## Example: Deploy a PAW That Uses the Baseline

Once the baseline folder is populated and the template JSON is updated, you can deploy normally.

### Deploy from the command line using splatting

```powershell
$params = @{
    Template     = 'Windows 11 x64 PAW for WORKGROUP ON'
    VMSwitchName = 'CorpSwitch'
}

.\New-PAWVM.ps1 @params
```

If that template JSON has:

```json
{
  "ApplySecurityBaseline": "True"
}
```

then `New-PAWVM.ps1` copies the selected folder into the guest as `C:\SECBL` and attempts to apply OS and Edge baselines after application installation. The OS script is run with the domain-joined or non-domain-joined switch according to template `DomainOrWorkGroup` (`Domain` or `Workgroup`); the Edge script is run without that switch.

---

### Preview a deployment first

```powershell
$params = @{
    Template     = 'Windows 11 x64 PAW for WORKGROUP ON'
    VMSwitchName = 'CorpSwitch'
    WhatIf       = $true
}

.\New-PAWVM.ps1 @params
```

This is useful when you want to confirm the correct template is being used before starting a real deployment.

---

## For Other Operating Systems (Customization Required)

The folder layout can be reused for another operating system, but the current `New-PAWVM.ps1` baseline invocation passes Windows 11-specific `-Win11DomainJoined` or `-Win11NonDomainJoined` arguments to the OS baseline script. Before running it, `New-PAWVM.ps1` checks that the OS baseline script declares that switch; if not, the baseline is reported as not applied and the available switches are listed in the log. Do not treat the examples below as supported out of the box; update the deployment code for the target OS.

### What to do

1. Create a **similar folder structure** for that operating system
2. Put the **OS baseline** into the `OS` subfolder
3. Put the **Edge baseline** into the `Edge` subfolder
4. Update the template JSON so `SecurityBaselineLocation` names the new baseline folder under `Settings.Configuration.SecurityBaseLineFolder`

### Example folder structure for another operating system

For folder-layout illustration only, a separate baseline directory could be named:

```text
C:\PAWDeploy\SecBaseLineW10_22H2
├── OS
└── Edge
```

Or, for a server baseline directory:

```text
C:\PAWDeploy\SecBaseLineServer2025
├── OS
└── Edge
```

### Example PowerShell folder creation with splatting

```powershell
$newOsFolderParams = @{
    Path      = 'C:\PAWDeploy\SecBaseLineServer2025\OS'
    ItemType  = 'Directory'
    Force     = $true
}

New-Item @newOsFolderParams

$newEdgeFolderParams = @{
    Path      = 'C:\PAWDeploy\SecBaseLineServer2025\Edge'
    ItemType  = 'Directory'
    Force     = $true
}

New-Item @newEdgeFolderParams
```

### Example template JSON update for another operating system

```json
{
  "SecurityBaselineLocation": "C:\\PAWDeploy\\SecBaseLineServer2025",
  "ApplySecurityBaseline": "True"
}
```

The important part is that the template must point to the correct baseline root folder.

---

## How to Check That the Baseline Is Ready

Before deploying, confirm these four things:

1. the baseline files were downloaded from Microsoft
2. the Windows baseline was unzipped into `OS`
3. the Edge baseline was unzipped into `Edge`
4. the template JSON points to the correct `SecurityBaselineLocation` under the configured baseline root

If all four are true, the template is ready to use the baseline.

---

## Common Mistakes to Avoid

| Mistake | Why it causes problems |
|---|---|
| Putting both baselines in the same folder | PAWDeploy expects separate `OS` and `Edge` subfolders |
| Pointing `SecurityBaselineLocation` to `OS` instead of the root folder | The setting should point to the folder that contains both `OS` and `Edge` |
| Forgetting to set `ApplySecurityBaseline` to `True` | The files may exist, but PAWDeploy will not apply them |
| Using the wrong baseline for the operating system | Security settings may not match the OS you are deploying |
| Forgetting to create a new baseline folder for a different OS version | One template may end up pointing to the wrong baseline files |

---

## Troubleshooting

| Problem | Likely Cause | What to check |
|---|---|---|
| The baseline is not applied during deployment | `ApplySecurityBaseline` is disabled, or `-SkipSecurityBaseLine` was used | Check that the template JSON has `"ApplySecurityBaseline": "True"` and the deployment did not use `-SkipSecurityBaseLine`. |
| PAWDeploy cannot find the baseline | `SecurityBaselineLocation` points to the wrong place | Make sure it points to the root folder, not directly to `OS` or `Edge` |
| Baseline application does not complete | The baseline directory is empty, incomplete, or has an extra nested folder level | Ensure `OS\Scripts\Baseline-LocalInstall.ps1` (and `Edge\Scripts\Baseline-LocalInstall.ps1` if you want the Edge baseline) exists under the selected baseline folder. `New-PAWVM.ps1` reports the baseline as not applied when a baseline script returns a non-zero exit code; the exit code is in the deployment log. |
| The wrong settings are being applied | The wrong baseline version was downloaded | Make sure the baseline matches the OS version you are deploying |
| Files are in the folder, but nothing happens | Folder structure is wrong | Confirm the structure is `BaselineRoot\<BaselineName>\OS\Scripts` and `BaselineRoot\<BaselineName>\Edge\Scripts`, with `Baseline-LocalInstall.ps1` in both `Scripts` folders |

---

## Good Practice for Customers

Use this simple process every time:

1. download the correct Microsoft baseline for the operating system
2. download the current Microsoft Edge baseline
3. unzip OS files into `OS`
4. unzip Edge files into `Edge`
5. update the template JSON
6. test with one deployment before using it widely

That keeps the setup simple, predictable, and easy to troubleshoot.

---

## Related Documents

- [Config.json.md](Config.json.md) — How to configure `SecurityBaselineLocation` and `ApplySecurityBaseline`
- [New-PAWVM.md](New-PAWVM.md) — Deployment engine that applies the baseline during VM build
- [Install-PAWDeploy.md](Install-PAWDeploy.md) — How the PAWDeploy solution is installed
- [Convert-PAWWIM2VHD.md](Convert-PAWWIM2VHD.md) — How the source VHDX image is created

---

## Quick Validation Checklist

After baseline preparation, verify the following:

1. `Settings.Configuration.SecurityBaseLineFolder` exists and contains the selected baseline subfolder (for example `Windows11_24H2`).
2. `OS` and `Edge` folders contain the expected `Scripts\Baseline-LocalInstall.ps1` files.
3. Template `SecurityBaselineLocation` names the selected baseline folder (or an absolute path to it).
4. Template `ApplySecurityBaseline` is set to `True`.
5. A test deployment confirms baseline application without errors.
