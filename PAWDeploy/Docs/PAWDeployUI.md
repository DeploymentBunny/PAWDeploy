# PAWDeployUI.ps1 — Graphical Deployment Tool

## What Is It?

`PAWDeployUI.ps1` is a **graphical (point-and-click) interface** for deploying Privileged Access Workstation (PAW) virtual machines. Instead of typing commands in a terminal, you fill in a form and click a button — the tool takes care of the rest.

It is a friendly front-end for `New-PAWVM.ps1`. The form passes supported deployment options to the engine; credentials are handed off through a short-lived file, while template-controlled values such as the domain OU remain in the template.

**Windows Defender Application Control** lists XML filenames in
`Resources\WDACPolicies`, with Refresh and template `WDACPolicyFile` selection. **Skip ASR**
and **Skip WDAC** are saved per user along with the selected policy. **Skip ASR**
is unchecked and available when template `ASR=True` (or missing in an older
template); check it to override and skip. With `ASR=False`, it is checked and
always selectable. Switching templates refreshes it; saved UI state cannot enable ASR
against template `False`. Copy CMD and Build pass the same security arguments. Missing selected
policies remain visible with a warning rather than silently disabling WDAC.
All Skip checkboxes remain enabled regardless of template values. Checking one
skips that feature; unchecking follows the template rather than forcing a
template-disabled feature on. The same precedence applies to CLI Skip switches.
See [ASR/WDAC behavior and next-boot activation](New-PAWVM.md#asr-and-windows-defender-application-control).

---

## Why Is It Needed?

Deploying a PAW virtual machine requires several settings — the right template, the correct disk image, network configuration, credentials, and security options. Keeping all of those straight in a command line can be error-prone, especially for operators who do not use PowerShell regularly.

`PAWDeployUI.ps1` solves this by:

- Presenting all options in a single, clearly labelled window
- Auto-filling most fields from the selected JSON template in Config
- Restoring the most recently used UI selections from a per-user settings file
- Highlighting required fields in orange if something is missing before you can proceed
- Launching the deployment in a separate window and writing log output you can review later

---

## Before You Start

Before opening the tool, make sure:

| Requirement | Details |
|---|---|
| **Run as Administrator** | An elevated local administrator session is required. Right-click the shortcut or PowerShell and choose **Run as Administrator**; the UI reports an error instead of opening when not elevated. |
| **Hyper-V is installed** | The tool reads your available VM switches from Hyper-V |
| **Solution is installed** | `Install-PAWDeploy.ps1` must have been run at least once |
| **Config.json is configured** | Deploying requires at least one valid JSON template beside it, not marked `Active = False` |
| **VHDX image exists** | Your source disk image (created by `Convert-PAWWIM2VHD.ps1`) must be available |

UI preferences are stored in `%TEMP%\PAWDeploySettings\PAWDeployUI.settings`. UI and deployment logs always use `%TEMP%\PAWDeploy`, regardless of configuration.

If there are no active templates, New PAW still opens and explains why deployment
is unavailable. Create or activate a template in **Templates**, then reopen New
PAW. Build and Copy CMD remain disabled until an active template is selected and
the Hyper-V switches have loaded.

---

## How to Open the Tool

**Option 1 — Use the Desktop Shortcut**

Double-click the **PAW Deploy** shortcut that was placed on your desktop by `Install-PAWDeploy.ps1`. This opens the graphical tool directly.

**Option 2 — Run from PowerShell (as Administrator)**

```powershell
$params = @{
   FilePath     = 'powershell.exe'
   ArgumentList = '-File "C:\PAWDeploy\Tools\PAWDeployUI.ps1"'
   Verb         = 'RunAs'
}

Start-Process @params
```

> The form title is **"PAWDeploy Toolkit - &lt;version&gt; - PAWDeployUI.ps1"**.

After **Build**, the form closes and the deployment runs in a classic PowerShell
console rather than a Windows Terminal tab. It stays on the form's monitor,
with the same width and half the height, aligned to the form's bottom edge.
When launched from PAWMenu, this places the console over the lower half of the
menu (1344 x 378 pixels). Direct GUI launches use the GUI's current position.
If the console cannot be started, the form stays open and the error is logged.

**Build** also checks whether the VM name already exists on the local Hyper-V
host. A duplicate highlights **VM Name**, selects its text and shows
**VM exists. Change VM Name.** The form and all entered values remain intact:
change the name and click **Build** again. Build also checks the target VM directory,
including empty directories and other existing filesystem entries, and shows
**VM folder exists. Change name.** when it is occupied. It reads the current Config
on each click, using `Settings.HyperV.VMFolder`, legacy `VMLocation`, then `C:\VMs`,
matching the engine. Config, Hyper-V or filesystem query errors block deployment
and are logged. Nothing existing is deleted or reused. These checks do not replace
the engine's safety checks against conflicts appearing after validation.

The deployment engine also runs shared resource preflight before staging and
again after application preparation, before VM creation. Active steps with
missing resources block the build; checked Skip options bypass their resource
requirements. RAM must cover VM startup memory + 1 GB overhead + 4 GB host
reserve. VM storage requires the actual source file size + 10 GB in Copy mode,
or 10 GB in Diff mode; separate host/system/temporary/cache volumes retain 5 GB.
Failures and calculations appear in the build console and deployment log.
See [resource preflight and read-only CLI inspection](New-PAWVM.md#deployment-resource-preflight).

### Copy CMD — reuse the form choices from PowerShell

Fill in the form and click **Copy CMD** instead of Build to copy one complete
PowerShell command. The form stays open and no deployment is launched. You can
close the wizard, paste the command into an elevated PowerShell prompt, then use
command history (Up Arrow) and edit the VM name for the next build.

Copy CMD and Build use the same command builder, including **Show Verbose**, all
checked Skip options, networking, changed domain OU, Run Script, Copy Folder,
WDAC and an explicitly selected source VHDX. Values are quoted as literal
PowerShell strings, including spaces and apostrophes. Empty optional VLAN and
computer-name fields are omitted so the engine/template resolves them.

Passwords are deliberately not copied to the clipboard or command history.
The engine prompts for them when running a copied command; Build retains its
existing encrypted credential-file handoff.

---

## The Deployment Form

When the tool opens, you will see a form divided into two columns.
The interface uses Segoe UI throughout, including headings and input fields;
the help reader and application document editor retain Consolas for code.
The **Application Bundle**
caption stays fixed, without appending the template's assigned bundle name.
Checking **Skip Application** disables the bundle dropdown; clearing it enables
the dropdown again without discarding the selection. This also applies when a
template or saved settings changes the checkbox.
The deployment window follows `Settings.Configuration.UITheme` in `Config\Config.json`.
`System` uses the Windows apps appearance preference; see
[PAWUIUtility themes](PAWUIUtility.md#themes).

Virtual Machine is aligned on the left and Guest OS on the right in equal-width
columns. Each column reserves the same three lanes for labels, optional
Browse/Refresh links, and value fields. On the Guest OS side, value fields
share a single left edge after the Override ComputerName checkbox. Primary
fields are 300 pixels wide.
Skip RunScript, Skip ASR and Skip WDAC checkboxes share a column close to
their labels.
Template is the first row in the
Virtual Machine column, directly below its heading and above VM Name. Its field
aligns with and has the same width as the VM Name, VM Switch, Disk Mode and
VHD(X) override fields. The VHD(X) override is directly below Disk Mode, with a
Browse link matching the VM Switch Refresh link. Copy Folder Browse, Run Script
Refresh and WDAC Refresh use the same accent link style and sit immediately
before their 300-pixel fields, as on the left. The source
VHD(X) normally comes from the selected template. Use **VHD(X) override** to
enter or browse to a different file for this build; leave it blank to use the
template. The override is not saved to the template. Application Bundle
is the first setting below Guest OS. The WDAC Policy selector is part of the
Guest OS column, not a separate third column. VM Skip options follow the VHD(X) override, with
Show Verbose before Domain Credentials. Guest Skip options immediately follow networking:
below Use DHCP when enabled, or below the static IP fields when DHCP is disabled.
The top ribbon has the horizontal toolkit logo at the left, the script name,
and Help/Close at the right. Build and Copy CMD are grouped at the lower right,
with Copy CMD immediately to the left of Build. Both use the theme's accent colors.

### Left Column — Virtual Machine Settings

| Field | Description | Required |
|---|---|---|
| **Template** | Select a deployment template from the dropdown. Templates are read from JSON files beside `Config.json`; `Active = False` entries are hidden and a missing `Active` property is treated as active. Choosing a template auto-fills many other fields. | Yes |
| **VM Name** | The name the virtual machine will have in Hyper-V. Auto-generated from the template, but you can change it. | Yes |
| **VM Switch** | The Hyper-V virtual network switch the VM will connect to. While switches load in the background, the header displays **Loading Hyper-V switches...**. Use **Refresh** to reload the list or retry a failed lookup. | Yes |
| **VLAN ID** | Optional VLAN number for network isolation. Leave blank if you do not use VLANs. | No |
| **Disk Mode** | How the VM disk is created — see [Disk Modes](#disk-modes) below. Auto-filled from the template. | Yes |
| **VHD(X) override** | Optional path or image filename to use instead of the template's `VHDFile`. Located directly below Disk Mode. Browse for a `.vhd` or `.vhdx`, or enter a filename resolved under the configured image folder. Clear the field to use the template. Build validates the effective image; Build and Copy CMD both pass `-VHDX` when populated. | No |
| **Skip Shielding** | Tick to skip Hyper-V shielding for the new VM. Leave unticked to keep the template or default shielding behavior. Defaults to **off**. | No |
| **Skip Link** | Adds `-SkipLink` to Build and Copy CMD to skip creating the VM Connect shortcut. Unchecked on every GUI launch; this choice is not saved. | No |

For diagnostic startup and Hyper-V switch loading timings, start the UI with
`.\Tools\PAWDeployUI.ps1 -PAWDebug` or set `$PAWDebug = $true` in the calling
PowerShell session before launching it. `-PAWDebug:$false` explicitly disables
the timings. Normal operation and functional timeout timers are unchanged.

#### Domain Credentials (domain-joined templates only)

These fields appear automatically when the selected template is configured for domain join.

| Field | Description |
|---|---|
| **Username** | Username-only domain account with permission to join computers to the domain (e.g. `SvcJoin`; do not include a domain prefix or `@domain`) |
| **Password** | Password for the domain join account (hidden as `*`) |
| **OU** | Shows the template's `MachineObjectOU`. If you change it, the new value is passed to `New-PAWVM.ps1` as `-MachineObjectOU` and overrides the template for this deployment. |

---

### Right Column — Guest OS Settings

| Field | Description | Required |
|---|---|---|
| **Administrator Password** | The local Administrator password that will be set inside the new VM. | Yes |
| **Override ComputerName** | Tick this box to enter a custom computer name for the VM guest OS. When unticked, the name is auto-assigned. | No |
| **Copy Folder** | Select a local folder to copy to guest `C:\` as a folder with the same name, including its contents. Enter a path or use **Browse**; cancelling preserves the current value. Does not change application selection: selected application resources are staged separately. | No |
| **Run Script** | Select a `.ps1` filename directly in `Resources\CustomScripts`, or **NA** to run no script. Only filenames are stored, e.g. `Sample1.ps1`; no paths/subfolder scripts. **Refresh** reloads imported choices and retains an available selection. CustomScripts is copied independently of Copy Folder and applications. **Skip RunScript** disables selection/execution, not copying. | No |
| **Skip Baseline** | Tick to skip applying the Microsoft Security Baseline. Defaults to **off**. | No |
| **Skip Application** | Tick to skip application installation steps defined by the deployment workflow. Defaults to **off**. | No |
| **Skip Disk Encryption** | Tick to skip disk encryption steps during deployment. Defaults to **off**. | No |
| **Skip RunScript** | Tick to skip the post-deployment run command or script stage. Defaults to **off**. | No |
| **Show Verbose** | Tick to keep verbose output enabled in the launched PowerShell deployment window. This preference is saved between launches. | No |
| **Use DHCP** | Tick to assign network settings automatically via DHCP. Untick to enter a static IP address. Defaults to **on**. | No |

#### Static IP Fields (visible only when Use DHCP is unticked)

| Field | Example |
|---|---|
| **IP Address** | `192.168.10.50` |
| **Subnet** | `24` |
| **DNS1** | `192.168.10.1` |
| **DNS2** | `8.8.8.8` |
| **Gateway** | `192.168.10.1` |

---

## Disk Modes

The **Disk Mode** controls how the VM's virtual hard disk is prepared:

| Mode | What Happens |
|---|---|
| **Diff** | Creates a differencing disk linked to the source VHDX. |
| **Copy** | Copies the full source VHDX to the VM folder. |

These are the only modes offered by this UI and accepted by `New-PAWVM.ps1`.

> **Recommended**: Use **Diff** or **Copy** for most deployments.

## Saved Settings and Logs

`PAWDeployUI.ps1` now keeps a small per-user settings file so the last-selected template and UI toggle choices can be restored the next time the tool starts.

During each run, the UI writes `%TEMP%\PAWDeploy\PAWDeployUI.log`. `New-PAWVM.ps1` writes structured deployment entries to `%TEMP%\PAWDeploy\New-PAWVM.log`. The UI also writes a short-lived credential file named `PAWDeploy-<VMName>.dat` under `%TEMP%`; `New-PAWVM.ps1` reads and removes it.

This makes it easier to troubleshoot failed launches or confirm which options were used for a specific deployment.

---

## Step-by-Step: Deploying a VM

1. **Open the tool** as Administrator (shortcut or PowerShell).
2. **Select a Template** from the dropdown. The form auto-fills from the selected JSON template and configuration.
3. If you want to use an image other than the template's, enter or browse for it in **VHD(X) override**, directly below **Disk Mode**.
4. **Select a VM Switch** from the dropdown.
5. **Enter the Administrator Password** for the new VM.
6. *(If domain-joined template)* Enter the **Domain Username** and **Password**, and verify or change the **OU**.
7. *(Optional)* Adjust the VM Name, VLAN ID, Disk Mode, or any other settings.
8. *(Optional)* Tick **Show Verbose** if you want the launched PowerShell window to include verbose output.
9. *(Optional)* Untick **Use DHCP** if you need a static IP and fill in the network fields.
10. Click **Build**.
   - If any required field is missing, it will turn **orange**. Fix the highlighted fields and click Build again.
   - If all fields are valid, the form writes the selected settings to disk, closes, and opens a new PowerShell window showing the deployment progress.

---

## What Happens After You Click Build

The tool validates required inputs, saves UI settings, stores passwords in a short-lived per-run credential file under `%TEMP%`, then launches `New-PAWVM.ps1` in a new PowerShell window with supported selected values passed as parameters.

Before launch, the UI logs to `%TEMP%\PAWDeploy\PAWDeployUI.log`. Deployment events are logged by `New-PAWVM.ps1` to `New-PAWVM.log` in the same fixed folder.

The deployment window stays open after it finishes so you can review the output. You can close it manually when done.

The deployment sequence follows the engine workflow:

1. Creates the VM and virtual disk in Hyper-V.
2. Mounts the source image and stages unattended setup, optional ExtraFolder content, and configured baseline files.
3. Starts the VM and waits for Windows setup and PowerShell Direct readiness.
4. Applies guest hardening, including VBS/Credential Guard and BitLocker unless disabled, then applies shielding when enabled.
5. Runs the selected `RunScript`, then PAWAppInstall when enabled and configured, then applies baselines when the template enables them.
6. Removes staging folders unless cleanup is skipped and creates a VM Connect shortcut unless skipped.
7. Leaves the VM stopped unless `-StartPAW` or `-ConnectPAW` was requested.

## Validation Errors

If you click **Build** before filling in all required fields, the tool highlights missing fields in orange and shows **"Fix validation errors"**. Domain templates also require a username and password. The form resolves the template `VHDFile` the same way the engine does (a filename resolves under `VHDFolder`) and checks that the file exists. A missing file highlights Template and reports the validation error. When populated, **VHD(X) override** is passed as `-VHDX` and validated in place of the template image.

| Orange field | What to do |
|---|---|
| **Template** | Select a template from the dropdown |
| **Source** | Enter or browse to a valid `.vhdx` file path |
| **VM Switch** | Select a switch from the dropdown |
| **Administrator Password** | Enter a password for the local Administrator account |
| **ComputerName** | Enter a 3–15 character name when Override ComputerName is ticked |

---

## Examples

### Example 1 — Deploy a standard workgroup PAW (DHCP)

1. Open the tool as Administrator
2. Select template `Windows 11 x64 PAW for WORKGROUP ON`
3. The source label shows the template `VHDFile`; confirm that it resolves to a file in the configured `VHDFolder`.
4. VM Switch: `Default Switch`
5. Administrator Password: *(your secure password)*
6. Leave **Skip Baseline**, **Skip Application**, **Skip Disk Encryption**, and **Skip RunScript** unticked
7. Leave all other settings at defaults
8. Click **Build**

---

### Example 2 — Deploy a domain-joined PAW with a static IP

1. Open the tool as Administrator
2. Select an active domain-joined template in Config
3. Verify the selected template references the correct VHD(X)
4. VM Switch: a domain-appropriate switch available on the host
5. VLAN ID: `20`
6. Disk Mode: `Copy`
7. Administrator Password: *(your secure password)*
8. Untick **Use DHCP** and enter:
   - IP Address: `10.0.20.50`
   - Subnet: `24`
   - DNS1: `10.0.20.10`
   - Gateway: `10.0.20.1`
9. Domain Username: `SvcJoin`
10. Domain Password: *(domain join account password)*
11. Verify the **OU** shows `OU=PAW Tier1,DC=corp,DC=local`, or change it to override the template for this deployment.
12. Optional: tick **Show Verbose** if you want extra output in the deployment window
13. Click **Build**

---

### Example 3 — Deploy with a custom folder and post-deploy script

1. Select your template
2. Fill in Source, VM Switch, and Administrator Password
3. Copy Folder: `C:\PAWFiles\AgentTools` *(this folder will be copied into the VM)*
4. Run Script: `Setup.ps1` *(import it into configured CustomScripts first; runs from `C:\PAWFiles\CustomScripts` in the VM)*
5. Leave **Skip RunScript** unticked so the command is allowed to run
6. Click **Build**

---

## Troubleshooting

| Problem | Likely Cause | Solution |
|---|---|---|
| Template dropdown is empty | No valid JSON templates exist in Config, or all have `Active = False` | Open the template JSON file in `Config` and set `Active` to `true` (or omit `Active`); do not add it to `Config.json` |
| VM Switch is still loading | The first Hyper-V query can take several seconds | Continue filling in the form. Build and Copy CMD are enabled once the list is available. |
| VM Switch reports a failed lookup or no switches | Hyper-V could not be queried, or no switches are defined | Check Hyper-V and Virtual Switch Manager, then click **Refresh**. Lookup failures and startup timings are recorded in the PAW Deploy UI log. |
| Source field turns orange | The file path does not exist or the file cannot be found | Click Browse to locate the correct `.vhdx` file |
| Domain fields do not appear | The selected template is configured as Workgroup | Select a domain-joined template, or update `Config.json` |
| Deployment window opens then closes immediately | Deployment failed very early in `New-PAWVM.ps1` | Check `New-PAWVM.log` and `PAWDeployUI.log` in `%TEMP%\PAWDeploy` |
| "Access denied" on launch | Script is not running as Administrator | Right-click the shortcut → Run as Administrator |
| VM already exists error | A VM with the same name already exists in Hyper-V | Change the VM Name field before clicking Build |
| Settings are not remembered | The settings file cannot be written to `%TEMP%\PAWDeploySettings` | Verify the folder is writable for the current user and that security software is not blocking writes |
| Need to review what options were used for the last build | The form closed after launching the deployment | Check `PAWDeployUI.log` and `New-PAWVM.log` in `%TEMP%\PAWDeploy` |

---

## Related Documents

- [Config.json.md](Config.json.md) — How to configure templates and settings
- [New-PAWVM.md](New-PAWVM.md) — The command-line deployment engine that this tool calls
- [Convert-PAWWIM2VHD.md](Convert-PAWWIM2VHD.md) — How to create the VHDX source image
- [Install-PAWDeploy.md](Install-PAWDeploy.md) — Setting up the solution for the first time
- [PAWRemoveVMUI.md](PAWRemoveVMUI.md) — Graphical tool for removing PAW virtual machines

---

## Quick Validation Checklist

After clicking **Build** and completing deployment, verify the following:

1. The new VM appears in Hyper-V.
2. The VM has the expected memory, CPU, switch, and VLAN settings.
3. The VM is stopped after deployment by default; start it from Hyper-V when ready.
4. Baseline, application option, disk encryption, and RunScript behavior match the selected template and toggles.
5. Shielding settings match what you selected.
6. A VM Connect shortcut is available in the `PAW Links` desktop folder.
7. `%TEMP%\PAWDeploy` contains the UI log and structured deployment log.
