# New-PAWVM.ps1

See [Commandline Samples](CommandlineSamples.md) for the full PowerShell workflow from image and resource imports through preflight and deployment.

## What Is It?

`New-PAWVM.ps1` is the core deployment engine of the PAWDeploy solution. It is the script that actually creates a Privileged Access Workstation (PAW) virtual machine from start to finish in a repeatable workflow; it prompts for any credentials not supplied.

You select a JSON deployment template from Config and provide any needed host/network choices. The script creates the VM, stages the Windows image, configures and hardens the guest, optionally joins it to a domain, and then stops or starts the VM according to the requested options.

VM Notes always begin with `###PAW42###`, followed by a space and the existing
template `vmnotes` text when present. Removal tools only offer/accept VMs whose
Notes contain this literal marker; older unmarked VMs are not automatically tagged.

This is the **headless** (command-line only) version. If you prefer a graphical interface with buttons and dropdowns, see `PAWDeployUI.ps1` instead  -  it uses this script behind the scenes.

## Deployment resource preflight

Before normal preflight, the engine removes leftovers from earlier builds,
automatically when safe and otherwise after asking `[y/N]` (`y`, `yes`, `j`
or `ja` mean yes). It reads every non-secret ownership journal in
`%TEMP%\PAWDeploy\Recovery`, regardless of which installation wrote it.

| Leftover | Action |
|---|---|
| Earlier build (interrupted or completed) whose staging folder has a verified ownership marker | Removed without asking: recorded offline setup files on a still-mounted disk, the mount itself, the staging folder and the credential file. **The VM and everything in its VM directory are always kept** |
| Staging folder ownership marker missing or different | Asks **Remove these leftovers anyway?** |
| The recorded mounted disk is outside the VM directory, or the staging folder is a reparse point | Nothing is removed; asks **Forget this recovery record and keep its resources for manual handling?** |
| Unreadable or invalid journal | Asks **Delete the journal file?** |
| `%TEMP%\PAWDeploy-<guid>` staging folder that no journal references | Removed if it has an ownership marker, otherwise asks |
| `%TEMP%\PAWDeploy-<VM>.dat` credential file that no journal references | Removed when older than one hour and not for the VM being built |

Answering no, or a failed removal, keeps the resources, logs a warning and lets
the new build continue; the leftovers are offered again next time. Resource
preflight runs after recovery, so conflicting leftovers still stop the build.
Active builds in other processes/runspaces are never touched, and
`-PreflightOnly` and `-WhatIf` never prompt for or perform recovery.
External/source disks are never detached or deleted.

Recovery never stops or removes a VM and never deletes files in a VM directory,
because a partly deployed VM may already be in use. Remove unwanted VMs manually
(for example with Remove-PAWVM or Hyper-V Manager).

Journals contain IDs, paths and process ownership only, never passwords or
credentials. The engine never guesses ownership from a name or an attached base image.

Applications are selected through the template's `ApplicationBundle`.
`-ApplicationBundle <Name or BundleId>` overrides that assignment for this build only.
Tab completion lists bundles by name and inserts the name; duplicate names and
reserved names (`NA` or GUIDs) are completed as IDs. To select a duplicate name
manually, specify its BundleId. Name matching is case-insensitive. Bundles are
suggested before `NA`.
`-SkipApplication` wins over both. `ApplicationBundle = NA` (template or
parameter) skips applications. New PAW exposes the same choice for Build
and Copy CMD. See [Application Manager](ApplicationManager.md) for catalog,
bundle and selection rules.

`Test-PAWDeployment` checks resources, not template format. The engine runs it
before staging or credential prompts and again after automatic application
preparation, immediately before creating the VM. UI Build and pasted Copy CMD
commands use this same engine gate. Missing resources for active steps block
build start; explicitly skipped steps require no corresponding payload.
Import's separate format/value validation is unchanged.

Capacity rules use binary GB/MB:

| Resource | Minimum free capacity |
|---|---|
| Host RAM | VM startup memory + 1 GB overhead + 4 GB remaining for the host |
| Copy VM disk | Source VHDX file's actual length + 5 GB build allowance + 5 GB reserve |
| Diff VM disk | 5 GB build allowance + 5 GB reserve |
| Separate system, temporary or configured payload/cache volumes | At least 5 GB free |

Checks include Hyper-V access/switch, VM name/directory conflicts, source VHD
and parent chain readability, Copy Folder, selected RunScript,
baseline scripts/LGPO, WDAC policy and application resources. WinGet installation
cache must pass its hash check; PSGallery dependencies must be cached. Host
capacity lookup errors block deployment rather than assuming capacity.
VHD attachment state is not a preflight condition: an attached base disk is
normal when existing VMs use differencing disks. Preflight checks that the source
and parent files exist and their metadata can be read, and rejects circular or
inaccessible parent chains. It does not dismount disks or change VM assignments.

Baseline preflight requires `OS\Scripts\Tools\LGPO.exe` and
`Edge\Scripts\Tools\LGPO.exe` under the selected baseline folder, matching
the LGPO import layout. Copies directly under `OS\Tools` or `Edge\Tools`
do not satisfy these checks.

Enabled application downloads may be prepared after the first check. Missing
downloadable caches are pending, not considered ready; missing Local installers
block immediately. Preparation failure or an incomplete cache blocks the final
gate. Runtime failures after successful preflight retain existing optional-step
reporting and VM-retention behavior.

To inspect without staging, downloading, credential prompts or creating a VM:

```powershell
$plan = .\New-PAWVM.ps1 -Template 'My template' -VMName 'PAW-01' -PreflightOnly
$plan.Settings
$plan.Steps
$plan.Checks | Format-Table Name, Passed, AvailableBytes, RequiredBytes, Message
$plan.Errors
$plan.PendingDownloads
```

`CanPrepare` means no resource blockers were found. `CanDeploy` additionally
requires no pending application preparation. To verify existing cache strictly,
call `Test-PAWDeployment` without `-AllowPendingDownloads` using the loaded
template and bound overrides. Normal runs log checks, resolved sources and
Run/Skip decisions. `-Validate` remains the existing verbose/notification option.
Both preflight gates include all blocking resource names and reasons directly
in the terminating error, so failures can be reviewed without scrolling through
earlier logs. The final gate also includes application preparation failures.
Select a missing/unspecified switch explicitly with `-VMSwitchName` before retrying.
Capacity is not reserved: concurrent workloads, download growth, guest OS/Defender
compatibility and domain access can still cause runtime failures.

---

## Why Is It Needed?

Building a PAW virtual machine manually is a time-consuming, error-prone process. Templates centralize the expected security settings and hardening so deployments can be repeated with less manual effort.

`New-PAWVM.ps1` eliminates that risk by automating the entire process in a fixed, auditable sequence. Deployments use the selected template and append activity to `%TEMP%\PAWDeploy\New-PAWVM.log`.

The engine uses combined `Write-PAWLog` calls for file and console/verbose/warning
output, retaining colors, streams and file severity. `Resolve-PAWSetting` shares
the precedence logic for DiskMode, VMGen, CPU, memory, dynamic memory,
domain/workgroup, time zone and four locale settings. Existing fallback rules
and downstream locale/time-zone validation remain unchanged; diagnostics now
consistently identify the selected source. See
[logging and resolution](PAWUtility.md#combined-logging-and-setting-resolution).

---

## Before You Start

Template `RunScript=NA` selects no post-deployment script.
`SecurityBaselineLocation=NA` selects no baseline: both baseline copy and
application are skipped, including when `ApplySecurityBaseline=True`.

### ASR and Windows Defender Application Control

- **Template `ASR` controls ASR (`"True"`/`"False"`), like Shielded and BitLocker.**
  New templates use `"ASR": "True"`; older templates without the field retain
  enabled-by-default behavior. `False` skips ASR configuration. After guest deployment and secret cleanup, rules
  applicable to the guest OS in the ASR master list are configured in their
  selected **Block**, **Audit** or **Disabled** mode and read back from Defender.
  Use `-SkipASR` to override template
  `True` and opt out; it does not enable ASR when the template is `False`.
- Active Microsoft Defender Antivirus and real-time protection are required.
  The reputation/ransomware rules also require cloud-delivered protection.
  Unsupported builds are logged as NotApplicable; rejected/unverified rules
  warn with corrective guidance and appear in the optional-failure summary.
  The master list is not an API enumeration of future rules, and read-back
  does not prove that a rule is enforced against every threat.
- **WDAC has no default policy.** Import XML into `PAWDeploy\Resources\WDACPolicies`.
  Set optional template `WDACPolicyFile` to a
  filename, e.g. `PAW.xml`. Override with `-WDACPolicy 'PAW.xml'`; an explicit
  empty/`NA` override selects no policy. No subpaths are accepted.
- `-SkipWDAC` bypasses policy validation and installation completely. Without it,
  the selected XML is schema-validated on host and guest, compiled **in the VM**
  and hash-verified at `System32\CodeIntegrity\CIPolicies\Active\{PolicyID}.cip`
  (legacy format uses `System32\CodeIntegrity\SiPolicy.p7b`).
- XML Audit/Enforced options are preserved. **Activation occurs at the next VM
  boot**, not during deployment. Validate your policy before Enforced deployment:
  restrictive policies can block applications and administration. Existing
  policy binaries are never replaced. Multi-policy XML requires Windows 10
  1903/Server equivalent or newer; supplemental XML requires its base binary
  already installed. Signed-required XML is refused at deployment because this
  workflow has no binary signing infrastructure; it never silently weakens XML.
- ASR/WDAC errors are logged as warnings, deployment continues, and the final
  report lists failures. Secret/autologon cleanup is verified first; staging
  folders are cleaned only after security succeeds, preserving diagnostics on
  optional failures or `-SkipGuestFolderCleanup`. Neither step runs on the host
  or removes VM/disks.

#### ASR master list

`Resources\ASR\MasterList.json` is the shared, offline list used for all guest
OS versions. It has a schema version, a list version and an ordered `Rules`
array. Each rule has a GUID `Id`, `Name`, `Mode` (`Block`, `Audit` or `Disabled`),
`ClientMinBuild`, `ServerMinBuild` and boolean `RequiresCloudProtection`.
A minimum build of `0` means the rule is not applicable to that OS type.
The deployment log records the list version and validates the whole list before
applying any rule. A missing, empty or invalid list is reported as an ASR failure;
no fallback list is silently substituted.
The supplied list contains the 18 selected client rules in Block mode. Rules
not listed are not removed from Defender, including rules already configured in
the reference image or by policy.

Use `Tools\Invoke-PAWASRSettings.ps1` to list, add, edit and remove entries.
The [Edit ASR Rules editor](PAWASREditorUI.md) provides the same operations
in Enterprise Edition. Both edit the list only; they do not change Defender on
the host or existing VMs. The editor increments the patch version after a
successful change and validates the whole list before replacing the file.
Removing the last rule is not allowed.

Review rule IDs, applicability and prerequisites against the
[Microsoft ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
before editing the list. Update its `Version` when changing the JSON manually; a new
Windows version does not by itself require a new list. New Microsoft rules are
not discovered automatically. The installer preserves an existing master list
during upgrades; compare it with the list in a newer package and update it
explicitly after review. Test changes before deployment. `Block` can affect
legitimate administration and applications, and central policy can override
local configuration.

Import several policies without activating them:

```powershell
.\Tools\Import-PAWWDACPolicy.ps1 -Path 'C:\Policies\PAW.xml','C:\Policies\Audit.xml'
# Explicit replacement approval:
.\Tools\Import-PAWWDACPolicy.ps1 -Path 'C:\Policies\PAW.xml' -Replace
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' -WDACPolicy 'PAW.xml'
# Opt out:
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' -SkipASR -SkipWDAC
```

The importer validates Microsoft Code Integrity XML schema before any writes,
requires explicit replacement, supports WhatIf, and logs success/errors to
`%TEMP%\PAWDeploy\Import-PAWWDACPolicy.log`. It does not compile or
activate policy. Windows Code Integrity tooling/schema must be installed.

Template tab-completion uses the shared `Get-PAWTemplateArgumentCompletion`
function; the completer imports PAWUtility with `-Scope Local`, so the
caller's session is not changed. It quotes names when
needed and falls back to substring suggestions when no prefix matches.
The parameter still rejects empty names; existence is checked against the
loaded Config templates after module import, before VM creation, rather than
reading every template again during parameter binding. Unknown names abort
deployment with the available names in the error and log.

Client, Server and the existing Client fallback share the same 23 unattend
arguments through splatting. The parameter bag is cleared in `finally`, also
on generator failure. The administrator password reference needed by later
guest setup remains until its existing cleanup point; clearing managed
references does not guarantee erasure of string memory.

Make sure the following are in place before running the script:

1. **Run as Administrator.** The script checks for an elevated PowerShell session and requires the Hyper-V module.
2. **PAWDeploy is installed.** The script, `Config.json`, and `Functions\PAWUtility` module must be present together (see `Install-PAWDeploy.md`).
3. **Configuration and templates are ready.** Config contains `Config.json` and the template JSON files alongside it. The command-line engine can select any valid template JSON; the GUI separately filters templates with `Active` set to false.
4. **The template VHDX exists.** A template's `VHDFile` is resolved against `Settings.Configuration.VHDFolder` when it is a filename, and must exist. See `Convert-PAWWIM2VHD.md` if you need to create one.
5. **A Hyper-V virtual switch exists.** The selected template's `VMSwitch` is used by default; `-VMSwitchName` can override it. Use `Get-VMSwitch` to list host switches.
6. **Credentials are ready.** The script prompts for a local Administrator password when none is supplied. Domain deployments also require a username-only domain join account and password.

## What the Script Does  -  Step by Step

When you run `New-PAWVM.ps1`, the script reads `Config.json` and the selected JSON template, resolves the VM name, storage path, VHDX, switch, and other defaults, then:

1. Validates the Hyper-V switch and source VHDX and gathers any missing credentials.
2. Creates the VM and its disk through `New-PAWHyperVVM` using the selected `DiskMode` (`Diff` or `Copy`). This module function handles Hyper-V creation only; `New-PAWVM.ps1` remains the complete deployment entry point.
3. Mounts the VM's new disk to stage Windows unattended setup data, the deployment-completion marker, optional `ExtraFolder` content, and baseline files when a `SecurityBaselineLocation` is configured and `-SkipSecurityBaseLine` is not set. Staging requires clean Panther and Setup\Scripts paths in the offline image.
4. Starts the VM and waits for Windows setup and PowerShell Direct readiness.
5. Configures the guest through PowerShell Direct, including virtual TPM/BitLocker (unless disabled), VBS and Credential Guard, and temporary first-boot autologon. It restarts the VM, then checks the guest for pending restarts (Component Based Servicing or Windows Update). If one is pending, it performs up to two extra controlled restarts so the guest does not restart itself later in the deployment. It then waits for encryption to complete when encryption is enabled. If the guest still restarts unexpectedly, PowerShell Direct reconnects for up to five minutes, and shutdown requests made while the guest restarts (`0x800706B5`) are repeated.
6. Applies the Shielded VM policy unless the template disables it or `-SkipShielding` is specified, runs the selected post-deployment script unless `-SkipRunScript` is set, installs configured applications when the required app-install files are present and `-SkipApplication` is not set, and applies baselines when template `ApplySecurityBaseline` is `True` and files were staged.
7. Removes and verifies temporary autologon values and staged setup files, removes guest staging folders unless `-SkipGuestFolderCleanup` is set, and cleans host staging artifacts. Then it stops the VM and creates a VM Connect shortcut unless `-SkipLink` is set. `-StartPAW` starts it after successful deployment; `-ConnectPAW` also launches VMConnect.

All three shutdown points (restart, shielding and final shutdown) wait until
Hyper-V reports `Off` before proceeding. If shutdown is already in progress
(`0x8007045B`), deployment reports that it is waiting rather than immediately
trying to start the VM again. State is checked every five seconds, with a
ten-minute timeout. While the VM still reports `Running`, the graceful shutdown
request is repeated every 30 seconds, because the guest can reject or cancel an
earlier request. Other shutdown/query errors and timeouts abort deployment;
the VM is never forcibly powered off by normal shutdown handling. Failed
failed-deployment cleanup does not stop or delete the VM.

Known guest configuration/read operations now share an explicit, deployment-owned
PowerShell Direct context within a boot cycle. It is closed before each of the
three shutdowns and in `finally`, before rollback cleanup. Reuse validates VM ID,
credential-object identity and session connectivity; unexpected broken sessions
are recreated. External application/module installers, RunScript, baselines and
guest cleanup retain isolated one-shot sessions so guest runspace state cannot
leak into the shared deployment session. Unknown-outcome commands are not replayed
without `-RetryCommand`. See [session ownership](PAWUtility.md#deployment-scoped-powershell-direct-sessions).

Polling already checks immediately without an initial interval sleep. Session
creation counts and lifecycle behavior are tested automatically; no live deployment
speed improvement has been measured.

## Optional-stage failures and final report

Application download/install, disk encryption, RunScript, shielding, security
baseline copy/application and shortcut creation are non-blocking deployment steps.
BitLocker warnings (including the restart/hardware-test instructions) are captured
inside the guest and written as timestamped WARN log/console lines, with all text retained.
Application downloads use `Resources\ApplicationDownloads`; definitions and
bundles use `Resources\ApplicationCatalog` and `Resources\ApplicationBundles`.
These fixed host paths are independent of `-ExtraFolder` / **Copy Folder**.
Only the selected install metadata, installers, modules and application payloads
are staged under `C:\PAWFiles\AppInstall`, alongside the shared PAWUtility module.
Unrelated content at these guest destinations is not overwritten: staging warns
and application installation is skipped.
Download failure still allows staging/installing an existing cache; staging
failure prevents application installation but not later optional steps.
Failures emit a warning, record the reason in the deployment log and allow the
next stage to run. Each application and PowerShell module is attempted separately.
OS and Edge baseline scripts are also attempted independently; subprocess stdout
and stderr are retained in the host log, including failures before rollback.
Missing prerequisites and nonzero exit codes are reported rather than treated as
success. Encryption completion is only awaited after enabling succeeded; stalled
states or a two-hour limit produce a warning instead of an unlimited wait.

The final console/log report lists failed steps and their causes. It says
**finished with optional-step failures**, not fully successful: the PAW is **not
verified as fully configured/hardened**. Review and remediate failed controls before
using it as a privileged workstation. Baseline/application guest folders remain for
diagnosis whenever optional failures occurred. Explicitly skipped steps are not
reported as failures. `-StartPAW`/`-ConnectPAW` handoff errors are reported similarly.

Core creation/storage/configuration, required guest readiness, secret removal and
normal final shutdown remain blocking safety requirements. Optional failure
handling does not automatically replay unknown-outcome commands, undo partially
applied policies, delete the VM or hide cleanup failures.

## Deployment cleanup and failure rollback

[Invoke-PAWDeploymentCleanup](PAWUtility.md#deployment-cleanup) consolidates
cleanup. Autologon remains enabled during installation and its required reboots.
After all installation steps, cleanup removes `AutoAdminLogon`, `DefaultPassword`,
`DefaultUsername`, `DefaultDomainName`, `AutoLogonCount` and `ForceAutoLogon`
**values**, not the Winlogon registry key. It verifies their absence before final
shutdown. Guest cleanup also removes staged `Windows\Panther\Unattend.xml`,
`Windows\Panther\Unattend\Unattend.xml` and
`Windows\Setup\Scripts\SetupComplete.cmd`.
`-SkipGuestFolderCleanup` preserves only `C:\SECBL` and `C:\PAWFiles`;
it never bypasses autologon or setup-file cleanup.

Each run uses a unique `%TEMP%\PAWDeploy-<GUID>` directory. It no longer deletes
the shared `%TEMP%\PAWDeploy` directory. Host cleanup removes the current run's
credential file and staging directory and detaches any offline disk mount it
claimed, including when staging fails partway through.

`New-PAWHyperVVM` exclusively creates and records the VM directory; the engine
does not pre-create it. Existing directories, even empty ones, are refused.
The helper also creates the disk subdirectory before Copy/Diff/Empty/Attached
operations. This avoids duplicate directory creation and keeps failure cleanup
ownership tied to the exact directory created by this deployment.

On installation failure, `finally` **retains the VM, its power state, VM directory,
disks and checkpoints** for diagnosis. It attempts autologon/setup-file cleanup
through PowerShell Direct without starting the VM or mounting an offline registry.
`C:\SECBL` and `C:\PAWFiles` remain for diagnosis regardless of
`-SkipGuestFolderCleanup`. If the deployment's offline disk is still mounted,
recorded staged unattend/setup files are removed before dismount is attempted.
Host temporary setup/credential files are cleaned. If dismount fails, the
mount/staging directory is retained to avoid deleting through a mounted disk;
credential-file cleanup is still attempted. Existing VM directories remain
refused for subsequent deployments: choose another name or remove the retained VM
and its files explicitly after investigation.

Cleanup failures are warned/logged without replacing the original deployment
error. If guest access or deletion is blocked (for example by shielding), logs
explicitly report incomplete cleanup: any retained disk may still contain
autologon credentials or unattended setup data and needs manual recovery.
Automatic cleanup cannot run after host power loss or forceful process termination.

Once verified cleanup and final shutdown have completed, the VM is considered
installed. Later shortcut/start/VMConnect errors do **not** delete that VM.

## How to Run It

Open Windows PowerShell 5.1 **as Administrator** and navigate to the PAWDeploy folder:

```powershell
Set-Location C:\PAWDeploy
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' -VMSwitchName 'Default Switch'
```

Only `-Template` is mandatory in the parameter declaration. `-VMSwitchName` is optional: the template's `VMSwitch` is used when omitted, and the script prompts for a host switch if neither is set. Other values come from the template/`Config.json` or are prompted for when needed.

## Parameters Reference

Every script parameter is in the default parameter set; no named parameter sets are defined. Only `-Template` is mandatory. `-Verbose`, `-WhatIf`, and `-Confirm` are standard common parameters provided by `[CmdletBinding(SupportsShouldProcess = $true)]`, not entries in the script's `param` block. `-WhatIf` is not a guarantee that every preliminary file operation or prompt is skipped.

| Parameter | Type | Mandatory | Default / behavior and accepted values |
|---|---|---:|---|
| `-Template` | String | Yes | No default. Must be non-empty and match a JSON template's `Name` (or filename if `Name` is empty); checked against templates found at runtime. Alias: `-Templaate`. |
| `-VMname` | String | No | Must be non-empty when supplied; otherwise generated from template `NamePrefix`, a random segment, and `NameSuffix`. |
| `-VMSwitchName` | String | No | Must be non-empty when supplied. Template `VMSwitch` is used when omitted; if absent the script prompts from host switches. Completion lists discovered switches; selected name must exist on the host. |
| `-VMLocation` | String | No | Must be non-empty when supplied. Defaults to `Settings.HyperV.VMFolder`, legacy `Settings.HyperV.VMLocation`, or `C:\VMs`. A configured/provided path must exist; the fallback `C:\VMs` can be created. |
| `-OSDAdapter0IPAddressList` | String | No | If omitted, all five network settings default to `DHCP`; otherwise the supplied address is used. |
| `-OSDAdapter0Gateways` | String | No | Defaults to `DHCP` when the IP parameter is omitted. |
| `-OSDAdapter0DNS1` | String | No | Defaults to `DHCP` when the IP parameter is omitted. |
| `-OSDAdapter0DNS2` | String | No | Defaults to `DHCP` when the IP parameter is omitted. |
| `-OSDAdapter0SubnetMaskPrefix` | String | No | Defaults to `DHCP` when the IP parameter is omitted. |
| `-AdminPassword` | SecureString | No | Prompts interactively when omitted (unless the UI's short-lived credential file supplies it). |
| `-DomainJoinAccount` | String | No | Prompts for Domain deployments when omitted. Username only; `@`, `\`, and `/` are rejected. |
| `-DomainJoinAccountPassword` | SecureString | No | Prompts for Domain deployments when no password was supplied. |
| `-VlanID` | String | No | Template `VLanID`; range 0–4095. |
| `-SkipShielding` | Switch | No | Off by default; prevents Shielded VM policy from being applied. Otherwise template `Shielding`/`Shielded` determines the request (missing value defaults to enabled). |
| `-ExtraFolder` | Object | No | No default; supplied folder content is staged in the guest under its leaf name. |
| `-RunScript` | Object | No | `.ps1` filename directly in `Resources\CustomScripts`, e.g. `Sample1.ps1`; no paths. Command-line overrides template. `NA`/empty skips execution. CustomScripts is always staged independently of apps/ExtraFolder at C:\PAWFiles\CustomScripts, and execution starts in that folder. |
| `-VHDX` | String | No | Template `VHDFile`; overrides it. Rooted paths are used directly; filename-only values resolve under configured `VHDFolder`; the resolved file must exist. |
| `-SkipSecurityBaseLine` | Switch | No | Off by default. Skips baseline file staging. A non-empty template `SecurityBaselineLocation` enables staging, and template `ApplySecurityBaseline = True` enables application in the guest. |
| `-OSDComputerName` | String | No | Defaults to the VM name. When supplied, ValidateLength is 3–15 characters. |
| `-DiskMode` | String | No | Template `DiskMode`, then `Settings.HyperV.DiskMode`, then `Diff`. ValidateSet: `Diff`, `Copy`. |
| `-SkipApplication` | Switch | No | Off by default; suppresses the application-install path. Template `Application = False` also disables it. |
| `-ApplicationBundle` | String | No | Bundle name or ID overriding the template for this build. Tab completion suggests available bundles; `NA` skips application installation. |
| `-SkipDiskEncryption` | Switch | No | Off by default; skips BitLocker setup and the encryption-completion wait. Template `BitLocker = False` also disables encryption. |
| `-SkipRunScript` | Switch | No | Off by default; prevents execution of the selected `RunScript`. |
| `-SkipLink` | Switch | No | Off by default; skips creation of the VM Connect shortcut. |
| `-StartPAW` | Switch | No | Off by default; VM is left stopped unless this or `-ConnectPAW` is supplied. |
| `-ConnectPAW` | Switch | No | Off by default; starts the VM and launches VMConnect after successful deployment; implies `-StartPAW`. |
| `-NoLaps` | Switch | No | Off by default; for Domain deployments, skips creating `PreventLAPS.txt`. |
| `-SkipGuestFolderCleanup` | Switch | No | Off by default; preserves guest `C:\SECBL` and `C:\PAWFiles` folders rather than removing them at completion. |
| `-Validate` | Switch | No | Off by default; enables verbose output and the final-phase notification before the last VM shutdown. |

## Examples

### Deploy using a template

The template supplies the switch and other defaults; the script prompts for credentials when required.

```powershell
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON'
```

### Select an application bundle by name

When application installation is enabled in the template, use a unique bundle
name or press Tab after `-ApplicationBundle` to choose an available bundle:

```powershell
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' `
    -ApplicationBundle 'Admin Tools'
```

### Specify a VM name and storage folder

```powershell
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' `
    -VMSwitchName 'Default Switch' -VMname 'PAW-ADM-001' -VMLocation 'D:\VMs'
```

### Deploy with a static IP

```powershell
.\New-PAWVM.ps1 -Template 'Windows 11 x64 PAW for WORKGROUP ON' `
    -VMSwitchName 'Default Switch' `
    -OSDAdapter0IPAddressList '10.0.1.50' `
    -OSDAdapter0Gateways '10.0.1.1' `
    -OSDAdapter0DNS1 '10.0.0.10' `
    -OSDAdapter0DNS2 '10.0.0.11' `
    -OSDAdapter0SubnetMaskPrefix '24'
```

### Deploy a Domain template with credentials and options

```powershell
$adminPwd = Read-Host -Prompt 'Local Admin Password' -AsSecureString
$domainPwd = Read-Host -Prompt 'Domain Join Password' -AsSecureString
.\New-PAWVM.ps1 -Template 'Domain PAW' -VMSwitchName 'Corp Switch' `
    -AdminPassword $adminPwd -DomainJoinAccount 'svcPAWDeploy' `
    -DomainJoinAccountPassword $domainPwd -SkipShielding -SkipLink
```

## Log File

The deployment log is `%TEMP%\PAWDeploy\New-PAWVM.log`. This fixed folder is created if needed and cannot be overridden by configuration. The log is appended to on each run, starting before template loading and resource preflight. Startup failures are logged and rethrown; a fatal process crash can leave only the last completed startup marker.

Offline directory staging uses Robocopy with long-path support, including deep
PowerShell module payloads. Its output and exit status are recorded in the deployment
log. Exit codes 8 or higher fail the copy instead of reporting success. Copy Folder
failures stop deployment; optional staging failures retain their existing warning
and summary behavior. Only selected typed application packages are staged; other
files and empty folders are copied without mirroring or deleting destination content.
Directory junctions are excluded to avoid following them outside the payload tree.
Regression tests enforce the deployment engine's copy contract: no recursive
`Copy-Item` staging, and explicit `-ErrorAction Stop` on every copy operation.

## The VM Connect Shortcut

Unless `-SkipLink` is set, a shortcut named for the VM is created under `PAW Links` on the All Users desktop. Existing shortcuts in the former `VMLinks` folder are left unchanged. Double-click a shortcut to open Hyper-V VM Connect. The VM itself is stopped after deployment by default; use `-StartPAW` or `-ConnectPAW` to leave it running.

---

## Troubleshooting

| Problem | What to check |
|---|---|
| *"No templates found"* or Tab completion shows nothing | Check that `Config\Config.json` exists and Config contains a valid template JSON file whose `Name` matches `-Template` (or whose filename is used as the name). |
| *"Cannot find VHDX"* or similar error at startup | The `.vhdx` file referenced in the template's `VHDFile` setting does not exist. Run `Convert-PAWWIM2VHD.ps1` to create it, or verify `VHDFile` and `VHDFolder` in the JSON template/config. |
| *"Cannot find virtual switch"* | The switch name you typed does not match any switch in Hyper-V. Run `Get-VMSwitch` to see all available switches. |
| Script stops after creating the VM and never continues | The VM may have failed to start, or Windows setup may have encountered an error. Open Hyper-V Manager, connect to the VM, and check what is displayed on screen. |
| Domain join fails | Verify that `DNSDomain` and `MachineObjectOU` in the selected JSON template are correct. Ensure the domain join account has permission to create computer objects in the specified OU. |
| PAWAppInstall is skipped | Ensure template `Application` is not `False`, `-SkipApplication` is not set, and `Resources\Applications\Invoke-PAWInstallApplications.ps1` exists. Selected application definitions and payloads are staged separately from Copy Folder. See download/staging warnings in the final report. |
| BitLocker step takes a very long time | This is normal. BitLocker encrypts the entire virtual disk. On a slow disk this can take 20-30 minutes. The script waits for 100% encryption before continuing. |
| *"Access is denied"* | Make sure you are running PowerShell as Administrator. |
| Script does not start | Run `Set-ExecutionPolicy RemoteSigned -Scope Process` in the same PowerShell window and try again. |

---

## Quick Validation Checklist

After a deployment run, verify the following:

1. The VM exists in Hyper-V with the expected name.
2. The VM network adapter is connected to the expected switch/VLAN.
3. A VM Connect shortcut exists in the `PAW Links` desktop folder.
4. `%TEMP%\PAWDeploy\New-PAWVM.log` contains the completed run and no critical errors.
5. Security baseline and post-deployment script steps were applied when enabled.
