# PAWUtility module

## Purpose

`PAWUtility` contains the core operational and deployment helpers used across the PAWDeploy automation workflows. It focuses on infrastructure actions, config resolution, VM lifecycle operations, logging, file and folder discovery, and the reusable logic behind deployment and removal scripts.

## Typical responsibilities

`Get-PAWVMDetails` supplies the shared removal CLI/UI display: Name, State,
DiskMode, Location and typed Hyper-V CreationTime. It follows checkpoint layers
to the underlying disk, reports mixed/no disks explicitly, and warns when
metadata is unavailable rather than guessing. See [removal](Remove-PAWVM.md).

Reusable guest security helpers: `Get-PAWASRRule` supplies the OS catalog;
`Enable-PAWASR` configures and verifies Block, Audit and Disabled rules and returns per-rule results.
`Get-PAWWDACPolicy` validates XML without execution,
`Get-PAWWDACPolicyOptions` lists filenames, `Import-PAWWDACPolicy` atomically imports
with explicit replacement, and `Install-PAWWDACPolicy` compiles/stages a verified
guest binary for next boot. The engine owns optional-failure logging and runs
security after guest cleanup. See [ASR/WDAC](New-PAWVM.md#asr-and-windows-defender-application-control).

- path and folder resolution from `Config.json`
- VM creation, startup, shutdown, and readiness checks
- VHD and Hyper-V helper routines
- security baseline and template discovery
- write/logging and config parsing helpers
- app-install and deployment conversion helpers

## Module location

- [PAWDeploy/Functions/PAWUtility](../Functions/PAWUtility)
- [PAWDeploy/Functions/PAWUtility/PAWUtility.psd1](../Functions/PAWUtility/PAWUtility.psd1)
- [PAWDeploy/Functions/PAWUtility/PAWUtility.psm1](../Functions/PAWUtility/PAWUtility.psm1)

## Design intent

This module is intended to hold the non-UI logic. Scripts such as the deployment engine and VM cleanup routines should load reusable behavior from here, while script-specific or form-specific behavior stays out of the module.

Unused scaffold functions `Get-Function` and `Get-PrivateFunction` have been
removed in 0.0.18; no compatibility aliases are provided. The private
`Test-PAWPSDirectSession` helper remains here for connectivity checks, not in
PAWUIUtility.

Function files with consolidated help have one complete comment-based help block
inside the function, before `[CmdletBinding()]`/`param`. Its `.NOTES` section
holds the script `Version` and `Author` metadata alongside operational notes.
Do not add a second file-level help block. Existing single-block files and
deployment entry-point help remain unchanged. `Get-Help`, metadata readers and
compact-module packages are covered by script-level help tests.

## Common examples

- `Write-PAWLog`
- `Resolve-PAWLogFolder`
- `Get-PAWTemplateFileCollection`
- `Test-PAWVMExists`
- `Start-PAWVM`
- `Stop-PAWVM`

PAWUtility exports `Import-PAWOSBaseline`, `Import-PAWEdgeBaseline` and
`Import-PAWLGPO` for separate validated ZIP imports with replacement approval.
The former `Import-PAWSecurityBaseline` command is removed.
The CLI and Enterprise menu share these implementations; see
[the import guide](Import-PAWSecurityBaseline.md).
Import OS/Edge baselines first; LGPO import places its single nonempty executable
in every imported type's `Scripts\Tools` folder. OS/Edge imports do not take LGPOZipPath.

## Function naming and migration

`Set-PAWScriptTitle` supplies all UI/entry-point titles as
`PAWDeploy Toolkit - <version> - <script filename> - <script folder>`.
The folder is the full directory containing the executing script, not the
caller's working directory, so different installed copies can be distinguished.

Starting with PAWUtility 0.0.20 and PAWUIUtility 0.0.10, every function uses
`Verb-PAW...`, including private, nested, script-local, installer, build and test
helpers. Public helper filenames, exports, calls and help examples use the same
names. Entry-point script filenames are unchanged.

This is a breaking API rename with no compatibility aliases. Update external
scripts that call the former names. Most names simply insert `PAW` after the
hyphen, for example `Find-Application` becomes `Find-PAWApplication`.
Notable core names are:

| Previous name | Current name |
|---|---|
| `Write-Log` | `Write-PAWLog` |
| `Get-TemplateCollection` | `Get-PAWTemplateFileCollection` |

`Get-PAWTemplateFileCollection` returns template file metadata; the existing
`Get-PAWTemplateCollection` returns parsed template content. They remain
separate functions with unchanged behavior. The WIM UI uses the local
`Write-PAWWIMUILog` wrapper to delegate to `Write-PAWLog` without shadowing it.

`PAWDeploy\test\FunctionNaming.Tests.ps1` enforces the naming convention and
public source-file/export consistency without inspecting historical release
packages.

## Combined logging and setting resolution

PAWUtility 0.0.21 adds optional `Write-PAWLog -OutputMode Console|Warning|Verbose`;
the default `None` remains file-only. `ConsoleType` preserves console colors
independently of file `Level`. `ConsoleMessage`, `Value` and `NoNewline` preserve
formatted console text when it differs from the file entry. Each call writes
one primary file entry; optional exception details remain separate entries.
Failed file writes now emit a warning instead of being visible only with Verbose.

```powershell
Write-PAWLog -Message 'Created PAW-01' -LogPath $LogPath -OutputMode Console -ConsoleType Success
$setting = Resolve-PAWSetting -Name DynamicMem -Kind Boolean -TemplateValue $TemplateData.DynamicMem -ConfigValue $HyperVData.DynamicMem -DefaultValue $false -LogPath $LogPath
$setting.Value
$setting.Source
```

`Resolve-PAWSetting` returns `{ Value, Source }` and applies explicit command-line
(when supplied), template, config and default precedence. It reuses the integer
and boolean converters. VM generation must be 1 or 2; CPU/memory must be positive.
Explicit false is valid. Domain/workgroup names retain canonical casing.
A nonempty invalid DiskMode defaults immediately rather than trying another
source. Locale/time-zone strings retain their previous template/config behavior,
including empty config values and downstream validation; no new defaults or
validation policies are introduced. Chosen values are logged as verbose
diagnostics, typed defaults as warnings (or colored info for DiskMode/VMGen).

## Generic test performance

`test\TSxUtility.Generic.Tests.ps1` runs PSScriptAnalyzer once per source file,
passing all enabled rules together through `-IncludeRule`. Rules are discovered
once; the existing excluded rules and `PSDSC*` exclusions are unchanged.
Each failing file reports every diagnostic with its rule, line and message.
Parser, manifest and module-import checks remain separate tests.

Run the generic suite in Windows PowerShell 5.1 with Pester 5:

```powershell
Import-Module Pester -MinimumVersion 5.0
Invoke-Pester -Path 'PAWDeploy\Functions\PAWUtility\test\TSxUtility.Generic.Tests.ps1' -Output Detailed
```

Fewer Pester cases reflect batching rules per file, not reduced rule coverage.
Existing analyzer violations still fail the suite.

## Deployment resource preflight

`Test-PAWDeployment -ConfigPath <Config.json> -TemplateData <loaded-template>
-Overrides <bound-parameters>` is a read-only resource/capacity check, separate
from template import validation. It returns `CanPrepare`, `CanDeploy`, `Settings`
(values and sources), `Steps`, `Checks`, `Errors`, `Warnings` and `PendingDownloads`.
`-AllowPendingDownloads` permits preparation of enabled application downloads,
but `CanDeploy` remains false until a strict check confirms all installation
resources. See [engine preflight](New-PAWVM.md#deployment-resource-preflight).

## Installer integrity

`Assert-PAWInstallerHash -Path <installer> -ExpectedHash <SHA256> -ApplicationName <name>`
is shared by host cache reuse and guest WinGet installation. It returns no success
output and throws with correction guidance for invalid/missing hashes, unreadable
files or mismatches. It never updates the expected hash or establishes publisher trust.

## VM creation versus deployment

`New-PAWHyperVVM` creates and configures the Hyper-V VM and its disk.
Its mandatory `DiskMode` parameter must be supplied explicitly; accepted modes
are `Copy`, `Diff`, `Empty`, `Attached` and `None`.
The [New-PAWVM.ps1](New-PAWVM.md) script orchestrates the complete guest
installation and hardening workflow. Starting with PAWUtility 0.0.15, the former
module function `New-PAWVM` is renamed to `New-PAWHyperVVM`; its parameters and
behavior are unchanged. No compatibility alias is provided. Update external
module-function calls; deployment-script and GUI launch commands are unchanged.

## Deployment-scoped PowerShell Direct sessions

PAWUtility 0.0.24 supports an explicit `Invoke-PAWPSDirect -SessionContext`
hashtable. No global cache is used. The context retains only its session, VM ID,
credential object and in-use flag; never serialize or log it. Each invocation
checks VM identity and credential-object identity and probes the retained session.
Unusable sessions are removed and reconnected. Use one context per sequential
deployment, never concurrently or across credentials/VMs.

```powershell
$context = @{}
try {
    Invoke-PAWPSDirect -VMName $VMName -Credential $Cred -SessionContext $context -ScriptBlock { Get-Date }
    Invoke-PAWPSDirect -VMName $VMName -Credential $Cred -SessionContext $context -ScriptBlock { Get-Service }
    Close-PAWPSDirectSessionContext -SessionContext $context
    # Shutdown/reboot may now proceed. The next invocation reconnects.
}
finally {
    Close-PAWPSDirectSessionContext -SessionContext $context
}
```

Always close before known shutdowns and in the owner's `finally`. A failed close
throws and retains the session for another cleanup attempt. Command failures
attempt session cleanup without replacing the original error; cleanup failures
warn explicitly. A transport error during execution means the outcome is unknown:
the command is never replayed unless `-RetryCommand` explicitly permits it.
Calls without a context retain one-shot behavior.

Guest runspace state (imports, explicit global/script variables, location and
process-scoped settings) can persist. Keep external installers, user scripts,
baselines and independently owned cleanup operations in one-shot sessions.
Only known deployment configuration/read operations share the engine's context.

## Shared VM condition polling

PAWUtility 0.0.23 adds `Wait-PAWCondition -Test { ... }`. Six readiness
wrappers (Exists, IsRunning, HaveIP, HaveICLoaded, HavePSDirect and Deployment)
and CompleteOOBE use it, preserving public names, credentials, defaults and
timeout diagnostics. Wait-PAWVMStart retains its startup/check order; service
waiting and shutdown remain separate.

Conditions are tested immediately, so an already-ready VM no longer incurs
an initial 5-10 second sleep. Timeout uses Stopwatch elapsed time; sleep is
capped to the remaining budget and no result completed after the deadline
counts as success. A probe must return exactly one Boolean, and terminating
or nonterminating errors abort the wait instead of reporting readiness.
Timeout and intervals must be positive; invalid zero/negative limits are
rejected explicitly. Wrappers still return no success output.

OOBE alone retains its existing guest-reboot retry policy and verbose
diagnostics; those errors are handled inside its probe, not swallowed by the
generic helper. Synchronous probes cannot be interrupted by the helper:
PSDirect and other potentially blocking operations must bound their own
execution time. The timeout governs polling, not forced cancellation.

```powershell
Wait-PAWCondition -Test { Test-PAWVMIsRunning -VMname 'PAW-01' } -TimeoutSeconds 300 -PollIntervalSeconds 5
```

## Graceful shutdown

`Stop-PAWVM -VMName 'PAW-01'` requests a graceful shutdown and waits for `Off`.
An existing shutdown (`Stopping` or error `0x8007045B`) is allowed to finish.
If the guest's shutdown service is unavailable because it is restarting
(`0x800706B5`), the request is retried.
While the VM still reports `Running`, the graceful request is repeated every
`-RetryIntervalSeconds` (default 30) until `Off` or timeout.
The default timeout is 600 seconds with five-second polling; callers can set
`-TimeoutSeconds` and `-PollIntervalSeconds`. Already-off VMs return immediately.
Unexpected errors and timeouts are terminating; there is no forced power-off.
The helper supports `-WhatIf`, `-Confirm` and `-Verbose`.

`Restart-PAWVMIfRebootPending -VMName 'PAW-01' -Credential $cred` checks the
guest for a pending Component Based Servicing or Windows Update restart. When
one is pending it restarts the VM gracefully, waits for PowerShell Direct and
OOBE, and checks again, up to `-MaxRestarts` (default 2) times. It returns the
number of restarts and warns if a restart is still pending afterwards.

## Deployment cleanup

`Invoke-PAWDeploymentCleanup -State $cleanupState -Credential $Cred -CleanupGuest`
removes and verifies guest autologon values and staged setup files. Use it only
after installation is finished or aborted. `-SkipGuestFolderCleanup` skips `C:\SECBL` and
`C:\PAWFiles`, not registry or setup-file cleanup.

The mutable `State` hashtable records ownership for a **single run**:

| State field | Meaning |
|---|---|
| `VMId`, `VMName`, `VMFolder` | Recorded by `New-PAWHyperVVM -CleanupState $cleanupState`; the folder is reserved without overwriting an existing directory, and ID is recorded immediately after VM creation |
| `MountedVHD` | Exact offline disk claimed before mounting; cleared only after verified dismount |
| `OfflineSetupFiles` | Setup files staged by this run on its mounted offline disk; removed before failure dismount, cleared after normal staging dismount |
| `TempFolder`, `CredentialFile` | This run's unique staging directory and credential file |
| `GuestCleaned` | Set only after guest registry/setup-file removal is verified |
| `InstallationComplete` | Marks a completed installation; its journal is deleted once host artifacts are gone |

Cleanup never stops or removes a VM and never deletes files in the VM directory,
because a partly deployed VM may already be in use. This applies to the engine's
`finally` and to startup recovery. Guest baseline/application folders are retained
on failure while autologon/setup secrets are still removed when the guest is
reachable. Host temporary/credential files and recorded mounts are cleaned
independently, and directory deletion refuses reparse points.

Never populate this record from unrelated resources.
Independent steps continue after errors, which are warned, optionally written
using `-LogPath`, and finally thrown together. The deployment engine invokes this
from `finally` and preserves the original installation exception.

The helper never starts a VM or mounts an offline registry for guest access.
Unverified guest cleanup is explicitly reported even if host cleanup continues.
Retained disks must be treated as potentially containing credentials.
`-WhatIf`, `-Confirm` and `-Verbose` are supported.

## Script logging

All scripts that write log files use `%TEMP%\PAWDeploy\<ScriptName>.log`,
for example `New-PAWVM.log` and `PAWDeployUI.log`. The shared log-folder helpers
create this fixed folder if needed; configuration and fallback paths are ignored.
The folder belongs to the current user and normally requires no administrator
rights for logging. Existing log files are not moved.

`Update-PAWLog` is exported for compatibility. It forwards `-Data`, `-Solution`,
`-Class` and `-LogPath` to `Write-PAWLog` and emits a deprecation message with
`-Verbose`. New code should use `Write-PAWLog` directly.

## Template editing helpers

`Get-PAWValidatedTemplate` reads a regular template JSON file and returns
Name/Source/Data/Warnings after required-field and shared value validation, without local
resource checks. `Import-PAWTemplate` and `Export-PAWTemplate` provide preflighted,
atomic per-file transfers, exclude Config.json, require explicit replacement and
report partial publication failures. Export checks JSON structure but preserves
saved values, including legacy settings; import rejects structural errors but warns
about all invalid scalar values with correction guidance and retains them for editing.
Import results include a Warnings array; export results retain Name/Source/Destination.
The CLI scripts add standard logging and the
Template Editor runs those scripts. See [Import/Export](PAWTemplateEditorUI.md).

In PAWUtility 0.0.22 / PAWUIUtility 0.0.11, templates always live beside the
current `Config.json` in Config. The five template-folder resolvers have been
removed, without aliases. Consumers obtain the config file's parent directory;
no alternate folder setting, fallback search or browse field remains.
Installer upgrades migrate old template locations before removing obsolete
configuration properties, retaining external originals and conflict checks.

`Get-PAWTemplateFileCollection` returns metadata including `InvalidJson` status;
`Get-PAWTemplateCollection` returns parsed data and throws for missing, empty or
entirely invalid folders; `Get-PAWTemplateFile` returns Name/FilePath/Data
records and warns/skips invalid files. Their output shapes and error policies
are unchanged. All three use the private `Read-PAWTemplateFile` reader, always
excluding `Config.json`.

`Resolve-PAWLogFolder` replaces the two configured log-folder functions. It
takes no config/fallback parameters, creates the fixed
`%TEMP%\PAWDeploy` folder and surfaces creation failures. External
callers must migrate to this name without the old arguments.

These functions back the command-line editors [Invoke-PAWTemplateSettings.ps1](Invoke-PAWTemplateSettings.md) and [Invoke-PAWConfigurationSettings.ps1](Invoke-PAWConfigurationSettings.md), and the setting order in [PAWTemplateEditorUI.ps1](PAWTemplateEditorUI.md):

| Function | Purpose |
|---|---|
| `Get-PAWTemplateSettingOrder` | Preferred display/save order of template settings |
| `Get-PAWTemplateFile` | Lists template JSON files and their template names |
| `Find-PAWTemplate` | Finds a template by name (case-insensitive) |
| `ConvertTo-PAWTemplateValue` | Validates and normalizes a template setting value |
| `ConvertTo-PAWOrderedTemplate` | Orders template properties using the standard setting order |
| `Test-PAWTemplateReference` | Warns when a template references a missing VHDX, run script, baseline folder or Hyper-V switch |
| `Get-PAWUniqueTemplateFilePath` | Returns a free `<Name>.json` path in the template folder |
| `Format-PAWTemplateSetting` | Formats a template as `Setting`/`Value` rows for display |
| `Resolve-PAWCultureName` | Normalizes culture and keyboard identifiers to canonical casing |
| `Get-PAWTemplateArgumentCompletion` | Tab-completion values for template names and settings; completers import PAWUtility with `-Scope Local`, so the caller's session is not changed |

The default configuration path is `<ScriptRoot>\Config\Config.json`; the default
template folder is `<ScriptRoot>\Config`. All template collection helpers exclude
`Config.json`, which is reserved for settings. Relative configured paths remain
relative to the configuration file's folder.

This module should remain the home for core automation behavior, not Windows Forms helpers or UI state management.

## Application download and install helpers

These functions back [Invoke-PAWApplicationDownload.ps1](Invoke-PAWApplicationDownload.md), [Invoke-PAWApplicationSettings.ps1](Invoke-PAWApplicationSettings.md) and [Invoke-PAWInstallApplications.ps1](Invoke-PAWInstallApplications.md):

| Function | Purpose |
|---|---|
| `Get-PAWApplicationDefinitions` | Loads and validates generated `Applications.json`: legacy source fields plus ApplicationId/Options for typed runtime definitions |
| `ConvertTo-PAWTypedApplicationDefinition` | Validates schema 2 type-specific configuration for WinGet, PowerShellModule, Classic and WindowsComponent |
| `ConvertTo-PAWApplicationRuntimeDefinition` | Projects a catalog application into a frozen runtime definition; deliberately excludes RestartRequired |
| `Resolve-PAWApplicationPayloadPath` | Resolves package-relative files/directories while rejecting traversal, reserved path segments and package reparse points |
| `Test-PAWApplicationResources` | Checks resources required by typed Classic, module and Windows-component definitions |
| `Invoke-PAWTypedApplication` | Executes typed application behavior inside the guest, using explicit commands and OS servicing APIs |
| `ConvertTo-PAWApplicationDefinition` | Validates one application against the `Applications.json` rules and returns it with the eight properties in order and in canonical casing |
| `Save-PAWApplicationDefinitions` | Validates the application list and writes it to `Applications.json` (UTF-8 without BOM, only when the content changes) |
| `Get-PAWApplicationArgumentCompletion` | Tab-completion values for application names, Ids and settings; completers import PAWUtility with `-Scope Local`, so the caller's session is not changed |
| `Get-PAWWinGetManifestInfo` | Reads the version, installer type, `InstallerSwitches` (for example `Silent`), product code and return codes from a manifest saved by `winget download` |
| `Get-PAWWinGetCacheFolder` | Returns the cache folder of a WinGet application (`<CacheRoot>\WinGet\<Name>`) |
| `Get-PAWLocalApplicationFolder` | Returns the installer folder of a Local application (`<LocalRoot>\<Name>`) |
| `Get-PAWApplicationInstallFilePath` | Returns the install file path of an application (`<InstallRoot>\<Name>.json`) |
| `Update-PAWApplicationInstallFile` | Creates or updates an install file: refreshes the `Installer` section from the manifest and keeps the `Settings` section |
| `Get-PAWApplicationInstallFile` | Reads and normalizes an install file |
| `Get-PAWWinGetInstallCommand` | Builds the silent install command (method, file, arguments and exit codes) from an install file |
