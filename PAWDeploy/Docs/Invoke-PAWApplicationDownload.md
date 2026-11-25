# Precache applications or prepare bundle resources

`Tools\Invoke-PAWApplicationDownload.ps1` precaches all enabled applications by
default, including those not assigned to a bundle. An explicit
[Application Manager bundle](ApplicationManager.md) limits preparation to its
enabled members. It resolves definitions under `Resources\ApplicationCatalog`
and ordered bundle references under `Resources\ApplicationBundles`. It does not
read or write a maintained host `Applications.json`; host application resources
use fixed paths under `Resources`.

```powershell
.\Tools\Invoke-PAWApplicationDownload.ps1
.\Tools\Invoke-PAWApplicationDownload.ps1 -ApplicationBundle cbade470-64cc-4628-9536-b58e3ca3be8d
.\Tools\Invoke-PAWApplicationDownload.ps1 -ApplicationBundle cbade470-64cc-4628-9536-b58e3ca3be8d -WhatIf
.\Tools\Invoke-PAWApplicationDownload.ps1 -ApplicationBundle cbade470-64cc-4628-9536-b58e3ca3be8d -Name '7-Zip' -Force
```

| Parameter | Meaning |
|---|---|
| `ApplicationBundle` | Optional bundle GUID; without a bundle or plan, precache all enabled catalog apps. `NA` reports that there are no applications to download and completes successfully |
| `Name` | Enabled names within the catalog or selected bundle/plan |
| `Force` | Download again even if cached version matches |
| `ApplicationPlan` | Already resolved build snapshot supplied by New-PAWVM; mutually exclusive with ApplicationBundle |
| `WhatIf` | Preview without changing cache, install metadata or logs |

Globally disabled applications are excluded, including from named downloads.
`Enabled` is the download gate; `InstallEnabled` affects installation only.
The removed `DownloadEnabled` property is no longer accepted in definitions.
`New-PAWVM.ps1` supplies its initial preflight plan so downloads, final resource
checks and guest installation use the same selection, including bundle overrides.

## Sources and prerequisites

- **WinGet:** App Installer/WinGet 1.8+ downloads the installer and merged YAML
  manifest using `winget download`. Architecture, scope and installer-type
  filters come from the definition; `NA` leaves selection to WinGet. If the latest
  version has no applicable installer, earlier versions are checked in WinGet's
  newest-first order with the same filters. The download is pinned to the first
  matching version; installer type, architecture and scope are never relaxed.
  Network/download failures (including HTTP 404) remain errors, not triggers to
  change versions. Install metadata is generated only after successful preparation.
- **PSGallery:** PowerShellGet downloads modules/dependencies with `Save-Module`.
- **PowerShellModule (schema 2):** chooses `Latest` or an exact version and the
  target runtime. `Origin=Local` validates a manually supplied versioned module
  tree and dependencies under `Packages\<ApplicationId>` instead of downloading.
- **Classic:** validates the command, working directory and multi-file
  `Packages\<ApplicationId>` payload. It never executes that command on the host.
- **WindowsComponent:** validates any package-relative offline Source directory.
  An empty Source explicitly defers resource acquisition to the guest OS;
  precaching does not download Windows feature media. Supply matching FoD/SxS
  media manually for offline deployments.
- **Local:** place exactly one installer in `Resources\ApplicationDownloads\Local\<Name>`. No download
  is performed. MSI metadata or the file version populates generated installer
  information. Configure required EXE silent arguments in catalog `Settings`.

Windows PowerShell 5.1 is supported. Internet is required for new downloads.
WinGet **search/creation** in the manager separately requires
`Microsoft.WinGet.Client`; downloading uses the existing WinGet executable.

## Cache and integrity

```text
Resources\ApplicationDownloads\WinGet\<Name>\        Installer, YAML, PAWApplication.json
Resources\ApplicationDownloads\Modules\<Module>\<Version>\
Resources\ApplicationDownloads\Local\<Name>\         Operator-provided installer
Resources\Applications\InstallFiles\<Name>.json      Generated Settings + Installer metadata
Resources\Applications\Packages\<ApplicationId>\     Classic/local-module/offline-component files
```

Legacy module definitions use the latest version. Typed module definitions can
pin a version; unrelated pinned versions must remain available for other bundles.
A current, intact cache is reused.
Offline reuse is allowed only when existing resources pass validation.
WinGet installers must match the SHA256 recorded in `PAWApplication.json`, both
on the host before reuse and inside the guest before execution. Missing/invalid
hashes or changed files are never trusted; online preparation refreshes them,
and offline preparation fails explicitly. This verifies integrity since
download, not publisher trust.

## Installation settings

Generated `Applications\<Name>.json` contains the selected manifest version,
installer file/type, product code, silent switches and success/reboot exit codes.
Persistent installation overrides come from the catalog definition's `Settings`.
Do not edit generated settings: preparation and staging apply the catalog values.
Staging also applies them when an existing cache is reused.

Manifest silent switches take precedence over installer-type defaults:
MSI/WiX/Burn use `/quiet /norestart`, Inno uses
`/SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`, and NSIS uses `/S`.
Generic EXE installers need manifest switches or explicit `SilentArguments`.
Portable installers use `DestinationPath`; ZIPs retain nested-installer metadata.
MSI/WiX/Burn success codes include 0, 1641 and 3010, alongside manifest codes.

The build stages a generated Applications.json selection inside the guest
payload. The host catalog and template are not rewritten. Failed preparation
blocks VM creation at final preflight. Existing per-application optional-failure
reporting remains in effect for runtime guest installation.

Logs: `%TEMP%\PAWDeploy\Invoke-PAWApplicationDownload.log`.
See [guest installation](Invoke-PAWInstallApplications.md) for runtime behavior.
