# Import OS baselines, Edge baselines and LGPO

See [Commandline Samples](CommandlineSamples.md) for the import order and how to select the imported baseline in a deployment template.

Acquire each ZIP separately from Microsoft. Three independent CLI tools replace
the former `Import-PAWSecurityBaseline.ps1` command (removed):

```powershell
.\Tools\Import-PAWOSBaseline.ps1 -ZipPath 'C:\Downloads\WindowsBaseline.zip' -OperatingSystem Windows11_26H2
.\Tools\Import-PAWEdgeBaseline.ps1 -ZipPath 'C:\Downloads\EdgeBaseline.zip' -OperatingSystem Windows11_26H2
.\Tools\Import-PAWLGPO.ps1 -ZipPath 'C:\Downloads\LGPO.zip'
```

The first two tools import one baseline to the freely chosen OS folder under the
installation's `Resources\SecurityBaselines`. They do not require or import an LGPO ZIP.
The LGPO tool updates **every imported OS/Edge baseline across all OS folders**:

```text
Resources\SecurityBaselines\Windows11_26H2\OS\Scripts\Baseline-LocalInstall.ps1
Resources\SecurityBaselines\Windows11_26H2\OS\Scripts\Tools\LGPO.exe
Resources\SecurityBaselines\Windows11_26H2\Edge\Scripts\Baseline-LocalInstall.ps1
Resources\SecurityBaselines\Windows11_26H2\Edge\Scripts\Tools\LGPO.exe
```

Only type folders containing `Scripts\Baseline-LocalInstall.ps1` are targeted.
Empty/.gitkeep skeletons are skipped; no imported baseline is an explicit error.
Run LGPO import **after** OS/Edge imports, and again after adding/replacing a
baseline. OS/Edge replacement replaces the whole type folder, including any LGPO.
Old misplaced copies under `OS\Tools`/`Edge\Tools` are not moved or deleted by LGPO
import; the selected ZIP supplies the executable at the correct `Scripts\Tools` path.

## Validation and replacement

Baseline ZIPs must contain exactly one `Scripts\Baseline-LocalInstall.ps1`.
Outer wrappers are stripped while scripts, GPOs, tools and documentation below
the package root are preserved. Missing/ambiguous roots are rejected.

The LGPO ZIP must contain exactly one nonempty `LGPO.exe`, either at root or under
wrapper folders. Only that file is extracted. Both import types validate the
entire ZIP for traversal, absolute paths, invalid/reserved names, duplicates,
file/directory conflicts and links. Destination trees cannot contain reparse points.
No downloads or imported script/executable execution occur.

OS/Edge imports accept missing, empty and `.gitkeep`-only destinations.
Existing baseline content requires `-Replace`. Staging happens before backing up
and publishing the type; failed publication restores the previous baseline.
Cleanup/recovery failures explicitly report retained paths.

LGPO import checks **all targets before writing**. Any existing `LGPO.exe` requires
`-Replace`; this approval applies to all targets. Each executable is published
atomically. Failures at individual targets do not prevent later targets from
being attempted; an incomplete import reports successful destinations and failure
causes rather than claiming total success.

```powershell
.\Tools\Import-PAWOSBaseline.ps1 -ZipPath 'C:\Downloads\UpdatedWindows.zip' -OperatingSystem Windows11_26H2 -Replace
.\Tools\Import-PAWLGPO.ps1 -ZipPath 'C:\Downloads\LGPO.zip' -Replace
```

`-WhatIf` makes no filesystem/log changes. `-Confirm` requests approval.
The CLI logs results/errors under `%TEMP%\PAWDeploy`, in the corresponding
`Import-PAWOSBaseline.log`, `Import-PAWEdgeBaseline.log` or `Import-PAWLGPO.log`.
All three tools ship in both editions. Module callers use the same-named exported
functions with an explicit absolute `-BaselineFolder`.

## Enterprise menu

Three buttons appear on the right: **Import OS Baseline**, **Import Edge Baseline**,
and **Import LGPO**. Each selects one ZIP. OS/Edge asks for an editable OS folder;
LGPO targets all imported baselines and does not ask for an OS folder.
**Replace existing content** starts unchecked and requires a Yes/No confirmation.
Cancellation changes nothing. Errors remain visible; successful imports list destinations.

## Deployment configuration

Import does not rewrite Config/templates. Set template `SecurityBaselineLocation`
to the imported OS folder, e.g. `C:\PAWDeploy\Resources\SecurityBaselines\Windows11_26H2`.
Alternatively configure `Settings.Configuration.SecurityBaseLineFolder` as the
root and use a relative OS-folder template value. Imported payloads are ignored
by Git and are not redistributed in release packages.

See [SecurityBaselines](SecurityBaselines.md).
