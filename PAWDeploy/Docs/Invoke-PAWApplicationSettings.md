# Command-line application editing

Command startup is logged to `%TEMP%\PAWDeploy\Invoke-PAWApplicationSettings.log`;
delegated operations also use `PAWApplicationManager.log` in the same folder.
`-WhatIf` does not create these logs.

The primary entry point is now
[Invoke-PAWApplicationManager.ps1](ApplicationManager.md), used by both CLI and
the Application Manager UI. It manages persistent per-application definitions,
ordered bundles, WinGet discovery, enable/disable, import/export and template
assignment.

`Invoke-PAWApplicationSettings.ps1` remains a convenience facade for common
name-based edits. It calls the manager CLI and never maintains a separate
Applications.json list:

```powershell
.\Tools\Invoke-PAWApplicationSettings.ps1 -List
.\Tools\Invoke-PAWApplicationSettings.ps1 -Show -Name '7-Zip'
.\Tools\Invoke-PAWApplicationSettings.ps1 -Edit -Name KeePass -InstallEnabled False
.\Tools\Invoke-PAWApplicationSettings.ps1 -New -Name 'Contoso Agent' -Source Local -InstallerType msi
.\Tools\Invoke-PAWApplicationSettings.ps1 -Clone -Name KeePass -NewName 'KeePass alternative'
.\Tools\Invoke-PAWApplicationSettings.ps1 -Remove -Name 'Contoso Agent' -WhatIf
```

New/clone operations allocate a stable application ID; add the resulting ID to
the desired bundle separately. Display names cannot be renamed in place because
cache and install files use them. Clone instead. Removal obeys bundle-reference
guards and retains installers/cache. `-Force` suppresses its removal prompt;
`-WhatIf`, `-Confirm` and `-PassThru` are supported.

Legacy schema 1 source settings are `Name`, `Source`, `Id`,
`InstallEnabled`, `Architecture`, `Scope` and `InstallerType`. Local apps use
`Id=NA` and an explicit install type. PSGallery apps use `NA` for architecture,
scope and installer type. Installation overrides belong in the managed
application's `Settings`, not the generated installation file.

For schema 2 definitions, the facade can edit applicable Configuration fields
such as Id/Architecture and the common InstallEnabled flag. It rejects Source
changes rather than changing the application's type implicitly. Use the manager
CLI's NewApplication/SaveApplication actions or the type-specific GUI for full
Classic, module and Windows-component configuration.
