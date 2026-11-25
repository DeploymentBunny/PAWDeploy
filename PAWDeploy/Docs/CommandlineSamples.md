# Commandline Samples

Each section is a standalone PowerShell example. Open PowerShell as Administrator
on the Hyper-V host and go to the installed folder containing `New-PAWVM.ps1`.
Replace the sample paths, names and IDs with your own.

```powershell
Set-Location 'C:\PAWDeploy'
```

All examples work in both Community and Enterprise Edition. Enterprise includes
additional graphical tools, but the command-line tools are the same.

## Read PAWDeploy logs

List the current user's logs, then read the latest matching entries:

```powershell
.\Tools\Get-PAWLogs.ps1
.\Tools\Get-PAWLogs.ps1 -Name 'New-PAWVM.log' -Level WARN,ERROR -Since (Get-Date).AddDays(-1) -Tail 50
.\Tools\Get-PAWLogs.ps1 -Name 'PAWMenu.log' -Text 'failed'
```

See [View PAWDeploy logs](PAWLogsUI.md) for the UI, date filters, live refresh
and reading logs from another folder.

## Convert a WIM to VHDX

If you don't have a sysprepped VHDX, mount a Windows installation ISO that
contains `sources\install.wim`. The command below shows the mounted drive letter.

```powershell
Mount-DiskImage -ImagePath 'D:\ISO\Windows11.iso' -PassThru |
    Get-Volume | Select-Object DriveLetter
```

Replace `E:` with that drive letter. List the image indexes, then use the index
for the Windows edition you want instead of the example index `1`. The destination
folder must already exist.

```powershell
Get-WindowsImage -ImagePath 'E:\sources\install.wim' | Select-Object ImageIndex, ImageName

.\Tools\Convert-PAWWIM2VHD.ps1 -SourceFile 'E:\sources\install.wim' `
    -DestinationFile 'D:\PAW-Staging\Win11-PAW.vhdx' -DiskLayout UEFI -Index 1
```

## Import a VHDX

Import the VHDX you converted or a disk from a reference VM that was generalized
with Sysprep and shut down. The importer copies it to the configured `VHDFolder`.

```powershell
.\Tools\Import-PAWVHDX.ps1 -Path 'D:\PAW-Staging\Win11-PAW.vhdx'
```

See [Import VHDX files](Import-PAWVHDX.md).

## Import security baselines

Use the Microsoft baseline ZIP for the Windows version you plan to deploy. Import
the Edge baseline under the same OS folder if you want to apply it alongside the
Windows baseline.

```powershell
.\Tools\Import-PAWOSBaseline.ps1 -ZipPath 'D:\PAW-Staging\WindowsBaseline.zip' -OperatingSystem 'Windows11_26H2'
.\Tools\Import-PAWEdgeBaseline.ps1 -ZipPath 'D:\PAW-Staging\EdgeBaseline.zip' -OperatingSystem 'Windows11_26H2'
```

## Import LGPO

Run this **after** importing the baselines. It puts `LGPO.exe` in `Scripts\Tools`
for every imported OS and Edge baseline. Run it again when adding or replacing a
baseline. Review the existing files before using `-Replace`.

```powershell
.\Tools\Import-PAWLGPO.ps1 -ZipPath 'D:\PAW-Staging\LGPO.zip'
```

See [Import OS baselines, Edge baselines and LGPO](Import-PAWSecurityBaseline.md).

## Import a WDAC policy

Use a reviewed WDAC XML policy. Start with an audit-mode policy on a test PAW:
the importer preserves the policy's mode; naming it `PAW-Audit.xml` does not
enable audit mode.

```powershell
.\Tools\Import-PAWWDACPolicy.ps1 -Path 'D:\PAW-Staging\PAW-Audit.xml'
```

See [ASR and Windows Defender Application Control](New-PAWVM.md#asr-and-windows-defender-application-control).

## Manage the ASR master list

The master list is used for future deployments. Editing it does not change
Defender on the host or on existing VMs. Review rule IDs and minimum builds
against the [Microsoft ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference).
`0` means the rule is not applicable to that OS type.

```powershell
.\Tools\Invoke-PAWASRSettings.ps1 -Action List |
    Format-Table Name, Id, Mode, ClientMinBuild, ServerMinBuild, RequiresCloudProtection

# Replace this placeholder with a documented rule ID not already in the list.
$id = '11111111-1111-4111-8111-111111111111'
.\Tools\Invoke-PAWASRSettings.ps1 -Action Add -Id $id -Name 'Example rule' `
    -ClientMinBuild 22000 -ServerMinBuild 0 -RequiresCloudProtection $false
.\Tools\Invoke-PAWASRSettings.ps1 -Action Edit -Id $id -Name 'Updated example rule' -Mode Audit
.\Tools\Invoke-PAWASRSettings.ps1 -Action Edit -Id $id -Mode Disabled
.\Tools\Invoke-PAWASRSettings.ps1 -Action Remove -Id $id -WhatIf
.\Tools\Invoke-PAWASRSettings.ps1 -Action Remove -Id $id
```

Replace the example ID, name and build values with verified values before
adding a real rule. Removal prompts for confirmation; use `-Force` only to
remove without prompting. The list cannot be empty. Every saved change
increments the list version. Modes are `Block` (1), `Audit` (2), and
`Disabled` (0); new rules default to `Block`. Disabled explicitly turns the
rule off on future deployments rather than removing it from the list.

## Import a Run Script

Review the `.ps1` before importing it. When selected by the template, it runs
inside the PAW after Windows setup, not on the Hyper-V host.

```powershell
.\Tools\Import-PAWRunScript.ps1 -Path 'D:\PAW-Staging\Configure-PAW.ps1'
```

See [Sample Custom RunScripts](SampleScripts.md).

## Import an application

Use a trusted single-application package exported by the PAW Application Manager
with `-Action ExportApplication`. This is a PAWDeploy package JSON, not an installer
or a raw catalog entry.

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Import -Path 'D:\PAW-Staging\7Zip-package.json'
```

See [Application Manager: Import, export and deletion](ApplicationManager.md#import-export-and-deletion).

## Create a WinGet application

Search for the exact WinGet package ID, then create a catalog entry. The
application is saved to the catalog but is not downloaded or installed by this
command.

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action Search -Query 'Notepad++' |
    Select-Object Id, Name

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewWinGet `
    -Id 'Notepad++.Notepad++' -Architecture x64 -Scope Machine
$application |
    Select-Object ApplicationId, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

The generated `ApplicationId` is the ID to add to an application bundle; see
the bundle example below.

## Create a PowerShell Gallery module application

This example creates a `PowerShellModule` definition for `Az.Accounts`. It
targets Windows PowerShell 5.1 and downloads the module and its dependencies
during application preparation, not when the definition is saved.

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type PowerShellModule -Name 'Az.Accounts'
$draft.Definition.Configuration.Id = 'Az.Accounts'
$draft.Definition.Configuration.Version = 'Latest'
$draft.Definition.Configuration.Runtime = 'WindowsPowerShell'
$draft.Definition.Configuration.Origin = 'PSGallery'

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

Set `Version` to a tested numeric version to pin it. For PowerShell 7, set
`Runtime` to `PowerShell7` and ensure it is installed in the guest.

## Create a local PowerShell module application

Use `Origin = 'Local'` for a module that is already available on the host.
Prepare a folder containing versioned modules and their dependencies, for
example `D:\PAW-Staging\PowerShellModules\Example.Module\1.2.3\Example.Module.psd1`.
Replace `Example.Module`, the version and the source path with your module.

```powershell
$source = 'D:\PAW-Staging\PowerShellModules'
$manifest = Join-Path $source 'Example.Module\1.2.3\Example.Module.psd1'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw "Module manifest not found: $manifest"
}

$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type PowerShellModule -Name 'Example.Module'
$draft.Definition.Configuration.Id = 'Example.Module'
$draft.Definition.Configuration.Version = '1.2.3'
$draft.Definition.Configuration.Runtime = 'WindowsPowerShell'
$draft.Definition.Configuration.Origin = 'Local'

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft
$package = Join-Path 'Resources\Applications\Packages' $application.ApplicationId
New-Item -Path $package -ItemType Directory -Force | Out-Null
Get-ChildItem -LiteralPath $source -Force |
    Copy-Item -Destination $package -Recurse -Force -ErrorAction Stop
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

The package must contain the selected module and its required modules in
`<ModuleName>\<Version>\<ModuleName>.psd1` folders. Missing dependencies fail
preflight. If copying fails after the definition is saved, fix the source and
copy it to the same `$package`; do not create a second definition.

## Create a Classic application

Use `Classic` for an offline installer or another command with its own payload.
Place a trusted MSI named `install.msi` in `D:\PAW-Staging\VendorApp`, and
replace the name, path and arguments for your installer. Check its silent
installation and restart options before deploying.

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type Classic -Name 'Vendor Application'
$draft.Definition.Configuration.FolderPath = '.'
$draft.Definition.Configuration.Executable = 'msiexec.exe'
$draft.Definition.Configuration.Arguments = '/i "%App%\install.msi" /qn /norestart'
$draft.Definition.Configuration.WorkingDirectory = '.'
$draft.Definition.Configuration.SuccessExitCodes = @(0, 3010)
$draft.Definition.Configuration.TimeoutSeconds = 1800

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft -SourceFolder 'D:\PAW-Staging\VendorApp'
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

Saving copies the source folder into the application package; it does not run
the installer. `%App%` resolves to the copied folder in the guest. Detection
is optional; see [Classic applications](ApplicationManager.md#classic-applications)
for detection scripts.

## Create a Windows component application

Use `WindowsComponent` for a Windows capability, optional feature or Windows
Server feature. These examples create definitions only. The component is
installed in the guest during deployment; availability depends on the guest OS.

### Windows capability

This example installs the Active Directory RSAT capability using an online
source available to the guest:

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type WindowsComponent -Name 'RSAT Active Directory'
$draft.Definition.Configuration.Kind = 'Capability'
$draft.Definition.Configuration.Names = @('Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0')
$draft.Definition.Configuration.Source = ''
$draft.Definition.Configuration.LimitAccess = $false

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

For an offline source, use matching Windows Features on Demand media, preserve
its repository metadata and dependencies, set `Source` to `Source` and
`LimitAccess` to `$true`, then save with `-SourceFolder`:

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type WindowsComponent -Name 'RSAT Active Directory Offline'
$draft.Definition.Configuration.Kind = 'Capability'
$draft.Definition.Configuration.Names = @('Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0')
$draft.Definition.Configuration.Source = 'Source'
$draft.Definition.Configuration.LimitAccess = $true

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft -SourceFolder 'D:\PAW-Staging\Windows11-FoD\LanguagesAndOptionalFeatures'
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

See [offline RSAT preparation](ApplicationManager.md#rsat-tools---offline-windowscomponent).

### Windows optional feature

This example enables .NET Framework 3.5 when the guest and its configured
feature source support it:

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type WindowsComponent -Name '.NET Framework 3.5'
$draft.Definition.Configuration.Kind = 'OptionalFeature'
$draft.Definition.Configuration.Names = @('NetFx3')
$draft.Definition.Configuration.Source = ''
$draft.Definition.Configuration.LimitAccess = $false

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

### Windows Server feature

This example is for a **Windows Server guest**, not Windows 11:

```powershell
$draft = .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewApplication `
    -Type WindowsComponent -Name 'Server AD PowerShell Tools'
$draft.Definition.Configuration.Kind = 'ServerFeature'
$draft.Definition.Configuration.Names = @('RSAT-AD-PowerShell')
$draft.Definition.Configuration.Source = ''
$draft.Definition.Configuration.LimitAccess = $false

$application = .\Tools\Invoke-PAWApplicationManager.ps1 -Action SaveApplication `
    -InputObject $draft
$application | Select-Object ApplicationId, Type, @{ Name = 'Name'; Expression = { $_.Definition.Name } }
```

These are separate application definitions. Add the desired `ApplicationId`
values to a bundle as shown below; creating a definition does not add it to a
bundle or install it.

## Create an Application Bundle

The PowerShell console opened from either menu loads both modules automatically.
In another console, import them from the installation folder:

```powershell
Import-Module .\Functions\PAWUtility\PAWUtility.psd1
Import-Module .\Functions\PAWApplicationManager\PAWApplicationManager.psd1
```

List applications, create an empty bundle, and add selected applications. The
pipeline order determines installation order. Duplicate IDs are warned about
and skipped; names must be unique.

```powershell
Get-PAWApplication
New-PAWApplicationBundle -Name 'PAW Commandline Tools'
Get-PAWApplication | Where-Object Name -in @('7-Zip', 'PowerShell 7') |
    Add-PAWApplicationToBundle -Bundle 'PAW Commandline Tools' -WhatIf
Get-PAWApplication | Where-Object Name -in @('7-Zip', 'PowerShell 7') |
    Add-PAWApplicationToBundle -Bundle 'PAW Commandline Tools'
```

To include the entire catalog in alphabetical installation order:

```powershell
New-PAWApplicationBundle -Name 'All applications'
Get-PAWApplication | Sort-Object Name |
    Add-PAWApplicationToBundle -Bundle 'All applications'
```

List bundles and inspect their applications in installation order:

```powershell
Get-PAWApplicationBundle
Get-PAWApplication -Bundle 'PAW Commandline Tools'
```

To reorder a bundle, pipe its complete desired list with `-Replace`. This
replaces **all** its members, not just their relative order. Preview first:

```powershell
Get-PAWApplication -Bundle 'PAW Commandline Tools' | Sort-Object Name |
    Add-PAWApplicationToBundle -Bundle 'PAW Commandline Tools' -Replace -WhatIf
Get-PAWApplication -Bundle 'PAW Commandline Tools' | Sort-Object Name |
    Add-PAWApplicationToBundle -Bundle 'PAW Commandline Tools' -Replace
```

An empty pipeline never changes the bundle. For older duplicate bundle names,
use `Get-PAWApplication -BundleId <guid>` and
`Add-PAWApplicationToBundle -BundleId <guid>` rather than `-Bundle`.
`Get-PAWApplication` exposes the canonical object as `.Application` for use
with `Save-PAWManagedApplication`; its other properties can be filtered normally.

See [Application Manager: Bundles and template assignment](ApplicationManager.md#bundles-and-template-assignment).

## List installed resources

After importing the modules as above, these commands return objects usable with
`Where-Object`, `Sort-Object` and other pipeline commands:

```powershell
Get-PAWVHDXImage
Get-PAWTemplate
Get-PAWApplication
Get-PAWApplicationBundle
Get-PAWCachedApplication
Get-PAWOSBaselinePolicy
Get-PAWEdgeBaselinePolicy
Get-PAWRunScript
Get-PAWWDACPolicy
```

`Get-PAWTemplate` exposes parsed settings in `.Data` and reports malformed JSON.
The cache list includes orphaned local folders containing files, but does **not**
verify completeness or installation readiness. VHD and baseline folders come
from Config.json. WDAC listing returns XML files without validation; validate
one separately with `Get-PAWWDACPolicy -Path <path>`.

The commands default to the modules' installation. For another installation,
`-Root` means the installation folder for utility commands and its `Resources`
folder for application commands.

## Import and remove resources

The corresponding module import commands use the installed paths by default:

```powershell
Import-PAWVHDX -Path 'D:\PAW-Staging\Win11-PAW.vhdx'
Import-PAWTemplate -Path 'D:\PAW-Staging\Template.json'
Import-PAWApplication -Path 'D:\PAW-Staging\Application-package.json'
Import-PAWApplicationBundle -Path 'D:\PAW-Staging\Bundle-package.json'
Import-PAWCachedApplication -Path 'D:\PAW-Staging\Cache-Local-Example.zip'
Import-PAWOSBaseline -ZipPath 'D:\PAW-Staging\WindowsBaseline.zip' -OperatingSystem 'Windows11_26H2'
Import-PAWEdgeBaseline -ZipPath 'D:\PAW-Staging\EdgeBaseline.zip' -OperatingSystem 'Windows11_26H2'
Import-PAWRunScript -Path 'D:\PAW-Staging\Configure-PAW.ps1'
Import-PAWWDACPolicy -Path 'D:\PAW-Staging\Policy.xml'
```

The application commands require portable PAW application packages, not raw
catalog or bundle JSON. Bundle packages also import their included application
definitions and payloads. Existing destinations require `-Replace`.
For cache preparation, use `.\Tools\Invoke-PAWApplicationDownload.ps1`.
`Import-PAWCachedApplication` restores ZIP files produced by
`Export-PAWCachedApplication`; it does not create application definitions.

Import accepts pipeline file objects, for example:

```powershell
Get-ChildItem 'D:\PAW-Staging\Scripts' -Filter '*.ps1' | Import-PAWRunScript -WhatIf
Get-ChildItem 'D:\PAW-Staging\Scripts' -Filter '*.ps1' | Import-PAWRunScript
```

## Export resources

Each export accepts the corresponding inventory object, defaults to the current
installation, and writes to the specified folder. Use `-WhatIf` to preview and
`-Replace` to allow overwriting existing exports. Unrelated files already in
the destination folder are not inspected or changed.

```powershell
$destination = 'D:\PAW-Export'
Get-PAWVHDXImage | Export-PAWVHDXImage -DestinationFolder $destination
Get-PAWTemplate | Export-PAWTemplate -DestinationFolder $destination
Get-PAWApplication | Export-PAWApplication -DestinationFolder $destination
Get-PAWApplicationBundle | Export-PAWApplicationBundle -DestinationFolder $destination
Get-PAWCachedApplication | Export-PAWCachedApplication -DestinationFolder $destination
Get-PAWOSBaselinePolicy | Export-PAWOSBaselinePolicy -DestinationFolder $destination
Get-PAWEdgeBaselinePolicy | Export-PAWEdgeBaselinePolicy -DestinationFolder $destination
Get-PAWRunScript | Export-PAWRunScript -DestinationFolder $destination
Get-PAWWDACPolicy | Export-PAWWDACPolicy -DestinationFolder $destination
```

Application and bundle exports are portable JSON packages; application filenames
include their name and ID, for example `7-Zip--<id>.json`. Bundle packages
include their applications and owned payloads. Cache ZIPs contain the entire
selected folder, including manually supplied and orphaned files, but no
application definitions. Restoring one with `-Replace` replaces the entire
existing cache folder. Handle exported files as potentially sensitive data.
Templates do not include referenced resources. Baseline ZIPs require an
installed `Scripts\Baseline-LocalInstall.ps1` and can be imported with
`Import-PAWOSBaseline` or `Import-PAWEdgeBaseline`; specify `-OperatingSystem`
when importing a ZIP from disk. File contents, including WDAC policies, are
validated by the corresponding import command.
Image export reads the contents of selected VHD/VHDX files even when the file
is a reparse point, such as a symbolic link; the export is a regular file.
This may hydrate cloud files and expand sparse or deduplicated files, so the
destination needs enough free space for the full image. The image folder itself
and its parent folders must not be reparse points.

```powershell
Get-PAWRunScript | Where-Object Name -eq 'Configure-PAW.ps1' |
    Export-PAWRunScript -DestinationFolder $destination -WhatIf
Get-ChildItem $destination -Filter 'Cache-*.zip' | Import-PAWCachedApplication -WhatIf
Get-ChildItem $destination -Filter 'Cache-*.zip' | Import-PAWCachedApplication
```

Remove commands accept their corresponding `Get-PAW*` objects or an exact
`-Name`. They ask for confirmation; use `-WhatIf` to preview:

```powershell
Get-PAWTemplate | Where-Object Name -eq 'Old template' | Remove-PAWTemplate -WhatIf
Get-PAWApplication -Bundle 'Tools' | Where-Object Name -eq 'Old app' |
    Remove-PAWApplicationFromBundle -Bundle 'Tools' -WhatIf
Get-PAWApplication | Where-Object Name -eq 'Old app' | Remove-PAWApplication
Get-PAWApplicationBundle | Where-Object Name -eq 'Old bundle' | Remove-PAWApplicationBundle
Get-PAWVHDXImage | Where-Object Name -eq 'Old.vhdx' | Remove-PAWVHDXImage
Get-PAWOSBaselinePolicy | Where-Object Name -eq 'Windows11_26H2' | Remove-PAWOSBaselinePolicy
Get-PAWEdgeBaselinePolicy | Where-Object Name -eq 'Windows11_26H2' | Remove-PAWEdgeBaselinePolicy
Get-PAWRunScript | Where-Object Name -eq 'Old.ps1' | Remove-PAWRunScript
Get-PAWWDACPolicy | Where-Object Name -eq 'Old.xml' | Remove-PAWWDACPolicy
Get-PAWCachedApplication | Where-Object Path -eq 'C:\PAWDeploy\Resources\ApplicationDownloads\Local\Old' |
    Remove-PAWCachedApplication -WhatIf
```

Removal is blocked when an application is in a bundle, or when a template
references a bundle, image, baseline, run script or WDAC policy. Correct
invalid templates before deleting referenced resource types. A template itself
can be removed even if its JSON is invalid. The older
`Remove-PAWManagedApplication` retains its existing behavior of removing the
application from bundles; use `Remove-PAWApplication` for reference protection.
Use `Remove-PAWApplicationFromBundle` first to remove an assignment without
deleting the application or changing the remaining installation order.

Cache removal deletes the **entire selected folder**, including manually
provided installers or packages that may not be downloadable again. It leaves
application definitions and bundles intact. Removing a WDAC file does not
change policies already installed on the host or a VM. For alternate
installations, import commands expose `-ConfigPath`, `-InstallFolderPath`,
`-BaselineFolder` or `-Root` as appropriate.

## Create a deployment template

Use the imported VHDX filename and an existing Hyper-V switch. This example
creates a workgroup template without an application bundle.

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -New -Name 'Windows 11 PAW' `
    -DomainOrWorkGroup WORKGROUP -DiskMode Copy -VMSwitch 'Default Switch' `
    -VHDFile 'Win11-PAW.vhdx' -ApplicationBundle NA
```

### Advanced domain template

This example sets VM hardware, security, applications, regional settings and
domain join options explicitly. First import the VHDX, baselines, LGPO, WDAC
policy and Run Script as shown above, and create an application bundle. List
bundles and replace the example GUID with the `BundleId` you want:

```powershell
.\Tools\Invoke-PAWApplicationManager.ps1 -Action ListBundles |
    Select-Object Name, BundleId

$params = @{
    New                      = $true
    Name                     = 'Windows 11 Advanced Domain PAW'
    VMNotes                  = 'Domain-joined administrator workstation'
    VMGen                    = '2'
    NoCPU                    = 4
    Memory                   = 8192
    DynamicMem               = 'False'
    DiskMode                 = 'Copy'
    Shielded                 = 'True'
    BitLocker                = 'True'
    ASR                      = 'True'
    Application              = 'True'
    ApplicationBundle        = 'cbade470-64cc-4628-9536-b58e3ca3be8d'
    ApplySecurityBaseline    = 'True'
    VHDFile                  = 'Win11-PAW.vhdx'
    RunScript                = 'Configure-PAW.ps1'
    WDACPolicyFile           = 'PAW-Audit.xml'
    SecurityBaselineLocation = 'Windows11_26H2'
    TimeZoneName             = 'W. Europe Standard Time'
    InputLocale              = 'sv-SE'
    SystemLocale             = 'sv-SE'
    UILanguage               = 'en-US'
    UserLocale               = 'sv-SE'
    DomainOrWorkGroup        = 'DOMAIN'
    DNSDomain                = 'corp.contoso.com'
    MachineObjectOU          = 'OU=PAW,DC=corp,DC=contoso,DC=com'
    NamePrefix               = 'PAW'
    NameSuffix               = 'T0'
    VLanID                   = 20
    VMSwitch                 = 'CorpSwitch'
    ProductKey               = ''
}

.\Tools\Invoke-PAWTemplateSettings.ps1 @params -WhatIf
.\Tools\Invoke-PAWTemplateSettings.ps1 @params
.\Tools\Invoke-PAWTemplateSettings.ps1 -Show -Name $params.Name
```

Replace the example resource names, domain, OU, switch and VLAN with values for
your environment. `RunScript` and `WDACPolicyFile` are filenames, not paths; a
template selects one Run Script. Use a reviewed WDAC policy: the filename does
not determine audit or enforcement mode. The baseline folder must match the OS
and contain the imported baseline scripts and LGPO. Ensure the image supports
the chosen display language and the host supports the selected security
settings. `ProductKey` is optional; do not put a real key in shared examples.
For a workgroup, set `DomainOrWorkGroup` to `WORKGROUP` and both `DNSDomain` and
`MachineObjectOU` to `NA`. Use `NA` for an unused Run Script, WDAC policy or
application bundle; set `ApplySecurityBaseline` to `False` and
`SecurityBaselineLocation` to `NA` to skip the baseline. Run preflight as shown
below before deploying the new template, using its name instead of `Windows 11 PAW`.

Importing resources does not assign them to a template. See the [Command-Line
Template Editor](Invoke-PAWTemplateSettings.md) for selecting a baseline, WDAC
policy or Run Script, and [Application Manager](ApplicationManager.md#bundles-and-template-assignment)
for assigning and preparing a bundle.

## Edit a deployment template

List the templates and inspect the one you want to change. Replace the example
name and settings with your own. `-WhatIf` previews the edit without saving it;
run the same command without `-WhatIf` to save the changes.

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -List
.\Tools\Invoke-PAWTemplateSettings.ps1 -Show -Name 'Windows 11 PAW'

.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 PAW' `
    -Memory 8192 -NoCPU 4 -InputLocale 'sv-SE' -UserLocale 'sv-SE' -WhatIf
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 PAW' `
    -Memory 8192 -NoCPU 4 -InputLocale 'sv-SE' -UserLocale 'sv-SE'

.\Tools\Invoke-PAWTemplateSettings.ps1 -Show -Name 'Windows 11 PAW'
```

Only the supplied settings change. To rename a template, use `-Edit` with
`-NewName`; the template filename remains unchanged.

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 PAW' `
    -NewName 'Windows 11 PAW Updated'
```

## Remove a deployment template

Replace the example name with the template to remove. Preview the deletion
first; the second command asks for confirmation before deleting the template
file. It does not delete deployed VMs.

```powershell
.\Tools\Invoke-PAWTemplateSettings.ps1 -Remove -Name 'Windows 11 PAW Updated' -WhatIf
.\Tools\Invoke-PAWTemplateSettings.ps1 -Remove -Name 'Windows 11 PAW Updated'
```

Use `-Force` only when you intentionally want to remove the template without
the confirmation prompt.

## Build a PAW

Run preflight first to check the selected template and resources without creating
a VM. Use an unused VM name.

```powershell
$plan = .\New-PAWVM.ps1 -Template 'Windows 11 PAW' -VMName 'PAW-CLI-01' -PreflightOnly
$plan.Checks | Format-Table Name, Passed, Message -AutoSize -Wrap
$plan.Errors
$plan.PendingDownloads
```

After resolving any problems, run the deployment and enter the guest's local
Administrator password when prompted.

```powershell
.\New-PAWVM.ps1 -Template 'Windows 11 PAW' -VMName 'PAW-CLI-01'
```

See [New-PAWVM.ps1](New-PAWVM.md) for deployment options and verification.
