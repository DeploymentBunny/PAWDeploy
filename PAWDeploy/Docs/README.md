# PAWDeploy Community Edition

PAWDeploy helps you deploy repeatable Privileged Access Workstations (PAWs) as
Hyper-V virtual machines for administrative work. Templates combine a reference
VHDX with VM, guest and security settings. A VM alone does not guarantee security:
protect and maintain the host, image, accounts, network and policies, and verify
the finished PAW against your organization's requirements.

Start with [Getting started](GettingStarted.md) for a step-by-step deployment.

## Editions

| Component | Community | Enterprise |
|---|---|---|
| Installer, configuration, templates and resources | Yes | Yes |
| New PAW deployment UI and command-line engine | Yes | Yes |
| Configuration and template editors, template import/export | Yes | Yes |
| Application Manager UI/CLI and bundles | Yes | Yes |
| OS/Edge baseline and LGPO import | CLI | CLI and menu actions |
| WDAC policy and Run Script import | CLI | CLI and menu actions |
| VHDX import | UI and CLI | UI, CLI and menu action |
| WIM conversion and VM removal | CLI | UI and CLI |
| ASR master list editor | CLI | UI and CLI |
| Menu | New PAW, Configuration, Templates, Applications/Bundles, PowerShell Prompt, Logs and Help | Full menu |

## Requirements

- Windows 11 Pro, Enterprise or Education with Hyper-V, hardware virtualization
  and SLAT enabled; use a supported, fully patched host.
- Windows PowerShell 5.1 or PowerShell 7 and an elevated local administrator
  session for installation and the tools that require it.
- A Hyper-V virtual switch, a suitable Windows VHDX reference image, sufficient
  disk space and memory, and network access appropriate for the PAW.
- Prepare and test any domain, security baseline, application and policy
  dependencies required by your environment.

The [getting-started guide](GettingStarted.md) covers host sizing, Hyper-V,
network preparation and deployment checks.

## Installation

Extract the Community ZIP and run the installer from its root in an elevated
PowerShell session:

```powershell
.\Install-PAWDeploy.ps1 -Path 'C:\PAWDeploy'
```

The installer creates the image destination but does not copy an image. Use
`-ImageLocation`, `-VMLocation` and `-Theme` to customize paths and appearance.
It preserves user-managed configuration and resources on upgrade. Installation
shortcuts are created under `<InstallPath>\ShortCuts` and in the Start menu;
they use the PowerShell installation that ran the installer. See the
[installation guide](Docs/Install-PAWDeploy.md) for prerequisites, upgrades,
parameters and `-WhatIf`.

Open the installed `PAWMenu.ps1` as administrator. Menu-launched tools and the
PowerShell Prompt use the same PowerShell installation as the menu. The prompt
opens in the installation root with the PAW utility and application manager
modules loaded.

## Prepare and deploy a PAW

1. Prepare a supported Windows VHDX. An existing generalized image can be used,
   or a WIM can be converted with the included
   [command-line converter](Docs/Convert-PAWWIM2VHD.md). Import the VHDX into
   the configured image folder using the [VHDX importer](Docs/Import-PAWVHDX.md).
2. In the menu, open **Configuration** and **Templates**. Configure paths and
   create or activate a template with the image, VM switch, resources, locale
   and domain or workgroup settings. See [configuration](Docs/Config.json.md),
   the [editor](Docs/PAWConfigEditorUI.md) and
   [template settings](Docs/Invoke-PAWTemplateSettings.md).
3. If needed, use **Applications/Bundles** to define applications and assign a
   bundle to the template. Prepare approved scripts, security baselines and
   WDAC policies as appropriate. The
   [Application Manager guide](Docs/ApplicationManager.md) explains application
   sources, caching, bundles and transfer.
4. Run `.\Tools\Invoke-PAWConfigValidation.ps1` from the installation root and
   resolve any reported problems. Open **New PAW**, select the active template,
   review its settings and build the VM. See the
   [deployment UI](Docs/PAWDeployUI.md) and [deployment engine](Docs/New-PAWVM.md)
   guides for options and preflight checks.
5. Verify Windows setup, networking, domain or workgroup membership, security
   settings, applications and scripts before production use. Repeat the checks
   when the image, template, applications or policies change.

## Configuration and resources

`Config\Config.json` holds environment defaults. Template JSON files are stored
beside it in `Config`; template enumeration excludes `Config.json`. Use
**Configuration** and **Templates**, or the
[configuration CLI](Docs/Invoke-PAWConfigurationSettings.md) and
[template CLI](Docs/Invoke-PAWTemplateSettings.md). The Templates editor also
supports import and export.

Host-side content lives under `Resources`, including application catalog and
bundles, application downloads, custom scripts, security baselines, ASR and
WDAC policies. See [baseline imports](Docs/Import-PAWSecurityBaseline.md) and
[sample scripts](Docs/SampleScripts.md). Templates control guest ASR rules;
WDAC XML policies can be selected in New PAW. The
[security deployment guide](Docs/New-PAWVM.md#asr-and-windows-defender-application-control)
describes overrides and WDAC activation.

## Tools and documentation

The menu provides **New PAW**, **Configuration**, **Templates**,
**Applications/Bundles**, **PowerShell Prompt**, **Logs**, **Help** and
**Close**. Tools can also be started from the installation's `Tools` folder or
their installed shortcuts. See the [Community menu guide](Docs/PAWMenuCommunity.md)
and [command-line walkthrough](Docs/CommandlineSamples.md).

Use **Logs** to inspect or delete logs in `%TEMP%\PAWDeploy`; the
[log viewer guide](Docs/PAWLogsUI.md) describes its controls. **Help** opens
the local documentation reader. The [Docs folder](Docs) contains the detailed
guides, including [configuration validation](Docs/Invoke-PAWConfigValidation.md),
[template editing](Docs/PAWTemplateEditorUI.md) and
[VM removal from PowerShell](Docs/Remove-PAWVM.md).

The solution version is recorded in `Config\Config.json`; module and script
versions are maintained separately.
