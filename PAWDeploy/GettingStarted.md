# Getting started with PAWDeploy

This guide takes you from a prepared Windows host to a test Privileged Access
Workstation (PAW). For the purpose and limitations of the solution, see
[README](README.md). Replace all example paths and names with values for your
environment.

## 1. Prepare the host

- Use a supported, fully patched Windows 11 Pro, Enterprise, or Education host
  with Windows PowerShell 5.1 and local administrator access.
- Enable hardware virtualization and SLAT in firmware. Plan for at least 16 GB
  RAM and 100 GB free disk space; additional VMs and full disk copies need more.
- Enable Hyper-V, restart when prompted, and verify it:

  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  # After restarting:
  Get-VMHost
  ```

- Create or select a Hyper-V virtual switch. For example, an external switch can
  connect a PAW to domain controllers and management networks. Configure DNS,
  firewall rules and any VLANs for the access the PAW actually needs.

The host is part of the security boundary: protect and maintain it as well as
the PAW guest.

## 2. Install PAWDeploy

Extract the source or release package. In an elevated Windows PowerShell window,
change to the folder containing `Install-PAWDeploy.ps1` and run:

```powershell
.\Install-PAWDeploy.ps1 -Path 'C:\PAWDeploy'
```

The installer creates the image destination but does not copy an image. The
installer is in the source/package root, not in the installed folder. For custom
image and VM locations, upgrades, and other options, see
[installation](Docs/Install-PAWDeploy.md).

## 3. Prepare the image and configuration

1. Provide a Windows reference disk in VHDX format. You can convert a Windows
   WIM using the [WIM conversion guide](Docs/Convert-PAWWIM2VHD.md), or use an
   existing VHDX generalized with Sysprep. Import the disk into the configured
   image folder using [VHDX import](Docs/Import-PAWVHDX.md). Keep the image
   patched and supported.
2. Open `C:\PAWDeploy\PAWMenu.ps1` as administrator and choose
   **Configuration** and **Templates**. Configure your paths and an active
   template, including its image, Hyper-V switch, VM resources, language and
   domain or workgroup settings. See [configuration](Docs/Config.json.md),
   [configuration editor](Docs/PAWConfigEditorUI.md), and
   [template settings](Docs/Invoke-PAWTemplateSettings.md).
3. If needed, assign an application bundle and prepare security baselines or
   scripts. See [Application Manager](Docs/ApplicationManager.md),
   [security baseline imports](Docs/Import-PAWSecurityBaseline.md), and
   [scripts](Docs/SampleScripts.md). Only include resources appropriate for
   the intended administrative work.

Both editions also provide command-line tools. For an end-to-end example,
including image conversion and imports, see
[Commandline Samples](Docs/CommandlineSamples.md).

## 4. Deploy and verify a test PAW

Run the configuration validator and resolve any reported problems:

```powershell
C:\PAWDeploy\Tools\Invoke-PAWConfigValidation.ps1
```

In the menu, choose **New PAW**, select the active template, review the
settings and build the VM. The [deployment UI guide](Docs/PAWDeployUI.md)
and [deployment engine guide](Docs/New-PAWVM.md) explain the options and
preflight checks.

Before production use, confirm that Windows setup completes; the name, language,
network and domain or workgroup are correct; and the intended security settings,
applications and scripts are effective. Review logs in `%TEMP%\PAWDeploy`.
Test again after changing the image, template, applications or baselines.

## Where to go next

- [Commandline Samples](Docs/CommandlineSamples.md) - preparation and deployment
  from PowerShell.
- [Configuration reference](Docs/Config.json.md) - settings and template layout.
- [Deployment engine](Docs/New-PAWVM.md) - preflight, security and deployment options.
- [Logs](Docs/PAWLogsUI.md) - reviewing and troubleshooting logs.
- [Documentation folder](Docs/) - detailed guides for the individual tools.
