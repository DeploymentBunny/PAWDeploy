# Getting started with PAWDeploy Community Edition

This guide takes you from a prepared Windows host to a test Privileged Access
Workstation (PAW). Replace the example paths and names with values for your
environment. See [README](README.md) for the solution overview and limitations.

## 1. Prepare the host

- Use a supported, fully patched Windows 11 Pro, Enterprise or Education host,
  Windows PowerShell 5.1 or PowerShell 7, and an elevated local administrator
  session.
- Enable hardware virtualization and SLAT in firmware. Plan for at least 16 GB
  RAM and 100 GB free disk space; additional VMs and full disk copies need more.
- Enable Hyper-V, restart when prompted, and verify it:

  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
  # After restarting:
  Get-VMHost
  ```

- Create or select a Hyper-V virtual switch. Configure network access, DNS,
  firewall rules and VLANs for the administrative work the PAW will perform.

The host is part of the security boundary. Protect and maintain it along with
the guest, accounts, reference image and network.

## 2. Install Community Edition

In an elevated PowerShell session, change to the folder containing
`Install-PAWDeploy.ps1` and run:

```powershell
.\Install-PAWDeploy.ps1 -Path 'C:\PAWDeploy'
```

The installer copies `GettingStarted.md` and `README.md` from beside it to
`C:\PAWDeploy`, alongside `Docs`.
The installer creates the image destination but does not copy an image. For
custom paths, themes, upgrades and other options, see the
[installation guide](PAWDeploy/Docs/Install-PAWDeploy.md).

## 3. Prepare the image and configuration

1. Provide a supported, patched Windows reference disk in VHDX format. You can
   use a generalized image or convert a WIM with the included
   [command-line converter](PAWDeploy/Docs/Convert-PAWWIM2VHD.md). The
   [command-line walkthrough](PAWDeploy/Docs/CommandlineSamples.md) shows how to select a
   WIM index and convert it.
2. From the installation root, import the VHDX into the configured image folder:

   ```powershell
   Set-Location 'C:\PAWDeploy'
   .\Tools\Import-PAWVHDX.ps1 -Path 'D:\PAW-Staging\Win11-PAW.vhdx'
   ```

   Alternatively, run `.\Tools\PAWVHDXImportUI.ps1` or use the installed
   **PAW VHDX Import** shortcut. The [VHDX import guide](PAWDeploy/Docs/Import-PAWVHDX.md)
   describes replacement and preview options.
3. Open `C:\PAWDeploy\PAWMenu.ps1` as administrator. Choose **Configuration**
   to configure paths, then **Templates** to create or activate a template.
   Select the VHDX, Hyper-V switch, VM resources, language and domain or
   workgroup settings. See [configuration](PAWDeploy/Docs/Config.json.md) and the
   [template editor](PAWDeploy/Docs/PAWTemplateEditorUI.md).
4. If needed, use **Applications/Bundles** to prepare applications and assign a
   bundle. Import approved security baselines, LGPO, scripts or WDAC policies
   with the included command-line tools. See
   [Application Manager](PAWDeploy/Docs/ApplicationManager.md),
   [baseline imports](PAWDeploy/Docs/Import-PAWSecurityBaseline.md),
   [sample scripts](PAWDeploy/Docs/SampleScripts.md), and the
   [command-line walkthrough](PAWDeploy/Docs/CommandlineSamples.md).

Only include resources appropriate for the intended administrative work.

## 4. Deploy and verify a test PAW

From the installation root, run the configuration validator and resolve any
reported problems:

```powershell
.\Tools\Invoke-PAWConfigValidation.ps1
```

In the menu, choose **New PAW**, select the active template, review the settings
and build the VM. The [deployment UI guide](PAWDeploy/Docs/PAWDeployUI.md) and
[deployment engine guide](PAWDeploy/Docs/New-PAWVM.md) explain the options and checks.

Before production use, confirm that Windows setup completes; the name, language,
network and domain or workgroup are correct; and the intended security settings,
applications and scripts are effective. Use **Logs** in the menu to review logs
in `%TEMP%\PAWDeploy`. Test again after changing the image, template,
applications or policies.

## Where to go next

- [Community menu](PAWDeploy/Docs/PAWMenuCommunity.md) - available menu actions.
- [Command-line walkthrough](PAWDeploy/Docs/CommandlineSamples.md) - image and resource
  preparation and deployment from PowerShell.
- [Configuration reference](PAWDeploy/Docs/Config.json.md) - settings and template layout.
- [Logs](PAWDeploy/Docs/PAWLogsUI.md) - reviewing and troubleshooting logs.
- [Documentation folder](PAWDeploy/Docs/) - detailed guides for the included tools.
