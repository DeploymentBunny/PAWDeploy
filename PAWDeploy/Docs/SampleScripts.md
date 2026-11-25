# Sample Custom RunScripts

See [Commandline Samples](CommandlineSamples.md) for a PowerShell example that imports a Run Script, assigns it to a template and builds a PAW.

## What Are These Files?

`Sample1.ps1` and `Sample2.ps1` are example custom scripts included with PAWDeploy.

Both files are stored in `Resources\CustomScripts` and show how a template `RunScript` can run a PowerShell script inside a newly deployed PAW virtual machine.

They are helper examples for the `RunScript` hook. In the current flow, `New-PAWVM.ps1` runs the selected script inside the VM after startup, encryption/shielding steps, and PowerShell Direct setup, but before PAWAppInstall and security-baseline application.

The `Resources\CustomScripts` folder is always copied independently of
`ExtraFolder`, application handling and SkipRunScript, to:

```text
C:\PAWFiles\CustomScripts\Sample1.ps1
C:\PAWFiles\CustomScripts\Sample2.ps1
```

---

## Why Is It Needed?

Many customers want a newly deployed PAW to do one or more extra tasks automatically after the operating system is ready.

Typical examples include:

- creating folders
- copying tools into place
- installing software
- applying organisation-specific customisations
- launching a bootstrap script for additional configuration

This sample file is included so you can:

- understand how custom RunScript behavior works in PAWDeploy
- test that PAWDeploy can successfully run a script inside the VM
- use it as a starting point for your own custom automation

Think of it as a **working example you can copy and adapt**.

---

## How PAWDeploy Uses It

PAWDeploy copies `Resources\CustomScripts` to `C:\PAWFiles\CustomScripts`.
`RunScript` is only a filename, e.g. `Sample1.ps1`.
The New PAW UI lists top-level `.ps1` files only. The guest runs the selected script
with that directory as its working directory through PowerShell Direct and
`powershell.exe -ExecutionPolicy Bypass -File`. Staging/execution failures warn.

RunScript is independent of both Copy Folder and applications.

In practical terms:

1. PAWDeploy copies CustomScripts into the VM independently of the extra folder
2. PAWDeploy starts the VM and completes the normal build process
3. `New-PAWVM.ps1` runs the chosen script inside the VM before the application-install and security-baseline phases

This makes the samples useful for testing or for adding your own extra steps during deployment.

## Import scripts

```powershell
.\Tools\Import-PAWRunScript.ps1 -Path 'C:\Downloads\Sample1.ps1','C:\Downloads\Sample2.ps1'
```

The CLI imports one or more existing `.ps1` files into `Resources\CustomScripts`,
keeping filenames and never executing them. Existing names require `-Replace`.
`-WhatIf` changes nothing. The Enterprise **Import Run Scripts** button allows
multiple files and asks for replacement approval. Refresh the New PAW script list
after importing. Change older template path values to filenames.

---

## Sample1.ps1

### What It Is

`Sample1.ps1` is a **very simple test script**.

Its current behavior is:

- create the folder `C:\RunMeTest`
- do nothing else

### Why It Is Useful

This script is useful when you want to verify one thing only:

> "Can PAWDeploy successfully run a custom script inside the VM during the build after guest startup?"

Because it does something small and easy to check, it is a good first test.

### What It Does

When it runs successfully, the VM will contain this folder:

```text
C:\RunMeTest
```

If you see that folder inside the deployed PAW, you know the RunScript hook is working.

### Sample2.ps1

`Sample2.ps1` has the same current behavior as `Sample1.ps1`: it creates `C:\RunMeTest` and does nothing else. Both samples write the same marker folder.

### When To Use It

Use either sample when you want to:

- test the RunScript feature
- confirm that `ExtraFolder` and `RunScript` are configured correctly
- demonstrate the concept before writing a more complex script

---

## How To Use This Script With PAWDeploy

The most common way to use this script is to point PAWDeploy at the folder containing it and specify which script should run during the build.

### Example 1  -  Deploy a VM and run Sample1.ps1

This is the simplest test case.

```powershell
$params = @{
    Template     = 'Windows 11 x64 PAW for WORKGROUP ON'
    VMSwitchName = 'CorpSwitch'
    RunScript    = 'Sample1.ps1'
}

.\New-PAWVM.ps1 @params
```

What this does:

- deploys a PAW using the selected template
- stages the selected script from `Resources\CustomScripts` into the VM
- runs `Sample1.ps1` inside the VM during deployment
- creates `C:\RunMeTest` inside the deployed VM

How to verify success:

1. Connect to the deployed VM
2. Open File Explorer
3. Check whether `C:\RunMeTest` exists

---

### Example 2  -  Preview the deployment before running a sample script

This is the safest approach when testing changes.

```powershell
$params = @{
    Template     = 'Windows 11 x64 PAW for WORKGROUP ON'
    VMSwitchName = 'CorpSwitch'
    RunScript    = 'Sample1.ps1'
    WhatIf       = $true
}

.\New-PAWVM.ps1 @params
```

This lets you confirm that PAWDeploy will use the correct template and script before any real deployment starts.

---

## How To Test the Script Manually Inside a VM

Sometimes you may want to test a sample script inside a VM after deployment, without running a full new build.

### Manually test Sample1.ps1

```powershell
$params = @{
    FilePath     = 'powershell.exe'
    ArgumentList = '-ExecutionPolicy Bypass -File "C:\PAWFiles\CustomScripts\Sample1.ps1"'
    Wait         = $true
}

Start-Process @params
```

After it finishes, check whether this folder now exists:

```text
C:\RunMeTest
```

---

## How To Configure a Sample RunScript

Templates are JSON files beside `Config.json` in Config. Select the script by filename:

```json
{
  "RunScript": "Sample1.ps1"
}
```

The same `RunScript` value can be supplied to `New-PAWVM.ps1` to override the template. The value is resolved relative to `C:\PAWFiles` inside the VM; a bare file name such as `Sample1.ps1` is also found in `C:\PAWFiles\CustomScripts`. If the script is not found, deployment logs a warning and skips it. If the script returns a non-zero exit code, deployment logs a warning with the exit code and continues.

---

## Adapting This Sample for Your Own Use

These files are meant to be edited and reused.

A common progression is:

1. start with `Sample1.ps1` to confirm the template RunScript works
2. create your own custom script based on it

Examples of custom tasks you might add:

- create standard folders
- copy approved tools into place
- install your organisation's management agent
- install browsers or admin tools
- configure registry settings
- run a bootstrap script from your internal repository

---

## Troubleshooting

| Problem | Likely Cause | What to check |
|---|---|---|
| The sample script does not seem to run | `RunScript` is not set to an available script | Verify that `Resources\CustomScripts\Sample1.ps1` or `Sample2.ps1` exists and set `RunScript` to the filename only. |
| Sample1.ps1 did not create `C:\RunMeTest` | The script did not run, or it ran in a different context than expected | Check the PAWDeploy log and verify the sample files were copied into the VM |
| The wrong script runs | The template or command points to the wrong file name | Check the `RunScript` value in the template JSON or your `New-PAWVM.ps1` command |

---

## Good Practice for Customers

Use this order when testing template RunScripts:

1. test with `Sample1.ps1`
2. confirm the VM shows `C:\RunMeTest`
3. only then move on to your own custom RunScript

That approach makes it much easier to see whether problems are caused by PAWDeploy itself or by your custom script logic. Return a non-zero exit code (`exit 1`) from your script on failure; `New-PAWVM.ps1` logs the exit code as a warning.

---

## Related Documents

- [Invoke-PAWInstallApplications.md](Invoke-PAWInstallApplications.md)  -  Application pre-staging and installation workflow
- [New-PAWVM.md](New-PAWVM.md)  -  Core deployment engine that runs the template RunScript
- [PAWDeployUI.md](PAWDeployUI.md)  -  Graphical deployment tool
- [Config.json.md](Config.json.md)  -  How template settings such as `ExtraFolder` and `RunScript` are configured
- [Install-PAWDeploy.md](Install-PAWDeploy.md)  -  How the solution is installed
- [Convert-PAWWIM2VHD.md](Convert-PAWWIM2VHD.md)  -  How the source template VHDX is created

---

## Quick Validation Checklist

After testing `Sample1.ps1`, verify the following:

1. `Sample1.ps1` creates `C:\RunMeTest` in the deployed VM.
2. `RunScript` and `ExtraFolder` values in template/command are correct.
3. The intended script runs only once per deployment as expected.
4. The deployment log records the RunScript attempt and its exit code.
