# Remove-PAWVM.ps1 — Command-Line VM Removal Tool

## What Is It?

`Remove-PAWVM.ps1` is a **command-line tool** for permanently removing one or more Hyper-V virtual machines from your computer.

It is the scripting and automation version of the graphical removal tool. Instead of clicking through a window, you run a PowerShell command and tell the script which VM name or names to remove.

By default, only VMs whose Notes contain the literal, case-sensitive marker
`###PAW42###` are eligible. Explicit names, wildcards and `-Force` alone do
not bypass the marker check. Use `-ShowAll` to opt in to listing or removing
unmarked VMs, including older PAWs without the marker. Type `-ShowAll` before
completing `-VMName` to include unmarked names in tab completion.

Use `.\Tools\Remove-PAWVM.ps1 -List | Format-Table -AutoSize -Wrap` to inspect
marked VMs without deleting anything. Add `-VMName 'PAW-*'` to filter the list.
Add `-ShowAll` to `-List` to list all Hyper-V VMs on this host.
The returned objects include Name, State (Off/Running/Saved/etc.), DiskMode,
Location (Hyper-V configuration folder) and CreationTime (Hyper-V creation date).
These details also appear before removal confirmation.

DiskMode describes the current underlying VHD: `Diff disk` for differencing,
`Copy disk` for standalone Dynamic/Fixed. Checkpoint AVHD layers are excluded.
It does not prove how an older VM was originally deployed. Mixed/no disks are
shown explicitly; unreadable metadata produces warnings and Unknown, not guesses.

The script is designed for situations where you want to:

> **Edition:** The command-line tool is included in both editions. The graphical removal tool is Enterprise only.

- remove a VM quickly from PowerShell
- remove several VMs in one command
- automate VM cleanup in another script
- preview what would be removed before deleting anything

> The actual script file in this solution is named `Remove-PAWVM.ps1`.

---

## Why Is It Needed?

Deleting a VM in Hyper-V is not always enough on its own. A VM can have:

- one or more attached virtual hard disk files
- a Hyper-V configuration folder still stored on disk
- a running power state that must be stopped first

`Remove-PAWVM.ps1` helps by doing the full cleanup process in one step:

1. Finds the VM by name
2. Stops it if it is running
3. Removes checkpoints and merges their differencing disks, then re-reads attached disk paths
4. Removes the VM from Hyper-V
5. Deletes the attached virtual hard disk files and VM configuration folder

This is useful when you want a cleaner and more repeatable removal process than deleting things manually.

---

## Important Warning

This script performs a **permanent deletion**.

When it runs successfully, the following can be removed:

- the Hyper-V virtual machine
- attached virtual hard disk files
- the VM configuration folder

There is **no undo**. If you may need the VM again, make a backup first.

---

## Before You Start

| Requirement | Details |
|---|---|
| **Run as Administrator** | An elevated local administrator session is required, including for `-List` and `-WhatIf`. Open PowerShell using **Run as Administrator**. |
| **Hyper-V is installed** | The script uses Hyper-V PowerShell commands such as `Get-VM`, `Stop-VM`, and `Remove-VM` |
| **Know the exact VM name** | The script removes VMs by name |
| **Understand the impact** | The VM and its related files can be permanently deleted |

---

## What the Script Does

For each eligible VM name you provide, the script:

1. Looks for a virtual machine with that name
2. If no VM is found, it shows a warning and skips that name
3. Reads the VM's attached hard disk paths and configuration folder
4. If the VM is running, it turns the VM off
5. Removes checkpoints and merges their differencing disks, then re-reads attached disk paths before removing the VM
6. Removes the VM from Hyper-V
7. Deletes the attached disk files and configuration folder from disk

> **Checkpoint note:** Checkpoints are removed without restoring an older checkpoint. Hyper-V merges their differencing disks before the attached disk paths are collected again, avoiding deletion of stale `.avhdx` paths. If checkpoint removal fails or checkpoints remain, removal of that VM and its files is aborted and the failure is logged.

With `-ShowAll`, unmarked VMs go through the same removal process, including
deletion of their attached disks and configuration folders. `-ShowAll` does not
select any VMs for removal; specify the VM names and preview with `-WhatIf`.

The script uses PowerShell `ShouldProcess` safety handling:

- `-WhatIf` to preview the planned action without stopping VMs, removing checkpoints, or deleting files, even when `-Force` is also specified
- `-Confirm` to request approval for each removal; because `ConfirmImpact` is `High`, the default PowerShell `ConfirmPreference` also prompts unless changed
- `-Verbose` to show more detail during execution
- `-Force` suppresses confirmation prompts only; `ShouldProcess` and `-WhatIf` remain effective

---

## Parameters

| Parameter | Type | Required | Default | Accepted values / constraints | Description |
|---|---|---|---|---|---|
| `-VMName` | `[string[]]` | For removal only | — | One or more non-empty VM names | Names of the VMs to remove or filter by. |
| `-List` | `[switch]` | No | Off | — | Lists VM details without removing anything. |
| `-ShowAll` | `[switch]` | No | Off | — | Includes unmarked VMs in listing, tab completion and removal. |
| `-Force` | `[switch]` | No | Off | — | Suppresses confirmation prompts without bypassing `ShouldProcess` or `-WhatIf`. |
| `-WhatIf` | `[switch]` | No | Off | — | Previews the action without deleting anything, including with `-Force`. |
| `-Confirm` | `[switch]` | No | Off | — | Requests a confirmation prompt. With `ConfirmImpact = High`, the default PowerShell preference also prompts unless changed. |
| `-Verbose` | `[switch]` | No | Off | — | Shows additional progress details. |

Timestamped log entries are written to `%TEMP%\PAWDeploy\Remove-PAWVM.log`. The folder is created if needed; configuration cannot override it.


## How to Run It

Open an elevated PowerShell window, go to the PAWDeploy folder, and run the script.

Example:

```powershell
Set-Location "C:\PAWDeploy\PAWDeploy"
```

Then run the script with the VM names you want to remove.

---

## Why Use Splatting?

**Splatting** is a PowerShell technique where you put parameters into a hashtable and then pass that hashtable to a command.

This makes commands:

- easier to read
- easier to edit later
- safer when there are many parameters
- better for documentation and automation

All examples below use splatting, as requested.

---

## Examples

### Example 1 — Preview the removal of one VM

Use this first when you want to check what the script would remove.

```powershell
$params = @{
    VMName = 'PAW-Client01'
    WhatIf = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

What this does:

- checks for the VM named `PAW-Client01`
- shows what would be removed
- does **not** delete anything

---

### Example 2 — Remove one VM with confirmation

```powershell
$params = @{
    VMName  = 'PAW-Client01'
    Confirm = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

What this does:

- removes one VM
- asks you to confirm before the permanent deletion happens

---

### Example 3 — Remove several VMs in one command

```powershell
$params = @{
    VMName = @(
        'PAW-Client01'
        'PAW-Client02'
        'PAW-Admin01'
    )
    Confirm = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

What this does:

- removes multiple VMs in sequence
- prompts before each removal

---

### Example 4 — Remove several VMs without prompts

Use this only when you are completely sure.

```powershell
$params = @{
    VMName = @(
        'PAW-Client01'
        'PAW-Client02'
    )
    Force = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

What this does:

- removes both VMs
- suppresses confirmation prompts
- is useful in automation or cleanup scripts

---

### Example 5 — Remove one VM and show detailed progress

```powershell
$params = @{
    VMName  = 'PAW-Client01'
    Confirm = $true
    Verbose = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

What this does:

- removes one VM
- prompts for confirmation
- shows extra messages such as when disks and configuration folders are being removed

---

### Example 6 — Safe workflow: preview first, then remove

```powershell
$previewParams = @{
    VMName = @(
        'PAW-Client01'
        'PAW-Client02'
    )
    WhatIf = $true
}

.\Tools\Remove-PAWVM.ps1 @previewParams

$removeParams = @{
    VMName = @(
        'PAW-Client01'
        'PAW-Client02'
    )
    Confirm = $true
}

.\Tools\Remove-PAWVM.ps1 @removeParams
```

This is the recommended approach for important systems:

1. preview the result with `-WhatIf`
2. review the output carefully
3. run the real removal only if the preview looks correct

---

## Typical Usage Patterns

### Remove a test VM after validation

```powershell
$params = @{
    VMName  = 'PAW-Test01'
    Confirm = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

### Clean up several old lab VMs

```powershell
$params = @{
    VMName = @(
        'PAW-Lab01'
        'PAW-Lab02'
        'PAW-Lab03'
    )
    Force = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

### Use from another PowerShell script

```powershell
$vmNames = @('PAW-Old01', 'PAW-Old02')

$params = @{
    VMName = $vmNames
    Force  = $true
}

.\Tools\Remove-PAWVM.ps1 @params
```

---

## Understanding the Safety Options

### `-WhatIf`

This previews what the script would do without stopping VMs, removing checkpoints, or deleting anything. `-Force -WhatIf` is also a preview: `-Force` never bypasses `-WhatIf`.

Use it when:

- you are not fully sure about the VM name
- you are removing multiple VMs
- you are testing a script or automation flow

### `-Confirm`

This requests approval before each removal. Since the script sets `ConfirmImpact` to `High`, PowerShell normally prompts by default when `ConfirmPreference` is `High` (the standard setting).

Use it when:

- you want a manual checkpoint before removal
- you are running the script interactively

### `-Force`

This suppresses confirmation prompts.

Use it when:

- you are running the script in an automated cleanup process
- you have already confirmed the VM names are correct

> `-Force` should be used carefully because the deletion is permanent. It never bypasses `-WhatIf`.

---

## Troubleshooting

| Problem | Likely Cause | What To Do |
|---|---|---|
| You get a warning that the VM was not found | The VM name is wrong, or the VM does not exist on this host | Check the exact VM name in Hyper-V Manager or run `Get-VM` first |
| Nothing is deleted during a test run | You used `-WhatIf` (with or without `-Force`) | This is expected. Remove `-WhatIf` when you are ready to perform the real deletion |
| You get access or permission errors | PowerShell was not started as Administrator, or files are locked | Close other tools using the VM and rerun PowerShell as Administrator |
| The script stops a running VM | The VM must be turned off before removal | This is normal behavior |
| Some files remain on disk | A file may be locked, missing, or protected | Rerun with `-Verbose`, review the messages, and manually inspect the folder if needed |
| You are unsure which VM will be deleted | The command has not been previewed yet | Run the same command with `-WhatIf` first |

---

## Good Practice for Customers

Use this order whenever possible:

1. confirm the VM name in Hyper-V Manager
2. run the script with `-WhatIf`
3. run it again with `-Confirm`
4. use `-Force` only for automation or bulk cleanup when you are already confident in the inputs

---

## Related Documents

- [PAWDeployUI.md](PAWDeployUI.md) — Graphical deployment tool
- [New-PAWVM.md](New-PAWVM.md) — Core deployment engine
- [Install-PAWDeploy.md](Install-PAWDeploy.md) — Initial setup of the solution

---

## Quick Validation Checklist

After running `Remove-PAWVM.ps1`, verify the following:

1. The VM no longer appears in `Get-VM` output.
2. The VM no longer appears in Hyper-V Manager.
3. Attached VHD/VHDX files are removed from storage.
4. The VM configuration folder is removed.
5. `-WhatIf` and `-Confirm` were used for high-risk operations when appropriate.
