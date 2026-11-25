<#
.SYNOPSIS
Removes one or more Hyper-V virtual machines and their associated virtual hard disk files.

.DESCRIPTION
For each specified VM name, stops any running virtual machine, removes and merges
its checkpoints, re-reads the attached disk paths, removes the virtual machine from
Hyper-V, and deletes the attached virtual hard disk files and configuration folder.
Checkpoint removal must succeed before the VM and its files are deleted.
By default, only VMs containing the literal marker ###PAW42### in Notes are eligible.
Use -ShowAll to include unmarked VMs in the same removal workflow.
Use -List to inspect eligible VMs without removing them. State, disk mode,
configuration location and Hyper-V creation time are included.

This operation is irreversible. All virtual hard disk files and configuration data
are permanently deleted.

Use -WhatIf to preview what would be removed without making any changes.
Use -Confirm to be prompted before each virtual machine is removed.
Use -Force to suppress confirmation prompts for scripted or unattended use. It never bypasses -WhatIf.

.PARAMETER VMName
One or more virtual machine names to remove.

.PARAMETER Force
Suppresses the confirmation prompt without bypassing -WhatIf. Use with caution â€” all data will be permanently deleted.

.PARAMETER List
Lists eligible VMs and their details without removal. VMName optionally filters names.

.PARAMETER ShowAll
Includes VMs without the PAW Notes marker in listing, completion and removal.
Does not select any VMs for removal; VMName is still required unless using List.

.EXAMPLE
.\Tools\Remove-PAWVM.ps1 -List | Format-Table -AutoSize -Wrap

Lists marked VMs with state, disk mode, location and creation date without removal.

.EXAMPLE
.\Tools\Remove-PAWVM.ps1 -List -ShowAll | Format-Table -AutoSize -Wrap

Lists all Hyper-V VMs on this host without removal.

.EXAMPLE
.\Tools\Remove-PAWVM.ps1 -VMName "PAW-Client01" -WhatIf

Shows what would be removed without making any changes.

.EXAMPLE
.\Tools\Remove-PAWVM.ps1 -VMName "PAW-Client01"

Removes the virtual machine named PAW-Client01, its virtual hard disk files, and
its configuration folder. Prompts for confirmation before proceeding.

.EXAMPLE
.\Tools\Remove-PAWVM.ps1 -VMName "PAW-Client01", "PAW-Client02" -Force

Removes multiple virtual machines and their associated files without prompting.

.NOTES
    Version : 2.0.0.6
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+, Hyper-V module, elevated local Administrator privileges.
    Safety  : Supports -WhatIf, -Confirm, and -Force for controlled deletion workflows.
    Log file: %TEMP%\PAWDeploy\Remove-PAWVM.log.
#>
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Remove')]
Param(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0, ParameterSetName = 'Remove')]
    [Parameter(Position = 0, ParameterSetName = 'List')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
        $includeUnmarked = $FakeBoundParameters -and $FakeBoundParameters['ShowAll']
        Get-VM -ErrorAction Stop |
            Where-Object { ($includeUnmarked -or ([string]$_.Notes).Contains('###PAW42###')) -and $_.Name -like "$WordToComplete*" } |
            Sort-Object Name | ForEach-Object {
                [Management.Automation.CompletionResult]::new(
                    ("'{0}'" -f $_.Name.Replace("'", "''")), $_.Name, 'ParameterValue', $_.Name)
            }
    })]
    [string[]]
    $VMName,

    [Parameter(Mandatory = $false, ParameterSetName = 'Remove')]
    [switch]
    $Force,

    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch]$List,

    [Parameter()]
    [switch]$ShowAll
)

$PawUtilityManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUtilityManifest"
}
Import-Module -Name $PawUtilityManifest -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

if ($List) {
    $listParameters = @{ ErrorAction = 'Stop' }
    if ($VMName) { $listParameters.Name = $VMName }
    Get-VM @listParameters |
        Where-Object { $ShowAll -or ([string]$_.Notes).Contains('###PAW42###') } |
        Sort-Object Name | Get-PAWVMDetails
    return
}


$LogFolder = Resolve-PAWLogFolder
$LogPath = Join-Path $LogFolder 'Remove-PAWVM.log'
Write-PAWLog -Message ("Starting VM removal for: " + ($VMName -join ', ')) -LogPath $LogPath

if ($Force -and -not $WhatIfPreference) {
    $ConfirmPreference = 'None'
}

foreach ($Name in $VMName) {
    $VMs = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if ($VMs.Count -eq 0) {
        Write-PAWLog -Level 'WARN' -Message "No virtual machine found with name '$Name'. Skipping." -LogPath $LogPath
        Write-Warning "No virtual machine found with name '$Name'. Skipping."
        Continue
    }
    foreach ($VM in $VMs) {
        if (-not $ShowAll -and -not ([string]$VM.Notes).Contains('###PAW42###')) {
            Write-PAWLog -Level 'WARN' -Message "VM '$($VM.Name)' does not contain ###PAW42### in Notes. Skipping." -LogPath $LogPath
            Write-Warning "VM '$($VM.Name)' does not contain ###PAW42### in Notes. Skipping."
            Continue
        }
        Write-Verbose "Working on $($VM.Name)"
        $details = Get-PAWVMDetails -VM $VM
        Write-Host ($details | Format-List Name, State, DiskMode, Location, CreationTime | Out-String)

        $Disks = Get-VMHardDiskDrive -VM $VM
        $ConfigLocation = $VM.ConfigurationLocation

        $DiskSummary = if ($Disks) { ($Disks | Select-Object -ExpandProperty Path) -join ', ' } else { '(none)' }
        $ShouldProcessTarget = "VM: $($VM.Name) | State: $($details.State) | Disk: $($details.DiskMode) | Created: $($details.CreationTime) | VHD(s): $DiskSummary | Config folder: $ConfigLocation"

        if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, 'Remove checkpoints and VM and permanently delete all associated files')) {
            try {
                if ($VM.State -eq 'Running') {
                    Write-Verbose "Stopping $($VM.Name)"
                    Stop-VM -VM $VM -Force -TurnOff -ErrorAction Stop
                }
                $Checkpoints = @(Get-VMSnapshot -VM $VM -ErrorAction Stop)
                if ($Checkpoints.Count -gt 0) {
                    Write-PAWLog -Message "Removing $($Checkpoints.Count) checkpoint(s) for $($VM.Name) and merging virtual disks." -LogPath $LogPath
                    $Checkpoints | Remove-VMSnapshot -Confirm:$false -ErrorAction Stop
                    if (@(Get-VMSnapshot -VM $VM -ErrorAction Stop).Count -gt 0) {
                        throw "Checkpoints remain for $($VM.Name). VM and disk deletion aborted."
                    }
                }
                $Disks = Get-VMHardDiskDrive -VM $VM -ErrorAction Stop
                Write-Verbose "Removing VM $($VM.Name)"
                Remove-VM -VM $VM -Force -ErrorAction Stop
                foreach ($Disk in $Disks) {
                    Write-Verbose "Removing $($Disk.Path)"
                    Remove-Item -LiteralPath $Disk.Path -Force -ErrorAction Continue
                }
                Write-Verbose "Removing configuration folder $ConfigLocation"
                Remove-Item -LiteralPath $ConfigLocation -Recurse -Force
                Write-PAWLog -Message "Removed VM '$($VM.Name)' and its associated files." -LogPath $LogPath
            }
            catch {
                Write-PAWLog -Message "Failed to remove $($VM.Name): $($_.Exception.Message)" -Level 'ERROR' -LogPath $LogPath
                Write-Warning "Removal of '$($VM.Name)' failed. Review '$LogPath' before retrying."
            }
        }
    }
}

Write-PAWLog -Message 'VM removal processing completed.' -LogPath $LogPath