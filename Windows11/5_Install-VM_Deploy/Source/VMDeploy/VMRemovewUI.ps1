<# This form was created using POSHGUI.com  a free online gui designer for PowerShell
.NAME
    Untitled
#>


$DLL = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
Add-Type -MemberDefinition $DLL -name NativeMethods -namespace Win32
#Get-Process PowerShell | Select MainWindowTitle
$Process = (Get-Process PowerShell | Where-Object MainWindowTitle -like '*VM Remove UI*').MainWindowHandle
# Minimize window
[Win32.NativeMethods]::ShowWindowAsync($Process, 2)

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

#Get Env:
$RootFolder = $MyInvocation.MyCommand.Path | Split-Path -Parent

$Font = 'Consolas,10'

#region begin GUI{ 

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '600,400'
$Form.text                       = "Form"
$Form.TopMost                    = $false
$Form.Text                       = "Virtual Machine remover tool"
$Form.StartPosition              = "CenterScreen"

$Close                           = New-Object system.Windows.Forms.Button
$Close.text                      = "Close"
$Close.width                     = 90
$Close.height                    = 30
$Close.location                  = New-Object System.Drawing.Point(480,350)
$Close.Font                      = $Font

$Update                          = New-Object system.Windows.Forms.Button
$Update.text                     = "Refresh"
$Update.width                    = 90
$Update.height                   = 30
$Update.location                 = New-Object System.Drawing.Point(320,130)
$Update.Font                     = $Font

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Select virtual machine(s)"
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(20,100)
$Label2.Font                     = $Font

$ListBox1                        = New-Object system.Windows.Forms.ListBox
$ListBox1.text                   = "listBox"
$ListBox1.width                  = 290
$ListBox1.height                 = 200
$ListBox1.location               = New-Object System.Drawing.Point(20,130)
$ListBox1.SelectionMode          = "MultiExtended"

$Delete                          = New-Object system.Windows.Forms.Button
$Delete.text                     = "Delete"
$Delete.width                    = 90
$Delete.height                   = 30
$Delete.location                 = New-Object System.Drawing.Point(320,300)
$Delete.Font                     = $Font

$PictureBox1                     = New-Object system.Windows.Forms.PictureBox
$PictureBox1.width               = 150
$PictureBox1.height              = 150
$PictureBox1.location            = New-Object System.Drawing.Point(420,0)
$PictureBox1.imageLocation       = "$RootFolder\image.png"
$PictureBox1.SizeMode            = [System.Windows.Forms.PictureBoxSizeMode]::zoom
$Form.controls.AddRange(@($Close,$Update,$Label2,$ListBox1,$Delete,$PictureBox1))

#region gui events {
$Update.Add_Click({ Update-TSxUI })
$Close.Add_Click({ Close-TSxUI })
$Delete.Add_Click({ Delete-TSxUI })
#endregion events }

#endregion GUI }

Function Remove-TSxVM{
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param
    (
        [parameter(mandatory=$True,ValueFromPipelineByPropertyName=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        $VMName
    )

    $Item = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    If($Item.count -eq "0"){
        Break
    }
        
    Write-Host "Working on $VMName"
    $Item = Get-VM -Name $VMName -ErrorAction SilentlyContinue

    if($Item.State -eq "Running"){
        Write-Host "Stopping $VMName"
        Get-VM -Id $Item.Id | Stop-VM -Force -TurnOff
    }
            
    If((Get-VM -Name $VMName | Get-VMSnapshot).count -ne 0){
        Write-Host "$vmname does have snapshots, restoring and removing..."
        Get-VMSnapshot -VMName $VMName | Where-Object ParentCheckpointName -EQ $null| Restore-VMSnapshot -Confirm:$false
        Remove-VMSnapshot -VMName $VMName
        do{Start-Sleep -Seconds 1}
        until((Get-VM -Name $VMName | Get-VMSnapshot).count -eq 0)
    }

    $Disks = Get-VMHardDiskDrive -VM $Item
    foreach ($Disk in $Disks){
        Write-Verbose "Removing $($Disk.Path)"
        Remove-Item -Path $Disk.Path -Force -ErrorAction Continue
    }
    $ItemLoc = (Get-VM -Id $Item.id).ConfigurationLocation
    Write-Verbose "Removing $item"
    Get-VM -Id $item.Id | Remove-VM -Force
    Write-Verbose "Removing $ItemLoc"
    Remove-Item -Path $Itemloc -Recurse -Force
}
Function Update-TSxUI{
    $VMs = Get-VM | Sort-Object

    $ListBox1.Items.Clear()
    foreach($VM in $VMs){
        [void] $Listbox1.Items.Add($VM.name)
        
    }
}
Function Close-TSxUI{
    $Form.close()
}
Function Delete-TSxUI{
    $SelectedItems = $ListBox1.SelectedItems
    foreach($SelectedItem in $SelectedItems){
        Write-Host "Deleting $SelectedItem"
        Remove-TSxVM -VMName $SelectedItem
    }
    Update-TSxUI
}

Update-TSxUI

[void]$Form.ShowDialog()
