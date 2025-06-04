<#
.Synopsis
   VIAHypervModule
.DESCRIPTION
   VIAHypervModule
.EXAMPLE
   Import-Module C:\Setup\Functions\VIAHypervModule.psm1
.NOTES
   http://www.deploymentbunny.com
.COMPONENT
   HYDv10
#>
Function Get-VIAKVPData
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMName
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    #Filter for parsing XML data
    filter Import-CimXml 
    { 
        $CimXml= [Xml]$_ 
        $CimObj=New-Object -TypeName System.Object

        foreach ($CimProperty in $CimXml.SelectNodes("/INSTANCE/PROPERTY")) 
        { 
            $CimObj | Add-Member -MemberType NoteProperty -Name $CimProperty.NAME -Value $CimProperty.VALUE 
        } 
        $CimObj 
    }

    #Get the KVP data
    $Vm = Get-WmiObject -Namespace root\virtualization\v2 -Query "Select * From Msvm_ComputerSystem Where ElementName='$VMName'" -ErrorAction Stop
    $Kvp = Get-WmiObject -Namespace root\virtualization\v2 -Query "Associators of {$Vm} Where AssocClass=Msvm_SystemDevice ResultClass=Msvm_KvpExchangeComponent" -ErrorAction Stop 
    $Kvp.GuestExchangeItems | Import-CimXml
}
Function Test-VIAVMExists
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    If (    ((Get-VM | Where-Object -Property Name -EQ -Value $VMname).Count) -eq "1"){
        Return $true
    }
    else{
        Return $False    
    }
}
Function Test-VIAVMIsRunning
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    if (((Get-VM -Name $VMname).State) -eq "Running"){
        Return $true
    }
    else{
        Return $False    
    }
}
Function Test-VIAVMHaveICLoaded
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )

    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    if (((Get-VM -Name $VMname).Heartbeat) -like "OK*"){
        Return $true
    }
    else{
        Return $False    
    }
}
Function Test-VIAVMHaveIP
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    if ((((Get-VMNetworkAdapter -VMName $VMname).IPAddresses[0]).count) -NE "0"){
        Return $true
    }
    else{
        Return $False    
    }
}
Function Test-VIAVMHavePSDirect
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname,
        $Credentials
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    if((Invoke-Command -VMName $VMName -Credential $Credentials -ErrorAction SilentlyContinue {"Test"}) -ne "Test"){
        Return $false
    }
    Else {
        Return $true    
    }
}
Function Test-VIAVMDeployment
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    If((Get-VIAKVPData -VMName $VMname | Where-Object -Property Name -EQ -Value OSDeployment).Data -eq "Done"){
        Return $True
    }
    else
    {
        Return $False
    }
}
Function Test-VIAVMTaskSequenceDeployment
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    If((Get-VIAKVPData -VMName $VMname | Where-Object -Property Name -EQ -Value TaskSequence).Data -eq "Done"){
        Return $True
    }
    else
    {
        Return $False
    }
}
Function Wait-VIAVMExists
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to exist"
        Start-Sleep -Seconds 2
    }
    until ((Test-VMExists -VMname $VMname) -eq $true)
    Write-Verbose "$VMname exists"
}
Function Wait-VIAVMIsRunning
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname is Running"
        Start-Sleep -Seconds 2
    }
    while ((Test-VIAVMIsRunning -VMname $VMname) -eq $false)
    Write-Verbose "$VMname is running"
}
Function Wait-VIAVMHaveICLoaded
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to load IC's"
         Start-Sleep -Seconds 10
    }
    while ((Test-VIAVMHaveICLoaded -VMname $VMname) -eq $false)
    Write-Verbose "$VMname has IC's loaded"
}
Function Wait-VIAVMHaveIP
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to get some kind of IP"
         Start-Sleep -Seconds 10
    }
    while ((Test-VIAVMIsRunning -VMname $VMname) -eq $false)
    Write-Verbose "$VMname has an IP"
}
Function Wait-VIAVMHavePSDirect
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname,
        $Credentials
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to give me PowerShell Direct access"
        Start-Sleep -Seconds 10
    }
    while ((Test-VIAVMHavePSDirect -VMname $VMname -Credentials $Credentials) -eq $false)
    Write-Verbose "$VMname has PowerShell Direct open"
}
Function Wait-VIAVMDeployment
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to write ""Done"" in the KVP registry"
         Start-Sleep -Seconds 10
    }
    while ((Test-VIAVMDeployment -VMname $VMname) -eq $false)
    Write-Verbose "$VMname has written done in the KVP Registry"
}
Function Wait-VIAVMTaskSequenceDeployment
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    do
    {
        Write-Verbose "Waiting for $VMname to finish TaskSequence in the KVP registry"
         Start-Sleep -Seconds 10
    }
    while ((Test-VIAVMTaskSequenceDeployment -VMname $VMname) -eq $false)
    Write-Verbose "$VMname has written done in the KVP Registry"
}
Function Mount-VIAVHDInFolder
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VHDfile,
        $MountFolder
    )
    $MountVHD = New-Item -Path $MountFolder -ItemType Directory -Force
    $VHD = Mount-DiskImage -ImagePath $VHDfile -NoDriveLetter -PassThru
    $DiskNumber = (Get-DiskImage -ImagePath $VHDfile | Get-Disk)
    if((Get-DiskImage -ImagePath $VHDfile | Get-Disk).PartitionStyle  -eq 'MBR'){
        $PartitionNumber = (Get-DiskImage -ImagePath $VHDfile | Get-Disk | Get-Partition | Where-Object Type -EQ IFS).PartitionNumber
        }
    if((Get-DiskImage -ImagePath $VHDfile | Get-Disk).PartitionStyle  -eq 'GPT'){
        $PartitionNumber = (Get-DiskImage -ImagePath $VHDfile | Get-Disk | Get-Partition | Where-Object Type -EQ Basic).PartitionNumber
        }
    Add-PartitionAccessPath -DiskNumber $DiskNumber.Number -PartitionNumber $PartitionNumber -AccessPath $($MountVHD.FullName)

}
Function Dismount-VIAVHDInFolder
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VHDfile,
        $MountFolder
    )
    Dismount-VHD -Path $VHDfile
    Remove-Item -Path $MountFolder -Force
}
Function Enable-VIANestedHyperV
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VMname
    )
    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

    $VM = Get-VM -Name $VMname
    $VMNic = Get-VMNetworkAdapter -VM $VM
    $VMCPU = Get-VMProcessor -VM $VM

    #Check if VM is saved
    if($VM.State -eq 'Saved'){Write-Warning "$VMname is saved, needs to be off";BREAK}

    #Check if VM has Snapshots
    if($VM.ParentSnapshotName -ne $null){Write-Warning "$VMname has snapshots, remove them";BREAK}
   
    #Check if VM is off
    if($VM.State -ne 'Off'){Write-Warning "$VMname is is not turned off, needs to be off";BREAK}

    #Check VM Configuration Version
    if($VM.Version -lt 7.0){Write-Warning "$VMname is not upgraded, needs to run VM Configuration 7.0";BREAK}

    #Check if VM allows Snapshot
    if($VM.CheckpointType -ne 'Disabled'){Write-Warning "$VMname allow Snapshot, Modifying";Set-VM -VM $VM -CheckpointType Disabled}
    
    #Check if VM has Dynamic Memory Enabled
    if($VM.DynamicMemoryEnabled -eq $true){Write-Warning "$VMname is set for Dynamic Memory, Modifying";Set-VMMemory -VM $VM -DynamicMemoryEnabled $false}

    #Check if VM has more then 4GB of RAM
    if($VM.MemoryStartup -lt 4GB){Write-Warning "$VMname has less then 4 GB of ram assigned, Modifying";Set-VMMemory -VM $VM -StartupBytes 4GB}

    #Check if VM has Mac Spoofing Enabled
    if(($VMNic).MacAddressSpoofing -ne 'On'){Write-Warning "$VMname does not have Mac Address Spoofing enabled, Modifying";Set-VMNetworkAdapter -VM $VM -MacAddressSpoofing on}

    #Check if VM has Expose Virtualization Extensions Enabled
    if(($VMCPU).ExposeVirtualizationExtensions -ne $true){Write-Warning "$VMname is not set to Expose Virtualization Extensions, Modifying";Set-VMProcessor -VM $VM -ExposeVirtualizationExtensions $true}
}
Function Restart-VIAVM
{
    param(
        $VMname
    )

    Foreach($VM in $VMname){
        #Check if VM exists
        if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

        Get-VM -VMName $VM | Stop-VM
        Get-VM -VMName $VM | Start-VM
    }
}
Function Start-VIAVM
{
    param(
        $VMname,
        $domainCred
    )

    Foreach($VM in $VMname){
        #Check if VM exists
        if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   

        Get-VM -VMName $VM | Start-VM
        Wait-VIAVMIsRunning -VMname $VMname
        Wait-VIAVMHaveICLoaded -VMname $VMname
        Wait-VIAVMHaveIP -VMname $VMname
        Wait-VIAVMHavePSDirect -VMname $VMname -Credentials $domainCred
    }
}
Function Copy-VIAVMFile
{
    Param(
        $VMName,
        $SourceFolder
    )
    Foreach($VM in $VMname){
        #Check if VM exists
        if((Test-VIAVMExists -VMname $VMName) -eq $false){Write-Warning "Could find $VMName";break}   
        IF((Test-VIAVMIsRunning -VMname $VMName) -eq $false){Write-Warning "$VMName is not running";break}
        $VMobj = Get-VM -VMName $VM

        #Copy scripts to VM
        $Contents = Get-ChildItem -Path $SourceFolder -Recurse -File *.*
        foreach($Item in $Contents){
            foreach($server in $servers){
                Copy-VMFile -VM $VMobj -SourcePath $Item.Fullname -DestinationPath $Item.Fullname -FileSource Host -CreateFullPath -Force
            }
        }
    }
}
Function New-VIAVM
{
    <#
    .Synopsis
        Script for Deployment Fundamentals Vol 6
    .DESCRIPTION
        Script for Deployment Fundamentals Vol 6
    .EXAMPLE
        C:\Setup\Scripts\CreateNew-VM.ps1 -VMName DF6-DC01 -VMMem 1GB -VMvCPU 2 -VMLocation C:\VMs -DiskMode Empty -EmptyDiskSize 100GB -VMSwitchName Internal -ISO C:\Setup\ISO\HydrationDF6.iso -VMGeneration 2
    .NOTES
        Created:	 2015-12-15
        Version:	 1.0

        Author - Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com

        Author - Johan Arwidmark
        Twitter: @jarwidmark
        Blog   : http://deploymentresearch.com

        Disclaimer:
        This script is provided "AS IS" with no warranties, confers no rights and 
        is not supported by the authors or Deployment Artist.
    .LINK
        http://www.deploymentfundamentals.com
    #>

    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        [Parameter(mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VMName,

        [Parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        #[Int]
        $VMMem = 1GB,

        [Parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]
        $VMvCPU = 1,
    
        [parameter(mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VMLocation,

        [parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VHDFile,

        [parameter(mandatory=$True)]
        [ValidateSet("Copy","Diff","Empty","Attached","None")]
        [String]
        $DiskMode = "Copy",

        [parameter(mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $VMSwitchName,

        [parameter(mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Int]
        $VlanID,

        [parameter(mandatory=$False)]
        [ValidateSet("1","2")]
        [Int]
        $VMGeneration,

        [parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ISO,

        [parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        $EmptyDiskSize,

        [parameter(mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [switch]
        $DynaMem
    )

    #Check if VM exists
    if((Test-VIAVMExists -VMname $VMName) -eq $true){Write-Warning "$VMName already exists";break}   

    #Create VM 
    $VM = New-VM -Name $VMName -MemoryStartupBytes $VMMem -Path $VMLocation -NoVHD -Generation $VMGeneration -ErrorAction Stop
    Remove-VMNetworkAdapter -VM $VM

    if($DynaMem -eq $True){
        Write-Verbose "Configure dynamic memory"
        Set-VMMemory -VM $VM -DynamicMemoryEnabled $True -MaximumBytes $VMMem -MinimumBytes $VMMem -StartupBytes $VMMem
    }else{
        Write-Verbose "Disable dynamic memory"
        Set-VMMemory -VM $VM -DynamicMemoryEnabled $false
    }




    #Add Networkadapter
    if($VMNetWorkType -eq "Legacy" -and $VMGeneration -eq "1")
    {
        Add-VMNetworkAdapter -VM $VM -SwitchName $VMSwitchName -IsLegacy $true
    }
    else
    {
        Add-VMNetworkAdapter -VM $VM -SwitchName $VMSwitchName
    }



    #Set vCPU
    if($VMvCPU -ne "1")
    {
        Set-VMProcessor -Count $VMvCPU -VM $VM
    }

    #Set VLAN
    If($VlanID -ne $NULL)
    {
        Set-VMNetworkAdapterVlan -VlanId $VlanID -Access -VM $VM
    }

    #Add Virtual Disk
    switch ($DiskMode)
    {
        Copy
        {
            $VHD = $VHDFile | Split-Path -Leaf
            New-Item -Path "$VMLocation\$VMName\Virtual Hard Disks\" -ItemType Directory
            Copy-Item $VHDFile -Destination "$VMLocation\$VMName\Virtual Hard Disks\"
            Add-VMHardDiskDrive -VM $VM -Path "$VMLocation\$VMName\Virtual Hard Disks\$VHD"
        }
        Diff
        {
            $VHD = $VHDFile | Split-Path -Leaf
            New-VHD -Path "$VMLocation\$VMName\Virtual Hard Disks\$VHD" -ParentPath $VHDFile -Differencing
            Add-VMHardDiskDrive -VMName $VMName -Path "$VMLocation\$VMName\Virtual Hard Disks\$VHD"
        }
        Empty
        {
            $VHD = $VMName + ".vhdx"
            New-VHD -Path "$VMLocation\$VMName\Virtual Hard Disks\$VHD" -SizeBytes $EmptyDiskSize -Dynamic
            Add-VMHardDiskDrive -VMName $VMName -Path "$VMLocation\$VMName\Virtual Hard Disks\$VHD"
        }
        Attached
        {
            New-Item "$VMLocation\$VMName\Virtual Hard Disks" -ItemType directory -Force | Out-Null
            Add-VMHardDiskDrive -VM $VM -Path $VHDFile
        }
        None
        {
        }
        Default
        {
            Write-Error "Epic Failure"
            throw
        }
    }

    #Add DVD for Gen2
    if($VMGeneration -ne "1")
    {
        Add-VMDvdDrive -VMName $VMName
    }

    #Mount ISO
    if($ISO -ne '')
    {
        Set-VMDvdDrive -VMName $VMName -Path $ISO
    }

    #Set Correct Bootorder for Gen 2
    if($VMGeneration -ne "1")
    {
        $VMDvdDrive = Get-VMDvdDrive -VMName $VMName
        $VMHardDiskDrive = Get-VMHardDiskDrive -VM $VM
        $VMNetworkAdapter = Get-VMNetworkAdapter -VMName $VMName
        Set-VMFirmware -VM $VM -BootOrder $VMDvdDrive,$VMHardDiskDrive,$VMNetworkAdapter
    }
    Return (Get-VM -Id $vm.id)
}
Function Remove-VIAVM
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param
    (
        [parameter(mandatory=$True,ValueFromPipelineByPropertyName=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        $VMName
    )

    foreach($Item in $VMName){
        $Items = Get-VM -Name $Item -ErrorAction SilentlyContinue
        If($Items.count -eq "0"){Break}
        foreach($Item in $Items){
            Write-Verbose "Working on $Item"
            if($((Get-VM -Id $Item.Id).State) -eq "Running"){
                Write-Verbose "Stopping $Item"
                Get-VM -Id $Item.Id | Stop-VM -Force -TurnOff
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
    }
}
Function New-VIAVMHarddrive
{
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param
    (
        [parameter(position=0,mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        #[ValidateRange(20GB-500GB)]
        $VMname,

        [parameter(position=1,mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        #[ValidateRange(1-10)]
        $NoOfDisks,

        [parameter(position=2,mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        #[ValidateRange(20GB-500GB)]
        $DiskSize
    )

    Foreach($DataDiskNo in (1..$NoOfDisks)){
        $DataDiskPath = (Get-VM -Name $VMname).path + "\Virtual Hard Disks"
        $DataDiskName = "$VMname-DataDisk_$DataDiskNo" + ".vhdx"
        Write-Verbose "Add Datadisk if needed"
        Write-Verbose "Check if the darn disk already exist..."
        $DiskCheck =Test-Path ($DataDiskPath+"\"+$DataDiskName)
        if($DiskCheck -eq $false){
            Write-Verbose ($DataDiskPath+"\"+$DataDiskName)
            $DataDiskToAdd = New-VHD -Path ($DataDiskPath+"\"+$DataDiskName) -Dynamic -SizeBytes $DiskSize -ErrorAction Stop
            Add-VMHardDiskDrive -Path $DataDiskToAdd.Path -VMName $VMname -ErrorAction Stop
        }
        else
        {
            Write-warning "Woops, disk is already created"
        }
    }
}
Function Test-VIAVMSwitchexistence
{
    Param(
        [string]$VMSwitchname
    )
        $Item = (Get-VMSwitch | Where-Object -Property Name -EQ -Value $VMSwitchname).count
        If($Item -eq '1'){Return $true}else{Return $false}
}
Function Get-VIADisconnectedVHDs
{
    <#
    .Synopsis
        Script used find .VHD files that are not connected to VM's
    .DESCRIPTION
        Created: 2016-11-07
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Get-Get-VIADisconnectedVHDs
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    
    Param(
    [string]$Folder
    )

    if((Test-Path -Path $Folder) -ne $true){
        Write-Warning "I'm sorry, that folder does not exist"
        Break
    }

    #Get the disk used by a VM
    $VMs = (Get-VM | Where-Object -Property ParentSnapshotName -EQ -Value $null).VMId

    if(($VMs.count) -eq '0'){
        Write-Information "Sorry, could not find any VM's"
        Break
    }
    $VHDsActive = foreach($VMsID in $VMs){
        Get-VMHardDiskDrive -VM (Get-VM -Id $VMsID)
    }

    #Get the disk in the folder
    $VHDsAll = Get-ChildItem -Path $Folder -Filter *.vhd* -Recurse
    if(($VHDsAll.count) -eq '0'){
        Write-Information "Sorry, could not find any VHD's in $folder"
        Break
    }

    $obj = Compare-Object -ReferenceObject $VHDsActive.Path -DifferenceObject $VHDsAll.FullName

    #Compare and give back the list of .vhd's that are not connected
    Return ($obj | Where-Object -Property SideIndicator -EQ -Value =>).InputObject
}
Function Get-VIAActiveDiffDisk
{
    <#
    .Synopsis
        Script used to Deploy and Configure Fabric
    .DESCRIPTION
        Created: 2016-11-07
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Get-VIAActiveDiffDisk
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
    )

    $VMHardDiskDrives = Get-VMHardDiskDrive -VM (Get-VM)
    $ActiveDisks = foreach($VMHardDiskDrive in $VMHardDiskDrives){
        $Diffs = Get-VHD -Path $VMHardDiskDrive.Path | Where-Object -Property VhdType -EQ -Value Differencing
        $Diffs.ParentPath
    }
    $ActiveDisks | Sort-Object | Select-Object -Unique
}
Function Wait-VIAVMRestart
{
    <#
    .Synopsis
        Script used to Deploy and Configure Fabric
    .DESCRIPTION
        Created: 2016-11-07
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Wait-VIAVMRestart -VMName FAADDS01 -Credentials $Credentials
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    $VMname,
    $Credentials
    )
    Restart-VIAVM -VMname $VMname
    Wait-VIAVMIsRunning -VMname $VMname
    Wait-VIAVMHaveICLoaded -VMname $VMname
    Wait-VIAVMHaveIP -VMname $VMname
    Wait-VIAVMHavePSDirect -VMname $VMname -Credentials $Credentials
}
Function Wait-VIAVMStart
{
    <#
    .Synopsis
        Script used to Deploy and Configure Fabric
    .DESCRIPTION
        Created: 2016-11-07
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Wait-VIAVMStart -VMName FAADDS01 -Credentials $Credentials
    #>    
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        $VMname,
        $Credentials
    )
    Start-VM -VMname $VMname
    Wait-VIAVMIsRunning -VMname $VMname
    Wait-VIAVMHaveICLoaded -VMname $VMname
    Wait-VIAVMHaveIP -VMname $VMname
    Wait-VIAVMHavePSDirect -VMname $VMname -Credentials $Credentials
}
Function Wait-VIAVMADDSReady
{
    <#
    .Synopsis
        Script used to Deploy and Configure Fabric
    .DESCRIPTION
        Created: 2016-12-14
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Wait-VIAVMADDSReady -VMName FAADDS01 -Credentials $Credentials
    #>    

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    $VMname,
    $Credentials
    )

    #Check that ADDS is up and running
    do{
    $result = Invoke-Command -VMName $VMname -ScriptBlock {
            Test-Path -Path \\$env:computername\NETLOGON
        } -Credential $Credentials
        Write-Verbose "Waiting for Domain Controller to be operational..."
        Start-Sleep -Seconds 30
    }until($result -eq $true)
    Write-Verbose "Waiting for Domain Controller is now operational..."
}
Function Enable-VIAVMDeviceNaming
{
    <#
    .Synopsis
        Script used to Deploy and Configure Fabric
    .DESCRIPTION
        Created: 2016-12-14
        Version: 1.0
        Author : Mikael Nystrom
        Twitter: @mikael_nystrom
        Blog   : http://deploymentbunny.com
        Disclaimer: This script is provided "AS IS" with no warranties.
    .EXAMPLE
        Wait-VIAVMADDSReady -VMName FAADDS01 -Credentials $Credentials
    #>    

    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        $VMName
    )

    Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapter -DeviceNaming On
}
