[cmdletbinding(SupportsShouldProcess=$true)]
Param
(
    [parameter(Position=1,mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $VMname,

    [parameter(Position=2,mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Template,

    [parameter(Position=3,mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $RootFolder="NA",

    [parameter(Position=4,mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $VMLocation="C:\VMs",

    [parameter(Position=5,mandatory=$False)]
    [String]
    $OSDAdapter0IPAddressList = "DHCP",

    [parameter(Position=6,mandatory=$False)]
    [String]
    $OSDAdapter0Gateways,

    [parameter(Position=7,mandatory=$False)]
    [String]
    $OSDAdapter0DNS1,

    [parameter(Position=8,mandatory=$False)]
    [String]
    $OSDAdapter0DNS2,

    [parameter(Position=9,mandatory=$False)]
    [String]
    $OSDAdapter0SubnetMaskPrefix,

    [parameter(Position=10,mandatory=$False)]
    [String]
    $AdminPassword,

    [parameter(Position=11,mandatory=$False)]
    [String]
    $DomainAdmin,

    [parameter(Position=12,mandatory=$False)]
    [String]
    $DomainAdminPassword,

    [parameter(Position=13,mandatory=$False)]
    [String]
    $VlanID = '0',

    [parameter(Position=13,mandatory=$False)]
    [Switch]
    $DataFromFile
)

if($RootFolder -eq "NA"){
    $RootFolder = $MyInvocation.MyCommand.Path | Split-Path -Parent 
}

Function New-TSxShortCut{
    Param    (
        $SoruceFile,
        $DestinationFile,
        $Arguments,
        $IconDLL = "NA",
        [switch]$RunAsAdmin
    )

    $WshShell = New-Object -ComObject WScript.Shell
    $ShortCut = $WshShell.CreateShortcut($DestinationFile)
    $ShortCut.TargetPath = $SoruceFile
    $ShortCut.Arguments = $Arguments
    

    if($IconDLL -ne "NA"){
            $ShortCut.IconLocation = $IconDLL
    }
    $ShortCut.Save()

    if($RunAsAdmin){
        $bytes = [System.IO.File]::ReadAllBytes("$($ShortCut.FullName)")
        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes("$($ShortCut.FullName)", $bytes)
    }
}

Start-Transcript -Path "$RootFolder\VMDeploy.log" -Append

#Get LData
$XMLLDatafile = "$RootFolder\lConfig.XML"
[XML]$XMLLData = Get-Content -Path $XMLLDatafile

switch ($XMLLData.Settings.Source)
{
    'local' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = Get-Content -Path "$RootFolder\$XMLDatafile"
    }
    'http' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = (New-Object System.Net.WebClient).DownloadString($XMLDatafile)
    }
    'unc' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = (New-Object System.Net.WebClient).DownloadString($XMLDatafile)
    }
    Default {}
}

$MountFolder = "$RootFolder\Mount"

$CustomerData = $XMLData.Settings.CustomerData
$TemplateData = $XMLData.Settings.Templates.Template | Where-Object Name -EQ $Template

$OrgName = $CustomerData.OrgName
$Fullname = $CustomerData.FullName

$Generation = $TemplateData.VMGen
$DomainOrWorkGroup = $TemplateData.DomainOrWorkGroup
$VMMemoryInMB = $TemplateData.Memory
$VMMemoryLowInMB = $TemplateData.MemoryLow
$VMMemoryHighInMB = $TemplateData.MemoryHigh
$VHDFile = $TemplateData.VHDFile
$NoCPU = $TemplateData.NoCPU
$TimeZoneName = $TemplateData.TimeZoneName
$DNSDomain = $TemplateData.DNSDomain
$DiskMode = $TemplateData.DiskMode
$MachineObjectOU = $TemplateData.MachineObjectOU
$OSClass = $TemplateData.OSClass
$OS = $TemplateData.OS
$VMSwitchName = $TemplateData.VMSwitch
$DomainAdminDomain = $TemplateData.DNSDomain

if($OSDAdapter0IPAddressList -eq 'DHCP'){
    $OSDAdapter0Gateways = 'DHCP'
    $OSDAdapter0DNS1 = 'DHCP'
    $OSDAdapter0DNS2 = 'DHCP'
    $OSDAdapter0SubnetMaskPrefix = 'DHCP'
}

#Default setting for verbose
$Global:VerbosePreference = "SilentlyContinue"

#Import-Modules
Import-Module -Global $rootFolder\Functions\VIAHypervModule.psm1 -ErrorAction Stop -Force
Import-Module -Global $rootFolder\Functions\VIAUtilityModule.psm1 -ErrorAction Stop -Force
Import-Module -Global $rootFolder\Functions\VIADeployModule.psm1 -ErrorAction Stop -Force

#Enable verbose for testing
$Global:VerbosePreference = "Continue"

$VIASetupCompletecmdCommand = "cmd.exe /c PowerShell.exe -Command New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest' -Name OSDeployment -Value Done -PropertyType String"

### End Init ###

# Check if $CredFromFile in use
if($DataFromFile){
    $clixmldata = Import-Clixml -Path "$env:TEMP\vmdeploy.xml"
    foreach($item in $clixmldata.GetEnumerator()){
        New-Variable -Name $item.Name -Value $item.Value -Force
    }
    Remove-Item -Path "$env:TEMP\vmdeploy.xml" -Force
}

# Check if the VM exists
Write-Verbose "Check if VM already exist"
If ((Test-VIAVMExists -VMname $VMName) -eq $true){
    Write-Warning "$VMName already exist"
    Start-Sleep -Seconds 5
    Exit 1
}
else{
    Write-Verbose "$VMname does not exist, continue"
}

# Check if the Switch exists
Write-Verbose "Check if switch $VMSwitchName exist"
If (!((Get-VMSwitch | Where-Object Name -EQ $VMSwitchName).count -eq 1)){
    Write-Warning "Switch $VMSwitchName does not exist"
    Start-Sleep -Seconds 5
    Exit 1
}
else{
    Write-Verbose "Switch $VMSwitchName exist"
}


#Download the VHDx
Write-Verbose "Creating folders"
$result = New-Item -Path "$VMlocation\$VMName" -ItemType Directory -Force
$result = New-Item -Path "$VMlocation\$VMName\Virtual Hard Disks" -ItemType Directory  -Force

if($VHDFile -ne 'NA'){
    Write-Verbose "Loading the webclient"
    $wc = New-Object System.Net.WebClient
    Write-Verbose "Download from from $VHDFile"
    Write-Verbose "Download to $VMlocation\$VMName\Virtual Hard Disks\$($VHDFile | Split-Path -Leaf)"
    Write-Verbose "This will take time...Take a break..."
    $wc.DownloadFile($VHDFile, "$VMlocation\$VMName\Virtual Hard Disks\$($VHDFile | Split-Path -Leaf)")
}

if($VHDFile -ne 'NA'){
    if((Test-Path -Path "$VMlocation\$VMName\Virtual Hard Disks\$($VHDFile | Split-Path -Leaf)") -ne $true){
        Write-Warning "Could not find the file $VMlocation\$VMName\Virtual Hard Disks\$($VHDFile | Split-Path -Leaf), sorry, but the file transfer was not sucessful"
        Start-Sleep -Seconds 5
        EXIT
    }
}

if($VHDFile -ne 'NA'){
    Write-Verbose "Creating $VMName"
    $VM = New-VIAVM -VMName $VMName -VMMem ([int]$VMMemoryInMB * 1024 * 1024) -VMvCPU $NoCPU -VMLocation $VMlocation -VHDFile "$VMlocation\$VMName\Virtual Hard Disks\$($VHDFile | Split-Path -Leaf)" -DiskMode $DiskMode -VMSwitchName $VMSwitchName -VMGeneration $Generation -Verbose -DynaMem
}
else{
    Write-Verbose "Creating $VMName"
    $VM = New-VIAVM -VMName $VMName -VMMem ([int]$VMMemoryInMB * 1024 * 1024) -VMvCPU $NoCPU -VMLocation $VMlocation -DiskMode $DiskMode -VMSwitchName $VMSwitchName -VMGeneration $Generation -Verbose -DynaMem -EmptyDiskSize 120GB
}

Write-Verbose "Check if exist"
If ((Test-VIAVMExists -VMname $VMName) -eq $False){
    Write-Warning "$VMName does not exist"
    Start-Sleep -Seconds 5
    Exit 1
}


if($VHDFile -ne 'NA'){
    #Create unattend xml
    switch ($OSClass){
        'Client'{
            if($OS -eq 'W7'){
                $VIAUnattendXML = New-VIAUnattendXMLClientForW7 -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $DomainOrWorkGroup -ProtectYourPC 3 -Verbose -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $OrgName -Fullname $Fullname -TimeZoneName $TimeZoneName -DNSDomain $DNSDomain -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $DomainAdminDomain -MachineObjectOU $MachineObjectOU -AdminPassword $AdminPassword
            }
            else{
                $VIAUnattendXML = New-VIAUnattendXMLClientfor1709 -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $DomainOrWorkGroup -ProtectYourPC 3 -Verbose -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $OrgName -Fullname $Fullname -TimeZoneName $TimeZoneName -DNSDomain $DNSDomain -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $DomainAdminDomain -MachineObjectOU $MachineObjectOU -AdminPassword $AdminPassword
            }
        }
        'Server'{
            $VIAUnattendXML = New-VIAUnattendXML -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $DomainOrWorkGroup -ProtectYourPC 3 -Verbose -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1  -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $OrgName -Fullname $Fullname -TimeZoneName $TimeZoneName -DNSDomain $DNSDomain -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $DomainAdminDomain -MachineObjectOU $MachineObjectOU -AdminPassword $AdminPassword
        }
        Default{
            $VIAUnattendXML = New-VIAUnattendXMLClientfor1709 -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $DomainOrWorkGroup -ProtectYourPC 3 -Verbose -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $OrgName -Fullname $Fullname -TimeZoneName $TimeZoneName -DNSDomain $DNSDomain -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $DomainAdminDomain -MachineObjectOU $MachineObjectOU -AdminPassword $AdminPassword
        }
    }

    $VIASetupCompletecmd = New-VIASetupCompleteCMD -Command $VIASetupCompletecmdCommand
    $VMVHDFile = (Get-VMHardDiskDrive -VMName $VMName)
    If((Test-Path -Path $MountFolder) -eq $true){Remove-Item -Path $MountFolder -Force -Recurse}
    Mount-VIAVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder
    New-Item -Path "$MountFolder\Windows\Panther" -ItemType Directory -Force | Out-Null
    New-Item -Path "$MountFolder\Windows\Setup" -ItemType Directory -Force | Out-Null
    New-Item -Path "$MountFolder\Windows\Setup\Scripts" -ItemType Directory -Force | Out-Null
    Copy-Item -Path $VIAUnattendXML.FullName -Destination "$MountFolder\Windows\Panther\$($VIAUnattendXML.Name)" -Force
    Copy-Item -Path $VIASetupCompletecmd.FullName -Destination "$MountFolder\Windows\Setup\Scripts\$($VIASetupCompletecmd.Name)" -Force

    # Check if SECBL is on the C drive
    if((Test-Path -Path C:\SECBL) -eq $true){
        & robocopy.exe "C:\SECBL" "$MountFolder\SECBL" /e /s
    }

    Dismount-VIAVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder
    Remove-Item -Path $VIAUnattendXML.FullName
    Remove-Item -Path $VIASetupCompletecmd.FullName
}

#Set VLANid for NIC01
if($VLanID -ne '0'){
    Write-Verbose "Setting VLAN $VLanID"
    Set-VMNetworkAdapterVlan -VMName $VMName -VlanId $VLanID -Access
}

#Adjust memory
#Set-VMMemory -VMName $VMname -StartupBytes ([int]$VMMemoryInMB * 1024 * 1024) -MinimumBytes ([int]$VMMemoryLowInMB * 1024 * 1024) -MaximumBytes ([int]$VMMemoryHighInMB * 1024 * 1024)
Set-VMMemory -VMName $VMname -DynamicMemoryEnabled $false -StartupBytes ([int]$VMMemoryInMB * 1024 * 1024)


# Configure VM
$Action = "Configure VM"
Write-Verbose "$Action"

# Disable AutomaticCheckpointsEnabled
Write-Verbose "Disable AutomaticCheckpointsEnabled"
Get-VM -Name $VMname | Set-VM -AutomaticCheckpointsEnabled 0 -ErrorAction SilentlyContinue -Verbose

# Set BatteryPassthroughEnabled
Write-Verbose "Set BatteryPassthroughEnabled"
Get-VM -Name $VMname | Set-VM -BatteryPassthroughEnabled $true -Verbose

# Create VM Protector for the VM and enable TPM
Write-Verbose "Create VM Protector for the VM and enable TPM"
Set-VMKeyProtector -VMName $VMname -NewLocalKeyProtector -Verbose
Get-VM -Name $VMname | Enable-VMTPM -Verbose

#Deploy VM
$Action = "Deploy VM"
Start-VM -VMname $VMname
Wait-VIAVMIsRunning -VMname $VMname
if($VHDFile -ne 'NA'){
    # Generate credentials for the VM
    Write-Verbose "Generate credentials for the VM"
    $SecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ".\Administrator",$SecurePassword

    # Wait for the VM to start
    Write-Verbose "Wait for the VM to start"
    Wait-VIAVMHaveICLoaded -VMname $VMname
    Wait-VIAVMHaveIP -VMname $VMname
    Wait-VIAVMDeployment -VMname $VMName
    Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred

    # Connect and enable bitlocker
    Write-Verbose "Connect and enable bitlocker"
    $ScriptBlock = {
        Initialize-Tpm -AllowClear
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TPMProtector -UsedSpaceOnly
    }
    Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred

    # Restart the VM
    Write-Verbose "Restarting VM"
    Stop-VM -Name $VMname
    Start-VM -Name $VMname
    Wait-VIAVMHaveICLoaded -VMname $VMname
    Wait-VIAVMHaveIP -VMname $VMname
    Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred

    # Connect and enable bitlocker
    Write-Verbose "Connect and enable bitlocker"
    $ScriptBlock = {
        do{
            Get-BitLockerVolume -MountPoint "C:" | Select-Object EncryptionPercentage
            Start-Sleep -Seconds 15
        }
        until ((Get-BitLockerVolume -MountPoint c:).volumestatus -eq "FullyEncrypted")
    }
    Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred

    # Create a short cut for the VM
    New-Item -Path "$env:ALLUSERSPROFILE\Desktop\VMLinks" -Type Directory -Force
    $linkName = "Connect to " + $VMName + ".lnk"
    New-TSxShortCut -SoruceFile vmconnect.exe -DestinationFile "$env:ALLUSERSPROFILE\Desktop\VMLinks\$LinkName" -Arguments "localhost $VMName" -IconDLL "$env:ProgramFiles\hyper-v\snapinabout.dll" -RunAsAdmin

    # Restart the VM
    Write-Verbose "Restarting VM"
    Stop-VM -Name $VMname
    Get-VM -Name $VMname | Set-VMSecurityPolicy -Shielded $true -Verbose
    Start-VM -Name $VMname
    Wait-VIAVMHaveICLoaded -VMname $VMname
    Wait-VIAVMHaveIP -VMname $VMname
    Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred

    if((Test-Path -Path C:\SECBL) -eq $true){
        $ScriptBlock = {
            switch ($DomainOrWorkGroup)
            {
                'Domain' {
                    PowerShell -ExecutionPolicy Bypass -File C:\SECBL\Local_Script\BaselineLocalInstall.ps1 -Win10DomainJoined
                }
                'Workgroup'{
                    PowerShell -ExecutionPolicy Bypass -File C:\SECBL\Local_Script\BaselineLocalInstall.ps1 -Win10NonDomainJoined
                }
                Default {
                }
            }
        }
        Invoke-Command -VMName $VMname -Credential $Cred -ScriptBlock $ScriptBlock
    }

    Stop-VM -Name $VMname
}

Stop-Transcript