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
    $VMLocation="NA",

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
    $DataFromFile,

    [parameter(Position=14,mandatory=$False)]
    [Switch]
    $ConfigFile
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

# Get Data
$XMLDatafile = "$RootFolder\Config.XML"
[XML]$XMLData = Get-Content -Path "$XMLDatafile"

$MountFolder = "$RootFolder\Mount"
$CustomerData = $XMLData.Settings.CustomerData
$TemplateData = $XMLData.Settings.Templates.Template | Where-Object Name -EQ $Template

if($OSDAdapter0IPAddressList -eq 'DHCP'){
    $OSDAdapter0Gateways = 'DHCP'
    $OSDAdapter0DNS1 = 'DHCP'
    $OSDAdapter0DNS2 = 'DHCP'
    $OSDAdapter0SubnetMaskPrefix = 'DHCP'
}

#Default setting for verbose
#$Global:VerbosePreference = "SilentlyContinue"

#Import-Modules
Import-Module -Global $rootFolder\Functions\VIAHypervModule.psm1 -ErrorAction Stop -Force
Import-Module -Global $rootFolder\Functions\VIAUtilityModule.psm1 -ErrorAction Stop -Force
Import-Module -Global $rootFolder\Functions\VIADeployModule.psm1 -ErrorAction Stop -Force

#Enable verbose for testing
# $Global:VerbosePreference = "Continue"

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
Write-Host -ForegroundColor Green "Check if VM already exist"
If ((Test-VIAVMExists -VMname $VMName) -eq $true){
    Write-Warning "$VMName already exist"
    Exit 1
}
else{
    Write-Host -ForegroundColor Green "$VMname does not exist, continue"
}

# Check if the Switch exists
Write-Host -ForegroundColor Green "Check if switch $($TemplateData.VMSwitch) exist"
If (!((Get-VMSwitch | Where-Object Name -EQ $($TemplateData.VMSwitch)).count -eq 1)){
    Write-Warning "Switch $($TemplateData.VMSwitch) does not exist"
    Exit 1
}
else{
    Write-Host -ForegroundColor Green "Switch $($TemplateData.VMSwitch) exist"
}

# Check VMLocation
if($VMlocation -eq "NA"){
    $VMlocation = $XMLData.Settings.Hyperv.VMLocation
}else{
    $VMlocation = "C:\VMs"
}
Write-Host -ForegroundColor Green "VMLocation is now $VMlocation"

# Creating VM Folder
if(Test-Path -path "$VMlocation\$VMName"){
    Write-Warning "Folder $VMlocation\$VMName already exist"
    Exit 1
}else{
    Write-Host -ForegroundColor Green "Creating folder $VMlocation\$VMName"
    $result = New-Item -Path "$VMlocation\$VMName" -ItemType Directory
}

# Creating VM Harddisk Folder
if(Test-Path -path "$VMlocation\$VMName\Virtual Hard Disks"){
    Write-Warning "Folder $VMlocation\$VMName\Virtual Hard Disks already exist"
    Exit 1
}else{
    $result = New-Item -Path "$VMlocation\$VMName\Virtual Hard Disks" -ItemType Directory
    Write-Host -ForegroundColor Green "Creating folder $($result.FullName)"
}

if(!(Test-Path -Path "$($TemplateData.VHDFile)")){
    Write-Warning "Could not find the file $($TemplateData.VHDFile)"
    EXIT 1
}

Write-Host -ForegroundColor Green "Creating $VMName"
$VM = New-VIAVM -VMName $VMName -VMMem ([int]$TemplateData.Memory * 1024 * 1024) -VMvCPU $TemplateData.NoCPU -VMLocation $VMlocation -DiskMode $($TemplateData.DiskMode) -VMSwitchName $($TemplateData.VMSwitch) -VMGeneration $TemplateData.VMGen -VHDFile $TemplateData.VHDFile

Write-Host -ForegroundColor Green "Check if $($VM.Name) exist"
If ((Test-VIAVMExists -VMname $VMName) -eq $False){
    Write-Warning "$VMName does not exist"
    Start-Sleep -Seconds 5
    Exit 1
}

# Create unattend xml
switch ($TemplateData.OSClass){
    'Client'{
        $VIAUnattendXML = New-VIAUnattendXMLClientfor1709 -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $TemplateData.DomainOrWorkGroup -ProtectYourPC 3 -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $CustomerData.OrgName -Fullname $CustomerData.FullName -TimeZoneName $TemplateData.TimeZoneName -DNSDomain $($TemplateData.DNSDomain) -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $TemplateData.DNSDomain -MachineObjectOU $TemplateData.MachineObjectOU -AdminPassword $AdminPassword
    }
    'Server'{
        $VIAUnattendXML = New-VIAUnattendXML -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $TemplateData.DomainOrWorkGroup -ProtectYourPC 3 -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1  -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $CustomerData.OrgName -Fullname $CustomerData.FullName -TimeZoneName $TemplateData.TimeZoneName -DNSDomain $($TemplateData.DNSDomain) -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $TemplateData.DNSDomain -MachineObjectOU $TemplateData.MachineObjectOU -AdminPassword $AdminPassword
    }
    Default{
        $VIAUnattendXML = New-VIAUnattendXMLClientfor1709 -Computername $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -DomainOrWorkGroup $TemplateData.DomainOrWorkGroup -ProtectYourPC 3 -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -OrgName $CustomerData.OrgName -Fullname $CustomerData.FullName -TimeZoneName $TemplateData.TimeZoneName -DNSDomain $($TemplateData.DNSDomain) -DomainAdmin $DomainAdmin -DomainAdminPassword $DomainAdminPassword -DomainAdminDomain $TemplateData.DNSDomain -MachineObjectOU $TemplateData.MachineObjectOU -AdminPassword $AdminPassword
    }
}
Write-Host -ForegroundColor Green "Created $($VIAUnattendXML.FullName)"

$VIASetupCompletecmdCommand = "cmd.exe /c PowerShell.exe -Command New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest' -Name OSDeployment -Value Done -PropertyType String"
$VIASetupCompletecmd = New-VIASetupCompleteCMD -Command $VIASetupCompletecmdCommand
Write-Host -ForegroundColor Green "Created $($VIASetupCompletecmd.FullName)"

$VMVHDFile = (Get-VMHardDiskDrive -VMName $VMName)
If((Test-Path -Path $MountFolder) -eq $true){
    Remove-Item -Path $MountFolder -Force -Recurse
}
Mount-VIAVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder
Write-Host -ForegroundColor Green "Mounted $($VMVHDFile.Path) in $MountFolder"

if(Test-Path -path "$MountFolder\Windows\Panther"){
    Write-Warning "Folder $MountFolder\Windows\Panther"
    Exit 1
}else{
    $Result = New-Item -Path "$MountFolder\Windows\Panther" -ItemType Directory
    Write-Host -ForegroundColor Green "Folder $($Result.FullName) was created"
}

if(Test-Path -path "$MountFolder\Windows\Setup\Scripts"){
    Write-Warning "Folder $MountFolder\Windows\Setup\Scripts"
    Exit 1
}else{
    $Result = New-Item -Path "$MountFolder\Windows\Setup\Scripts" -ItemType Directory
    Write-Host -ForegroundColor Green "Folder $($Result.FullName) was created"
}

Copy-Item -Path $VIAUnattendXML.FullName -Destination "$MountFolder\Windows\Panther\$($VIAUnattendXML.Name)"
Write-Host -ForegroundColor Green "$($VIAUnattendXML.FullName) was copied to $MountFolder\Windows\Panther\$($VIAUnattendXML.Name)"

Copy-Item -Path $VIASetupCompletecmd.FullName -Destination "$MountFolder\Windows\Setup\Scripts\$($VIASetupCompletecmd.Name)"
Write-Host -ForegroundColor Green "$($VIASetupCompletecmd.FullName) was copied to $MountFolder\Windows\Setup\Scripts\$($VIASetupCompletecmd.Name)"

# Check if SECBL is on the C drive
if((Test-Path -Path $($TemplateData.SecurityBaselineLocation)) -eq $true){
    Write-Host -ForegroundColor Green "Copying Security Baselines"
    Copy-Item -Path "$($TemplateData.SecurityBaselineLocation)" -Destination "$MountFolder\SECBL" -Recurse -Container -Force
}

Write-Host -ForegroundColor Green "Dismounting VHD file"
Dismount-VIAVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder

Write-Host -ForegroundColor Green "Removing $($VIAUnattendXML.FullName)"
Remove-Item -Path $VIAUnattendXML.FullName

Write-Host -ForegroundColor Green "Removing $($VIASetupCompletecmd.FullName)"
Remove-Item -Path $VIASetupCompletecmd.FullName

#Set VLANid for NIC01
if($VLanID -ne '0'){
    Write-Host -ForegroundColor Green "Setting VLAN $VLanID"
    Set-VMNetworkAdapterVlan -VMName $VMName -VlanId $VLanID -Access
}

#Adjust memory
if($TemplateData.DynamicMem -eq "True"){
    Write-Host -ForegroundColor Green "Enable Dynamic Memory"
    Set-VMMemory -VMName $VMname -DynamicMemoryEnabled $True
}

# Disable AutomaticCheckpointsEnabled
if((Get-VM $VMName).AutomaticCheckpointsEnabled -eq $true){
    Write-Host -ForegroundColor Green "Disable AutomaticCheckpointsEnabled"
    Get-VM -Name $VMname | Set-VM -AutomaticCheckpointsEnabled 0 -ErrorAction SilentlyContinue
}


# Set BatteryPassthroughEnabled
Write-Host -ForegroundColor Green "Set BatteryPassthroughEnabled"
Get-VM -Name $VMname | Set-VM -BatteryPassthroughEnabled $true

# Create VM Protector for the VM and enable TPM
Write-Host -ForegroundColor Green "Create VM Protector for the VM and enable TPM"
Set-VMKeyProtector -VMName $VMname -NewLocalKeyProtector
Get-VM -Name $VMname | Enable-VMTPM

#Deploy VM
Write-Host -ForegroundColor Green "Starting $VMname"
Start-VM -VMname $VMname -ErrorAction Inquire
Wait-VIAVMIsRunning -VMname $VMname

# Generate credentials for the VM
Write-Host -ForegroundColor Green "Generate credentials for the VM"
$SecurePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ".\Administrator",$SecurePassword

# Wait for the VM to start
Write-Host -ForegroundColor Green "Wait for the VM to have IC loaded"
Wait-VIAVMHaveICLoaded -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM to have an IP address"
Wait-VIAVMHaveIP -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM to write complete in KVP"
Wait-VIAVMDeployment -VMname $VMName
Write-Host -ForegroundColor Green "Wait for the VM accept PowerShell Direct"
Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred
Write-Host -ForegroundColor Green "Waiting is over, moving on"

# Connect and enable bitlocker
Write-Host -ForegroundColor Green "Connect and enable bitlocker"
$ScriptBlock = {
    Write-Host -ForegroundColor Green "Clearing vTPM"
    $Result = Initialize-Tpm -AllowClear -WarningAction SilentlyContinue

    Write-Host -ForegroundColor Green "Enable Bitlocker"
    $Result = Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TPMProtector -UsedSpaceOnly
}
Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred

# Restart the VM
Write-Host -ForegroundColor Green "Restarting VM"
Stop-VM -Name $VMname
Start-VM -Name $VMname
# Wait for the VM to start
Write-Host -ForegroundColor Green "Wait for the VM to have IC loaded"
Wait-VIAVMHaveICLoaded -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM to have an IP address"
Wait-VIAVMHaveIP -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM accept PowerShell Direct"
Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred
Write-Host -ForegroundColor Green "Waiting is over, moving on"

# Connect and enable bitlocker
Write-Host -ForegroundColor Green "Connect and encrypt disk"
$ScriptBlock = {
    do{
        $EncryptionPercentage = (Get-BitLockerVolume -MountPoint C:).EncryptionPercentage
        Write-Host -ForegroundColor Green "Percentige of disk encryptet: $EncryptionPercentage"
        Start-Sleep -Seconds 15
    }
    until ((Get-BitLockerVolume -MountPoint c:).volumestatus -eq "FullyEncrypted")
}
Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred

# Restart the VM
Write-Host -ForegroundColor Green "Restarting VM"
Stop-VM -Name $VMname
Get-VM -Name $VMname | Set-VMSecurityPolicy -Shielded $true
Start-VM -Name $VMname
# Wait for the VM to start
Write-Host -ForegroundColor Green "Wait for the VM to have IC loaded"
Wait-VIAVMHaveICLoaded -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM to have an IP address"
Wait-VIAVMHaveIP -VMname $VMname
Write-Host -ForegroundColor Green "Wait for the VM accept PowerShell Direct"
Wait-VIAVMHavePSDirect -VMname $VMName -Credentials $Cred
Write-Host -ForegroundColor Green "Waiting is over, moving on"


if($TemplateData.ApplySecurityBaseline -eq "True"){
    Switch ($TemplateData.DomainOrWorkGroup)
    {
        'Domain'{
                    # Running SecurityBaselines
                    $ScriptBlock = {
                        if(Test-Path -Path C:\SECBL){
                            Write-Host -ForegroundColor Green "Running SecurityBaselines"
                            Set-Location -Path C:\SECBL\OS\Scripts
                            PowerShell -ExecutionPolicy Bypass -File .\Baseline-LocalInstall.ps1 -Win11DomainJoined
                            Set-Location -Path C:\SECBL\Edge\Scripts
                            PowerShell -ExecutionPolicy Bypass -File .\Baseline-LocalInstall.ps1
                        }
                    }
                    Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred
                }
        'Workgroup'{
                    # Running SecurityBaselines
                    $ScriptBlock = {
                        if(Test-Path -Path C:\SECBL){
                            Write-Host -ForegroundColor Green "Running SecurityBaselines"
                            Set-Location -Path C:\SECBL\OS\Scripts
                            PowerShell -ExecutionPolicy Bypass -File .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined
                            Set-Location -Path C:\SECBL\Edge\Scripts
                            PowerShell -ExecutionPolicy Bypass -File .\Baseline-LocalInstall.ps1
                        }
                    }
                    Invoke-Command -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred
                }
        Default {
                }
    }
    Invoke-Command -VMName $VMname -Credential $Cred -ScriptBlock $ScriptBlock
}

# Stopping the VM
Write-Host -ForegroundColor Green "Stopping $VMname"
Stop-VM -Name $VMname

# Create the folder to store shortcuts
If((Test-Path -Path "$env:ALLUSERSPROFILE\Desktop\VMLinks") -ne $true){
    Write-Host -ForegroundColor Green "Creating $env:ALLUSERSPROFILE\Desktop\VMLinks"
    New-Item -Path "$env:ALLUSERSPROFILE\Desktop\VMLinks" -Type Directory -Force
}

# Create a short cut for the VM
$linkName = "Connect to " + $VMName + ".lnk"
Write-Host -ForegroundColor Green "Creating a shortcut to $VMName in $env:ALLUSERSPROFILE\Desktop\VMLinks\$LinkName named $linkName"
New-TSxShortCut -SoruceFile vmconnect.exe -DestinationFile "$env:ALLUSERSPROFILE\Desktop\VMLinks\$LinkName" -Arguments "localhost $VMName" -IconDLL "$env:ProgramFiles\hyper-v\snapinabout.dll" -RunAsAdmin

# Stop logging
Write-Host -ForegroundColor Green "Stop Transcript logging"
Stop-Transcript