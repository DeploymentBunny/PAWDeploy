<#
.SYNOPSIS
    Baseconfig for W10
.DESCRIPTION
    Baseconfig for W10
.EXAMPLE
    Baseconfig for W10
.NOTES
        ScriptName: Baseconfig for W10.ps1
        Author:     Mikael Nystrom
        Twitter:    @mikael_nystrom
        Email:      mikael.nystrom@truesec.se
        Blog:       https://deploymentbunny.com

    Version History
    1.0.0 - Script created [01/16/2019 13:12:16]

Copyright (c) 2019 Mikael Nystrom

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>

[cmdletbinding(SupportsShouldProcess=$True)]
Param(
)

# Set Vars
$VerbosePreference = "continue"
$writetoscreen = $true
$osv = ''
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path
$ARCHITECTURE = $env:PROCESSOR_ARCHITECTURE

#Import TSxUtility

try
{
    $tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
    $Logpath = $tsenv.Value("LogPath")
    $LogFile = $Logpath + "\" + "$ScriptName.log"
    $DeployRoot = $tsenv.Value("DeployRoot")
    $TSMake = $tsenv.Value("Make")
    $TSModel = $tsenv.Value("Model")
    $TSServerCoreOS = $tsenv.Value("IsServerCoreOS")
}
catch
{
    Write-Warning "COMObject Microsoft.SMS.TSEnvironment could not be imported"
    $Logpath = $env:TEMP
    $LogFile = $Logpath + "\" + "$ScriptName.log"
    Write-Verbose "Logfile is now $LogFile"
    $Deployroot = $ScriptDir | Split-Path -Parent | Split-Path -Parent
    $TSMake = (Get-WmiObject -Class win32_computersystem).Manufacturer
    $TSModel = (Get-WmiObject -Class win32_computersystem).Model
    $TSServerCoreOS = "True"
    if((Test-Path -Path 'C:\Program Files\Internet Explorer\iexplore.exe') -eq $true){
        $TSServerCoreOS = "False"
    }
}
Import-Module $ScriptDir\TSxUtility.psm1

#Start logging
Start-Log -FilePath $LogFile
Write-Log "$ScriptName - Logging to $LogFile"

# Generate Vars
$OSSKU = Get-OSSKU



Get-VIAOSVersion -osv ([ref]$osv)  

#Output more info
Write-Log "$ScriptName - ScriptDir: $ScriptDir"
Write-Log "$ScriptName - ScriptName: $ScriptName"
Write-Log "$ScriptName - Integration with TaskSequence(LTI/ZTI): $MDTIntegration"
Write-Log "$ScriptName - Log: $LogFile"
Write-Log "$ScriptName - OSSKU: $OSSKU"
Write-Log "$ScriptName - OSVersion: $osv"
Write-Log "$ScriptName - Make:: $TSMake"
Write-Log "$ScriptName - Model: $TSModel"

#Custom Code Starts--------------------------------------

#Configure global settings for all servers
$Action = "Enable SmartScreen"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 60 -Id 1
Write-Log "$ScriptName - $Action"
$OptionType = 2
$KeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-ItemProperty -Path $KeyPath -Name EnableSmartScreen -Value $OptionType -PropertyType DWord -Force

#Set CrashControl
$Action = "Set CrashControl"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 70 -Id 1
Write-Log "$ScriptName - $Action"
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "AutoReboot" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "CrashDumpEnabled" -value 00000007
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "LogEvent" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "MinidumpsCount" -value 00000005
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "Overwrite" -value 00000001
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl -Name "AlwaysKeepMemoryDump" -value 00000000

#Firewall File/Printsharing
$Action = "Configure firewall rules"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 80 -Id 1
Write-Log "$ScriptName - $Action"
#Get-NetFirewallRule -DisplayName "*File and Printer Sharing*" | Enable-NetFirewallRule -Verbose
#Get-NetFirewallRule -Group "@FirewallAPI.dll,-28752" | Enable-NetFirewallRule -Verbose

#Configure Eventlogs
$Action = "Configure Eventlogs"
Write-Progress -Activity "Configure" -Status "Baseconfig WS2019 - $Action" -PercentComplete 90 -Id 1
Write-Log "$ScriptName - $Action"
$EventLogs = "Application","Security","System"
$MaxSize = 2GB
foreach($EventLog in $EventLogs){
    try{
        Limit-EventLog -LogName $EventLog -MaximumSize $MaxSize
    }
    catch{
        Write-Warning "Could not set $EventLog to $MaxSize, sorry"
    }
}

#Set PowerSchemaSettings to High Performance
$Action = "Set PowerSchemaSettings to High Performance"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
Invoke-VIAExe -Executable powercfg.exe -Arguments "/SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" -Verbose

# Disable "Connected User Experiences and Telemetry " Service
$Action = "Disable Connected User Experiences and Telemetry Service"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
Get-Service -Name DiagTrack | Set-Service -StartupType Disabled

#Configure dam kernel driver Time 2018-11-16
$Action = "Configure dam kernel driver"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1
$Arguments =  "config dam start= disabled"
$Executable = "sc.exe"
Invoke-VIAExe -Executable $Executable -Arguments $Arguments -Verbose
 
$Action = "Configure Screen Saver for Admin User and for Current User"
Write-Log "$ScriptName - $Action"
Write-Progress -Activity "Running " -Status "$ScriptName - $Action" -Id 1

$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900 -PropertyType String -Force
Write-Log "$ScriptName - ScreenSaverIsSecure is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaverIsSecure").ScreenSaverIsSecure)"
Write-Log "$ScriptName - ScreenSaveActive is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaveActive").ScreenSaveActive)"
Write-Log "$ScriptName - ScreenSaveTimeOut is now: $((Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name "ScreenSaveTimeOut").ScreenSaveTimeOut)"

REG LOAD HKEY_LOCAL_MACHINE\defuser  "C:\Users\Default\NTUSER.DAT"

$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaverIsSecure -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaveActive -Value 1 -PropertyType String -Force
$null = New-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name ScreenSaveTimeOut -Value 900 -PropertyType String -Force
Write-Log "$ScriptName - ScreenSaverIsSecure is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaverIsSecure").ScreenSaverIsSecure)"
Write-Log "$ScriptName - ScreenSaveActive is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaveActive").ScreenSaveActive)"
Write-Log "$ScriptName - ScreenSaveTimeOut is now: $((Get-ItemProperty -Path 'HKLM:\defuser\Control Panel\Desktop' -Name "ScreenSaveTimeOut").ScreenSaveTimeOut)"

[gc]::collect()
REG UNLOAD HKEY_LOCAL_MACHINE\defuser


#'// Show small icons on taskbar
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name TaskbarSmallIcons -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.TaskbarSmallIcons)"	

#'// Folderoptions Show file extensions	
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideFileExt is now: $($result.HideFileExt)"	
    
#'// Folderoptions Show hidden files, show hidden systemfiles file
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Hidden -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - Hidden is now: $($result.Hidden)"	
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowSuperHidden -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - SuperHidden is now: $($result.ShowSuperHidden)"	

#'// Folderoptions Always shows Menus
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name AlwaysShowMenus -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - AlwaysShowMenus is now: $($result.AlwaysShowMenus)"	

#'// Folderoptions Display the full path in the title bar
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name FullPath -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - FullPath is now: $($result.FullPath)"	

#'// Folderoptions HideMerge Conflicts
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideMergeConflicts -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideMergeConflicts is now: $($result.HideMergeConflicts)"	

#'// Folderoptions Hide empty drives in the computer folder	
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideDrivesWithNoMedia -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideDrivesWithNoMedia is now: $($result.HideDrivesWithNoMedia)"	

#'// Folderoptions launch folder windows in separate process
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name SeparateProcess -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - SeparateProcess is now: $($result.SeparateProcess)"	

#'// Folderoptions Always show icons never thumbnails
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name IconsOnly -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - IconsOnly is now: $($result.IconsOnly)"	

#'// Dont show tooltip	
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowInfoTip -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - ShowInfoTip is now: $($result.ShowInfoTip)"	

#'// Show computer on desktop
$null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' -Force
$null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.'{20D04FE0-3AEA-1069-A2D8-08002B30309D}')"	

#'// Always show all taskbar icons and notifcations
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name EnableAutoTray -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - EnableAutoTray is now: $($result.EnableAutoTray)"	

#'// Set control panel to small icons view 
$null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Force
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name AllItemsIconView -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - AllItemsIconView is now: $($result.AllItemsIconView)"	
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name StartupPage -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - StartupPage is now: $($result.StartupPage)"	
	
#'// Disable the Volume Icon in system icons
$null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Force
$null = New-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HideSCAVolume -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideSCAVolume is now: $($result.HideSCAVolume)"	

#'// Disable Search in the address bar and the search box on the new tab page
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name Autosearch -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - Autosearch is now: $($result.Autosearch)"	

#'// Set AutoDetectProxySettings Empty 
$result = New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - AutoDetect is now: $($result.AutoDetect)"	

& REG LOAD HKEY_LOCAL_MACHINE\defuser  "C:\Users\Default\NTUSER.DAT"

#'// Show small icons on taskbar
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name TaskbarSmallIcons -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.TaskbarSmallIcons)"	

#'// Folderoptions Show file extensions	
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideFileExt -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideFileExt is now: $($result.HideFileExt)"	
    
#'// Folderoptions Show hidden files, show hidden systemfiles file
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Hidden -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - Hidden is now: $($result.Hidden)"	
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowSuperHidden -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - SuperHidden is now: $($result.ShowSuperHidden)"	

#'// Folderoptions Always shows Menus
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name AlwaysShowMenus -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - AlwaysShowMenus is now: $($result.AlwaysShowMenus)"	

#'// Folderoptions Display the full path in the title bar
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name FullPath -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - FullPath is now: $($result.FullPath)"	

#'// Folderoptions HideMerge Conflicts
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideMergeConflicts -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideMergeConflicts is now: $($result.HideMergeConflicts)"	

#'// Folderoptions Hide empty drives in the computer folder	
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name HideDrivesWithNoMedia -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideDrivesWithNoMedia is now: $($result.HideDrivesWithNoMedia)"	

#'// Folderoptions launch folder windows in separate process
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name SeparateProcess -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - SeparateProcess is now: $($result.SeparateProcess)"	

#'// Folderoptions Always show icons never thumbnails
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name IconsOnly -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - IconsOnly is now: $($result.IconsOnly)"	

#'// Dont show tooltip	
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name ShowInfoTip -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - ShowInfoTip is now: $($result.ShowInfoTip)"	

#'// Show computer on desktop
$null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons' -Force
$null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - TaskbarSmallIcons is now: $($result.'{20D04FE0-3AEA-1069-A2D8-08002B30309D}')"	

#'// Always show all taskbar icons and notifcations
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name EnableAutoTray -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - EnableAutoTray is now: $($result.EnableAutoTray)"	

#'// Set control panel to small icons view 
$null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Force
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name AllItemsIconView -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - AllItemsIconView is now: $($result.AllItemsIconView)"	
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel' -Name StartupPage -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - StartupPage is now: $($result.StartupPage)"	
	
#'// Disable the Volume Icon in system icons
$null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' -Force
$null = New-Item -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Force
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HideSCAVolume -Value 1 -PropertyType DWORD -Force
Write-Log "$ScriptName - HideSCAVolume is now: $($result.HideSCAVolume)"	

#'// Disable Search in the address bar and the search box on the new tab page
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Internet Explorer\Main' -Name Autosearch -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - Autosearch is now: $($result.Autosearch)"	

#'// Set AutoDetectProxySettings Empty 
$result = New-ItemProperty -Path 'HKLM:\defuser\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoDetect -Value 0 -PropertyType DWORD -Force
Write-Log "$ScriptName - AutoDetect is now: $($result.AutoDetect)"	

[gc]::collect()

Start-Sleep -Seconds 5

& REG UNLOAD HKEY_LOCAL_MACHINE\defuser

# Remove Apps

$Apps = @(
    "Microsoft.BingWeather"
    "Microsoft.GetHelp"                     
    "Microsoft.Getstarted"                  
    "Microsoft.HEIFImageExtension"          
    "Microsoft.Messaging"                   
    "Microsoft.Microsoft3DViewer"           
    "Microsoft.MicrosoftOfficeHub"          
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MicrosoftStickyNotes"        
    "Microsoft.MixedReality.Portal"         
    "Microsoft.Office.OneNote"              
    "Microsoft.OneConnect"                  
    "Microsoft.People"                      
    "Microsoft.Print3D"                     
    "Microsoft.ScreenSketch"                
    "Microsoft.SkypeApp"                    
    "Microsoft.VP9VideoExtensions"          
    "Microsoft.Wallet"                      
    "Microsoft.WebMediaExtensions"          
    "Microsoft.WebpImageExtension"          
    "Microsoft.Windows.Photos"              
    "Microsoft.WindowsAlarms"               
    "Microsoft.WindowsCamera"               
    "Microsoft.WindowsFeedbackHub"          
    "Microsoft.WindowsMaps"                 
    "Microsoft.WindowsSoundRecorder"        
    "Microsoft.Xbox.TCUI"                   
    "Microsoft.XboxApp"                     
    "Microsoft.XboxGameOverlay"             
    "Microsoft.XboxGamingOverlay"           
    "Microsoft.XboxIdentityProvider"        
    "Microsoft.XboxSpeechToTextOverlay"     
    "Microsoft.YourPhone"                   
    "Microsoft.ZuneMusic"                   
    "Microsoft.ZuneVideo"
    "Microsoft.MSPaint"
)

foreach($App in $Apps)
{
    Get-AppxProvisionedPackage -Online | where DisplayName -like $App | Remove-AppxProvisionedPackage -AllUsers
}

Write-Log "Importing startlayout"
IF((Test-Path -Path "$ScriptDir\start.xml") -eq $true){
    $item = Get-ChildItem -Path "$ScriptDir\start.xml"
    Import-StartLayout -LayoutPath "$($item.FullName)" -MountPath $env:SystemDrive -Verbose
}


# Disable BT and WiFi adapter
Write-Log "$ScriptName - Disable Disconnected Networkadapters"
Get-NetAdapter | Where-Object Status -EQ Disconnected | Disable-NetAdapter -Confirm:$false -Verbose

Write-Log "$ScriptName - Disable BlueTooth devices"
$BTDevices = Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Where-Object Instanceid -NotLike BT*
foreach($BTDevice in $BTDevices)
{
    Disable-PnpDevice -InstanceId $BTDevice.InstanceId -Confirm:$false
    Write-Log "$ScriptName - $($BTDevice.FriendlyName) is now disabled"
}

Initialize-Tpm -ErrorAction SilentlyContinue
Get-Tpm -ErrorAction SilentlyContinue

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

Write-Log "$ScriptName - Done"
#Custom Code Ends--------------------------------------