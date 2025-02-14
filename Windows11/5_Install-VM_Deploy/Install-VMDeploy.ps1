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

#Start logging
Start-Log -FilePath $LogFile
Write-Log "$ScriptName - Logging to $LogFile"

# Generate Vars
$OSSKU = Get-OSSKU
$TSMake = $tsenv.Value("Make")
$TSModel = $tsenv.Value("Model")
$TSServerCoreOS = $tsenv.Value("IsServerCoreOS")

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

& Robocopy $ScriptDir\Source C:\ /e

New-Item -Path "$env:ALLUSERSPROFILE\Desktop\VMTools" -Type Directory -Force

New-TSxShortCut -SoruceFile PowerShell.exe -DestinationFile "$env:ALLUSERSPROFILE\Desktop\VMTools\VM Deploy.lnk" -Arguments "-ExecutionPolicy Bypass -File C:\VMDeploy\VMDeploywUI.ps1" -IconDLL "$env:ProgramFiles\hyper-v\snapinabout.dll" -RunAsAdmin
New-TSxShortCut -SoruceFile PowerShell.exe -DestinationFile "$env:ALLUSERSPROFILE\Desktop\VMTools\VM Destroy.lnk" -Arguments "-ExecutionPolicy Bypass -File C:\VMDeploy\VMRemovewUI.ps1" -IconDLL "$env:ProgramFiles\hyper-v\snapinabout.dll" -RunAsAdmin
Copy-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Administrative Tools\Hyper-V Manager.lnk" -Destination "$env:ALLUSERSPROFILE\Desktop\VMTools\Hyper-V Manager.lnk" -Force
