<#
.SYNOPSIS
    Baseconfig for WS2019
.DESCRIPTION
    Baseconfig for WS2019
.EXAMPLE
    Baseconfig for WS2019
.NOTES
        ScriptName: Baseconfig for WS2019.ps1
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
$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
$Logpath = $tsenv.Value("LogPath")
$LogFile = $Logpath + "\" + "$ScriptName.log"
$DeployRoot = $tsenv.Value("DeployRoot")
Import-Module $DeployRoot\Tools\Modules\TSxOSDUtility\TSxOSDUtility.psm1

#Start logging
Start-Log -FilePath $LogFile
Write-Log "$ScriptName - Logging to $LogFile"

# Generate Vars
$OSSKU = Get-OSSKU
$TSMake = $tsenv.Value("Make")
$TSModel = $tsenv.Value("Model")
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


& Robocopy "$ScriptDir\Source" "$env:SystemDrive\" /e /s 