<#
.SYNOPSIS
    Opens the VHDX file import dialog.
.PARAMETER ConfigPath
    Config.json path. Defaults to the installed configuration file.
.PARAMETER WindowX
    Optional left screen coordinate for the dialog owner.
.PARAMETER WindowY
    Optional top screen coordinate for the dialog owner.
.EXAMPLE
    .\Tools\PAWVHDXImportUI.ps1
.NOTES
    Version : 2.0.0.21
    Author  : The Fantastic PAWDeploy Team
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [int]$WindowX,
    [int]$WindowY
)

$script:PAWEdition = 'Community'
$root = Split-Path -Parent $PSScriptRoot
Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
[System.Windows.Forms.Application]::EnableVisualStyles()
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
Import-Module (Join-Path $root 'Functions\PAWUIUtility\PAWUIUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$owner = $null
try {
    if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
        $owner = New-Object System.Windows.Forms.Form
        $owner.StartPosition = 'Manual'
        $owner.Location = New-Object System.Drawing.Point($WindowX, $WindowY)
        $owner.Size = New-Object System.Drawing.Size(1, 1)
        $owner.ShowInTaskbar = $false
    }
    Show-PAWFileImportDialog -Owner $owner -RootFolder $root -ImportType VHDX -ConfigPath $ConfigPath
}
finally {
    if ($null -ne $owner) { $owner.Dispose() }
}
