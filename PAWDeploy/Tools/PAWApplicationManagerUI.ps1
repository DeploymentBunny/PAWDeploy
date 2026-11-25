<#
.SYNOPSIS
    Opens the Application Manager UI; all data operations use the CLI script.
.PARAMETER WindowX
    Optional menu-aligned horizontal position.
.PARAMETER WindowY
    Optional menu-aligned vertical position.
.NOTES
    Version : 2.0.0.4
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding()]
param([int]$WindowX, [int]$WindowY)
$ErrorActionPreference = 'Stop'
$script:PAWEdition = 'Community'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
$script:LogPath = Join-Path (Resolve-PAWLogFolder) 'PAWApplicationManager.log'
Write-PAWLog -Message 'PAW Application Manager UI starting.' -LogPath $script:LogPath
Import-Module (Join-Path $root 'Functions\PAWUIUtility\PAWUIUtility.psd1') -ErrorAction Stop
$title = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$position = @{}
if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
    $position.WindowX = $WindowX
    $position.WindowY = $WindowY
}
try {
    Show-PAWApplicationManager -CommandPath (Join-Path $PSScriptRoot 'Invoke-PAWApplicationManager.ps1') `
        -ConfigPath (Join-Path $root 'Config\Config.json') -Title $title -Edition $script:PAWEdition @position
}
catch {
    Add-Type -AssemblyName System.Windows.Forms
    Show-PAWUiError -Title 'Application Manager' -ErrorRecord $_ -Copyable `
        -LogPath (Join-Path (Resolve-PAWLogFolder) 'PAWApplicationManager.log') @position
    throw
}
