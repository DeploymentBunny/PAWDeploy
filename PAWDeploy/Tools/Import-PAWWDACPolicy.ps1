<#
.SYNOPSIS
    Imports validated WDAC XML policies with standard PAWDeploy logging.
.PARAMETER Path
    One or more XML policy files.
.PARAMETER Replace
    Explicit approval to replace existing policy filenames.
.EXAMPLE
    .\Tools\Import-PAWWDACPolicy.ps1 -Path C:\Policies\PAW.xml
.NOTES
    Version : 2.0.0.2
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Path,
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$log = $null
try {
    if (-not $WhatIfPreference) { $log = Join-Path (Resolve-PAWLogFolder) 'Import-PAWWDACPolicy.log' }
    $confirmImport = $PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']
    Import-PAWWDACPolicy -Path $Path -InstallFolderPath $root -Replace:$Replace -WhatIf:$WhatIfPreference -Confirm:$confirmImport |
        ForEach-Object {
            Write-PAWLog -Message "Imported $($_.Mode) WDAC policy '$($_.Source)' to '$($_.Destination)'." -LogPath $log -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $failure = $_
    if (-not $WhatIfPreference) {
        try { Write-PAWLog -Level ERROR -Message "WDAC policy import failed: $($failure.Exception.Message)" -LogPath $log -OutputMode Warning }
        catch { Write-Warning "WDAC import logging failed: $($_.Exception.Message)" }
    }
    throw $failure
}
