<#
.SYNOPSIS
    Imports PowerShell scripts into Resources\CustomScripts.
.PARAMETER Path
    One or more .ps1 files.
.PARAMETER Replace
    Explicit approval to replace existing scripts.
.EXAMPLE
    .\Tools\Import-PAWRunScript.ps1 -Path C:\Downloads\Sample1.ps1,C:\Downloads\Sample2.ps1
    Imports two scripts without executing them.
.NOTES
    Version : 2.0.0.3
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
try {
    if (-not $PSCmdlet.ShouldProcess($root, 'Import PowerShell scripts into CustomScripts')) { return }
    Import-PAWRunScript -Path $Path -InstallFolderPath $root -Replace:$Replace -Confirm:$false |
        ForEach-Object {
            Write-PAWLog -Message "Imported script '$($_.Source)' into '$($_.Destination)'." `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWRunScript.log') -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $importError = $_
    if (-not $WhatIfPreference) {
        try {
            Write-PAWLog -Level ERROR -Message "Script import failed: $($importError.Exception.Message)" `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWRunScript.log') -OutputMode Warning
        }
        catch { Write-Warning "Script import logging failed: $($_.Exception.Message)" }
    }
    throw $importError
}
