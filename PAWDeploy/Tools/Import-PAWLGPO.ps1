<#
.SYNOPSIS
    Imports LGPO.exe into all imported OS/Edge baselines.
.DESCRIPTION
    Extracts only LGPO.exe and places it in Scripts\Tools of each imported baseline.
    Empty directory skeletons are skipped. Existing copies require Replace.
    No executable is run. WhatIf makes no filesystem/log changes.
.PARAMETER ZipPath
    Local Microsoft LGPO ZIP.
.PARAMETER Replace
    Explicit approval to replace existing LGPO.exe files.
.EXAMPLE
    .\Tools\Import-PAWLGPO.ps1 -ZipPath C:\Downloads\LGPO.zip -Replace
    Updates LGPO in all imported baselines under the installation root.
.NOTES
    Version : 2.0.0.3
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ZipPath,
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
try {
    if (-not $PSCmdlet.ShouldProcess("$root\Resources\SecurityBaselines", 'Import LGPO into all imported OS/Edge baselines')) { return }
    Import-PAWLGPO -ZipPath $ZipPath -BaselineFolder (Join-Path $root 'Resources\SecurityBaselines') -Replace:$Replace -Confirm:$false |
        ForEach-Object {
            Write-PAWLog -Message "Imported LGPO from '$ZipPath' into '$($_.Destination)'." `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWLGPO.log') -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $importError = $_
    if (-not $WhatIfPreference) {
        try {
            Write-PAWLog -Level ERROR -Message "LGPO import failed: $($importError.Exception.Message)" `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWLGPO.log') -OutputMode Warning
        }
        catch { Write-Warning "Import error logging failed: $($_.Exception.Message)" }
    }
    throw $importError
}
