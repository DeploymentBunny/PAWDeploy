<#
.SYNOPSIS
    Imports a Microsoft Edge baseline ZIP under Resources\SecurityBaselines.
.DESCRIPTION
    Normalizes the ZIP wrapper into the selected OS folder's Edge directory.
    Existing content requires Replace. Run Import-PAWLGPO after baseline imports.
    No imported scripts are executed. WhatIf makes no filesystem/log changes.
.PARAMETER ZipPath
    Local Edge baseline ZIP.
.PARAMETER OperatingSystem
    Destination OS directory name.
.PARAMETER Replace
    Explicit replacement approval.
.EXAMPLE
    .\Tools\Import-PAWEdgeBaseline.ps1 -ZipPath C:\Downloads\Edge.zip -OperatingSystem Windows11_26H2
    Imports Edge without replacing existing content.
.NOTES
    Version : 2.0.0.3
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ZipPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OperatingSystem,
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
try {
    if (-not $PSCmdlet.ShouldProcess("$root\Resources\SecurityBaselines", "Import Edge baseline for '$OperatingSystem'")) { return }
    Import-PAWEdgeBaseline -ZipPath $ZipPath -OperatingSystem $OperatingSystem `
        -BaselineFolder (Join-Path $root 'Resources\SecurityBaselines') -Replace:$Replace -Confirm:$false |
        ForEach-Object {
            Write-PAWLog -Message "Imported '$ZipPath' into '$($_.Destination)'. Run Import-PAWLGPO to populate Scripts\Tools." `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWEdgeBaseline.log') -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $importError = $_
    if (-not $WhatIfPreference) {
        try {
            Write-PAWLog -Level ERROR -Message "Edge import failed: $($importError.Exception.Message)" `
                -LogPath (Join-Path (Resolve-PAWLogFolder) 'Import-PAWEdgeBaseline.log') -OutputMode Warning
        }
        catch { Write-Warning "Import error logging failed: $($_.Exception.Message)" }
    }
    throw $importError
}
