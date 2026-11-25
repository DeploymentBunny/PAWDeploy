<#
.SYNOPSIS
    Imports VHDX files into the configured virtual hard disk folder.
.DESCRIPTION
    Imports one or more local VHDX files into Settings.Configuration.VHDFolder
    in Config.json. Existing files are preserved unless -Replace is supplied.
.PARAMETER Path
    One or more source .vhdx files.
.PARAMETER ConfigPath
    Config.json path. Defaults to the installed configuration file.
.PARAMETER Replace
    Allows files with matching names in VHDFolder to be replaced.
.EXAMPLE
    .\Tools\Import-PAWVHDX.ps1 -Path 'D:\Downloads\Reference.vhdx'
.EXAMPLE
    .\Tools\Import-PAWVHDX.ps1 -Path 'D:\Images\First.vhdx','D:\Images\Second.vhdx' -Replace
.NOTES
    Version : 2.0.0.20
    Author  : The Fantastic PAWDeploy Team
    Log file: %TEMP%\PAWDeploy\Import-PAWVHDX.log.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'),

    [switch]$Replace
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$logPath = $null
if (-not $WhatIfPreference) {
    $logPath = Join-Path (Resolve-PAWLogFolder) 'Import-PAWVHDX.log'
}

try {
    $confirmImport = $PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']
    Import-PAWVHDX -Path $Path -ConfigPath $ConfigPath -Replace:$Replace -WhatIf:$WhatIfPreference -Confirm:$confirmImport |
        ForEach-Object {
            Write-PAWLog -Message "Imported VHDX '$($_.Source)' into '$($_.Destination)'." -LogPath $logPath -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $importError = $_
    if (-not $WhatIfPreference -and -not [string]::IsNullOrWhiteSpace($logPath)) {
        try {
            Write-PAWLog -Level ERROR -Message "VHDX import failed: $($importError.Exception.Message)" -LogPath $logPath -OutputMode Warning
        }
        catch { Write-Warning "VHDX import error logging failed: $($_.Exception.Message)" }
    }
    throw $importError
}
