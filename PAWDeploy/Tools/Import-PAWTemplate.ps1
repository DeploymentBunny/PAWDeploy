<#
.SYNOPSIS
    Imports one or more validated template JSON files with normal PAWDeploy logging.
.PARAMETER Path
    One or more template JSON files.
.PARAMETER ConfigPath
    Config.json; templates are imported beside it.
.PARAMETER Replace
    Explicit approval to replace templates with matching names.
.EXAMPLE
    .\Tools\Import-PAWTemplate.ps1 -Path C:\Templates\Workgroup.json
.NOTES
    Version : 2.0.0.3
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Path,
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'),
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$log = $null
try {
    if (-not $WhatIfPreference) { $log = Join-Path (Resolve-PAWLogFolder) 'Import-PAWTemplate.log' }
    $confirmTransfer = $PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']
    Import-PAWTemplate -Path $Path -ConfigPath $ConfigPath -Replace:$Replace -WhatIf:$WhatIfPreference -Confirm:$confirmTransfer -WarningAction Continue 3>&1 |
        ForEach-Object {
            if ($_ -is [System.Management.Automation.WarningRecord]) {
                if (-not $WhatIfPreference) { Write-PAWLog -Level WARN -Message $_.Message -LogPath $log }
                Write-Warning $_.Message
            }
            else {
                Write-PAWLog -Message "Imported template '$($_.Name)' from '$($_.Source)' to '$($_.Destination)'." -LogPath $log -OutputMode Console -ConsoleType Success
                $_
            }
        }
}
catch {
    $failure = $_
    if (-not $WhatIfPreference) {
        try { Write-PAWLog -Level ERROR -Message "Template import failed: $($failure.Exception.Message)" -LogPath $log -OutputMode Warning }
        catch { Write-Warning "Template import logging failed: $($_.Exception.Message)" }
    }
    throw $failure
}
