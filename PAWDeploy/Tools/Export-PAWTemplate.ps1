<#
.SYNOPSIS
    Exports saved templates to separate JSON files with normal PAWDeploy logging.
.PARAMETER Name
    One or more saved template names.
.PARAMETER ConfigPath
    Config.json; templates are read from its parent.
.PARAMETER DestinationFolder
    Folder receiving exported template JSON files.
.PARAMETER Replace
    Explicit approval to overwrite exported files.
.EXAMPLE
    .\Tools\Export-PAWTemplate.ps1 -Name 'Windows 11 PAW' -DestinationFolder C:\Templates
.NOTES
    Version : 2.0.0.2
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Name,
    [Parameter(Mandatory)][string]$DestinationFolder,
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'),
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$log = $null
try {
    if (-not $WhatIfPreference) { $log = Join-Path (Resolve-PAWLogFolder) 'Export-PAWTemplate.log' }
    $confirmTransfer = $PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']
    Export-PAWTemplate -Name $Name -ConfigPath $ConfigPath -DestinationFolder $DestinationFolder -Replace:$Replace -WhatIf:$WhatIfPreference -Confirm:$confirmTransfer |
        ForEach-Object {
            Write-PAWLog -Message "Exported template '$($_.Name)' from '$($_.Source)' to '$($_.Destination)'." -LogPath $log -OutputMode Console -ConsoleType Success
            $_
        }
}
catch {
    $failure = $_
    if (-not $WhatIfPreference) {
        try { Write-PAWLog -Level ERROR -Message "Template export failed: $($failure.Exception.Message)" -LogPath $log -OutputMode Warning }
        catch { Write-Warning "Template export logging failed: $($_.Exception.Message)" }
    }
    throw $failure
}
