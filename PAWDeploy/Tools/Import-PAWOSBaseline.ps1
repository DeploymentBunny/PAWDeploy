<#
.SYNOPSIS
    Imports one Microsoft OS baseline ZIP into the installed baseline tree.
.DESCRIPTION
    Places the package beside other baselines under Resources\SecurityBaselines.
    Select the OS directory explicitly. The ZIP wrapper is
    normalized so Scripts\Baseline-LocalInstall.ps1 is directly below that type.
    No downloads or imported script execution occur. Existing content requires
    explicit -Replace approval. WhatIf makes no filesystem or log changes.
.PARAMETER ZipPath
    Local ZIP file acquired from Microsoft.
.PARAMETER OperatingSystem
    Destination OS directory name, for example Windows11_26H2.
.PARAMETER Replace
    Explicit approval to replace this type's existing baseline.
.EXAMPLE
    .\Tools\Import-PAWOSBaseline.ps1 -ZipPath C:\Downloads\WindowsBaseline.zip -OperatingSystem Windows11_26H2
    Imports an OS baseline.
.EXAMPLE
    .\Tools\Import-PAWOSBaseline.ps1 -ZipPath C:\Downloads\WindowsBaseline.zip -OperatingSystem Windows11_26H2 -Replace
    Replaces the OS baseline. Run Import-PAWLGPO afterwards to populate Scripts\Tools.
.NOTES
    Version : 2.0.0.4
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+, Microsoft OS baseline ZIP and write access to the installation.
    Log file: %TEMP%\PAWDeploy\Import-PAWOSBaseline.log.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipPath,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OperatingSystem,
    [switch]$Replace
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Force -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$baselineFolder = Join-Path $root 'Resources\SecurityBaselines'
try {
    if (-not $PSCmdlet.ShouldProcess($baselineFolder, "Import OS baseline for '$OperatingSystem' from '$ZipPath'")) { return }
    $result = Import-PAWOSBaseline -ZipPath $ZipPath -OperatingSystem $OperatingSystem `
        -BaselineFolder $baselineFolder -Replace:$Replace `
        -WhatIf:$WhatIfPreference -Confirm:$false -ErrorAction Stop
    if ($null -ne $result) {
        $log = Join-Path (Resolve-PAWLogFolder) 'Import-PAWOSBaseline.log'
        Write-PAWLog -Message "Imported '$ZipPath' into '$($result.Destination)'. Run Import-PAWLGPO to populate Scripts\Tools." -LogPath $log -OutputMode Console -ConsoleType Success
        $result
    }
}
catch {
    $importError = $_
    if (-not $WhatIfPreference) {
        try {
            $log = Join-Path (Resolve-PAWLogFolder) 'Import-PAWOSBaseline.log'
            Write-PAWLog -Level ERROR -Message "Baseline import failed: $($importError.Exception.Message)" -LogPath $log -OutputMode Warning
        }
        catch { Write-Warning "Baseline import error logging failed: $($_.Exception.Message)" }
    }
    throw $importError
}
