<#
.SYNOPSIS
    Opens the PAW Template Editor UI.
.DESCRIPTION
    Provides a dedicated template-management window while reusing the shared
    editor implementation.
.PARAMETER ConfigPath
    Config.json path; template JSON files are stored beside it.
.PARAMETER WindowX
    Optional left screen coordinate.
.PARAMETER WindowY
    Optional top screen coordinate.
.EXAMPLE
    .\Tools\PAWTemplateEditorUI.ps1
.NOTES
    Version : 2.0.0.27
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [int]$WindowX,
    [int]$WindowY
)

try {
    $script:PAWEdition = 'Community'
    $utilityManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1'
    Import-Module -Name $utilityManifest -Force -ErrorAction Stop
    $script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
    $editor = Join-Path $PSScriptRoot 'PAWConfigEditorUI.ps1'
    if (-not (Test-Path -LiteralPath $editor -PathType Leaf)) {
        throw "Required editor implementation not found: $editor"
    }

    $parameters = @{ EditorMode = 'Templates' }
    $parameters.LogPath = Join-Path (Join-Path $env:TEMP 'PAWDeploy') 'PAWTemplateEditorUI.log'
    if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) { $parameters.ConfigPath = $ConfigPath }
    if ($PSBoundParameters.ContainsKey('WindowX')) { $parameters.WindowX = $WindowX }
    if ($PSBoundParameters.ContainsKey('WindowY')) { $parameters.WindowY = $WindowY }
    & $editor @parameters
}
catch {
    $startupError = $_
    $logPath = Join-Path $env:TEMP 'PAWDeploy\PAWTemplateEditorUI.log'
    $logStatus = "Log path: $logPath"
    if (Get-Command -Name Write-PAWLog -ErrorAction SilentlyContinue) {
        try {
            Write-PAWLog -Level 'ERROR' -Message 'PAW Template Editor failed to start.' -Exception $startupError.Exception -LogPath $logPath
        }
        catch {
            $logStatus = "Unable to write the startup log: $($_.Exception.Message)"
        }
    }

    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $message = "PAW Template Editor could not start.`r`n`r`n$($startupError.Exception.Message)`r`n`r`n$logStatus"
    [void][System.Windows.Forms.MessageBox]::Show($message, 'PAW Template Editor failed to start', 'OK', 'Error')
    throw $startupError
}
