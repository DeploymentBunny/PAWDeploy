<#
.SYNOPSIS
    Convenience application editor backed by Invoke-PAWApplicationManager.ps1.
.DESCRIPTION
    Uses the canonical application catalog, not a second Applications.json list.
    Prefer Invoke-PAWApplicationManager.ps1 for bundle and portable-package operations.
.EXAMPLE
    .\Tools\Invoke-PAWApplicationSettings.ps1 -Edit -Name 'KeePass' -InstallEnabled False
.NOTES
    Version : 2.0.0.8
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$List, [switch]$Show, [switch]$New, [switch]$Clone, [switch]$Edit, [switch]$Remove,
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $command = Get-Command $commandAst.GetCommandName() -CommandType ExternalScript -ErrorAction SilentlyContinue
        if ($null -eq $command) { return }
        $root = Split-Path -Parent (Split-Path -Parent $command.Path)
        $manifest = Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1'
        if (Test-Path -LiteralPath $manifest -PathType Leaf) {
            Import-Module -Name $manifest -Scope Local -ErrorAction Stop
            Get-PAWApplicationArgumentCompletion -ParameterName Name -WordToComplete $wordToComplete -ScriptFolder $root -BoundParameters $fakeBoundParameters
        }
    })]
    [string]$Name, [string]$NewName, [switch]$Force, [switch]$PassThru,
    [hashtable]$Setting = @{},
    [ValidateSet('WinGet','PSGallery','Local')][string]$Source,
    [string]$Id,
    [ValidateSet('True','False')][string]$InstallEnabled,
    [string]$Architecture, [string]$Scope, [string]$InstallerType,
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json')
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
if (-not $WhatIfPreference) {
    Write-PAWLog -Message 'Application settings command starting.' -LogPath (Join-Path (Resolve-PAWLogFolder) 'Invoke-PAWApplicationSettings.log')
}
$command = Join-Path $PSScriptRoot 'Invoke-PAWApplicationManager.ps1'
$actions = @('List','Show','New','Clone','Edit','Remove' | Where-Object { $PSBoundParameters[$_] })
if ($actions.Count -gt 1) { throw 'Specify one application action.' }
$apps = @(& $command -Action ListApplications -ConfigPath $ConfigPath)
if ($actions.Count -eq 0 -or $List) { return ($apps | ForEach-Object Definition) }
if ([string]::IsNullOrWhiteSpace($Name)) { throw 'Name is required.' }
$matches = @($apps | Where-Object { $_.Definition.Name -eq $Name })
if (-not $New -and $matches.Count -ne 1) { throw "Application '$Name' not found." }
if ($Show) { return $matches[0] }
if ($Remove) {
    if ($PSCmdlet.ShouldProcess($Name, 'Remove application definition')) {
        if (-not $Force -and -not $PSBoundParameters.ContainsKey('Confirm') -and
            -not $PSCmdlet.ShouldContinue("Remove application '$Name' and its membership in all bundles? Cached files are retained.", 'Application Manager')) { return }
        & $command -Action RemoveApplication -ApplicationId $matches[0].ApplicationId -ConfigPath $ConfigPath -Confirm:$false
    }
    return
}
if ($New) {
    $app = [pscustomobject]@{
        SchemaVersion = 1; Enabled = $true
        Definition = [pscustomobject]@{
            Name = $Name; Source = 'WinGet'; Id = 'NA'; InstallEnabled = $true
            Architecture = 'NA'; Scope = 'NA'; InstallerType = 'NA'
        }
        Settings = [pscustomobject]@{}
    }
}
else { $app = $matches[0] }
if ($Clone) {
    $app.PSObject.Properties.Remove('ApplicationId')
    $app.Definition.Name = if ($NewName) { $NewName } else { "$Name - Clone" }
}
elseif ($NewName -and $NewName -ne $Name) {
    throw 'Application display names are immutable. Clone the application to use a new name.'
}
$settings = @{}
foreach ($key in $Setting.Keys) { $settings[$key] = $Setting[$key] }
foreach ($key in @('Source','Id','InstallEnabled','Architecture','Scope','InstallerType')) {
    if ($PSBoundParameters.ContainsKey($key)) {
        if ($settings.ContainsKey($key)) { throw "Setting '$key' is supplied twice." }
        $settings[$key] = $PSBoundParameters[$key]
    }
}
foreach ($key in $settings.Keys) {
    if ($key -notin @('Source','Id','InstallEnabled','Architecture','Scope','InstallerType')) { throw "Unknown application setting '$key'." }
    if ($app.SchemaVersion -eq 2) {
        if ($key -eq 'InstallEnabled') { $app.Definition.InstallEnabled = [Convert]::ToBoolean($settings[$key]) }
        elseif ($key -eq 'Source') { throw 'Typed application Source cannot be changed here. Edit Configuration through Application Manager.' }
        elseif ($null -eq $app.Definition.Configuration.PSObject.Properties[$key]) { throw "Setting '$key' is not applicable to $($app.Type)." }
        else { $app.Definition.Configuration.$key = $settings[$key] }
    }
    else { $app.Definition.$key = $settings[$key] }
}
if ($app.SchemaVersion -eq 1 -and $settings.ContainsKey('Source') -and $app.Definition.Source -eq 'PSGallery') {
    foreach ($key in @('Architecture','Scope','InstallerType')) {
        if (-not $settings.ContainsKey($key)) { $app.Definition.$key = 'NA' }
    }
}
elseif ($app.SchemaVersion -eq 1 -and $settings.ContainsKey('Source') -and $app.Definition.Source -eq 'Local' -and -not $settings.ContainsKey('Id')) {
    $app.Definition.Id = 'NA'
}
if ($PSCmdlet.ShouldProcess($app.Definition.Name, 'Save managed application')) {
    $result = & $command -Action SaveApplication -InputObject $app -Replace:$Edit -ConfigPath $ConfigPath -Confirm:$false
    if ($PassThru) { $result.Definition }
}
