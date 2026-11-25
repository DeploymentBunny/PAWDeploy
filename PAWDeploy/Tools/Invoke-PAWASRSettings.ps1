<#
.SYNOPSIS
    Lists and edits the ASR master list.
.DESCRIPTION
    Changes the offline master list only; it does not change Defender on the host.
    Each successful change increments the list's patch version.
.EXAMPLE
    .\Tools\Invoke-PAWASRSettings.ps1 -Action List
.EXAMPLE
    .\Tools\Invoke-PAWASRSettings.ps1 -Action Edit -Id 'd1e49aac-8f56-4280-b9ba-993a6d77406c' -Name 'Block PSExec/WMI'
.NOTES
    Version : 2.0.0.2
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('List', 'Add', 'Edit', 'Remove')]
    [string]$Action = 'List',
    [string]$Id,
    [string]$NewId,
    [string]$Name,
    [ValidateSet('Block', 'Audit', 'Disabled')][string]$Mode,
    [ValidateRange(0, 2147483647)][int]$ClientMinBuild,
    [ValidateRange(0, 2147483647)][int]$ServerMinBuild,
    [bool]$RequiresCloudProtection,
    [string]$Path,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $PSBoundParameters.ContainsKey('Path')) {
    $Path = Join-Path $root 'Resources\ASR\MasterList.json'
}
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$original = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
$existingRules = @(Get-PAWASRRule -Path $Path)
if ($Action -eq 'List') { return $existingRules }
if ([string]::IsNullOrWhiteSpace($Id)) { throw 'Id is required for Add, Edit and Remove.' }
$matches = @($existingRules | Where-Object { $_.Id -eq $Id })
if ($Action -eq 'Add' -and $matches.Count -ne 0) { throw "ASR rule '$Id' already exists." }
if ($Action -ne 'Add' -and $matches.Count -ne 1) { throw "ASR rule '$Id' was not found." }

$document = $original | ConvertFrom-Json -ErrorAction Stop
$before = $document.Rules | ConvertTo-Json -Depth 10 -Compress
switch ($Action) {
    'Add' {
        foreach ($required in @('Name', 'ClientMinBuild', 'ServerMinBuild', 'RequiresCloudProtection')) {
            if (-not $PSBoundParameters.ContainsKey($required)) { throw "$required is required when adding a rule." }
        }
        if ($PSBoundParameters.ContainsKey('NewId')) { throw 'NewId is only valid for Edit.' }
        $document.Rules = @($document.Rules) + @([pscustomobject]@{
            Id = $Id; Name = $Name; Mode = if ($PSBoundParameters.ContainsKey('Mode')) { $Mode } else { 'Block' }; ClientMinBuild = $ClientMinBuild
            ServerMinBuild = $ServerMinBuild; RequiresCloudProtection = $RequiresCloudProtection
        })
    }
    'Edit' {
        $entry = @($document.Rules | Where-Object { $_.Id -eq $Id })[0]
        foreach ($field in @('Name', 'Mode', 'ClientMinBuild', 'ServerMinBuild', 'RequiresCloudProtection')) {
            if ($PSBoundParameters.ContainsKey($field)) { $entry.$field = $PSBoundParameters[$field] }
        }
        if ($PSBoundParameters.ContainsKey('NewId')) { $entry.Id = $NewId }
    }
    'Remove' {
        if (@($document.Rules).Count -le 1) { throw 'The ASR master list must contain at least one rule.' }
        $document.Rules = @($document.Rules | Where-Object { $_.Id -ne $Id })
    }
}
$after = $document.Rules | ConvertTo-Json -Depth 10 -Compress
if ($before -eq $after) {
    Write-Verbose 'No ASR rule changes requested.'
    return
}
$version = [version]$document.Version
if ($version.Build -eq [int]::MaxValue) { throw 'ASR master list patch version cannot be incremented.' }
$document.Version = '{0}.{1}.{2}' -f $version.Major, $version.Minor, ($version.Build + 1)
$null = @(Get-PAWASRRule -InputObject $document)

if (-not $PSCmdlet.ShouldProcess($Path, "$Action ASR rule $Id")) { return }
if ($Action -eq 'Remove' -and -not $Force -and -not $PSBoundParameters.ContainsKey('Confirm') -and
    -not $PSCmdlet.ShouldContinue("Remove ASR rule '$($matches[0].Name)' [$Id] from the master list?", 'Remove ASR rule')) { return }

$resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
$temporary = Join-Path (Split-Path -Parent $resolvedPath) ('.asr-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $json = $document | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    $null = @(Get-PAWASRRule -Path $temporary)
    if ([IO.File]::ReadAllText($resolvedPath) -cne $original) {
        throw "ASR master list changed while editing; reload and try again: '$resolvedPath'."
    }
    [IO.File]::Replace($temporary, $resolvedPath, [Management.Automation.Language.NullString]::Value)
}
finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction Stop }
}
Write-PAWLog -Message "ASR master list $Action rule '$Id'; version $($document.Version)." `
    -LogPath (Join-Path (Resolve-PAWLogFolder) 'PAWASRSettings.log')
[pscustomobject]@{ Action = $Action; Id = if ($NewId) { $NewId } else { $Id }; Version = $document.Version; Path = $resolvedPath }
