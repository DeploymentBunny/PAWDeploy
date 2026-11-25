<#
.SYNOPSIS
    Validates PAWDeploy configuration, required files, and environment readiness.

.DESCRIPTION
    Invoke-PAWConfigValidation.ps1 reads Config\Config.json below the parent installation folder and reports on:
      - Whether configured folders (HyperV, InstallFolder, VHDFolder,
        SecurityBaseLineFolder, LogFilesFolder) resolve
        to existing paths.
      - Discovered template JSON files and their parse state.
      - Discovered .vhdx files and basic read-access checks.
      - Solution version and installed script versions.
      - PowerShell version and whether the PAWUtility module can be imported.
      - Detected version numbers for the other top-level PAWDeploy scripts.

.EXAMPLE
    .\Tools\Invoke-PAWConfigValidation.ps1

    Validates Config\Config.json and the templates in Config and writes the results
    to the console.

.NOTES
    Version : 2.0.0.5
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+.
    Files   : Config\Config.json must exist below the parent installation folder.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptFolder = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    Split-Path -Parent $PSScriptRoot
}
elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
else {
    throw 'Cannot resolve the PAWDeploy installation folder from the script path.'
}

$ConfigPath = Join-Path $scriptFolder 'Config\Config.json'

$utilityManifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $utilityManifest -PathType Leaf)) {
    throw "Required module not found: $utilityManifest"
}
Import-Module $utilityManifest -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$LogPath = Join-Path (Resolve-PAWLogFolder) 'Invoke-PAWConfigValidation.log'
Write-PAWLog -Message 'Configuration validation starting.' -LogPath $LogPath

function Get-PAWNodeText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Json,

        [Parameter(Mandatory = $true)]
        [string]$XPath
    )

    $nodeName = ($XPath -split '/')[-1]
    $parentPath = ($XPath -split '/')[1..(($XPath -split '/').Count - 2)]

    $current = $Json
    foreach ($segment in $parentPath) {
        if ($null -eq $current -or $null -eq $current.PSObject.Properties[$segment]) {
            return $null
        }
        $current = $current.$segment
    }

    if ($null -eq $current -or $null -eq $current.PSObject.Properties[$nodeName]) {
        return $null
    }

    $value = [string]$current.$nodeName
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }

    return $value.Trim()
}

function Resolve-PAWConfigPathValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseFolder,

        [Parameter(Mandatory = $true)]
        [string]$RawValue
    )

    $expandedValue = [Environment]::ExpandEnvironmentVariables($RawValue)
    if ([System.IO.Path]::IsPathRooted($expandedValue)) {
        return $expandedValue
    }

    return (Join-Path $BaseFolder $expandedValue)
}

function Get-PAWScriptVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptContent
    )

    $solutionVersionMatch = [regex]::Match($ScriptContent, '(?m)^\s*\$SolutionVersion\s*=\s*''([^'']+)''')
    if ($solutionVersionMatch.Success) {
        return $solutionVersionMatch.Groups[1].Value
    }

    $headerVersionMatch = [regex]::Match($ScriptContent, '(?is)\.NOTES\b.*?\bVersion\s*:\s*([0-9]+(?:\.[0-9]+){1,3})')
    if ($headerVersionMatch.Success) {
        return $headerVersionMatch.Groups[1].Value.Trim()
    }

    $headerVersionMatch = [regex]::Match($ScriptContent, '(?i)\bVersion\s*:\s*([0-9]+(?:\.[0-9]+){1,3})')
    if ($headerVersionMatch.Success) {
        return $headerVersionMatch.Groups[1].Value.Trim()
    }

    return $null
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw 'FATAL ERROR, unable to find Config.json'
}

$configXml = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$configFolder = Split-Path -Parent $resolvedConfigPath

$pathNodeDefinitions = @(
    '/Settings/HyperV/VMFolder',
    '/Settings/HyperV/VMLocation',
    '/Settings/Configuration/InstallFolder',
    '/Settings/Configuration/VHDFolder',
    '/Settings/Configuration/SecurityBaseLineFolder',
    '/Settings/Configuration/LogFilesFolder',
    '/Settings/Configuration/LogFolder'
)

$pathValidation = @()
foreach ($xpath in $pathNodeDefinitions) {
    $rawValue = Get-PAWNodeText -Json $configXml -XPath $xpath
    if ($null -eq $rawValue) {
        continue
    }

    $resolvedPath = Resolve-PAWConfigPathValue -BaseFolder $configFolder -RawValue $rawValue
    $existsAsContainer = Test-Path -LiteralPath $resolvedPath -PathType Container
    $existsAsLeaf = Test-Path -LiteralPath $resolvedPath -PathType Leaf

    $existingType = 'Missing'
    if ($existsAsContainer) {
        $existingType = 'Container'
    }
    elseif ($existsAsLeaf) {
        $existingType = 'Leaf'
    }

    $pathValidation += [PSCustomObject]@{
        Node         = $xpath
        RawValue     = $rawValue
        ResolvedPath = $resolvedPath
        Exists       = ($existsAsContainer -or $existsAsLeaf)
        ExistingType = $existingType
    }
}

$templateFolderResolved = $configFolder

Write-Host "=== PAW Config Path Validation ===" -ForegroundColor Cyan
Write-Host "Config file: $ConfigPath" -ForegroundColor Gray
$discoveredVhdxFiles = @()

if ($pathValidation.Count -eq 0) {
    Write-Host "No path values found in known path nodes." -ForegroundColor Yellow
}
else {
    foreach ($pathItem in ($pathValidation | Sort-Object Node)) {
        Write-Host ''
        Write-Host ("=== " + $pathItem.Node + " ===") -ForegroundColor Cyan
        Write-Host ("RawValue: " + $pathItem.RawValue) -ForegroundColor Gray
        Write-Host ("ResolvedPath: " + $pathItem.ResolvedPath) -ForegroundColor Gray
        if ($pathItem.Exists) {
            Write-Host ("PathStatus: Found (" + $pathItem.ExistingType + ")") -ForegroundColor Green

            if (($pathItem.Node -eq '/Settings/Configuration/VHDFolder') -and ($pathItem.ExistingType -eq 'Container')) {
                $vhdxFiles = @(Get-ChildItem -LiteralPath $pathItem.ResolvedPath -Filter '*.vhdx' -File -ErrorAction SilentlyContinue)
                $discoveredVhdxFiles = @($vhdxFiles)
                Write-Host ("VHDXFileCount: " + $vhdxFiles.Count) -ForegroundColor Gray
                if ($vhdxFiles.Count -eq 0) {
                    Write-Warning 'No .vhdx files found in VHDFolder.'
                }
            }
        }
        else {
            Write-Host 'PathStatus: Missing' -ForegroundColor Red
        }
    }
}

Write-Host ''
Write-Host "=== Selectable JSON Templates ===" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($templateFolderResolved)) {
    Write-Host "Unable to determine the Config folder." -ForegroundColor Yellow
}
else {
    Write-Host "Template folder (resolved): $templateFolderResolved" -ForegroundColor Gray
    $templateFolderExists = Test-Path -LiteralPath $templateFolderResolved -PathType Container
    if ($templateFolderExists) {
        Write-Host 'TemplateFolderPathTest: Passed (Container found)' -ForegroundColor Green
    }
    else {
        Write-Host 'TemplateFolderPathTest: Failed (Container missing)' -ForegroundColor Red
    }

    if (-not $templateFolderExists) {
        Write-Host "Template folder does not exist." -ForegroundColor Red
    }
    else {
        $templates = Get-PAWTemplateFileCollection -TemplateFolder $templateFolderResolved
        if ($templates.Count -eq 0) {
            Write-Host "No .json template files found." -ForegroundColor Yellow
        }
        else {
            foreach ($templateItem in $templates) {
                Write-Host ''
                Write-Host ("=== Template: " + $templateItem.Name + " ===") -ForegroundColor Cyan
                Write-Host ("FileName: " + $templateItem.FileName) -ForegroundColor Gray
                Write-Host ("FullPath: " + $templateItem.FullPath) -ForegroundColor Gray
                if ($templateItem.ParseState -eq 'OK') {
                    Write-Host 'ParseState: OK' -ForegroundColor Green
                }
                else {
                    Write-Host ("ParseState: " + $templateItem.ParseState) -ForegroundColor Yellow
                }
            }

            $invalidTemplates = @($templates | Where-Object ParseState -ne 'OK')
            if ($invalidTemplates.Count -gt 0) {
                Write-Host ''
                Write-Host "Warning: one or more templates have invalid JSON." -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ''
Write-Host "=== VHDX File Access Test ===" -ForegroundColor Cyan
if ($discoveredVhdxFiles.Count -eq 0) {
    Write-Host 'No VHDX files discovered in VHDFolder.' -ForegroundColor Yellow
}
else {
    foreach ($vhdxFile in ($discoveredVhdxFiles | Sort-Object FullName)) {
        $fileExists = Test-Path -LiteralPath $vhdxFile.FullName -PathType Leaf
        $accessState = 'NotTested'
        if ($fileExists) {
            try {
                $readStream = [System.IO.File]::Open($vhdxFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $readStream.Close()
                $accessState = 'ReadAccess: OK'
            }
            catch {
                $accessState = 'ReadAccess: Failed'
            }
        }
        else {
            $accessState = 'ReadAccess: Failed (file missing)'
        }

        Write-Host ''
        Write-Host ("=== VHDX File: " + $vhdxFile.Name + " ===") -ForegroundColor Cyan
        Write-Host ("FilePath: " + $vhdxFile.FullName) -ForegroundColor Gray
        if ($fileExists) {
            Write-Host 'FileExistsTest: Passed' -ForegroundColor Green
        }
        else {
            Write-Host 'FileExistsTest: Failed' -ForegroundColor Red
        }

        if ($accessState -eq 'ReadAccess: OK') {
            Write-Host $accessState -ForegroundColor Green
        }
        else {
            Write-Host $accessState -ForegroundColor Red
        }
    }
}

Write-Host ''
Write-Host "=== Solution Version ===" -ForegroundColor Cyan
$solutionVersionMajor = Get-PAWNodeText -Json $configXml -XPath '/Settings/SolutionVersion/Major'
$solutionVersionMinor = Get-PAWNodeText -Json $configXml -XPath '/Settings/SolutionVersion/Minor'
$packageVersion = Get-PAWNodeText -Json $configXml -XPath '/Solution/Version'
if (-not [string]::IsNullOrWhiteSpace($packageVersion)) {
    Write-Host ("SolutionVersion: {0}" -f $packageVersion) -ForegroundColor Green
}
elseif ([string]::IsNullOrWhiteSpace($solutionVersionMajor) -or [string]::IsNullOrWhiteSpace($solutionVersionMinor)) {
    Write-Host 'SolutionVersion: Not configured in Config.json' -ForegroundColor Yellow
}
else {
    Write-Host ("SolutionVersion: {0}.{1}" -f $solutionVersionMajor, $solutionVersionMinor) -ForegroundColor Green
}

Write-Host ''
Write-Host "=== Environment Checks ===" -ForegroundColor Cyan

Write-Host ''
Write-Host '=== PowerShell Version ===' -ForegroundColor Cyan
$psVersionString = $PSVersionTable.PSVersion.ToString()
if (($PSVersionTable.PSVersion.Major -eq 5) -and ($PSVersionTable.PSVersion.Minor -eq 1)) {
    Write-Host ("PowerShellVersion: " + $psVersionString + ' (Pass: 5.1 detected)') -ForegroundColor Green
}
else {
    Write-Host ("PowerShellVersion: " + $psVersionString + ' (Fail: PowerShell 5.1 required)') -ForegroundColor Red
}

Write-Host ''
Write-Host '=== PAWUtility Module ===' -ForegroundColor Cyan
$installFolderRaw = Get-PAWNodeText -Json $configXml -XPath '/Settings/Configuration/InstallFolder'
$installFolderResolved = $null
if (-not [string]::IsNullOrWhiteSpace($installFolderRaw)) {
    $installFolderResolved = Resolve-PAWConfigPathValue -BaseFolder $configFolder -RawValue $installFolderRaw
}

$pawUtilityManifestCandidates = @()
if (-not [string]::IsNullOrWhiteSpace($installFolderResolved)) {
    $pawUtilityManifestCandidates += (Join-Path $installFolderResolved 'Functions\PAWUtility\PAWUtility.psd1')
}
$pawUtilityManifestCandidates += (Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1')

$pawUtilityManifestPath = $null
foreach ($candidateManifest in $pawUtilityManifestCandidates) {
    if (Test-Path -LiteralPath $candidateManifest -PathType Leaf) {
        $pawUtilityManifestPath = $candidateManifest
        break
    }
}

if ([string]::IsNullOrWhiteSpace($pawUtilityManifestPath)) {
    Write-Host 'PAWUtilityManifest: Missing' -ForegroundColor Red
    Write-Host 'PAWUtilityLoadable: Failed' -ForegroundColor Red
}
else {
    Write-Host ("PAWUtilityManifest: " + $pawUtilityManifestPath) -ForegroundColor Gray
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $importedModule = Import-Module -Name $pawUtilityManifestPath -Force -PassThru -ErrorAction Stop
        Write-Host 'PAWUtilityLoadable: Passed' -ForegroundColor Green
        if ($null -ne $importedModule) {
            Remove-Module -Name $importedModule.Name -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host 'PAWUtilityLoadable: Failed' -ForegroundColor Red
        Write-Host ("PAWUtilityLoadError: " + $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host "=== Script Version Checks ===" -ForegroundColor Cyan

$scriptVersionTargets = @(
    'New-PAWVM.ps1',
    'Tools\Convert-PAWWIM2VHD.ps1',
    'Tools\Remove-PAWVM.ps1',
    'Tools\PAWDeployUI.ps1',
    'Tools\PAWConfigEditorUI.ps1',
    'Tools\PAWTemplateEditorUI.ps1',
    'Tools\PAWVHDXImportUI.ps1',
    'Tools\Import-PAWVHDX.ps1',
    'Tools\Invoke-PAWConfigurationSettings.ps1',
    'Tools\Invoke-PAWTemplateSettings.ps1',
    'Tools\Invoke-PAWApplicationSettings.ps1',
    'Tools\Invoke-PAWApplicationDownload.ps1',
    'Tools\Invoke-PAWApplicationManager.ps1',
    'Tools\PAWApplicationManagerUI.ps1',
    'PAWMenu.ps1'
)

$scriptVersionTargets += @(
        'Tools\PAWRemoveVMUI.ps1',
        'Tools\PAWWIM2VHDUI.ps1'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $scriptFolder $_) -PathType Leaf }

foreach ($scriptName in $scriptVersionTargets) {
    $targetPath = Join-Path $scriptFolder $scriptName
    Write-Host ''
    Write-Host ("=== " + $scriptName + " ===") -ForegroundColor Cyan

    if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        Write-Host ("Error " + $scriptName + " is missing") -ForegroundColor Red
        continue
    }

    $scriptRaw = Get-Content -LiteralPath $targetPath -Raw
    $detectedVersion = Get-PAWScriptVersion -ScriptContent $scriptRaw
    if (-not [string]::IsNullOrWhiteSpace($detectedVersion)) {
        Write-Host ($scriptName + " Version: " + $detectedVersion) -ForegroundColor Green
    }
    else {
        Write-Host ($scriptName + ' Version: Unknown') -ForegroundColor Yellow
    }
}
