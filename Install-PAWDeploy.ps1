<#
.SYNOPSIS
    Installs or upgrades PAWDeploy to a target path.
.DESCRIPTION
    Installs the PAWDeploy solution to a specific folder path.

    - If the target folder does not exist, this is treated as a new install:
      all files are copied and Config.json paths are updated to match the chosen
      install path, image location, and optional VM storage location.
    - If the target folder already exists, this is treated as an upgrade:
      all files are overwritten except content in Config and Resources,
      .vhdx files       and existing application catalog, bundle, download and package payload files
      under Resources.
      Legacy application-list migration is not performed.

    By default, PAW images are installed to <Path>\VHDFolder. Use -ImageLocation
    to place PAWImages somewhere else. Use -VMLocation to set the configured
    Hyper-V VM storage folder.
    Use -Theme to choose System, Dark, Light or another theme filename under
    PAWDeploy\Assets\Themes. System resolves to the current Windows app appearance
    setting and is saved as Dark or Light.

    The provided paths must be on existing drives and writable.
    All operations, including self-test, require an elevated local administrator.
    After a successful install or upgrade, the current location changes to the
    install path.
    Use -WhatIf to preview changes without creating install or image folders,
    probing write access, copying files, updating configuration, or creating
    shortcuts. No log file is written.
.PARAMETER Path
    The destination folder for the PAWDeploy content.
    Example: C:\PAWDeploy
.PARAMETER ImageLocation
    Optional destination folder for PAWImages. If omitted, defaults to
    <Path>\VHDFolder.
.PARAMETER VMLocation
    Optional Hyper-V VM storage folder. When specified, updates
    Settings.HyperV.VMFolder in Config.json. If omitted, the configured value
    is preserved. The path must be on a valid drive with a writable parent.
.PARAMETER Theme
    Optional UI theme name. System resolves to the current Windows app appearance
    setting and is saved as Dark or Light. Any other value must match a JSON
    filename under PAWDeploy\Assets\Themes. When omitted, both installs and
    upgrades use the current Windows setting. Tab completion suggests Dark and Light.
.PARAMETER Force
    Skips the interactive upgrade confirmation when the destination Path already
    exists.

    When used together with -Uninstall, it allows PAWImages folders under -Path
    to also be removed, but only after an additional confirmation prompt.
.PARAMETER Uninstall
    Removes the folder specified by -Path. This switch can only be used together
    with -Path.

    The image location is never deleted. If it is under -Path, all other
    content under -Path is deleted except the image location.
.PARAMETER SelfTest
    Runs a small built-in self-test for JSON config path update logic and exits.
    When this switch is used, -Path is ignored.
.PARAMETER SkipShortCut
    Skips creation of install-time shortcuts in the install folder and Start menu.
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path C:\PAWDeploy
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path D:\Tools\PAWDeploy -ImageLocation E:\PAWImages -Verbose
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path C:\PAWDeploy -VMLocation D:\VMs
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path C:\PAWDeploy -Theme Dark
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path C:\PAWDeploy -Force
.EXAMPLE
    .\Install-PAWDeploy.ps1 -Path C:\PAWDeploy -Uninstall
.EXAMPLE
    .\Install-PAWDeploy.ps1 -SelfTest
.NOTES
    Version : 2.0.0.25
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$ImageLocation,

    [Parameter(Mandatory = $false)]
    [string]$VMLocation,

    [Parameter(Mandatory = $false)]
    [ArgumentCompleter({
        param($CommandName, $ParameterName, $WordToComplete)
        'Dark', 'Light' | Where-Object { $_ -like "$WordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    })]
    [string]$Theme,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$Uninstall

    ,
    [Parameter(Mandatory = $false)]
    [switch]$SelfTest,

    [Parameter(Mandatory = $false)]
    [switch]$SkipShortCut
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptName = Split-Path -Leaf $MyInvocation.MyCommand.Path

function New-PAWInstallShortcut {
    # Self-contained: the installer must not load modules or helper files.
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DestinationFile,

        [Parameter(Mandatory = $false)]
        [string]$Arguments,

        [Parameter(Mandatory = $false)]
        [switch]$RunAsAdmin
    )

    $destinationDirectory = Split-Path -Path $DestinationFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -Path $destinationDirectory)) {
        New-Item -Path $destinationDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if ($PSCmdlet.ShouldProcess($DestinationFile, "Create shortcut to '$TargetPath'")) {
        $wshShell = New-Object -ComObject WScript.Shell
        $shortCut = $wshShell.CreateShortcut($DestinationFile)
        $shortCut.TargetPath = $TargetPath
        if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
            $shortCut.Arguments = $Arguments
        }
        $shortCut.Save()
    }

    if ($RunAsAdmin -and (Test-Path -Path $DestinationFile)) {
        if ($PSCmdlet.ShouldProcess($DestinationFile, 'Set RunAsAdmin flag')) {
            $bytes = [System.IO.File]::ReadAllBytes($DestinationFile)
            # Byte 0x15, bit 0x20 is the .lnk "Run as administrator" flag.
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($DestinationFile, $bytes)
        }
    }

    Get-Item -Path $DestinationFile -ErrorAction Stop
}

function Resolve-PAWAbsolutePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath
    )

    if (Test-Path -Path $InputPath) {
        return (Resolve-Path -Path $InputPath).Path
    }

    return [System.IO.Path]::GetFullPath($InputPath)
}

function Test-PAWWritableLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetPath,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolvedTarget = Resolve-PAWAbsolutePath -InputPath $TargetPath
    $driveRoot      = [System.IO.Path]::GetPathRoot($resolvedTarget)

    if ([string]::IsNullOrWhiteSpace($driveRoot) -or -not (Test-Path -Path $driveRoot -PathType Container)) {
        throw "$Description '$TargetPath' is not on a valid drive."
    }

    $probeParent = if (Test-Path -Path $resolvedTarget -PathType Container) {
        $resolvedTarget
    }
    else {
        [System.IO.Path]::GetDirectoryName($resolvedTarget)
    }

    if ([string]::IsNullOrWhiteSpace($probeParent)) {
        $probeParent = $driveRoot
    }

    if (-not (Test-Path -Path $probeParent -PathType Container)) {
        throw "$Description '$TargetPath' is invalid because parent path '$probeParent' does not exist."
    }

    $probeFolder = Join-Path $probeParent ('.pawdeploy_write_probe_' + [guid]::NewGuid().ToString('N'))
    if ($PSCmdlet.ShouldProcess($probeParent, 'Check write access using a temporary probe folder')) {
        try {
            New-Item -Path $probeFolder -ItemType Directory -Force | Out-Null
        }
        catch {
            throw "Unable to write to $Description '$TargetPath'. Error: $($_.Exception.Message)"
        }
        finally {
            if (Test-Path -Path $probeFolder) {
                Remove-Item -Path $probeFolder -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    return $resolvedTarget
}

function Test-PAWIsSameOrSubPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RootPath
    )

    if ([string]::Equals($Path, $RootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }

        $normalizedRoot = $RootPath.TrimEnd('\', '/') + '\'
    return $Path.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PAWRebasedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$OldRoot,

        [Parameter(Mandatory = $true)]
        [string]$NewRoot
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $Value
    }

    $trimmedValue = $Value.Trim()
    if (-not $trimmedValue.StartsWith($OldRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $Value
    }

    if ($trimmedValue.Length -eq $OldRoot.Length) {
        return $NewRoot
    }

    $nextChar = $trimmedValue.Substring($OldRoot.Length, 1)
    if ($nextChar -notin @('\', '/')) {
        return $Value
    }

    $suffix = $trimmedValue.Substring($OldRoot.Length).TrimStart('\', '/')
    return (Join-Path $NewRoot $suffix)
}

function Normalize-PAWCommandLinePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $trimmed = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        return $trimmed
    }

    $root = [System.IO.Path]::GetPathRoot($trimmed)
    if (-not [string]::IsNullOrWhiteSpace($root) -and [string]::Equals($trimmed, $root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $trimmed
    }

    return $trimmed.TrimEnd('\', '/')
}

function Set-PAWJsonPropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Value
    )

    $Object | Add-Member -NotePropertyName $Name -NotePropertyValue ([string]$Value) -Force
}

function Get-PAWJsonPropertyValue {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($null -eq $Object.PSObject.Properties[$Name]) {
        return $null
    }

    return [string]$Object.$Name
}

function Copy-PAWBrandingAssets {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$InstallPath
    )
    $files = @(
        'PAW-Deployment-Toolkit-Full-Logo.png',
        'PAW-Deployment-Toolkit-Horizontal-Logo.png',
        'PAW-Deployment-Toolkit-App-Icon.png',
        'PAW-Deployment-Toolkit-Logo-Color.png',
        'DeploymentBunnyLogo.png',
        'Truesec-Logo-Small-White-Community-Editidion.png',
        'Truesec-Logo-Small-White-Enterprise-Editidion.png'
    )
    $sources = foreach ($file in $files) {
        $source = Join-Path $SourceRoot "Resources\$file"
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            $source = Join-Path $SourceRoot "PAWDeploy\Assets\img\$file"
        }
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required branding image not found: $file" }
        $source
    }
    $destination = Join-Path $InstallPath 'Assets\img'
    foreach ($source in $sources) {
        $target = Join-Path $destination ([IO.Path]::GetFileName($source))
        if ($PSCmdlet.ShouldProcess($target, 'Install toolkit branding image')) {
            $null = New-Item -Path $destination -ItemType Directory -Force -ErrorAction Stop
            Copy-Item -LiteralPath $source -Destination $target -Force -ErrorAction Stop
        }
    }
}

function Set-PAWInstallTheme {
    param(
        [Parameter(Mandatory = $true)][string]$InstallPath,
        [Parameter(Mandatory = $true)][string]$ThemeName
    )

    $settingsPath = Join-Path $InstallPath 'Config\Config.json'
    if ($PSCmdlet.ShouldProcess($settingsPath, "Set PAWDeploy UI theme to '$ThemeName'")) {
        $config = Get-Content -LiteralPath $settingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $config.Settings.Configuration | Add-Member -NotePropertyName UITheme -NotePropertyValue $ThemeName -Force
        $config | ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $settingsPath -Encoding UTF8 -ErrorAction Stop
    }
}

function Resolve-PAWInstallThemeName {
    param([Parameter(Mandatory = $true)][string]$ThemeName)

    if (-not [string]::Equals($ThemeName, 'System', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $ThemeName
    }

    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize')
    if ($null -eq $key) {
        return 'Dark'
    }
    try {
        $useLightTheme = $key.GetValue('AppsUseLightTheme', $null)
    }
    finally {
        $key.Dispose()
    }
    if ($null -eq $useLightTheme) {
        return 'Dark'
    }
    return $(if ([int]$useLightTheme -eq 0) { 'Dark' } else { 'Light' })
}

function Get-PAWRebasedInstallPathValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CurrentValue,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath
    )

    $value = $CurrentValue.Trim()
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $CurrentValue
    }

    if ($value.StartsWith($InstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $value
    }

    $marker = '\PAWDeploy\'
    $markerIndex = $value.IndexOf($marker, [System.StringComparison]::OrdinalIgnoreCase)
    if ($markerIndex -ge 0) {
        $suffix = $value.Substring($markerIndex + $marker.Length)
        return (Join-Path $InstallPath $suffix)
    }

    if ($value.EndsWith('\PAWDeploy', [System.StringComparison]::OrdinalIgnoreCase)) {
        return $InstallPath
    }

    return $value
}

function Update-PAWConfigForInstallPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$ImagesPath
    )

    $configJson = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $changes = New-Object System.Collections.Generic.List[string]

    # Read the current root paths from Config.json so nothing is hardcoded
    $oldInstallRoot = Get-PAWJsonPropertyValue -Object $configJson.Settings.Configuration -Name 'InstallFolder'
    $oldImageRoot   = Get-PAWJsonPropertyValue -Object $configJson.Settings.Configuration -Name 'VHDFolder'
    if ([string]::IsNullOrWhiteSpace($oldImageRoot)) {
        $oldImageRoot = Get-PAWJsonPropertyValue -Object $configJson.Settings.Configuration -Name 'ImageLocation'
    }
    if ([string]::IsNullOrWhiteSpace($oldImageRoot)) {
        $oldImageRoot = Get-PAWJsonPropertyValue -Object $configJson.Settings.Configuration -Name 'IImageLocation'
    }

    $templates = @($configJson.Settings.Templates)
    if ([string]::IsNullOrWhiteSpace($oldInstallRoot)) {
        foreach ($templateCandidate in $templates) {
            foreach ($candidatePropertyName in @('ExtraFolder', 'SecurityBaselineLocation')) {
                $candidateValue = Get-PAWJsonPropertyValue -Object $templateCandidate -Name $candidatePropertyName
                if ([string]::IsNullOrWhiteSpace($candidateValue)) {
                    continue
                }

                $candidateParent = Split-Path -Path $candidateValue -Parent
                if (-not [string]::IsNullOrWhiteSpace($candidateParent)) {
                    $oldInstallRoot = $candidateParent
                    break
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($oldInstallRoot)) {
                break
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($oldInstallRoot)) { $oldInstallRoot = $InstallPath }
    if ([string]::IsNullOrWhiteSpace($oldImageRoot)) {
        foreach ($templateCandidate in $templates) {
            $firstVhdValue = Get-PAWJsonPropertyValue -Object $templateCandidate -Name 'VHDFile'
            if (-not [string]::IsNullOrWhiteSpace($firstVhdValue)) {
                $firstVhdFolder = Split-Path -Path $firstVhdValue -Parent
                if (-not [string]::IsNullOrWhiteSpace($firstVhdFolder)) {
                    $oldImageRoot = $firstVhdFolder
                    break
                }
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($oldImageRoot)) { $oldImageRoot = $ImagesPath }

    foreach ($template in $templates) {
        $templateName = Get-PAWJsonPropertyValue -Object $template -Name 'Name'
        if ([string]::IsNullOrWhiteSpace($templateName)) {
            $templateName = '<UnnamedTemplate>'
        }

        $pathDefinitions = @(
            @{ Name = 'VHDFile';                  OldRoot = $oldImageRoot;   NewRoot = $ImagesPath },
            @{ Name = 'ExtraFolder';              OldRoot = $oldInstallRoot; NewRoot = $InstallPath },
            @{ Name = 'SecurityBaselineLocation'; OldRoot = $oldInstallRoot; NewRoot = $InstallPath }
        )

        foreach ($pathDefinition in $pathDefinitions) {
            $oldValue = Get-PAWJsonPropertyValue -Object $template -Name $pathDefinition.Name
            if ([string]::IsNullOrWhiteSpace($oldValue)) {
                continue
            }

            $newValue = Get-PAWRebasedPath -Value $oldValue -OldRoot $pathDefinition.OldRoot -NewRoot $pathDefinition.NewRoot
            if ([string]::Equals($oldValue, $newValue, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            Set-PAWJsonPropertyValue -Object $template -Name $pathDefinition.Name -Value $newValue
            $changes.Add("Template '$templateName' | $($pathDefinition.Name): '$oldValue' -> '$newValue'")
        }
    }

    if ($changes.Count -gt 0) {
        ($configJson | ConvertTo-Json -Depth 20) | Set-Content -Path $ConfigPath -Encoding UTF8
    }

    return [pscustomobject]@{
        UpdatedCount = $changes.Count
        Changes      = @($changes)
    }
}

function Get-PAWShellHostPath {
    [CmdletBinding()]
    param()

    # $PSHOME points at whichever host is currently running (Windows PowerShell or PowerShell 7),
    # but the executable name differs between editions, so it must be selected explicitly.
    $hostExeName = if ($PSVersionTable.PSEdition -eq 'Core' -or $PSVersionTable.PSVersion.Major -ge 6) {
        'pwsh.exe'
    }
    else {
        'powershell.exe'
    }

    $hostPath = Join-Path $PSHOME $hostExeName
    if (-not (Test-Path -Path $hostPath -PathType Leaf)) {
        throw "Unable to locate PowerShell host executable: $hostPath"
    }

    return $hostPath
}

function Test-PAWInstallAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
}

function New-PAWConfigEditorShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallPath
    )

    $shortcutPath = Join-Path $InstallPath 'ShortCuts\PAW Configuration Editor.lnk'
    $targetScript = Join-Path $InstallPath 'Tools\PAWConfigEditorUI.ps1'
    $configPath = Join-Path $InstallPath 'Config\Config.json'

    if (-not (Test-Path -Path $targetScript -PathType Leaf)) {
        Write-Warning "Skipping config editor shortcut because target script was not found: $targetScript"
        return
    }

    $null = New-PAWInstallShortcut -TargetPath (Get-PAWShellHostPath) -DestinationFile $shortcutPath -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$targetScript`" -ConfigPath `"$configPath`"" -RunAsAdmin

    Write-Host -ForegroundColor Green "Created shortcut: $shortcutPath"
}

function Rename-PAWConfigEditorShortcut {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallPath
    )

    $shortcutFolder = Join-Path $InstallPath 'ShortCuts'
    $legacyShortcut = Join-Path $shortcutFolder 'PAW Config Editor.lnk'
    $newShortcut = Join-Path $shortcutFolder 'PAW Configuration Editor.lnk'
    if (-not (Test-Path -LiteralPath $legacyShortcut -PathType Leaf)) { return }
    if (Test-Path -LiteralPath $newShortcut -PathType Leaf) {
        throw "Shortcuts exist at both '$legacyShortcut' and '$newShortcut'. Resolve the conflict before upgrading."
    }
    if ($PSCmdlet.ShouldProcess($legacyShortcut, "Rename shortcut to '$newShortcut'")) {
        Rename-Item -LiteralPath $legacyShortcut -NewName 'PAW Configuration Editor.lnk' -ErrorAction Stop
    }
}

function Move-PAWConfigurationLayout {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallPath
    )

    $configFolder = Join-Path $InstallPath 'Config'
    $configPath = Join-Path $configFolder 'Config.json'
    $legacyConfigPath = Join-Path $InstallPath 'Config.json'
    $hasLegacyConfig = Test-Path -LiteralPath $legacyConfigPath -PathType Leaf
    if ($hasLegacyConfig -and (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Configuration exists at both '$legacyConfigPath' and '$configPath'. Resolve the conflict before upgrading."
    }

    $sourceConfigPath = $configPath
    if ($hasLegacyConfig) {
        $sourceConfigPath = $legacyConfigPath
    }
    $templateFolders = @((Join-Path $InstallPath 'TemplateFolder'), (Join-Path $InstallPath 'Templates'))
    $configJson = $null
    if (Test-Path -LiteralPath $sourceConfigPath -PathType Leaf) {
        $configJson = Get-Content -LiteralPath $sourceConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $configJson.PSObject.Properties['Settings'] -or $null -eq $configJson.Settings) {
            throw "Config.json is missing the Settings root object."
        }
        foreach ($nodeName in @('TemplateFolder', 'TemplatesFolder', 'Templates')) {
            $folder = $null
            if ($null -ne $configJson.Settings.PSObject.Properties['Configuration']) {
                $folder = Get-PAWJsonPropertyValue -Object $configJson.Settings.Configuration -Name $nodeName
            }
            if ([string]::IsNullOrWhiteSpace($folder)) { continue }
            $folder = [Environment]::ExpandEnvironmentVariables($folder.Trim())
            if (-not [IO.Path]::IsPathRooted($folder)) {
                $folder = Join-Path (Split-Path -Parent $sourceConfigPath) $folder
            }
            $folder = [IO.Path]::GetFullPath($folder).TrimEnd('\')
            if ($folder -ne $configFolder.TrimEnd('\')) {
                $templateFolders += $folder
            }
        }
    }

    $plan = @()
    $destinations = @{}
    $rebaseTemplate = {
        param([object]$Template)
        $changed = $false
        foreach ($nodeName in @('VHDFile', 'SecurityBaselineLocation', 'ExtraFolder')) {
            $value = Get-PAWJsonPropertyValue -Object $Template -Name $nodeName
            if ([string]::IsNullOrWhiteSpace($value)) { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables($value)
            if (-not [IO.Path]::IsPathRooted($expanded) -and ($nodeName -eq 'ExtraFolder' -or $expanded -match '[\\/]')) {
                $Template.$nodeName = [IO.Path]::GetFullPath((Join-Path $InstallPath $expanded))
                $changed = $true
            }
        }
        return $changed
    }
    foreach ($folder in @($templateFolders | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
        if ([IO.Path]::GetFullPath($folder).TrimEnd('\') -eq $InstallPath.TrimEnd('\')) {
            $files = @(Get-ChildItem -LiteralPath $folder -File -Filter '*.json' -ErrorAction Stop | Where-Object Name -ne 'Config.json')
        }
        else {
            $files = @(Get-ChildItem -LiteralPath $folder -File -Recurse -ErrorAction Stop)
        }
        foreach ($file in $files) {
            $relative = $file.FullName.Substring($folder.TrimEnd('\').Length).TrimStart('\')
            $destination = Join-Path $configFolder $relative
            if ($destinations.ContainsKey($destination) -and $destinations[$destination] -eq $file.FullName) { continue }
            if ($destination -eq $configPath -or (Test-Path -LiteralPath $destination) -or $destinations.ContainsKey($destination)) {
                throw "Cannot migrate '$($file.FullName)' to '$destination': destination conflict. Resolve it before upgrading."
            }
            $destinations[$destination] = $file.FullName
            $content = $null
            if ($hasLegacyConfig -and $file.Extension -eq '.json') {
                $rawContent = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                try {
                    $template = $rawContent | ConvertFrom-Json -ErrorAction Stop
                    if (& $rebaseTemplate $template) {
                        $content = $template | ConvertTo-Json -Depth 20
                    }
                }
                catch {
                    Write-Warning "Migrating template '$($file.FullName)' unchanged because it could not be normalized: $($_.Exception.Message)"
                }
            }
            $plan += @{ Source = $file.FullName; Destination = $destination; Move = (Test-PAWIsSameOrSubPath -Path $file.FullName -RootPath $InstallPath); Content = $content }
        }
    }

    if ($hasLegacyConfig -and $PSCmdlet.ShouldProcess($legacyConfigPath, "Move configuration to $configPath")) {
        # Relative settings previously used the installation root as their base.
        $configurationProperties = @()
        if ($null -ne $configJson.Settings.PSObject.Properties['Configuration'] -and $null -ne $configJson.Settings.Configuration) {
            $configurationProperties = @($configJson.Settings.Configuration.PSObject.Properties)
        }
        foreach ($property in $configurationProperties) {
            if ($property.Name -notin @('InstallFolder', 'VHDFolder', 'ImageLocation', 'IImageLocation', 'SecurityBaseLineFolder', 'SecurityBaselineFolder', 'SecurityBaselines')) { continue }
            $value = [Environment]::ExpandEnvironmentVariables([string]$property.Value)
            if (-not [string]::IsNullOrWhiteSpace($value) -and -not [IO.Path]::IsPathRooted($value)) {
                $property.Value = [IO.Path]::GetFullPath((Join-Path $InstallPath $value))
            }
            $hyperVProperties = @()
            if ($null -ne $configJson.Settings.PSObject.Properties['HyperV'] -and $null -ne $configJson.Settings.HyperV) {
                $hyperVProperties = @($configJson.Settings.HyperV.PSObject.Properties)
            }
            foreach ($property in $hyperVProperties) {
                if ($property.Name -notin @('VMFolder', 'VMLocation')) { continue }
                $value = [Environment]::ExpandEnvironmentVariables([string]$property.Value)
                if (-not [string]::IsNullOrWhiteSpace($value) -and -not [IO.Path]::IsPathRooted($value)) {
                    $property.Value = [IO.Path]::GetFullPath((Join-Path $InstallPath $value))
                }
            }
            if ($null -ne $configJson.Settings.PSObject.Properties['Templates']) {
                foreach ($template in @($configJson.Settings.Templates)) {
                    if ($null -ne $template) {
                        $null = & $rebaseTemplate $template
                    }
                }
            }
        }
        New-Item -Path $configFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        $configJson | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $legacyConfigPath -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $legacyConfigPath -Destination $configPath -ErrorAction Stop
    }

    foreach ($entry in $plan) {
        if ($PSCmdlet.ShouldProcess($entry.Source, "Migrate template content to $($entry.Destination)")) {
            New-Item -Path (Split-Path -Parent $entry.Destination) -ItemType Directory -Force -ErrorAction Stop | Out-Null
            if ($entry.Move) {
                Move-Item -LiteralPath $entry.Source -Destination $entry.Destination -ErrorAction Stop
            }
            else {
                Copy-Item -LiteralPath $entry.Source -Destination $entry.Destination -ErrorAction Stop
            }
            if ($null -ne $entry.Content) {
                Set-Content -LiteralPath $entry.Destination -Value $entry.Content -Encoding UTF8 -ErrorAction Stop
            }
        }
    }
    foreach ($folder in @((Join-Path $InstallPath 'TemplateFolder'), (Join-Path $InstallPath 'Templates'))) {
        if ((Test-Path -LiteralPath $folder -PathType Container) -and -not (Get-ChildItem -LiteralPath $folder -Force | Select-Object -First 1)) {
            if ($PSCmdlet.ShouldProcess($folder, 'Remove empty legacy template folder')) {
                Remove-Item -LiteralPath $folder -ErrorAction Stop
            }
        }
    }
    if ($WhatIfPreference -and $hasLegacyConfig) {
        return $legacyConfigPath
    }
    return $configPath
}

function New-PAWInstallScriptShortcut {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [string]$ShortcutName,

        [Parameter(Mandatory = $false)]
        [string[]]$AdditionalArguments
    )

    $targetScript = Join-Path (Join-Path $InstallPath 'Tools') $ScriptName
    if ($ScriptName -eq 'PAWMenu.ps1') {
        $targetScript = Join-Path $InstallPath $ScriptName
    }
    if (-not (Test-Path -Path $targetScript -PathType Leaf)) {
        Write-Warning "Skipping shortcut because target script was not found: $targetScript"
        return
    }

    $shortcutPath = Join-Path (Join-Path $InstallPath 'ShortCuts') $ShortcutName
    $shortcutArguments = @(
        '-NoProfile',
        '-ExecutionPolicy Bypass',
        "-File `"$targetScript`""
    )

    if (@($AdditionalArguments | Where-Object { $null -ne $_ }).Count -gt 0) {
        $shortcutArguments += $AdditionalArguments
    }

    $null = New-PAWInstallShortcut -TargetPath (Get-PAWShellHostPath) -DestinationFile $shortcutPath -Arguments ($shortcutArguments -join ' ') -RunAsAdmin
    Write-Host -ForegroundColor Green "Created shortcut: $shortcutPath"
}

function New-PAWStartMenuShortcuts {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$InstallPath,
        [Parameter(Mandatory = $true)][string]$ProgramsPath
    )

    $menu = Join-Path $SourcePath 'PAWMenu.ps1'
    if (-not (Test-Path -LiteralPath $menu -PathType Leaf)) {
        throw "Cannot determine the edition: source menu not found: $menu"
    }
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($menu, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw "Cannot determine the edition: source menu contains syntax errors: $menu" }
    $assignments = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$script:PAWEdition' -and
            $node.Right.Extent.Text -match '^[''"](Community|Enterprise)[''"]$'
    }, $true))
    if ($assignments.Count -ne 1) { throw "Cannot determine the edition from source menu: $menu" }
    $edition = $assignments[0].Right.Find({
        param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
    }, $true).Value
    $folder = Join-Path $ProgramsPath "PAW $edition Toolkit"
    $tools = Join-Path $SourcePath 'Tools'
    if (-not (Test-Path -LiteralPath $tools -PathType Container)) {
        throw "Cannot create Start menu shortcuts: source tools folder not found: $tools"
    }
    $names = @{
        'PAWASREditorUI.ps1' = 'PAW ASR Master List.lnk'
        'PAWApplicationManagerUI.ps1' = 'PAW Application Manager.lnk'
        'PAWConfigEditorUI.ps1' = 'PAW Configuration Editor.lnk'
        'PAWDeployUI.ps1' = 'PAW Deploy.lnk'
        'PAWHelpUI.ps1' = 'PAW Help.lnk'
        'PAWLogsUI.ps1' = 'PAW Logs.lnk'
        'PAWRemoveVMUI.ps1' = 'PAW Remove VM.lnk'
        'PAWTemplateEditorUI.ps1' = 'PAW Template Editor.lnk'
        'PAWVHDXImportUI.ps1' = 'PAW VHDX Import.lnk'
        'PAWWIM2VHDUI.ps1' = 'PAW WIM-2-VHD.lnk'
    }
    $shortcuts = @(
        [pscustomobject]@{ Name = 'PAW Menu.lnk'; Target = (Join-Path $InstallPath 'PAWMenu.ps1') }
        foreach ($script in @(Get-ChildItem -LiteralPath $tools -Filter '*UI.ps1' -File -ErrorAction Stop)) {
            $name = if ($names.ContainsKey($script.Name)) { $names[$script.Name] } else { "$($script.BaseName).lnk" }
            [pscustomobject]@{ Name = $name; Target = (Join-Path $InstallPath "Tools\$($script.Name)") }
        }
    )
    $duplicates = @($shortcuts | Group-Object Name | Where-Object Count -gt 1)
    if ($duplicates.Count) { throw "Duplicate Start menu shortcut name: $($duplicates[0].Name)" }
    $shell = $null
    $matchesTarget = {
        param($existing, $target)
        $pattern = '(?i)(?:^|\s)-File\s+"' + [regex]::Escape($target) + '"(?:\s|$)'
        [IO.Path]::GetFileName($existing.TargetPath) -in @('powershell.exe', 'pwsh.exe') -and
            $existing.Arguments -match $pattern
    }
    foreach ($shortcut in $shortcuts) {
        $path = Join-Path $folder $shortcut.Name
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Start menu shortcut path is not a file: $path" }
            if ($null -eq $shell) { $shell = New-Object -ComObject WScript.Shell }
            $existing = $shell.CreateShortcut($path)
            if (-not (& $matchesTarget $existing $shortcut.Target)) {
                throw "Start menu shortcut already exists with a different target: $path"
            }
        }
    }
    $migrated = New-Object 'System.Collections.Generic.List[object]'
    foreach ($shortcut in $shortcuts) {
        $path = Join-Path $folder $shortcut.Name
        if ($PSCmdlet.ShouldProcess($path, "Create Start menu shortcut for $($shortcut.Target)")) {
            if (-not (Test-Path -LiteralPath $shortcut.Target -PathType Leaf)) {
                throw "Cannot create Start menu shortcut; target not found: $($shortcut.Target)"
            }
            $arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($shortcut.Target)`""
            $null = New-PAWInstallShortcut -TargetPath (Get-PAWShellHostPath) -DestinationFile $path -Arguments $arguments -RunAsAdmin
            Write-Host -ForegroundColor Green "Created Start menu shortcut: $path"
            $migrated.Add($shortcut)
        }
        elseif ($WhatIfPreference) { $migrated.Add($shortcut) }
    }
    $legacy = Join-Path $ProgramsPath 'PAW Toolkit'
    if (Test-Path -LiteralPath $legacy -PathType Container) {
        $legacyItem = Get-Item -LiteralPath $legacy -Force -ErrorAction Stop
        if ($legacyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Write-Warning "Skipping legacy Start menu folder because it is a link: $legacy"
        }
        else {
            foreach ($shortcut in $migrated) {
                $path = Join-Path $legacy $shortcut.Name
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
                if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($null -eq $shell) { $shell = New-Object -ComObject WScript.Shell }
                if ((& $matchesTarget ($shell.CreateShortcut($path)) $shortcut.Target) -and
                    $PSCmdlet.ShouldProcess($path, 'Remove migrated Start menu shortcut')) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
                }
            }
            if (-not (Get-ChildItem -LiteralPath $legacy -Force -ErrorAction Stop | Select-Object -First 1) -and
                $PSCmdlet.ShouldProcess($legacy, 'Remove empty legacy Start menu folder')) {
                Remove-Item -LiteralPath $legacy -Force -ErrorAction Stop
            }
        }
    }
}

function Update-PAWConfigVhdImageLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $true)]
        [string]$ImagesPath
    )

    $configJson = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $templates = @($configJson.Settings.Templates)
    $updatedCount = 0
    $changes = New-Object System.Collections.Generic.List[string]

    foreach ($template in $templates) {
        $templateName = Get-PAWJsonPropertyValue -Object $template -Name 'Name'
        if ([string]::IsNullOrWhiteSpace($templateName)) {
            $templateName = '<UnnamedTemplate>'
        }

        $currentVhdPath = Get-PAWJsonPropertyValue -Object $template -Name 'VHDFile'
        if ([string]::IsNullOrWhiteSpace($currentVhdPath)) {
            continue
        }

        $currentFolder = Split-Path -Path $currentVhdPath -Parent
        if ([string]::IsNullOrWhiteSpace($currentFolder)) {
            continue
        }

        if ([string]::Equals($currentFolder, $ImagesPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $fileName = Split-Path -Path $currentVhdPath -Leaf
        if ([string]::IsNullOrWhiteSpace($fileName)) {
            continue
        }

        $newVhdPath = Join-Path $ImagesPath $fileName
        Set-PAWJsonPropertyValue -Object $template -Name 'VHDFile' -Value $newVhdPath
        $updatedCount++
        $changes.Add("Template '$templateName' | VHDFile: '$currentVhdPath' -> '$newVhdPath'")
    }

    if ($updatedCount -gt 0) {
        ($configJson | ConvertTo-Json -Depth 20) | Set-Content -Path $ConfigPath -Encoding UTF8
    }

    return [pscustomobject]@{
        UpdatedCount = $updatedCount
        Changes      = @($changes)
    }
}

function Update-PAWConfigUpgradeInstallPaths {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath
    )

    $configJson = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $templates = @($configJson.Settings.Templates)
    $updatedCount = 0
    $changes = New-Object System.Collections.Generic.List[string]

    foreach ($template in $templates) {
        $templateName = Get-PAWJsonPropertyValue -Object $template -Name 'Name'
        if ([string]::IsNullOrWhiteSpace($templateName)) {
            $templateName = '<UnnamedTemplate>'
        }

        foreach ($propertyName in @('ExtraFolder', 'SecurityBaselineLocation')) {
            $oldValue = Get-PAWJsonPropertyValue -Object $template -Name $propertyName
            if ([string]::IsNullOrWhiteSpace($oldValue)) {
                continue
            }

            $newValue = Get-PAWRebasedInstallPathValue -CurrentValue $oldValue -InstallPath $InstallPath
            if ([string]::Equals($oldValue, $newValue, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            Set-PAWJsonPropertyValue -Object $template -Name $propertyName -Value $newValue
            $updatedCount++
            $changes.Add("Template '$templateName' | ${propertyName}: '$oldValue' -> '$newValue'")
        }
    }

    if ($updatedCount -gt 0) {
        ($configJson | ConvertTo-Json -Depth 20) | Set-Content -Path $ConfigPath -Encoding UTF8
    }

    return [pscustomobject]@{
        UpdatedCount = $updatedCount
        Changes      = @($changes)
    }
}

function Update-PAWConfigInstallMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,

        [Parameter(Mandatory = $true)]
        [string]$InstallPath,

        [Parameter(Mandatory = $false)]
        [string]$ImagesPath,

        [Parameter(Mandatory = $false)]
        [switch]$SetImageLocation,

        [Parameter(Mandatory = $false)]
        [string]$VMLocation,

        [Parameter(Mandatory = $false)]
        [switch]$SetVMLocation
    )

    $configJson = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    $changes = New-Object System.Collections.Generic.List[string]

    if ($null -eq $configJson.Settings) {
        throw "Config.json is missing the Settings root object."
    }

    if ($null -eq $configJson.Settings.Configuration) {
        $configJson.Settings | Add-Member -NotePropertyName Configuration -NotePropertyValue ([PSCustomObject]@{}) -Force
        $changes.Add("Created missing object: Settings.Configuration")
    }
    $configurationNode = $configJson.Settings.Configuration
    foreach ($name in @('TemplateFolder', 'TemplatesFolder', 'Templates')) {
        if ($null -ne $configurationNode.PSObject.Properties[$name]) {
            $configurationNode.PSObject.Properties.Remove($name)
            $changes.Add("Configuration | removed obsolete property '$name'; templates use Config")
        }
    }

    $currentInstallFolder = Get-PAWJsonPropertyValue -Object $configurationNode -Name 'InstallFolder'
    if (-not [string]::Equals($currentInstallFolder, $InstallPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        Set-PAWJsonPropertyValue -Object $configurationNode -Name 'InstallFolder' -Value $InstallPath
        $changes.Add("Configuration | InstallFolder: '$currentInstallFolder' -> '$InstallPath'")
    }

    # Rebase configuration paths using the current InstallFolder as the old root.
    $pathNodeDefinitions = @(
        @{ Name = 'SecurityBaseLineFolder'; LegacyName = 'SecurityBaselines'; DefaultValue = (Join-Path $InstallPath 'Resources\SecurityBaselines') },
        @{ Name = 'LogFilesFolder'; LegacyName = 'LogFolder'; DefaultValue = '%TEMP%\PAWDeploy' }
    )

    foreach ($pathNodeDefinition in $pathNodeDefinitions) {
        $nodeName = [string]$pathNodeDefinition.Name
        $legacyNodeName = [string]$pathNodeDefinition.LegacyName
        $defaultValue = [string]$pathNodeDefinition.DefaultValue

        $currentValue = Get-PAWJsonPropertyValue -Object $configurationNode -Name $nodeName
        if ([string]::IsNullOrWhiteSpace($currentValue) -and -not [string]::IsNullOrWhiteSpace($legacyNodeName)) {
            $legacyValue = Get-PAWJsonPropertyValue -Object $configurationNode -Name $legacyNodeName
            if (-not [string]::IsNullOrWhiteSpace($legacyValue)) {
                $currentValue = $legacyValue
                if ($null -ne $configurationNode.PSObject.Properties[$legacyNodeName]) {
                    $configurationNode.PSObject.Properties.Remove($legacyNodeName)
                }
                $changes.Add("Configuration | renamed property '$legacyNodeName' -> '$nodeName'")
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($legacyNodeName) -and $null -ne $configurationNode.PSObject.Properties[$legacyNodeName]) {
            $configurationNode.PSObject.Properties.Remove($legacyNodeName)
        }

        if ($nodeName -in @('SecurityBaseLineFolder', 'LogFilesFolder')) {
            $newValue = $defaultValue
        }
        elseif (-not [string]::IsNullOrWhiteSpace($currentValue) -and -not [string]::IsNullOrWhiteSpace($currentInstallFolder)) {
            $newValue = Get-PAWRebasedPath -Value $currentValue -OldRoot $currentInstallFolder -NewRoot $InstallPath
        }
        else {
            $newValue = $defaultValue
        }

        if (-not [string]::Equals($currentValue, $newValue, [System.StringComparison]::OrdinalIgnoreCase)) {
            Set-PAWJsonPropertyValue -Object $configurationNode -Name $nodeName -Value $newValue
            $changes.Add("Configuration | ${nodeName}: '$currentValue' -> '$newValue'")
        }
    }

    if ($SetImageLocation -and -not [string]::IsNullOrWhiteSpace($ImagesPath)) {
        $currentImageLocation = Get-PAWJsonPropertyValue -Object $configurationNode -Name 'VHDFolder'
        $normalizedFromLegacy = $false
        if ([string]::IsNullOrWhiteSpace($currentImageLocation)) {
            $currentImageLocation = Get-PAWJsonPropertyValue -Object $configurationNode -Name 'ImageLocation'
            $normalizedFromLegacy = -not [string]::IsNullOrWhiteSpace($currentImageLocation)
        }
        if ([string]::IsNullOrWhiteSpace($currentImageLocation)) {
            $currentImageLocation = Get-PAWJsonPropertyValue -Object $configurationNode -Name 'IImageLocation'
            $normalizedFromLegacy = -not [string]::IsNullOrWhiteSpace($currentImageLocation)
        }

        foreach ($legacyImagePropertyName in @('ImageLocation', 'IImageLocation')) {
            if ($null -ne $configurationNode.PSObject.Properties[$legacyImagePropertyName]) {
                $configurationNode.PSObject.Properties.Remove($legacyImagePropertyName)
            }
        }

        if ($normalizedFromLegacy) {
            $changes.Add("Configuration | normalized image location property to 'VHDFolder'")
        }

        if (-not [string]::Equals($currentImageLocation, $ImagesPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            Set-PAWJsonPropertyValue -Object $configurationNode -Name 'VHDFolder' -Value $ImagesPath
            $changes.Add("Configuration | VHDFolder: '$currentImageLocation' -> '$ImagesPath'")
        }
    }

    if ($SetVMLocation -and -not [string]::IsNullOrWhiteSpace($VMLocation)) {
        if ($null -eq $configJson.Settings.PSObject.Properties['HyperV']) {
            $configJson.Settings | Add-Member -NotePropertyName HyperV -NotePropertyValue ([PSCustomObject]@{}) -Force
            $changes.Add("Created missing object: Settings.HyperV")
        }

        $hyperVNode = $configJson.Settings.HyperV
        $currentVMLocation = Get-PAWJsonPropertyValue -Object $hyperVNode -Name 'VMFolder'
        if (-not [string]::Equals($currentVMLocation, $VMLocation, [System.StringComparison]::OrdinalIgnoreCase)) {
            Set-PAWJsonPropertyValue -Object $hyperVNode -Name 'VMFolder' -Value $VMLocation
            $changes.Add("HyperV | VMFolder: '$currentVMLocation' -> '$VMLocation'")
        }

        if ($null -ne $hyperVNode.PSObject.Properties['VMLocation']) {
            $hyperVNode.PSObject.Properties.Remove('VMLocation')
            $changes.Add("HyperV | removed legacy property 'VMLocation'")
        }
    }

    if ($changes.Count -gt 0) {
        ($configJson | ConvertTo-Json -Depth 20) | Set-Content -Path $ConfigPath -Encoding UTF8
    }

    return [pscustomobject]@{
        UpdatedCount = $changes.Count
        Changes      = @($changes)
    }
}

function Invoke-PAWDeployJsonPathSelfTest {
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('PAWDeployJsonSelfTest_' + [guid]::NewGuid().ToString('N'))
    $configPath = Join-Path $tempRoot 'Config.json'
    $testDriveRoot = [System.IO.Path]::GetPathRoot($tempRoot)
    if ([string]::IsNullOrWhiteSpace($testDriveRoot)) {
        throw 'Unable to resolve a valid drive root for self-test.'
    }

    $tests = New-Object System.Collections.Generic.List[psobject]

    try {
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

        # Current schema fixture used for path rebasing tests.
        $jsonTemplate = @"
{
  "Settings": {
    "CustomerData": { "OrgName": "Corp", "FullName": "Corp" },
    "HyperV": { "VMFolder": "C:\\Data\\VMs" },
    "Configuration": {
      "InstallFolder": "C:\\PAWDeploy",
      "VHDFolder": "C:\\PAWImages",
      "SecurityBaseLineFolder": "C:\\PAWDeploy\\Resources\\SecurityBaselines",
      "TemplateFolder": ".\\Templates"
    },
    "Templates": [
      {
        "Name": "BaseTemplate",
        "VHDFile": "C:\\PAWImages\\Base.vhdx",
        "ExtraFolder": "C:\\PAWDeploy\\Resources\\CustomScripts",
        "SecurityBaselineLocation": "C:\\PAWDeploy\\SecBaseLineW11_24H2"
      }
    ]
  }
}
"@

        Set-Content -Path $configPath -Value $jsonTemplate -Encoding UTF8

        $installPathA = Join-Path $testDriveRoot 'PAWDeployA'
        $imagesPathA = Join-Path $testDriveRoot 'PAWImagesA'
        $resultA = Update-PAWConfigForInstallPaths -ConfigPath $configPath -InstallPath $installPathA -ImagesPath $imagesPathA
        $jsonA = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $vhdA = [string]$jsonA.Settings.Templates[0].VHDFile
        $extraA = [string]$jsonA.Settings.Templates[0].ExtraFolder
        $secA = [string]$jsonA.Settings.Templates[0].SecurityBaselineLocation
        $passA = ($vhdA -eq (Join-Path $imagesPathA 'Base.vhdx')) -and
                 ($extraA -eq (Join-Path $installPathA 'Resources\CustomScripts')) -and
                 ($secA -eq (Join-Path $installPathA 'SecBaseLineW11_24H2')) -and
                 ($resultA.UpdatedCount -ge 1)
        $tests.Add([pscustomobject]@{ Name = 'InstallPathRebase'; Passed = $passA })

        $jsonB = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $jsonB.Settings.Templates[0].VHDFile = 'C:\LegacyImages\Legacy.vhdx'
        ($jsonB | ConvertTo-Json -Depth 20) | Set-Content -Path $configPath -Encoding UTF8
        $imagesPathB = Join-Path $testDriveRoot 'PAWImagesB'
        $resultB = Update-PAWConfigVhdImageLocation -ConfigPath $configPath -ImagesPath $imagesPathB
        $jsonB2 = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $vhdB = [string]$jsonB2.Settings.Templates[0].VHDFile
        $passB = ($vhdB -eq (Join-Path $imagesPathB 'Legacy.vhdx')) -and ($resultB.UpdatedCount -eq 1)
        $tests.Add([pscustomobject]@{ Name = 'UpgradeImageLocationRebase'; Passed = $passB })

        $jsonC = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $jsonC.Settings.Templates[0].ExtraFolder = 'C:\PAWDeploy\Resources\CustomScripts'
        $jsonC.Settings.Templates[0].SecurityBaselineLocation = 'C:\PAWDeploy\SecBaseLineW11_24H2'
        ($jsonC | ConvertTo-Json -Depth 20) | Set-Content -Path $configPath -Encoding UTF8
        $installPathC = Join-Path $testDriveRoot 'PAWDeployC'
        $resultC = Update-PAWConfigUpgradeInstallPaths -ConfigPath $configPath -InstallPath $installPathC
        $jsonC2 = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $extraC = [string]$jsonC2.Settings.Templates[0].ExtraFolder
        $secC = [string]$jsonC2.Settings.Templates[0].SecurityBaselineLocation
        $passC = ($extraC -eq (Join-Path $installPathC 'Resources\CustomScripts')) -and
                 ($secC -eq (Join-Path $installPathC 'SecBaseLineW11_24H2')) -and
                 ($resultC.UpdatedCount -eq 2)
        $tests.Add([pscustomobject]@{ Name = 'UpgradeInstallPathValidation'; Passed = $passC })

        # Legacy schema fixture used to validate migration to current Configuration property names.
        $jsonLegacyMetadataTemplate = @"
{
  "Settings": {
    "Configuration": {
      "InstallFolder": "C:\\PAWDeploy",
      "IImageLocation": "C:\\PAWImages",
      "SecurityBaselines": "C:\\PAWDeploy\\Resources\\SecurityBaselines",
      "Templates": "C:\\PAWDeploy\\Templates",
      "LogFolder": "C:\\PAWDeploy\\OldLogs"
    },
    "HyperV": { "VMLocation": "C:\\OldVMs" }
  }
}
"@

        Set-Content -Path $configPath -Value $jsonLegacyMetadataTemplate -Encoding UTF8
        $installPathD = Join-Path $testDriveRoot 'PAWDeployD'
        $imagesPathD = Join-Path $testDriveRoot 'PAWImagesD'
        $vmLocationD = Join-Path $testDriveRoot 'VMsD'
        $resultD = Update-PAWConfigInstallMetadata -ConfigPath $configPath -InstallPath $installPathD -ImagesPath $imagesPathD -SetImageLocation -VMLocation $vmLocationD -SetVMLocation
        $jsonD = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $installD = [string]$jsonD.Settings.Configuration.InstallFolder
        $imageD = [string]$jsonD.Settings.Configuration.VHDFolder
        $securityD = [string]$jsonD.Settings.Configuration.SecurityBaseLineFolder
        $templateD = $jsonD.Settings.Configuration.PSObject.Properties['TemplateFolder']
        $logFilesD = [string]$jsonD.Settings.Configuration.LogFilesFolder
        $legacySecurityPropD = $jsonD.Settings.Configuration.PSObject.Properties['SecurityBaselines']
        $legacyTemplatePropD = $jsonD.Settings.Configuration.PSObject.Properties['Templates']
        $legacyImagePropD = $jsonD.Settings.Configuration.PSObject.Properties['IImageLocation']
        $legacyLogPropD = $jsonD.Settings.Configuration.PSObject.Properties['LogFolder']
        $vmFolderD = [string]$jsonD.Settings.HyperV.VMFolder
        $legacyVMLocationPropD = $jsonD.Settings.HyperV.PSObject.Properties['VMLocation']
        $passD = ($installD -eq $installPathD) -and
             ($imageD -eq $imagesPathD) -and
             ($vmFolderD -eq $vmLocationD) -and
             ($null -eq $legacyVMLocationPropD) -and
             ($securityD -eq (Join-Path $installPathD 'Resources\SecurityBaselines')) -and
             ($null -eq $templateD) -and
                         ($logFilesD -eq '%TEMP%\PAWDeploy') -and
                         ($null -eq $legacySecurityPropD) -and
                         ($null -eq $legacyTemplatePropD) -and
                         ($null -eq $legacyImagePropD) -and
                         ($null -eq $legacyLogPropD) -and
                         ($resultD.UpdatedCount -ge 1)
        $tests.Add([pscustomobject]@{ Name = 'InstallMetadataLegacySchemaMigration'; Passed = $passD })

        $resultE = Update-PAWConfigInstallMetadata -ConfigPath $configPath -InstallPath $installPathD -ImagesPath $imagesPathD -SetImageLocation
        $jsonE = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $passE = ([string]$jsonE.Settings.HyperV.VMFolder -eq $vmLocationD) -and ($resultE.UpdatedCount -eq 0)
        $tests.Add([pscustomobject]@{ Name = 'VMLocationPreservedWhenOmitted'; Passed = $passE })

        $jsonE.Settings.PSObject.Properties.Remove('HyperV')
        ($jsonE | ConvertTo-Json -Depth 20) | Set-Content -Path $configPath -Encoding UTF8
        $vmLocationF = Join-Path $testDriveRoot 'VMsF'
        $resultF = Update-PAWConfigInstallMetadata -ConfigPath $configPath -InstallPath $installPathD -VMLocation $vmLocationF -SetVMLocation
        $jsonF = Get-Content -Path $configPath -Raw | ConvertFrom-Json
        $passF = ([string]$jsonF.Settings.HyperV.VMFolder -eq $vmLocationF) -and ($resultF.UpdatedCount -ge 1)
        $tests.Add([pscustomobject]@{ Name = 'VMLocationCreatesMissingHyperVNode'; Passed = $passF })

        return [pscustomobject]@{
            Passed = -not ($tests.Passed -contains $false)
            Tests  = @($tests)
        }
    }
    finally {
        if (Test-Path -Path $tempRoot) {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if (-not (Test-PAWInstallAdministrator)) {
    throw 'Install-PAWDeploy.ps1 requires an elevated local administrator. Run PowerShell as Administrator and try again.'
}

if ($PSBoundParameters.ContainsKey('Path') -and -not [string]::IsNullOrWhiteSpace($Path)) {
    $Path = Normalize-PAWCommandLinePath -Value $Path
}

if ($PSBoundParameters.ContainsKey('ImageLocation') -and -not [string]::IsNullOrWhiteSpace($ImageLocation)) {
    $ImageLocation = Normalize-PAWCommandLinePath -Value $ImageLocation
}

try {
    if ($SelfTest) {
        if (-not $PSCmdlet.ShouldProcess('JSON path update fixtures', 'Run self-test')) {
            return
        }
        Write-Host -ForegroundColor Green 'Running Install-PAWDeploy self-test...'
        $selfTestResult = Invoke-PAWDeployJsonPathSelfTest
        foreach ($test in $selfTestResult.Tests) {
            $color = if ($test.Passed) { 'Green' } else { 'Red' }
            $status = if ($test.Passed) { 'PASS' } else { 'FAIL' }
            Write-Host -ForegroundColor $color ("  [{0}] {1}" -f $status, $test.Name)
        }

        if (-not $selfTestResult.Passed) {
            throw 'Self-test failed. One or more JSON path update checks did not pass.'
        }

        Write-Host -ForegroundColor Green 'Self-test passed.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw '-Path is required unless -SelfTest is used.'
    }

    if ($Uninstall -and ($PSBoundParameters.ContainsKey('ImageLocation') -or
            $PSBoundParameters.ContainsKey('VMLocation') -or $PSBoundParameters.ContainsKey('Theme'))) {
        throw '-Uninstall cannot be used with -ImageLocation, -VMLocation or -Theme.'
    }

    if ($PSBoundParameters.ContainsKey('VMLocation')) {
        if ([string]::IsNullOrWhiteSpace($VMLocation)) {
            throw '-VMLocation cannot be empty or whitespace.'
        }

        $VMLocation = Normalize-PAWCommandLinePath -Value $VMLocation
        $VMLocation = Test-PAWWritableLocation -TargetPath $VMLocation -Description 'VMLocation'
    }

    if ($Uninstall) {
        $UninstallPath = Resolve-PAWAbsolutePath -InputPath $Path

        Write-Host -ForegroundColor Green "#########################################"
        Write-Host -ForegroundColor Green "## $ScriptName started at $(Get-Date) ##"
        Write-Host -ForegroundColor Green "#########################################"
        Write-Host -ForegroundColor Green "Path          : $UninstallPath"
        Write-Host -ForegroundColor Green 'Mode          : Uninstall'

        if (-not (Test-Path -Path $UninstallPath -PathType Container)) {
            Write-Warning "Path does not exist. Nothing to uninstall: $UninstallPath"
            return
        }

        $uninstallConfirmMessage = "Are you sure you want to uninstall the PAWdeploy solution at path '$UninstallPath'?`nNote, you VHDs will not be removed"
        if (-not $PSCmdlet.ShouldContinue($uninstallConfirmMessage, 'Uninstall confirmation')) {
            Write-Warning 'Uninstall canceled by user.'
            return
        }

        $destConfig = Join-Path $UninstallPath 'Config\Config.json'
        if (-not (Test-Path -LiteralPath $destConfig -PathType Leaf)) {
            $destConfig = Join-Path $UninstallPath 'Config.json'
        }
        $imageLocations = New-Object System.Collections.Generic.List[string]

        if (Test-Path -Path $destConfig -PathType Leaf) {
            try {
                $configJson = Get-Content -Path $destConfig -Raw | ConvertFrom-Json
                $configImageLocation = [string]$configJson.Settings.Configuration.VHDFolder
                if ([string]::IsNullOrWhiteSpace($configImageLocation)) {
                    $configImageLocation = [string]$configJson.Settings.Configuration.IImageLocation
                }
                if ([string]::IsNullOrWhiteSpace($configImageLocation)) {
                    $configImageLocation = [string]$configJson.Settings.Configuration.ImageLocation
                }

                if (-not [string]::IsNullOrWhiteSpace($configImageLocation)) {
                    $resolvedConfigImageLocation = Resolve-PAWAbsolutePath -InputPath $configImageLocation
                    $hasConfigImageLocation = $false
                    foreach ($existingPath in $imageLocations) {
                        if ([string]::Equals($existingPath, $resolvedConfigImageLocation, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $hasConfigImageLocation = $true
                            break
                        }
                    }

                    if (-not $hasConfigImageLocation) {
                        $imageLocations.Add($resolvedConfigImageLocation)
                    }
                }

                $vhdPaths = @($configJson.Settings.Templates | ForEach-Object { [string]$_.VHDFile } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                foreach ($vhdPath in $vhdPaths) {
                    $vhdFolder = Split-Path -Path $vhdPath -Parent
                    if ([string]::IsNullOrWhiteSpace($vhdFolder)) {
                        continue
                    }

                    $resolvedVhdFolder = Resolve-PAWAbsolutePath -InputPath $vhdFolder
                    $hasImageLocation = $false
                    foreach ($existingPath in $imageLocations) {
                        if ([string]::Equals($existingPath, $resolvedVhdFolder, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $hasImageLocation = $true
                            break
                        }
                    }

                    if (-not $hasImageLocation) {
                        $imageLocations.Add($resolvedVhdFolder)
                    }
                }
            }
            catch {
                Write-Warning "Unable to parse Config.json image location data. Error: $($_.Exception.Message)"
            }
        }

        if ($imageLocations.Count -eq 0) {
            $defaultImagesPath = Resolve-PAWAbsolutePath -InputPath (Join-Path $UninstallPath 'VHDFolder')
            $imageLocations.Add($defaultImagesPath)
        }

        $protectedTopLevelItems = New-Object System.Collections.Generic.List[string]
        foreach ($imageLocationPath in $imageLocations) {
            if (-not (Test-PAWIsSameOrSubPath -Path $imageLocationPath -RootPath $UninstallPath)) {
                continue
            }

            $relative = $imageLocationPath.Substring($UninstallPath.Length).TrimStart('\', '/')
            if ([string]::IsNullOrWhiteSpace($relative)) {
                continue
            }

            $topSegment = $relative.Split([char[]]@('\', '/'))[0]
            if ([string]::IsNullOrWhiteSpace($topSegment)) {
                continue
            }

            $protectedPath = Join-Path $UninstallPath $topSegment
            $hasProtectedPath = $false
            foreach ($existingProtectedPath in $protectedTopLevelItems) {
                if ([string]::Equals($existingProtectedPath, $protectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $hasProtectedPath = $true
                    break
                }
            }

            if (-not $hasProtectedPath) {
                $protectedTopLevelItems.Add($protectedPath)
            }
        }

        $removeProtectedImageFolders = $false
        if ($Force -and $protectedTopLevelItems.Count -gt 0) {
            $protectedList = ($protectedTopLevelItems | ForEach-Object { "  - $_" }) -join "`n"
            $removeImagesConfirm = "-Force is set for uninstall and image folders were found under the uninstall path.`n`n$protectedList`n`nDo you also want to remove these VHDFolder folders?"
            if ($PSCmdlet.ShouldContinue($removeImagesConfirm, 'Uninstall image folders confirmation')) {
                $removeProtectedImageFolders = $true
            }
            else {
                Write-Warning 'VHDFolder folders will be preserved.'
            }
        }

        if ($protectedTopLevelItems.Count -eq 0 -or $removeProtectedImageFolders) {
            if ($PSCmdlet.ShouldProcess($UninstallPath, 'Delete folder')) {
                Remove-Item -Path $UninstallPath -Recurse -Force
                Write-Host -ForegroundColor Green "Deleted folder: $UninstallPath"
            }
        }
        else {
            Write-Host -ForegroundColor Yellow 'Preserving image location under uninstall path:'
            foreach ($protectedPath in $protectedTopLevelItems) {
                Write-Host -ForegroundColor Yellow "  - $protectedPath"
            }

            $children = Get-ChildItem -Path $UninstallPath -Force
            foreach ($child in $children) {
                $isProtected = $false
                foreach ($protectedPath in $protectedTopLevelItems) {
                    if ([string]::Equals($child.FullName, $protectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $isProtected = $true
                        break
                    }
                }

                if ($isProtected) {
                    Write-Host -ForegroundColor Yellow "  Preserved: $($child.FullName)"
                    continue
                }

                if ($PSCmdlet.ShouldProcess($child.FullName, 'Delete item')) {
                    Remove-Item -Path $child.FullName -Recurse -Force
                    Write-Host -ForegroundColor Green "  Deleted: $($child.FullName)"
                }
            }
        }

        Write-Host -ForegroundColor Green "#########################################"
        Write-Host -ForegroundColor Green "## Uninstall complete. Path: $UninstallPath ##"
        Write-Host -ForegroundColor Green "#########################################"
        return
    }

    $configChangeLog = New-Object System.Collections.Generic.List[string]

    $InstallPath = Test-PAWWritableLocation -TargetPath $Path -Description 'Path'
    if ([string]::IsNullOrWhiteSpace($ImageLocation)) {
        $ImagesPath = Join-Path $InstallPath 'VHDFolder'
    }
    else {
        $ImagesPath = Test-PAWWritableLocation -TargetPath $ImageLocation -Description 'ImageLocation'
    }

    # Ensure VHDFolder exists, create it if it doesn't
    if (-not (Test-Path -Path $ImagesPath -PathType Container)) {
        if ($PSCmdlet.ShouldProcess($ImagesPath, 'Create image directory')) {
            try {
                Write-Host -ForegroundColor Green "Creating VHDFolder directory: $ImagesPath"
                New-Item -Path $ImagesPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Host -ForegroundColor Green "  Successfully created: $ImagesPath"
            }
            catch {
                throw "Failed to create VHDFolder at '$ImagesPath'. Error: $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Host -ForegroundColor Green "Note: ImageLocation folder already exists: $ImagesPath"
    }

    $installFolderExists = Test-Path -Path $InstallPath -PathType Container
    $destConfig = Join-Path $InstallPath 'Config\Config.json'
    $legacyConfig = Join-Path $InstallPath 'Config.json'
    $hasExistingConfig = (Test-Path -Path $destConfig -PathType Leaf) -or (Test-Path -LiteralPath $legacyConfig -PathType Leaf)
    $isFolderEmpty = $false
    if ($installFolderExists) {
        $isFolderEmpty = -not (Get-ChildItem -Path $InstallPath -Force | Select-Object -First 1)
    }

    $isUpgrade = $installFolderExists -and $hasExistingConfig
    if ($PSBoundParameters.ContainsKey('Theme')) {
        $themeToInstall = $Theme
    }
    else {
        $themeToInstall = 'System'
    }

    if ([string]::Equals($themeToInstall, 'System', [System.StringComparison]::OrdinalIgnoreCase)) {
        $themeToInstall = 'System'
    }
    elseif ($themeToInstall -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]*$') {
        throw "Invalid theme name '$themeToInstall'. Use a theme filename without its .json extension."
    }
    else {
        $sourceThemePath = Join-Path $ScriptDir "PAWDeploy\Assets\Themes\$themeToInstall.json"
        $installedThemePath = Join-Path $InstallPath "Assets\Themes\$themeToInstall.json"
        if (-not (Test-Path -LiteralPath $sourceThemePath -PathType Leaf) -and
            -not (Test-Path -LiteralPath $installedThemePath -PathType Leaf)) {
            throw "Theme '$themeToInstall' was not found under PAWDeploy\Assets\Themes."
        }
    }
    $themeToInstall = Resolve-PAWInstallThemeName -ThemeName $themeToInstall

    if ($isUpgrade -and -not $Force) {
        Write-Host -ForegroundColor Green "Note: Installation folder already exists: $InstallPath"
        $confirmMessage = 'Are you sure you want to upgrade?'
        if (-not $PSCmdlet.ShouldContinue($confirmMessage, 'Upgrade confirmation')) {
            Write-Warning 'Upgrade canceled by user.'
            return
        }
    }
    elseif ($isUpgrade -and $Force) {
        Write-Warning 'The folder exists. -Force specified, continuing with upgrade without confirmation.'
    }
    elseif ($installFolderExists -and $isFolderEmpty) {
        Write-Verbose 'The folder exists and is empty. Proceeding as new install.'
    }
    elseif ($installFolderExists -and -not $hasExistingConfig) {
        Write-Verbose 'The folder exists but Config.json is not present. Proceeding as new install.'
    }

    Write-Host -ForegroundColor Green "#########################################"
    Write-Host -ForegroundColor Green "## $ScriptName started at $(Get-Date) ##"
    Write-Host -ForegroundColor Green "#########################################"
    Write-Host -ForegroundColor Green "Path          : $InstallPath"
    Write-Host -ForegroundColor Green "ImageLocation : $ImagesPath"
    Write-Host -ForegroundColor Green "Theme         : $themeToInstall"
    if ($PSBoundParameters.ContainsKey('VMLocation')) {
        Write-Host -ForegroundColor Green "VMLocation    : $VMLocation"
    }
    Write-Host -ForegroundColor Green "Mode          : $(if ($isUpgrade) { 'Upgrade' } else { 'New install' })"

    # Files that must NOT be overwritten during upgrades if they already exist.
    $NoOverwriteNames      = @('Config.json')
    $NoOverwriteExtensions = @('.vhdx')
    # Retain user-managed configuration, policies, baselines and application data.
    $NoOverwriteRelativePaths = @(
        'Config\*',
        'Resources\SecurityBaselines\*',
        'Resources\WDACPolicies\*',
        'Resources\ASR\*',
        'Resources\ApplicationCatalog\*',
        'Resources\ApplicationBundles\*',
        'Resources\Applications\*',
        'Resources\ApplicationDownloads\*',
        'Resources\CustomScripts\*'
    )

    if ($isUpgrade) {
        $destConfig = Move-PAWConfigurationLayout -InstallPath $InstallPath
    }

    $copyPlan = New-Object System.Collections.Generic.List[hashtable]
    $copyPlan.Add(@{ Name = 'PAWDeploy'; SourcePath = Join-Path $ScriptDir 'PAWDeploy'; DestinationPath = $InstallPath })

    foreach ($item in $copyPlan) {
        if (-not (Test-Path -Path $item.SourcePath -PathType Container)) {
            Write-Warning "Source folder not found, skipping: $($item.SourcePath)"
            continue
        }

        Write-Host -ForegroundColor Green "Processing folder: $($item.Name)"
        Write-Host -ForegroundColor Green "  Source      : $($item.SourcePath)"
        Write-Host -ForegroundColor Green "  Destination : $($item.DestinationPath)"

        if (-not (Test-Path -Path $item.DestinationPath)) {
            if ($PSCmdlet.ShouldProcess($item.DestinationPath, 'Create directory')) {
                New-Item -Path $item.DestinationPath -ItemType Directory -Force | Out-Null
                Write-Host -ForegroundColor Green "  Created directory: $($item.DestinationPath)"
            }
        }

        # Create all source subdirectories first so empty folders are preserved.
        $allDirectories = Get-ChildItem -Path $item.SourcePath -Recurse -Directory -Force
        foreach ($directory in $allDirectories) {
            $relativeDirectory = $directory.FullName.Substring($item.SourcePath.Length).TrimStart('\', '/')
            if ([string]::IsNullOrWhiteSpace($relativeDirectory) -or
                $relativeDirectory -match '(^|[\\/])\.(git|github)([\\/]|$)') {
                continue
            }

            $destDirectory = Join-Path $item.DestinationPath $relativeDirectory
            if (-not (Test-Path -Path $destDirectory -PathType Container)) {
                if ($PSCmdlet.ShouldProcess($destDirectory, 'Create directory')) {
                    New-Item -Path $destDirectory -ItemType Directory -Force | Out-Null
                    Write-Host -ForegroundColor Green "  Created directory: $destDirectory"
                }
            }
        }

        $placeholderPaths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($relativePath in @(
            'Resources\ApplicationBundles\.gitkeep',
            'Resources\ApplicationCatalog\.gitkeep',
            'Resources\ApplicationDownloads\.gitkeep',
            'Resources\Applications\InstallFiles\.gitkeep',
            'Resources\CustomScripts\.gitkeep',
            'Resources\SecurityBaselines\.gitkeep',
            'Resources\WDACPolicies\.gitkeep'
        )) { $placeholderPaths.Add($relativePath) }
        $allFiles = Get-ChildItem -Path $item.SourcePath -Recurse -File
        foreach ($file in $allFiles) {
            $relative = $file.FullName.Substring($item.SourcePath.Length).TrimStart('\', '/')
            if ($relative -match '(^|[\\/])\.(git|github)([\\/]|$)') { continue }
            if ($relative -in @('ReadmeCommunity.md', 'GettingStartedCommunity.md')) { continue }
            if ($file.Name -in @('.gitkeep', '.gitignore', '.gitattributes', '.gitmodules')) {
                if ($file.Name -eq '.gitkeep' -and -not $placeholderPaths.Contains($relative)) {
                    $placeholderPaths.Add($relative)
                }
                continue
            }
            $destFile = Join-Path $item.DestinationPath $relative
            $destDir  = Split-Path -Path $destFile -Parent

            if (-not (Test-Path -Path $destDir)) {
                if ($PSCmdlet.ShouldProcess($destDir, 'Create directory')) {
                    New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                    Write-Host -ForegroundColor Green "  Created directory: $destDir"
                }
            }

            $isProtected = ($NoOverwriteNames -contains $file.Name) -or
                           ($NoOverwriteExtensions -contains $file.Extension.ToLowerInvariant()) -or
                           (@($NoOverwriteRelativePaths | Where-Object { $relative -like $_ }).Count -gt 0)

            if ($isUpgrade -and $isProtected -and (Test-Path -Path $destFile)) {
                Write-Host -ForegroundColor Yellow "  Skipped (protected, already exists): $destFile"
                continue
            }

            if ($PSCmdlet.ShouldProcess($destFile, 'Copy file')) {
                Copy-Item -Path $file.FullName -Destination $destFile -Force
                Write-Verbose "Copied: $relative"
            }
        }

        foreach ($relativePath in $placeholderPaths) {
            $placeholder = Join-Path $item.DestinationPath $relativePath
            if (Test-PAWIsSameOrSubPath -Path $placeholder -RootPath $item.SourcePath) {
                Write-Warning "Skipping Git placeholder in the installation source: $placeholder"
                continue
            }
            $partPath = [IO.Path]::GetPathRoot($item.DestinationPath)
            $hasLink = $false
            if (Test-Path -LiteralPath $partPath) {
                $rootItem = Get-Item -LiteralPath $partPath -Force -ErrorAction Stop
                $hasLink = [bool]($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)
            }
            $parts = @($item.DestinationPath.Substring($partPath.Length) -split '[\\/]' | Where-Object { $_ })
            $parts += $relativePath -split '[\\/]'
            foreach ($part in $parts) {
                if ($hasLink) { break }
                $partPath = Join-Path $partPath $part
                if (Test-Path -LiteralPath $partPath) {
                    $partItem = Get-Item -LiteralPath $partPath -Force -ErrorAction Stop
                    if ($partItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { $hasLink = $true; break }
                }
            }
            if ($hasLink) {
                Write-Warning "Skipping Git placeholder under a link: $placeholder"
                continue
            }
            if (Test-Path -LiteralPath $placeholder -PathType Leaf) {
                $existing = Get-Item -LiteralPath $placeholder -Force -ErrorAction Stop
                if ($existing.Length -ne 0) {
                    Write-Warning "Keeping non-empty Git placeholder: $placeholder"
                }
                elseif ($PSCmdlet.ShouldProcess($placeholder, 'Remove empty Git placeholder')) {
                    Remove-Item -LiteralPath $placeholder -Force -ErrorAction Stop
                }
            }
        }

        Write-Host -ForegroundColor Green "Finished folder: $($item.Name)"
    }

    foreach ($guideName in @('README.md', 'GettingStarted.md')) {
        $sourceGuide = Join-Path $ScriptDir $guideName
        $installedGuide = Join-Path $InstallPath $guideName
        if (Test-Path -LiteralPath $sourceGuide -PathType Leaf) {
            if ($PSCmdlet.ShouldProcess($installedGuide, "Install guide from '$sourceGuide'")) {
                $content = [IO.File]::ReadAllText($sourceGuide)
                $content = [regex]::Replace($content, '(?<=\]\()PAWDeploy/', '')
                [IO.File]::WriteAllText($installedGuide, $content, (New-Object System.Text.UTF8Encoding($false)))
            }
        }
        elseif (-not (Test-Path -LiteralPath (Join-Path $ScriptDir "PAWDeploy\$guideName") -PathType Leaf)) {
            Write-Warning "Guide not found in the installation source: $sourceGuide"
        }
    }

    Copy-PAWBrandingAssets -SourceRoot $ScriptDir -InstallPath $InstallPath
    Set-PAWInstallTheme -InstallPath $InstallPath -ThemeName $themeToInstall

    foreach ($toolName in @('PAWConfigEditorUI.ps1', 'PAWTemplateEditorUI.ps1', 'PAWVHDXImportUI.ps1', 'Import-PAWVHDX.ps1',
            'PAWDeployUI.ps1', 'PAWRemoveVMUI.ps1', 'PAWWIM2VHDUI.ps1',
            'Convert-PAWWIM2VHD.ps1', 'Remove-PAWVM.ps1', 'Invoke-PAWApplicationDownload.ps1', 'Invoke-PAWApplicationSettings.ps1',
            'Invoke-PAWConfigurationSettings.ps1', 'Invoke-PAWConfigValidation.ps1', 'Invoke-PAWTemplateSettings.ps1')) {
        $legacyTool = Join-Path $InstallPath $toolName
        $newTool = Join-Path $InstallPath "Tools\$toolName"
        $sourceTool = Join-Path $ScriptDir "PAWDeploy\Tools\$toolName"
        if ((Test-Path -LiteralPath $legacyTool -PathType Leaf) -and
            ((Test-Path -LiteralPath $newTool -PathType Leaf) -or ($WhatIfPreference -and (Test-Path -LiteralPath $sourceTool -PathType Leaf)))) {
            if ($PSCmdlet.ShouldProcess($legacyTool, 'Remove obsolete root-level script replaced by Tools')) {
                Remove-Item -LiteralPath $legacyTool -ErrorAction Stop
            }
        }
    }

    foreach ($relativePath in @(
        'PAWUtility\public\Get-PAWTemplateFolderPath.ps1',
        'PAWUtility\public\Resolve-PAWTemplateFolderFromConfigJson.ps1',
        'PAWUtility\public\Resolve-PAWTemplateFolder.ps1',
        'PAWUtility\public\Get-PAWConfiguredTemplateFolder.ps1',
        'PAWUtility\public\Resolve-PAWConfiguredLogFolder.ps1',
        'PAWUtility\public\Resolve-PAWConfiguredLogFolderFromJson.ps1',
        'PAWUIUtility\public\Resolve-PAWConfiguredTemplateFolder.ps1'
    )) {
        $obsoleteHelper = Join-Path $InstallPath "Functions\$relativePath"
        if ((Test-Path -LiteralPath $obsoleteHelper -PathType Leaf) -and
            $PSCmdlet.ShouldProcess($obsoleteHelper, 'Remove retired template/log folder helper')) {
            Remove-Item -LiteralPath $obsoleteHelper -ErrorAction Stop
        }
    }

    foreach ($menuName in @('PAWMenu.ps1', 'PAWMenuCommunity.ps1')) {
        $legacyMenu = Join-Path $InstallPath "Tools\$menuName"
        $newMenu = Join-Path $InstallPath $menuName
        $sourceMenu = Join-Path $ScriptDir "PAWDeploy\$menuName"
        if ((Test-Path -LiteralPath $legacyMenu -PathType Leaf) -and
            ((Test-Path -LiteralPath $newMenu -PathType Leaf) -or ($WhatIfPreference -and (Test-Path -LiteralPath $sourceMenu -PathType Leaf)))) {
            if ($PSCmdlet.ShouldProcess($legacyMenu, 'Remove obsolete Tools menu replaced by root-level menu')) {
                Remove-Item -LiteralPath $legacyMenu -ErrorAction Stop
            }
        }
    }

    $requestedShortcuts = @(
        @{ ScriptName = 'PAWTemplateEditorUI.ps1'; ShortcutName = 'PAW Template Editor.lnk' },
        @{ ScriptName = 'PAWVHDXImportUI.ps1'; ShortcutName = 'PAW VHDX Import.lnk' },
        @{ ScriptName = 'PAWWIM2VHDUI.ps1'; ShortcutName = 'PAW WIM-2-VHD UI.lnk' },
        @{ ScriptName = 'PAWRemoveVMUI.ps1'; ShortcutName = 'PAW Remove VM UI.lnk' },
        @{ ScriptName = 'PAWDeployUI.ps1'; ShortcutName = 'PAW Deploy UI.lnk' },
        @{ ScriptName = 'PAWApplicationManagerUI.ps1'; ShortcutName = 'PAW Application Manager.lnk' },
        @{ ScriptName = 'PAWMenu.ps1'; ShortcutName = 'PAW Menu.lnk' }
    )
    $shortcutFolder = Join-Path $InstallPath 'ShortCuts'
    $legacyShortcutFolder = Join-Path $InstallPath 'shortscut'
    if (Test-Path -LiteralPath $legacyShortcutFolder -PathType Container) {
        if (Test-Path -LiteralPath $shortcutFolder) {
            throw "Shortcut folders exist at both '$legacyShortcutFolder' and '$shortcutFolder'. Resolve the conflict before upgrading."
        }
        if ($PSCmdlet.ShouldProcess($legacyShortcutFolder, "Rename shortcut folder to $shortcutFolder")) {
            Rename-Item -LiteralPath $legacyShortcutFolder -NewName 'ShortCuts' -ErrorAction Stop
            Write-Host -ForegroundColor Green "Renamed shortcut folder: $shortcutFolder"
        }
    }
    foreach ($shortcutName in @('PAW Config Editor.lnk', 'PAW Configuration Editor.lnk') + @($requestedShortcuts | ForEach-Object { $_.ShortcutName })) {
        $legacyShortcut = Join-Path $InstallPath $shortcutName
        if (-not (Test-Path -LiteralPath $legacyShortcut -PathType Leaf)) { continue }
        $destination = Join-Path $shortcutFolder $shortcutName
        if (Test-Path -LiteralPath $destination) {
            throw "Shortcut exists at both '$legacyShortcut' and '$destination'. Resolve the conflict before upgrading."
        }
        if ($PSCmdlet.ShouldProcess($legacyShortcut, "Move shortcut to $destination")) {
            New-Item -Path $shortcutFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Move-Item -LiteralPath $legacyShortcut -Destination $destination -ErrorAction Stop
            Write-Host -ForegroundColor Green "Moved shortcut: $destination"
        }
    }
    Rename-PAWConfigEditorShortcut -InstallPath $InstallPath -WhatIf:$WhatIfPreference -Confirm:$false

    if ($SkipShortCut) {
        Write-Host -ForegroundColor Yellow 'SkipShortCut is set; skipping shortcut creation.'
    }
    else {
        if ($PSCmdlet.ShouldProcess((Join-Path $shortcutFolder 'PAW Configuration Editor.lnk'), 'Create configuration editor shortcut')) {
            New-PAWConfigEditorShortcut -InstallPath $InstallPath
        }

        foreach ($requestedShortcut in $requestedShortcuts) {
            $shortcutPath = Join-Path $shortcutFolder $requestedShortcut.ShortcutName
            if ($PSCmdlet.ShouldProcess($shortcutPath, "Create shortcut for $($requestedShortcut.ScriptName)")) {
                New-PAWInstallScriptShortcut -InstallPath $InstallPath -ScriptName $requestedShortcut.ScriptName -ShortcutName $requestedShortcut.ShortcutName
            }
        }
        $programsPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)
        if ([string]::IsNullOrWhiteSpace($programsPath)) {
            throw 'Cannot locate the all-users Start menu Programs folder.'
        }
        New-PAWStartMenuShortcuts -SourcePath (Join-Path $ScriptDir 'PAWDeploy') -InstallPath $InstallPath -ProgramsPath $programsPath
    }

    if (Test-Path -Path $destConfig -PathType Leaf) {
        # New install: always set image location metadata.
        # Upgrade: set image location only when caller explicitly provided -ImageLocation.
        $shouldSetImageLocation = (-not $isUpgrade) -or $PSBoundParameters.ContainsKey('ImageLocation')
        $shouldSetVMLocation = $PSBoundParameters.ContainsKey('VMLocation')
        if ($PSCmdlet.ShouldProcess($destConfig, 'Update Config.json install metadata values')) {
            $result = Update-PAWConfigInstallMetadata -ConfigPath $destConfig -InstallPath $InstallPath -ImagesPath $ImagesPath -SetImageLocation:$shouldSetImageLocation -VMLocation $VMLocation -SetVMLocation:$shouldSetVMLocation
            if ($result.UpdatedCount -gt 0) {
                $result.Changes | ForEach-Object { $configChangeLog.Add($_) }
                Write-Host -ForegroundColor Green "Updated Config.json install metadata values. Updated entries: $($result.UpdatedCount)"
            }
            else {
                Write-Verbose 'Config.json install metadata already matches target values. No update needed.'
            }
        }
    }

    Write-Host -ForegroundColor Green '-----------------------------------------'
    Write-Host -ForegroundColor Green 'Config.json path changes summary:'
    if ($configChangeLog.Count -gt 0) {
        foreach ($entry in $configChangeLog) {
            Write-Host -ForegroundColor Green "  - $entry"
        }
    }
    else {
        Write-Host -ForegroundColor Yellow '  - No Config.json path changes were made.'
    }

    Write-Host -ForegroundColor Green "#########################################"
    Write-Host -ForegroundColor Green "## Installation complete. Path: $InstallPath ##"
    Write-Host -ForegroundColor Green "#########################################"

    if (-not $WhatIfPreference) {
        Set-Location -LiteralPath $InstallPath
    }

}
catch {
    throw
}
