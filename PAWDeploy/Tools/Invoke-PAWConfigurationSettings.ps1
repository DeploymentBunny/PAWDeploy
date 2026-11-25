<#
.SYNOPSIS
Views or edits the settings in the PAWDeploy Config.json file from the command line.

.DESCRIPTION
Updates one or more settings in Config.json without opening the graphical editor.
Each setting is exposed as a named parameter. Only the parameters you supply are
changed; all other settings are preserved.

Run the script without any setting parameters, or with -Show, to display the
current settings.

Values are validated before the file is written:
- VMGen, DynamicMem, DiskMode, and DomainOrWorkGroup accept only supported values.
- NoCPU and Memory must be positive whole numbers.
- TimeZoneName must be a valid Windows time zone ID on this host.
- UILanguage, SystemLocale, and UserLocale must be valid culture names (for example en-US).
- Folder settings must be absolute paths. A warning is shown if a folder does not exist.

When saving, the legacy Settings.HyperV.VMLocation property is removed in favor of VMFolder,
matching the behavior of PAWConfigEditorUI.ps1.

Use -WhatIf to preview changes without writing the file.

.PARAMETER ConfigPath
Path to the Config.json file. Defaults to Config\Config.json below the parent installation folder.

.PARAMETER Show
Displays the current settings. When combined with setting parameters, the settings
are displayed after the update.

.PARAMETER PassThru
Returns the updated settings as objects after saving.

.PARAMETER OrgName
Settings.CustomerData.OrgName - short organization name.

.PARAMETER FullName
Settings.CustomerData.FullName - full organization name.

.PARAMETER VMFolder
Settings.HyperV.VMFolder - folder where Hyper-V VM configuration folders are created.

.PARAMETER VMGen
Settings.HyperV.VMGen - Hyper-V generation, 1 or 2.

.PARAMETER NoCPU
Settings.HyperV.NoCPU - number of virtual processors.

.PARAMETER Memory
Settings.HyperV.Memory - VM memory in MB.

.PARAMETER DynamicMem
Settings.HyperV.DynamicMem - True or False.

.PARAMETER DiskMode
Settings.HyperV.DiskMode - Diff (differencing disk) or Copy (full copy).

.PARAMETER DomainOrWorkGroup
Settings.OperatingSystemConfiguration.DomainOrWorkGroup - DOMAIN or WORKGROUP.

.PARAMETER TimeZoneName
Settings.OperatingSystemConfiguration.TimeZoneName - Windows time zone ID, for example "W. Europe Standard Time".

.PARAMETER InputLocale
Settings.OperatingSystemConfiguration.InputLocale - keyboard layout, for example sv-SE or 041d:0000041d.

.PARAMETER SystemLocale
Settings.OperatingSystemConfiguration.SystemLocale - system locale, for example sv-SE.

.PARAMETER UILanguage
Settings.OperatingSystemConfiguration.UILanguage - display language, for example en-US.

.PARAMETER UserLocale
Settings.OperatingSystemConfiguration.UserLocale - regional format, for example sv-SE.

.PARAMETER InstallFolder
Settings.Configuration.InstallFolder - PAWDeploy installation folder.

.PARAMETER VHDFolder
Settings.Configuration.VHDFolder - folder containing reference VHD/VHDX files.

.PARAMETER SecurityBaseLineFolder
Settings.Configuration.SecurityBaseLineFolder - folder containing security baselines.

.PARAMETER LogFilesFolder
Settings.Configuration.LogFilesFolder - folder for PAWDeploy log files.

.EXAMPLE
.\Tools\Invoke-PAWConfigurationSettings.ps1

Displays the current settings.

.EXAMPLE
.\Tools\Invoke-PAWConfigurationSettings.ps1 -OrgName 'Contoso' -FullName 'Contoso Ltd'

Updates the organization name settings.

.EXAMPLE
$params = @{
    VMFolder  = 'D:\VMs'
    NoCPU     = 4
    Memory    = 8192
    DiskMode  = 'Diff'
}
.\Tools\Invoke-PAWConfigurationSettings.ps1 @params -Show

Updates the Hyper-V defaults and displays the resulting settings.

.EXAMPLE
.\Tools\Invoke-PAWConfigurationSettings.ps1 -TimeZoneName 'W. Europe Standard Time' -InputLocale 'sv-SE' -SystemLocale 'sv-SE' -UserLocale 'sv-SE' -WhatIf

Shows what would change without writing Config.json.

.NOTES
    Version : 2.0.0.4
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+.
    Safety  : Supports -WhatIf and -Confirm.
    Log file: %TEMP%\PAWDeploy\Invoke-PAWConfigurationSettings.log.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
Param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'),

    [Parameter(Mandatory = $false)]
    [switch]$Show,

    [Parameter(Mandatory = $false)]
    [switch]$PassThru,

    # CustomerData
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OrgName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$FullName,

    # HyperV
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$VMFolder,

    [Parameter(Mandatory = $false)]
    [ValidateSet('1', '2')]
    [string]$VMGen,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1024)]
    [int]$NoCPU,

    [Parameter(Mandatory = $false)]
    [ValidateRange(512, 16777216)]
    [int]$Memory,

    [Parameter(Mandatory = $false)]
    [ValidateSet('True', 'False')]
    [string]$DynamicMem,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Diff', 'Copy')]
    [string]$DiskMode,

    # OperatingSystemConfiguration
    [Parameter(Mandatory = $false)]
    [ValidateSet('DOMAIN', 'WORKGROUP')]
    [string]$DomainOrWorkGroup,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$TimeZoneName,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InputLocale,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SystemLocale,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$UILanguage,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$UserLocale,

    # Configuration
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InstallFolder,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$VHDFolder,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$SecurityBaseLineFolder,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        $expectedPath = Join-Path $env:TEMP 'PAWDeploy'
        if ($_ -ne '%TEMP%\PAWDeploy' -and -not [string]::Equals($_, $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "LogFilesFolder must be '$expectedPath' or '%TEMP%\PAWDeploy'."
        }
        $true
    })]
    [string]$LogFilesFolder
)

$PawUtilityManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUtilityManifest"
}
Import-Module -Name $PawUtilityManifest -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

# Maps each setting parameter to its section under Settings in Config.json.
$SettingMap = [ordered]@{
    OrgName                = 'CustomerData'
    FullName               = 'CustomerData'
    VMFolder               = 'HyperV'
    VMGen                  = 'HyperV'
    NoCPU                  = 'HyperV'
    Memory                 = 'HyperV'
    DynamicMem             = 'HyperV'
    DiskMode               = 'HyperV'
    DomainOrWorkGroup      = 'OperatingSystemConfiguration'
    TimeZoneName           = 'OperatingSystemConfiguration'
    InputLocale            = 'OperatingSystemConfiguration'
    SystemLocale           = 'OperatingSystemConfiguration'
    UILanguage             = 'OperatingSystemConfiguration'
    UserLocale             = 'OperatingSystemConfiguration'
    InstallFolder          = 'Configuration'
    VHDFolder              = 'Configuration'
    SecurityBaseLineFolder = 'Configuration'
    LogFilesFolder         = 'Configuration'
}
$FolderSettings = @('VMFolder', 'InstallFolder', 'VHDFolder', 'SecurityBaseLineFolder', 'LogFilesFolder')
$CultureSettings = @('SystemLocale', 'UILanguage', 'UserLocale')

function Get-PAWConfigSettingList {
    param(
        [Parameter(Mandatory = $true)]
        [psobject]$Config
    )

    foreach ($settingName in $SettingMap.Keys) {
        $section = $SettingMap[$settingName]
        $value = $null
        $sectionObject = $Config.Settings.PSObject.Properties[$section]
        if ($null -ne $sectionObject -and $null -ne $sectionObject.Value) {
            $property = $sectionObject.Value.PSObject.Properties[$settingName]
            if ($null -ne $property) {
                $value = $property.Value
            }
        }
        [PSCustomObject]@{
            Section = $section
            Setting = $settingName
            Value   = $value
        }
    }
}

$ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Config file not found: $ConfigPath"
}

$LogFolder = Resolve-PAWLogFolder
$LogPath = Join-Path $LogFolder 'Invoke-PAWConfigurationSettings.log'

try {
    $Config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-PAWLog -LogPath $LogPath -Message "Unable to read '$ConfigPath'." -Level 'ERROR' -Exception $_.Exception
    throw "Unable to read '$ConfigPath' as JSON: $($_.Exception.Message)"
}

if ($null -eq $Config.PSObject.Properties['Settings'] -or $null -eq $Config.Settings) {
    throw "Invalid Config.json format: missing Settings root object in '$ConfigPath'."
}

$RequestedSettings = @($SettingMap.Keys | Where-Object { $PSBoundParameters.ContainsKey($_) })

if ($RequestedSettings.Count -eq 0) {
    Get-PAWConfigSettingList -Config $Config
    return
}

# Validate and normalize all requested values before anything is changed.
$NewValues = [ordered]@{}
foreach ($settingName in $RequestedSettings) {
    $value = ([string]$PSBoundParameters[$settingName]).Trim()

    if ($FolderSettings -contains $settingName) {
        $expanded = [Environment]::ExpandEnvironmentVariables($value)
        if (-not [System.IO.Path]::IsPathRooted($expanded) -or $expanded -match '^[\\/](?![\\/])') {
            throw "$settingName must be an absolute path, for example C:\PAWDeploy. Value: '$value'"
        }
        $value = $value.TrimEnd('\', '/')
        if ($value -match '^[A-Za-z]:$') {
            $value = "$value\"
        }
        if (-not (Test-Path -LiteralPath $expanded -PathType Container)) {
            Write-Warning "$settingName folder does not exist yet: $value"
        }
    }
    elseif ($settingName -eq 'TimeZoneName') {
        $timeZone = [System.TimeZoneInfo]::GetSystemTimeZones() | Where-Object { $_.Id -eq $value } | Select-Object -First 1
        if ($null -eq $timeZone) {
            throw "TimeZoneName '$value' is not a valid Windows time zone ID. Use Get-TimeZone -ListAvailable to list valid IDs."
        }
        $value = $timeZone.Id
    }
    elseif ($CultureSettings -contains $settingName) {
        $cultureName = Resolve-PAWCultureName -Name $value
        if ([string]::IsNullOrEmpty($cultureName)) {
            throw "$settingName '$value' is not a valid culture name, for example en-US or sv-SE."
        }
        $value = $cultureName
    }
    elseif ($settingName -eq 'InputLocale') {
        if ($value -notmatch '^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}$') {
            $cultureName = Resolve-PAWCultureName -Name $value
            if ([string]::IsNullOrEmpty($cultureName)) {
                throw "InputLocale '$value' is not a valid culture name (for example sv-SE) or keyboard identifier (for example 041d:0000041d)."
            }
            $value = $cultureName
        }
    }

    $NewValues[$settingName] = $value
}

$Changes = @()
foreach ($settingName in $NewValues.Keys) {
    $section = $SettingMap[$settingName]
    if ($null -eq $Config.Settings.PSObject.Properties[$section] -or $null -eq $Config.Settings.$section) {
        $Config.Settings | Add-Member -NotePropertyName $section -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    $sectionObject = $Config.Settings.$section
    $oldValue = $null
    if ($null -ne $sectionObject.PSObject.Properties[$settingName]) {
        $oldValue = $sectionObject.$settingName
    }
    $newValue = $NewValues[$settingName]
    if ([string]$oldValue -ceq $newValue) {
        Write-Verbose "$section.$settingName is already '$newValue'."
        continue
    }
    $sectionObject | Add-Member -NotePropertyName $settingName -NotePropertyValue $newValue -Force
    $Changes += [PSCustomObject]@{
        Section  = $section
        Setting  = $settingName
        OldValue = $oldValue
        NewValue = $newValue
    }
}

foreach ($obsoleteSetting in @('PAWFiles', 'PAWFilesFolder')) {
    $configurationSection = $Config.Settings.PSObject.Properties['Configuration']
    if ($null -ne $configurationSection -and $null -ne $configurationSection.Value -and
        $null -ne $configurationSection.Value.PSObject.Properties[$obsoleteSetting]) {
        $configurationSection.Value.PSObject.Properties.Remove($obsoleteSetting)
        $Changes += [PSCustomObject]@{
            Section  = 'Configuration'
            Setting  = $obsoleteSetting
            OldValue = '(configured)'
            NewValue = '(removed)'
        }
    }
}

if ($NewValues.Contains('VMFolder') -and $null -ne $Config.Settings.HyperV.PSObject.Properties['VMLocation']) {
    $Config.Settings.HyperV.PSObject.Properties.Remove('VMLocation')
    $Changes += [PSCustomObject]@{
        Section  = 'HyperV'
        Setting  = 'VMLocation'
        OldValue = '(legacy)'
        NewValue = '(removed)'
    }
}

if ($Changes.Count -eq 0) {
    Write-Host "No changes. Config.json already contains the requested values: $ConfigPath"
}
else {
    $changeSummary = ($Changes | ForEach-Object { "$($_.Section).$($_.Setting): '$($_.OldValue)' -> '$($_.NewValue)'" }) -join '; '
    if ($PSCmdlet.ShouldProcess($ConfigPath, "Update settings: $changeSummary")) {
        try {
            $jsonOutput = $Config | ConvertTo-Json -Depth 20
            Set-Content -LiteralPath $ConfigPath -Value $jsonOutput -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-PAWLog -LogPath $LogPath -Message "Failed to save '$ConfigPath'." -Level 'ERROR' -Exception $_.Exception
            throw "Failed to save '$ConfigPath': $($_.Exception.Message)"
        }
        foreach ($change in $Changes) {
            Write-PAWLog -LogPath $LogPath -Message "Updated $($change.Section).$($change.Setting) in '$ConfigPath': '$($change.OldValue)' -> '$($change.NewValue)'"
        }
        $Changes | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Saved: $ConfigPath"
    }
}

if ($Show) {
    Get-PAWConfigSettingList -Config $Config | Format-Table -AutoSize | Out-String | Write-Host
}

if ($PassThru) {
    Get-PAWConfigSettingList -Config $Config
}
