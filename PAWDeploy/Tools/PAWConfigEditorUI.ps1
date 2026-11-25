<#
.SYNOPSIS
    Graphical editor for the PAWDeploy Config.json configuration file.

.DESCRIPTION
    PAWConfigEditorUI.ps1 presents a Windows Forms interface for editing Config.json
    without manually editing JSON. Template files are managed separately by
    PAWTemplateEditorUI.ps1.

    The editor allows changes to general configuration fields. The Templates mode
    provides the separate PAW Template Editor experience.

        General fields exposed in the UI:
            - OrgName                 (Settings.CustomerData.OrgName)
            - FullName                (Settings.CustomerData.FullName)
            - VMFolder                (Settings.HyperV.VMFolder)
            - InstallFolder           (Settings.Configuration.InstallFolder)
            - VHDFolder               (Settings.Configuration.VHDFolder)
            - SecurityBaseLineFolder  (Settings.Configuration.SecurityBaseLineFolder)

    Save writes the general fields back to Config.json (CustomerData,
    HyperV and Configuration sections) and removes the legacy HyperV.VMLocation
    property in favour of VMFolder.

    All operations are logged. UI errors are caught,
    logged with a script stack trace, and shown in an error dialog that includes the log
    path so issues can be diagnosed easily.

.PARAMETER ConfigPath
    Full path to the Config.json file to load and save.
    Defaults to Config\Config.json below the parent installation folder.

.PARAMETER LogPath
    Retained for compatibility. Must match the active editor's fixed log path
    in %TEMP%\PAWDeploy; the log location cannot be overridden.

.PARAMETER EditorMode
    Internal UI mode. Configuration is the default; Templates is launched by
    PAWTemplateEditorUI.ps1.

.EXAMPLE
    .\Tools\PAWConfigEditorUI.ps1

    Opens the editor for Config\Config.json below the parent installation folder.

.EXAMPLE
    .\Tools\PAWConfigEditorUI.ps1 -ConfigPath 'D:\PAWDeploy\Config\Config.json'

    Opens the editor for a specific Config.json file.

.NOTES
    Version : 2.0.0.28
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+.
    Files   : Config.json must exist at the resolved ConfigPath before the editor opens.
    Data    : UI state is persisted separately for each editor in %TEMP%\PAWDeploySettings.
    Log file: %TEMP%\PAWDeploy\PAWConfigEditorUI.log or PAWTemplateEditorUI.log.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [ValidateSet('Configuration', 'Templates')]
    [string]$EditorMode = 'Configuration',
    [string]$LogPath,
    [int]$WindowX,
    [int]$WindowY
)

if ($PSBoundParameters.ContainsKey('LogPath')) {
    if ([string]::IsNullOrWhiteSpace($env:TEMP)) {
        throw 'TEMP is not set; unable to validate the editor log path.'
    }
    $logName = if ($EditorMode -eq 'Templates') { 'PAWTemplateEditorUI.log' } else { 'PAWConfigEditorUI.log' }
    $expectedPath = [System.IO.Path]::GetFullPath((Join-Path $env:TEMP "PAWDeploy\$logName"))
    $actualPath = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($LogPath))
    if (-not [string]::Equals($actualPath, $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "LogPath must be '$expectedPath'."
    }
}

# Edition branding (logo); Build rewrites this value for the Community package.
$script:PAWEdition = 'Community'

$scriptFolder = $null
if ($PSScriptRoot) {
    $scriptFolder = Split-Path -Parent $PSScriptRoot
}
elseif ($MyInvocation.MyCommand.Path) {
    $scriptFolder = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
else {
    throw 'Unable to resolve the PAWDeploy installation root from the Tools script path.'
}


$pawUtilityManifestPath = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $pawUtilityManifestPath -PathType Leaf)) {
    throw "Required module not found: $pawUtilityManifestPath"
}
Import-Module -Name $pawUtilityManifestPath -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
if ($EditorMode -eq 'Templates') {
    $script:PAWToolTitle = $script:PAWToolTitle.Replace('PAWConfigEditorUI.ps1', 'PAW Template Editor')
}
else {
    $script:PAWToolTitle = $script:PAWToolTitle.Replace('PAWConfigEditorUI.ps1', 'PAW Configuration Editor')
}

$pawUiUtilityManifestPath = Join-Path $scriptFolder 'Functions\PAWUIUtility\PAWUIUtility.psd1'
if (-not (Test-Path -LiteralPath $pawUiUtilityManifestPath -PathType Leaf)) {
    throw "Required module not found: $pawUiUtilityManifestPath"
}
Import-Module -Name $pawUiUtilityManifestPath -Force -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $scriptFolder 'Config\Config.json'
}
$configuredLogFolder = Resolve-PAWLogFolder
$logName = if ($EditorMode -eq 'Templates') { 'PAWTemplateEditorUI.log' } else { 'PAWConfigEditorUI.log' }
$LogPath = Join-Path $configuredLogFolder $logName

$script:SettingsRoot = Join-Path $env:TEMP 'PAWDeploySettings'
$script:SettingsFile = Join-Path $script:SettingsRoot ("{0}.settings" -f $(if ($EditorMode -eq 'Templates') { 'PAWTemplateEditorUI' } else { 'PAWConfigEditorUI' }))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

$Font1 = [System.Drawing.Font]::new('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$FontHeading1 = [System.Drawing.Font]::new('Segoe UI', 24, [System.Drawing.FontStyle]::Bold)
$FontHeading2 = [System.Drawing.Font]::new('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$FontData = [System.Drawing.Font]::new('Segoe UI', 10)

$Palette = Get-PAWUiPalette


function New-PAWTemplateTableFromJsonFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TemplateFolderPath
    )

    $script:TemplateFilePathsByName = @{}

    # Define column order to match JSON template structure
    $preferredColumnOrder = @(Get-PAWTemplateSettingOrder)

    $columnNames = New-Object System.Collections.Generic.List[string]
    foreach ($col in $preferredColumnOrder) {
        [void]$columnNames.Add($col)
    }

    $templateItems = New-Object System.Collections.Generic.List[object]
    $additionalColumns = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $TemplateFolderPath -PathType Container) {
        $jsonFiles = Get-ChildItem -LiteralPath $TemplateFolderPath -Filter '*.json' -File | Where-Object Name -ne 'Config.json' | Sort-Object Name
        foreach ($jsonFile in $jsonFiles) {
            try {
                $rawContent = Get-Content -LiteralPath $jsonFile.FullName -Raw
                $jsonData = ConvertFrom-Json -InputObject $rawContent -ErrorAction Stop

                # Track any properties not in the preferred order (for future extensibility)
                foreach ($prop in @($jsonData.PSObject.Properties)) {
                    $propName = [string]$prop.Name
                    if (-not [string]::IsNullOrWhiteSpace($propName) -and -not $columnNames.Contains($propName) -and -not $additionalColumns.Contains($propName)) {
                        [void]$additionalColumns.Add($propName)
                    }
                }

                [void]$templateItems.Add([PSCustomObject]@{
                        FilePath = $jsonFile.FullName
                        Data     = $jsonData
                        FileName = $jsonFile.BaseName
                    })
            }
            catch {
                Write-PAWLog -Level 'WARN' -Message ("Skipping invalid template JSON file '{0}': {1}" -f $jsonFile.FullName, $_.Exception.Message) -LogPath $LogPath
            }
        }
    }

    # Add any additional columns found in templates (for future extensibility)
    foreach ($addCol in $additionalColumns) {
        [void]$columnNames.Add($addCol)
    }

    $table = New-Object System.Data.DataTable
    foreach ($col in $columnNames) {
        if (-not $table.Columns.Contains($col)) {
            [void]$table.Columns.Add($col, [string])
        }
    }

    foreach ($templateItem in $templateItems) {
        $row = $table.NewRow()
        $nameValue = [string]$templateItem.Data.Name
        if ([string]::IsNullOrWhiteSpace($nameValue)) {
            $nameValue = [string]$templateItem.FileName
        }

        $baseName = $nameValue
        $suffix = 2
        while ($script:TemplateFilePathsByName.ContainsKey($nameValue)) {
            $nameValue = "{0} ({1})" -f $baseName, $suffix
            $suffix++
        }

        $null = ($row['Name'] = $nameValue)
        $script:TemplateFilePathsByName[$nameValue] = $templateItem.FilePath

        foreach ($column in @($table.Columns)) {
            $columnName = [string]$column.ColumnName
            if ($columnName -eq 'Name') {
                continue
            }

            $property = $templateItem.Data.PSObject.Properties[$columnName]
            if ($null -ne $property) {
                $null = ($row[$columnName] = [string]$property.Value)
            }
            elseif ($columnName -eq 'ASR') {
                $null = ($row[$columnName] = 'True')
            }
        }

        [void]$table.Rows.Add($row)
    }

    $script:TemplateColumns = @($columnNames.ToArray())
    Write-Output -NoEnumerate $table
}

function Save-PAWSelectedTemplateToJson {
    $table = Get-PAWTemplateTableFromGrid
    if ($script:SelectedTemplateRowIndex -lt 0 -or $script:SelectedTemplateRowIndex -ge $table.Rows.Count) {
        throw 'No template selected.'
    }

    $oldName = [string]$table.Rows[$script:SelectedTemplateRowIndex]['Name']
    Update-PAWSelectedTemplateToGrid
    $row = $table.Rows[$script:SelectedTemplateRowIndex]
    $newName = [string]$row['Name']

    $templateFolder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path

    $targetFilePath = $null
    if ($script:TemplateFilePathsByName.ContainsKey($oldName)) {
        $targetFilePath = [string]$script:TemplateFilePathsByName[$oldName]
    }

    if ([string]::IsNullOrWhiteSpace($targetFilePath)) {
        $targetFilePath = Get-PAWUniqueTemplateFilePath -TemplateFolder $templateFolder -TemplateName $newName
    }

    $templateObject = [ordered]@{}
    foreach ($column in @($table.Columns)) {
        $columnName = [string]$column.ColumnName
        $templateObject[$columnName] = [string]$row[$columnName]
    }

    $jsonOutput = $templateObject | ConvertTo-Json -Depth 20
    Set-Content -LiteralPath $targetFilePath -Value $jsonOutput -Encoding UTF8

    if ($script:TemplateFilePathsByName.ContainsKey($oldName)) {
        [void]$script:TemplateFilePathsByName.Remove($oldName)
    }
    $script:TemplateFilePathsByName[$newName] = $targetFilePath

    Write-PAWLog -Message ("Template '{0}' saved to '{1}'." -f $newName, $targetFilePath) -LogPath $LogPath
}


function Save-PAWConfigFromUi {
    param(
        [Parameter(Mandatory = $true)]
        [object]$JsonData,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtOrgName,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtFullName,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtVmFolder,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtInstallFolder,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtVhdFolder,
        [Parameter(Mandatory = $true)]
        [System.Windows.Forms.TextBox]$TxtSecurityBaselineFolder,
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if ($null -eq $JsonData.PSObject.Properties['Settings']) {
        throw 'Invalid Config.json format: missing Settings root object.'
    }

    if ($null -eq $JsonData.Settings.PSObject.Properties['CustomerData']) {
        $JsonData.Settings | Add-Member -NotePropertyName CustomerData -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    if ($null -eq $JsonData.Settings.PSObject.Properties['HyperV']) {
        $JsonData.Settings | Add-Member -NotePropertyName HyperV -NotePropertyValue ([PSCustomObject]@{}) -Force
    }
    if ($null -eq $JsonData.Settings.PSObject.Properties['Configuration']) {
        $JsonData.Settings | Add-Member -NotePropertyName Configuration -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    $JsonData.Settings.CustomerData | Add-Member -NotePropertyName OrgName -NotePropertyValue ([string]$TxtOrgName.Text) -Force
    $JsonData.Settings.CustomerData | Add-Member -NotePropertyName FullName -NotePropertyValue ([string]$TxtFullName.Text) -Force
    $JsonData.Settings.HyperV | Add-Member -NotePropertyName VMFolder -NotePropertyValue ([string]$TxtVmFolder.Text) -Force

    # Drop legacy VMLocation property in favor of VMFolder.
    if ($null -ne $JsonData.Settings.HyperV.PSObject.Properties['VMLocation']) {
        $JsonData.Settings.HyperV.PSObject.Properties.Remove('VMLocation')
    }

    $JsonData.Settings.Configuration | Add-Member -NotePropertyName InstallFolder -NotePropertyValue ([string]$TxtInstallFolder.Text) -Force
    $JsonData.Settings.Configuration | Add-Member -NotePropertyName VHDFolder -NotePropertyValue ([string]$TxtVhdFolder.Text) -Force
    $JsonData.Settings.Configuration | Add-Member -NotePropertyName SecurityBaseLineFolder -NotePropertyValue ([string]$TxtSecurityBaselineFolder.Text) -Force
    foreach ($name in @('TemplateFolder', 'TemplatesFolder', 'Templates')) {
        $JsonData.Settings.Configuration.PSObject.Properties.Remove($name)
    }
    $JsonData.Settings.Configuration.PSObject.Properties.Remove('PAWFiles')
    $JsonData.Settings.Configuration.PSObject.Properties.Remove('PAWFilesFolder')

    $jsonOutput = $JsonData | ConvertTo-Json -Depth 20
    Set-Content -LiteralPath $OutputPath -Value $jsonOutput -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

if (-not (Test-Path -LiteralPath $LogPath)) {
    New-Item -Path $LogPath -ItemType File -Force | Out-Null
}

Write-PAWLog -Message "PAWConfigEditor starting. ConfigPath='$ConfigPath' LogPath='$LogPath'" -LogPath $LogPath

$script:ConfigJson = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$script:TemplateColumns = @('Name')
$script:TemplateFilePathsByName = @{}

[System.Windows.Forms.Application]::EnableVisualStyles()
try {
    [System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
}
catch {
    Write-PAWLog -Level 'WARN' -Message ('SetUnhandledExceptionMode skipped: ' + $_.Exception.Message) -LogPath $LogPath
}
[System.Windows.Forms.Application]::add_ThreadException({
    param($senderObj, $e)
    Write-PAWLog -Level 'ERROR' -Message 'Unhandled UI thread exception.' -Exception $e.Exception -LogPath $LogPath
})
[System.AppDomain]::CurrentDomain.add_UnhandledException({
    param($senderObj, $e)
    $ex = $e.ExceptionObject -as [System.Exception]
    if ($null -ne $ex) {
        Write-PAWLog -Level 'ERROR' -Message 'Unhandled AppDomain exception.' -Exception $ex -LogPath $LogPath
    }
    else {
        Write-PAWLog -Level 'ERROR' -Message 'Unhandled AppDomain exception with non-Exception payload.' -LogPath $LogPath
    }
})

# Log DataGridView data errors instead of showing the WinForms "DataGridView Default Error" dialog.
$script:PAWGridDataErrorHandler = {
    param($senderObj, $e)
    $e.ThrowException = $false
    try {
        $setting = ''
        $value = ''
        if ($e.RowIndex -ge 0 -and $e.RowIndex -lt $senderObj.Rows.Count) {
            $row = $senderObj.Rows[$e.RowIndex]
            if ($senderObj.Columns.Contains('Setting')) { $setting = [string]$row.Cells['Setting'].Value }
            if ($e.ColumnIndex -ge 0) { $value = [string]$row.Cells[$e.ColumnIndex].Value }
        }
        Write-PAWLog -Level 'WARN' -Message ("DataGridView '{0}' data error. Row={1} Column={2} Setting='{3}' Value='{4}' Context={5}: {6}" -f $senderObj.Name, $e.RowIndex, $e.ColumnIndex, $setting, $value, $e.Context, $e.Exception.Message) -Exception $e.Exception -LogPath $LogPath
    }
    catch {
        Write-PAWLog -Level 'WARN' -Message ('DataGridView data error: ' + $e.Exception.Message) -LogPath $LogPath
    }
}




$form = New-Object System.Windows.Forms.Form
$form.Text = 'Truesec PAW Deployment Toolkit - Enterprise Edition'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1344, 756)
$form.MinimumSize = New-Object System.Drawing.Size(1344, 756)
$form.MaximumSize = New-Object System.Drawing.Size(1344, 756)
$form.MaximizeBox = $false
$form.Font = $Font1
$form.BackColor = $Palette.Background

$editorTabs = New-Object System.Windows.Forms.TabControl
$editorTabs.Location = New-Object System.Drawing.Point(10, 75)
$editorTabs.Size = New-Object System.Drawing.Size(1300, 585)
$configurationTab = New-Object System.Windows.Forms.TabPage
$configurationTab.Text = 'Configuration'
$templatesTab = New-Object System.Windows.Forms.TabPage
$templatesTab.Text = 'Templates'
$transferTab = New-Object System.Windows.Forms.TabPage
$transferTab.Text = 'Import/Export'
[void]$editorTabs.TabPages.Add($configurationTab)
[void]$editorTabs.TabPages.Add($templatesTab)
[void]$editorTabs.TabPages.Add($transferTab)
if ($EditorMode -eq 'Templates') {
    [void]$editorTabs.TabPages.Remove($configurationTab)
}
else {
    [void]$editorTabs.TabPages.Remove($templatesTab)
    [void]$editorTabs.TabPages.Remove($transferTab)
}
$form.Controls.Add($editorTabs)

# Set the Icon for the GUI
$form.Icon = Get-PAWWindowIcon

$groupGeneral = New-Object System.Windows.Forms.GroupBox
$groupGeneral.Text = 'General Settings'
$groupGeneral.Name = 'PAWGeneralSettings'
$groupGeneral.Location = New-Object System.Drawing.Point(342, 10)
$groupGeneral.Size = New-Object System.Drawing.Size(940, 300)
$groupGeneral.Font = $Font1
$configurationTab.Controls.Add($groupGeneral)

$labelLeft = 15
$labelWidth = 190
$inputLeft = 270
$inputWidth = 480
$browseGap = 10
$browseWidth = 45
$browseLeft = $inputLeft - $browseWidth - $browseGap
$rowHeight = 32
$firstRowTop = 26

$labelOrg = New-Object System.Windows.Forms.Label
$labelOrg.Text = 'Organization Name'
$labelOrg.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, $firstRowTop
$labelOrg.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelOrg.TextAlign = 'MiddleRight'
$labelOrg.Font = $Font1
$groupGeneral.Controls.Add($labelOrg)

$txtOrgName = New-Object System.Windows.Forms.TextBox
$txtOrgName.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, $firstRowTop
$txtOrgName.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtOrgName.Font = $FontData
$groupGeneral.Controls.Add($txtOrgName)

$labelFull = New-Object System.Windows.Forms.Label
$labelFull.Text = 'Full Name'
$labelFull.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + $rowHeight)
$labelFull.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelFull.TextAlign = 'MiddleRight'
$labelFull.Font = $Font1
$groupGeneral.Controls.Add($labelFull)

$txtFullName = New-Object System.Windows.Forms.TextBox
$txtFullName.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + $rowHeight)
$txtFullName.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtFullName.Font = $FontData
$groupGeneral.Controls.Add($txtFullName)

$labelVm = New-Object System.Windows.Forms.Label
$labelVm.Text = 'Virtual Machine Folder'
$labelVm.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + ($rowHeight * 2))
$labelVm.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelVm.TextAlign = 'MiddleRight'
$labelVm.Font = $Font1
$groupGeneral.Controls.Add($labelVm)

$txtVmFolder = New-Object System.Windows.Forms.TextBox
$txtVmFolder.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + ($rowHeight * 2))
$txtVmFolder.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtVmFolder.Font = $FontData
$groupGeneral.Controls.Add($txtVmFolder)

$linkBrowseVmFolder = New-Object System.Windows.Forms.LinkLabel
$linkBrowseVmFolder.Text = 'Browse'
$linkBrowseVmFolder.AccessibleName = 'Browse for Virtual Machine Folder'
$linkBrowseVmFolder.Location = New-Object System.Drawing.Point -ArgumentList $browseLeft, ($firstRowTop + ($rowHeight * 2) + 4)
$linkBrowseVmFolder.AutoSize = $true
$linkBrowseVmFolder.LinkBehavior = [System.Windows.Forms.LinkBehavior]::AlwaysUnderline
$linkBrowseVmFolder.LinkColor = $Palette.Accent
$linkBrowseVmFolder.ActiveLinkColor = $Palette.Accent
$groupGeneral.Controls.Add($linkBrowseVmFolder)

$labelInstallFolder = New-Object System.Windows.Forms.Label
$labelInstallFolder.Text = 'Installation Folder'
$labelInstallFolder.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + ($rowHeight * 3))
$labelInstallFolder.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelInstallFolder.TextAlign = 'MiddleRight'
$labelInstallFolder.Font = $Font1
$groupGeneral.Controls.Add($labelInstallFolder)

$txtInstallFolder = New-Object System.Windows.Forms.TextBox
$txtInstallFolder.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + ($rowHeight * 3))
$txtInstallFolder.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtInstallFolder.Font = $FontData
$txtInstallFolder.ReadOnly = $true
$txtInstallFolder.BackColor = $Palette.ReadOnly
$groupGeneral.Controls.Add($txtInstallFolder)

$labelVhdFolder = New-Object System.Windows.Forms.Label
$labelVhdFolder.Text = 'Virtual Harddisk Folder'
$labelVhdFolder.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + ($rowHeight * 4))
$labelVhdFolder.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelVhdFolder.TextAlign = 'MiddleRight'
$labelVhdFolder.Font = $Font1
$groupGeneral.Controls.Add($labelVhdFolder)

$txtVhdFolder = New-Object System.Windows.Forms.TextBox
$txtVhdFolder.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + ($rowHeight * 4))
$txtVhdFolder.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtVhdFolder.Font = $FontData
$groupGeneral.Controls.Add($txtVhdFolder)

$linkBrowseVhdFolder = New-Object System.Windows.Forms.LinkLabel
$linkBrowseVhdFolder.Text = 'Browse'
$linkBrowseVhdFolder.AccessibleName = 'Browse for Virtual Harddisk Folder'
$linkBrowseVhdFolder.Location = New-Object System.Drawing.Point -ArgumentList $browseLeft, ($firstRowTop + ($rowHeight * 4) + 4)
$linkBrowseVhdFolder.AutoSize = $true
$linkBrowseVhdFolder.LinkBehavior = [System.Windows.Forms.LinkBehavior]::AlwaysUnderline
$linkBrowseVhdFolder.LinkColor = $Palette.Accent
$linkBrowseVhdFolder.ActiveLinkColor = $Palette.Accent
$groupGeneral.Controls.Add($linkBrowseVhdFolder)

$labelSecurityBaselineFolder = New-Object System.Windows.Forms.Label
$labelSecurityBaselineFolder.Text = 'Security Baseline Folder'
$labelSecurityBaselineFolder.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + ($rowHeight * 5))
$labelSecurityBaselineFolder.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelSecurityBaselineFolder.TextAlign = 'MiddleRight'
$labelSecurityBaselineFolder.Font = $Font1
$groupGeneral.Controls.Add($labelSecurityBaselineFolder)

$txtSecurityBaselineFolder = New-Object System.Windows.Forms.TextBox
$txtSecurityBaselineFolder.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + ($rowHeight * 5))
$txtSecurityBaselineFolder.Size = New-Object System.Drawing.Size($inputWidth, 25)
$txtSecurityBaselineFolder.Font = $FontData
$groupGeneral.Controls.Add($txtSecurityBaselineFolder)

$linkBrowseSecurityBaselineFolder = New-Object System.Windows.Forms.LinkLabel
$linkBrowseSecurityBaselineFolder.Text = 'Browse'
$linkBrowseSecurityBaselineFolder.AccessibleName = 'Browse for Security Baseline Folder'
$linkBrowseSecurityBaselineFolder.Location = New-Object System.Drawing.Point -ArgumentList $browseLeft, ($firstRowTop + ($rowHeight * 5) + 4)
$linkBrowseSecurityBaselineFolder.AutoSize = $true
$linkBrowseSecurityBaselineFolder.LinkBehavior = [System.Windows.Forms.LinkBehavior]::AlwaysUnderline
$linkBrowseSecurityBaselineFolder.LinkColor = $Palette.Accent
$linkBrowseSecurityBaselineFolder.ActiveLinkColor = $Palette.Accent
$groupGeneral.Controls.Add($linkBrowseSecurityBaselineFolder)

# --- New UI Layout for lower right ---
# Shrink grid, add right column for template actions, left column for Save Config, Close button bottom right

# Hidden grid used as the backing template table host.
$gridTemplates = New-Object System.Windows.Forms.DataGridView
$gridTemplates.Dock = 'None'
$gridTemplates.Visible = $false
$gridTemplates.Size = New-Object System.Drawing.Size(10, 10)
$gridTemplates.AllowUserToAddRows = $true
$gridTemplates.AllowUserToDeleteRows = $true
$gridTemplates.AllowUserToOrderColumns = $true
$gridTemplates.AutoSizeColumnsMode = 'AllCells'
$gridTemplates.RowHeadersVisible = $false
$gridTemplates.SelectionMode = 'CellSelect'
$gridTemplates.EditMode = 'EditOnEnter'
$gridTemplates.Font = $FontData
$gridTemplates.Name = 'gridTemplates'
$gridTemplates.add_DataError($script:PAWGridDataErrorHandler)
$form.Controls.Add($gridTemplates)

# Shrink the template grid to make space for side columns
$gridTemplates.Width = 800
$gridTemplates.Height = 320
$gridTemplates.Location = New-Object System.Drawing.Point(15, 400)

# Save below the right-aligned settings group.
$panelSaveConfig = New-Object System.Windows.Forms.Panel
$panelSaveConfig.Name = 'PAWSaveConfiguration'
$panelSaveConfig.Size = New-Object System.Drawing.Size(200, 30)
$panelSaveConfig.Location = New-Object System.Drawing.Point(1082, 320)
$configurationTab.Controls.Add($panelSaveConfig)
$configurationTab.Add_Layout({
    param($sender, $eventArgs)
    $settings = $sender.Controls['PAWGeneralSettings']
    $savePanel = $sender.Controls['PAWSaveConfiguration']
    $settings.Left = $sender.ClientSize.Width - $settings.Width - 10
    $savePanel.Left = $settings.Right - $savePanel.Width
})

$labelTheme = New-Object System.Windows.Forms.Label
$labelTheme.Text = 'UI Theme'
$labelTheme.Location = New-Object System.Drawing.Point -ArgumentList $labelLeft, ($firstRowTop + ($rowHeight * 7))
$labelTheme.Size = New-Object System.Drawing.Size($labelWidth, 24)
$labelTheme.TextAlign = 'MiddleRight'
$labelTheme.Font = $Font1
$groupGeneral.Controls.Add($labelTheme)
$themeSelect = New-Object System.Windows.Forms.ComboBox
$themeSelect.Name = 'PAWThemeSelect'
$themeSelect.DropDownStyle = 'DropDownList'
$themeSelect.Location = New-Object System.Drawing.Point -ArgumentList $inputLeft, ($firstRowTop + ($rowHeight * 7))
$themeSelect.Size = New-Object System.Drawing.Size(200, 25)
$themeSelect.Items.AddRange(@('Dark', 'Light'))
$themeSelect.SelectedItem = $Palette.Theme
$groupGeneral.Controls.Add($themeSelect)
$themeSelect.Add_SelectionChangeCommitted({
    param($sender, $eventArgs)
    if ([string]$sender.SelectedItem -ne $Palette.Theme) {
        [void][System.Windows.Forms.MessageBox]::Show($form,
            'Save the configuration, then restart the application to apply the selected theme.',
            'Restart required', 'OK', 'Information')
    }
})

$btnSaveConfig = New-Object System.Windows.Forms.Button
$btnSaveConfig.Text = 'Save'
$btnSaveConfig.Size = New-Object System.Drawing.Size(200, 30)
$btnSaveConfig.Location = New-Object System.Drawing.Point(0, 0)
Set-PAWThemedButton -Button $btnSaveConfig -Accent
$panelSaveConfig.Controls.Add($btnSaveConfig)
$btnSave = $btnSaveConfig

# Panel for template actions (right column)
 $panelTemplateActions = New-Object System.Windows.Forms.Panel
 $panelTemplateActions.Size = New-Object System.Drawing.Size(1270, 30)
 $panelTemplateActions.Location = New-Object System.Drawing.Point(10, 10)
 $templatesTab.Controls.Add($panelTemplateActions)


$btnSelectTemplate = New-Object System.Windows.Forms.Button
$btnSelectTemplate.Text = 'Select Template'
$btnSelectTemplate.Size = New-Object System.Drawing.Size(150, 30)
$btnSelectTemplate.Location = New-Object System.Drawing.Point(0, 0)
Set-PAWThemedButton -Button $btnSelectTemplate
$panelTemplateActions.Controls.Add($btnSelectTemplate)

$btnAddTemplate = New-Object System.Windows.Forms.Button
$btnAddTemplate.Text = 'New Template'
$btnAddTemplate.Size = New-Object System.Drawing.Size(150, 30)
$btnAddTemplate.Location = New-Object System.Drawing.Point(210, 0)
Set-PAWThemedButton -Button $btnAddTemplate
$panelTemplateActions.Controls.Add($btnAddTemplate)

$btnRemoveTemplate = New-Object System.Windows.Forms.Button
$btnRemoveTemplate.Text = 'Remove Template'
$btnRemoveTemplate.Size = New-Object System.Drawing.Size(150, 30)
$btnRemoveTemplate.Location = New-Object System.Drawing.Point(420, 0)
Set-PAWThemedButton -Button $btnRemoveTemplate
$panelTemplateActions.Controls.Add($btnRemoveTemplate)

$btnCopyTemplate = New-Object System.Windows.Forms.Button
$btnCopyTemplate.Text = 'Clone Template'
$btnCopyTemplate.Size = New-Object System.Drawing.Size(150, 30)
$btnCopyTemplate.Location = New-Object System.Drawing.Point(630, 0)
Set-PAWThemedButton -Button $btnCopyTemplate
$panelTemplateActions.Controls.Add($btnCopyTemplate)

$btnSaveTemplate = New-Object System.Windows.Forms.Button
$btnSaveTemplate.Text = 'Save Template'
$btnSaveTemplate.Size = New-Object System.Drawing.Size(150, 30)
$btnSaveTemplate.Location = New-Object System.Drawing.Point(1050, 0)
Set-PAWThemedButton -Button $btnSaveTemplate -Accent
$panelTemplateActions.Controls.Add($btnSaveTemplate)

$btnReload = New-Object System.Windows.Forms.Button
$btnReload.Text = 'Reload Template'
$btnReload.Size = New-Object System.Drawing.Size(150, 30)
$btnReload.Location = New-Object System.Drawing.Point(840, 0)
$panelTemplateActions.Controls.Add($btnReload)
Set-PAWThemedButton -Button $btnReload

$transferLabel = New-Object System.Windows.Forms.Label
$transferLabel.Text = 'Import validated template JSON files, or select saved templates below to export. Save template edits before transferring.'
$transferLabel.Location = New-Object System.Drawing.Point(15, 15)
$transferLabel.Size = New-Object System.Drawing.Size(1240, 40)
$transferLabel.Font = $FontData
$transferTab.Controls.Add($transferLabel)

$btnImportTemplates = New-Object System.Windows.Forms.Button
$btnImportTemplates.Text = 'Import Templates'
$btnImportTemplates.Location = New-Object System.Drawing.Point(15, 65)
$btnImportTemplates.Size = New-Object System.Drawing.Size(200, 30)
Set-PAWThemedButton -Button $btnImportTemplates -Accent
$transferTab.Controls.Add($btnImportTemplates)

$btnExportTemplates = New-Object System.Windows.Forms.Button
$btnExportTemplates.Text = 'Export Selected'
$btnExportTemplates.Location = New-Object System.Drawing.Point(225, 65)
$btnExportTemplates.Size = New-Object System.Drawing.Size(200, 30)
Set-PAWThemedButton -Button $btnExportTemplates
$transferTab.Controls.Add($btnExportTemplates)

$btnRefreshTransfer = New-Object System.Windows.Forms.Button
$btnRefreshTransfer.Text = 'Refresh'
$btnRefreshTransfer.Location = New-Object System.Drawing.Point(435, 65)
$btnRefreshTransfer.Size = New-Object System.Drawing.Size(150, 30)
Set-PAWThemedButton -Button $btnRefreshTransfer
$transferTab.Controls.Add($btnRefreshTransfer)

$transferTemplates = New-Object System.Windows.Forms.ListBox
$transferTemplates.Location = New-Object System.Drawing.Point(15, 110)
$transferTemplates.Size = New-Object System.Drawing.Size(1240, 400)
$transferTemplates.SelectionMode = 'MultiExtended'
$transferTemplates.DisplayMember = 'Name'
$transferTemplates.Font = $FontData
$transferTab.Controls.Add($transferTemplates)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Size = New-Object System.Drawing.Size(150, 30)
$btnClose.Location = New-Object System.Drawing.Point(1160, 665)
Set-PAWThemedButton -Button $btnClose
$form.Controls.Add($btnClose)
$btnClose.BringToFront()

$linkBrowseVhdFolder.Add_LinkClicked({
    try {
        $selectedPath = Select-PAWFolderPath -InitialPath ([string]$txtVhdFolder.Text) -Description 'Select VHDFolder'
        if (-not [string]::IsNullOrWhiteSpace($selectedPath)) {
            $txtVhdFolder.Text = $selectedPath
            $dropdownPaths = Update-PAWResolvedDropdownSourcePaths -ConfigPath $ConfigPath -VhdFolderText ([string]$txtVhdFolder.Text) -SecurityBaselineFolderText ([string]$txtSecurityBaselineFolder.Text)
            $script:ResolvedVhdFolder = $dropdownPaths.VhdFolder
            $script:ResolvedSecurityBaselineFolder = $dropdownPaths.SecurityBaselineFolder
            $script:ResolvedCustomScriptsFolder = $dropdownPaths.CustomScriptsFolder
        }
    }
    catch {
        Show-PAWUiError -Title 'Browse VHDFolder Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$linkBrowseVmFolder.Add_LinkClicked({
    try {
        $selectedPath = Select-PAWFolderPath -InitialPath ([string]$txtVmFolder.Text) -Description 'Select VMFolder'
        if (-not [string]::IsNullOrWhiteSpace($selectedPath)) {
            $txtVmFolder.Text = $selectedPath
        }
    }
    catch {
        Show-PAWUiError -Title 'Browse VMFolder Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$linkBrowseSecurityBaselineFolder.Add_LinkClicked({
    try {
        $selectedPath = Select-PAWFolderPath -InitialPath ([string]$txtSecurityBaselineFolder.Text) -Description 'Select SecurityBaseLineFolder'
        if (-not [string]::IsNullOrWhiteSpace($selectedPath)) {
            $txtSecurityBaselineFolder.Text = $selectedPath
            $dropdownPaths = Update-PAWResolvedDropdownSourcePaths -ConfigPath $ConfigPath -VhdFolderText ([string]$txtVhdFolder.Text) -SecurityBaselineFolderText ([string]$txtSecurityBaselineFolder.Text)
            $script:ResolvedVhdFolder = $dropdownPaths.VhdFolder
            $script:ResolvedSecurityBaselineFolder = $dropdownPaths.SecurityBaselineFolder
            $script:ResolvedCustomScriptsFolder = $dropdownPaths.CustomScriptsFolder
        }
    }
    catch {
        Show-PAWUiError -Title 'Browse SecurityBaseLineFolder Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$panelTemplateEditor = New-Object System.Windows.Forms.Panel
$panelTemplateEditor.Dock = 'None'
$panelTemplateEditor.Location = New-Object System.Drawing.Point(10, 50)
$panelTemplateEditor.Size = New-Object System.Drawing.Size(1270, 470)
$templatesTab.Controls.Add($panelTemplateEditor)

$groupTemplate = New-Object System.Windows.Forms.GroupBox
$groupTemplate.Text = 'Template Settings'
$groupTemplate.Dock = 'Fill'
$groupTemplate.Padding = New-Object System.Windows.Forms.Padding(8, 20, 8, 8)
$groupTemplate.Font = $Font1
$panelTemplateEditor.Controls.Add($groupTemplate)

$panelTemplateHeader = New-Object System.Windows.Forms.Panel
$panelTemplateHeader.Dock = 'Top'
$panelTemplateHeader.Height = 0
$panelTemplateHeader.Padding = New-Object System.Windows.Forms.Padding(0, 6, 0, 0)
$groupTemplate.Controls.Add($panelTemplateHeader)

$panelTemplateGridHost = New-Object System.Windows.Forms.Panel
$panelTemplateGridHost.Dock = 'Fill'
$panelTemplateGridHost.Padding = New-Object System.Windows.Forms.Padding(0)
$groupTemplate.Controls.Add($panelTemplateGridHost)

$txtSelectedTemplate = New-Object System.Windows.Forms.TextBox
$txtSelectedTemplate.Visible = $false
$txtSelectedTemplate.Font = $FontData

$gridTemplateSettings = New-Object System.Windows.Forms.DataGridView
$gridTemplateSettings.Dock = 'Fill'
$gridTemplateSettings.AllowUserToAddRows = $false
$gridTemplateSettings.AllowUserToDeleteRows = $false
$gridTemplateSettings.RowHeadersVisible = $false
$gridTemplateSettings.ColumnHeadersVisible = $false
$gridTemplateSettings.AutoSizeColumnsMode = 'None'
$gridTemplateSettings.SelectionMode = 'CellSelect'
$gridTemplateSettings.EditMode = 'EditOnEnter'
$gridTemplateSettings.Font = $FontData
$gridTemplateSettings.ScrollBars = 'Both'
$gridTemplateSettings.Name = 'gridTemplateSettings'
$gridTemplateSettings.add_DataError($script:PAWGridDataErrorHandler)
$gridTemplateSettings.add_DataBindingComplete({
    param($sender, $e)
    # Rebuilding dropdown cells after each committed value (ItemChanged) replaces cells mid-edit and raises ArgumentException.
    if ($e.ListChangedType -ne [System.ComponentModel.ListChangedType]::Reset) {
        return
    }
    try {
        Add-PAWTemplateSettingsEditorDropDowns -Grid $gridTemplateSettings -AllowedValuesProvider {
        param($settingName)
        Get-PAWTemplateSettingAllowedValues -SettingName $settingName
    }
        Set-PAWTemplateEditorColumnWidths -Grid $gridTemplateSettings -KeyWidth 300 -ValueWidth 900
    }
    catch {
        Write-PAWLog -Level 'WARN' -Message ("Failed to apply template editor grid formatting: {0}" -f $_.Exception.Message) -LogPath $LogPath
    }
})
$panelTemplateGridHost.Controls.Add($gridTemplateSettings)
$groupTemplate.Controls.SetChildIndex($panelTemplateGridHost, 1)
$groupTemplate.Controls.SetChildIndex($panelTemplateHeader, 0)

$script:SelectedTemplateRowIndex = -1
$script:TemplateTable = $null
$script:CachedTimeZoneOptions = $null
$script:CachedUnattendLocaleOptions = $null

function Import-PAWUiFromJson {
    param([object]$JsonData)
    $configuredTheme = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.Configuration -Name 'UITheme')
    $themeSelect.SelectedItem = if ($configuredTheme -in @('Dark', 'Light')) { $configuredTheme } else { (Get-PAWUiPalette).Theme }

    $txtOrgName.Text = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.CustomerData -Name 'OrgName')
    $txtFullName.Text = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.CustomerData -Name 'FullName')

    $vmFolderValue = Get-PAWJsonPropertyValue -Object $JsonData.Settings.HyperV -Name 'VMFolder'
    if ([string]::IsNullOrWhiteSpace($vmFolderValue)) {
        $vmFolderValue = Get-PAWJsonPropertyValue -Object $JsonData.Settings.HyperV -Name 'VMLocation'
    }
    $txtVmFolder.Text = [string]$vmFolderValue

    $txtInstallFolder.Text = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.Configuration -Name 'InstallFolder')
    $vhdFolderText = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.Configuration -Name 'VHDFolder')
    $txtVhdFolder.Text = $vhdFolderText
    $securityBaselineFolderText = [string](Get-PAWJsonPropertyValue -Object $JsonData.Settings.Configuration -Name 'SecurityBaseLineFolder')
    $txtSecurityBaselineFolder.Text = $securityBaselineFolderText

    $resolvedTemplateFolder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path

    $dropdownPaths = Update-PAWResolvedDropdownSourcePaths -ConfigPath $ConfigPath -VhdFolderText ([string]$txtVhdFolder.Text) -SecurityBaselineFolderText ([string]$txtSecurityBaselineFolder.Text)
    $script:ResolvedVhdFolder = $dropdownPaths.VhdFolder
    $script:ResolvedSecurityBaselineFolder = $dropdownPaths.SecurityBaselineFolder
    $script:ResolvedCustomScriptsFolder = $dropdownPaths.CustomScriptsFolder

    $rawTable = New-PAWTemplateTableFromJsonFolder -TemplateFolderPath $resolvedTemplateFolder
    $rawType = if ($null -ne $rawTable) { $rawTable.GetType().FullName } else { '<null>' }
    Write-PAWLog -Message "Import-PAWUiFromJson raw table type: $rawType" -LogPath $LogPath
    $table = Resolve-PAWTemplateTable -InputObject $rawTable
    if ($null -eq $table) {
        $rawType = if ($null -ne $rawTable) { $rawTable.GetType().FullName } else { '<null>' }
        throw "Unable to resolve template table from loaded data. Type was: $rawType"
    }
    $script:TemplateTable = $table
    [void]($gridTemplates.DataSource = $script:TemplateTable)
    Write-PAWLog -Message ("Import-PAWUiFromJson resolved table rows: {0}" -f (Get-PAWTemplateRowCount -InputObject $script:TemplateTable)) -LogPath $LogPath

    foreach ($col in $gridTemplates.Columns) {
        if ($col.Name -eq 'Name') {
            $col.Frozen = $true
            $col.HeaderText = 'Template Name'
            $col.DefaultCellStyle.BackColor = (Get-PAWUiPalette).ReadOnly
        }
    }

    $rowCount = Get-PAWTemplateRowCount -InputObject $script:TemplateTable
}

function Get-PAWTemplateTableFromGrid {
    $table = Resolve-PAWTemplateTable -InputObject $script:TemplateTable
    if ($null -eq $table) {
        $table = Resolve-PAWTemplateTable -InputObject $gridTemplates.DataSource
        if ($null -ne $table) {
            $script:TemplateTable = $table
            Write-PAWLog -Message ("Recovered template table from grid DataSource. Rows: {0}" -f $table.Rows.Count) -LogPath $LogPath
        }
    }
    if ($null -eq $table) {
        $cacheType = if ($null -ne $script:TemplateTable) { $script:TemplateTable.GetType().FullName } else { '<null>' }
        $gridType = if ($null -ne $gridTemplates.DataSource) { $gridTemplates.DataSource.GetType().FullName } else { '<null>' }
        Write-PAWLog -Level 'ERROR' -Message "Template table not initialized. CacheType=$cacheType GridDataSourceType=$gridType. Creating empty table fallback." -LogPath $LogPath

        $fallback = New-Object System.Data.DataTable
        $columnSet = @($script:TemplateColumns)
        if ($columnSet.Count -eq 0) {
            $columnSet = @('Name')
        }
        foreach ($col in $columnSet) {
            if (-not $fallback.Columns.Contains([string]$col)) {
                [void]$fallback.Columns.Add([string]$col, [string])
            }
        }
        if (-not $fallback.Columns.Contains('Name')) {
            [void]$fallback.Columns.Add('Name', [string])
        }

        $script:TemplateTable = $fallback
        [void]($gridTemplates.DataSource = $script:TemplateTable)
        $table = $script:TemplateTable
    }
    Write-Output -NoEnumerate $table
}

function New-PAWTemplateSettingsTable {
    param(
        [Parameter(Mandatory = $true)]
        [System.Data.DataRow]$TemplateRow,
        [Parameter(Mandatory = $true)]
        [System.Data.DataTable]$TemplateTable
    )

    $settings = New-Object System.Data.DataTable
    [void]$settings.Columns.Add('Setting', [string])
    [void]$settings.Columns.Add('Value', [string])

    $nameRow = $settings.NewRow()
    $null = ($nameRow['Setting'] = 'Name')
    $null = ($nameRow['Value'] = [string]$TemplateRow['Name'])
    [void]$settings.Rows.Add($nameRow)

    foreach ($column in @($TemplateTable.Columns)) {
        $columnName = [string]$column.ColumnName
        if ($columnName -eq 'Name') {
            continue
        }

        $settingRow = $settings.NewRow()
        $null = ($settingRow['Setting'] = $columnName)
        $null = ($settingRow['Value'] = [string]$TemplateRow[$columnName])
        [void]$settings.Rows.Add($settingRow)
    }

    Write-Output -NoEnumerate $settings
}

function Get-PAWTemplateSettingAllowedValues {
    param([string]$SettingName)

    switch -Regex ($SettingName) {
        '^ApplicationBundle$' {
            $command = Join-Path (Split-Path -Parent $PSScriptRoot) 'Tools\Invoke-PAWApplicationManager.ps1'
            return @([pscustomobject]@{ Name = 'NA'; Value = 'NA' }) + @(& $command -Action ListBundles | ForEach-Object {
                [pscustomobject]@{ Name = [string]$_.Name; Value = [string]$_.BundleId }
            })
        }
        '^WDACPolicyFile$' {
            $root = Split-Path -Parent $PSScriptRoot
            return @('NA') + @(Get-PAWWDACPolicyOptions -InstallFolderPath $root -ErrorAction Stop)
        }
        '^VMGen$' {
            return @('2')
        }
        '^Memory$' {
            $values = New-Object System.Collections.Generic.List[string]
            foreach ($memory in (2048..65535 | Where-Object { ($_ - 2048) % 1024 -eq 0 })) {
                [void]$values.Add([string]$memory)
            }
            if (-not $values.Contains('65535')) {
                [void]$values.Add('65535')
            }
            return $values.ToArray()
        }
        '^(NoCPU|NoCpu)$' {
            return @('2', '3', '4', '5', '6', '7', '8')
        }
        '^DynamicMem$' {
            return @('True', 'False')
        }
        '^DiskMode$' {
            return @('Diff', 'Copy')
        }
        '^Shielded$' {
            return @('True', 'False')
        }
        '^BitLocker$' {
            return @('True', 'False')
        }
        '^ASR$' {
            return @('True', 'False')
        }
        '^Application$' {
            return @('True', 'False')
        }
        '^ApplySecurityBaseline$' {
            return @('True', 'False')
        }
        '^DomainOrWorkGroup$' {
            return @('DOMAIN', 'WORKGROUP')
        }
        '^TimeZoneName$' {
            if ($null -eq $script:CachedTimeZoneOptions) {
                if (Get-Command -Name 'Get-PAWTimeZoneOptions' -ErrorAction SilentlyContinue) {
                    $script:CachedTimeZoneOptions = @(Get-PAWTimeZoneOptions)
                }
                else {
                    $script:CachedTimeZoneOptions = @()
                }
            }

            if ($script:CachedTimeZoneOptions.Count -eq 0) {
                return $null
            }

            return $script:CachedTimeZoneOptions
        }
        '^(InputLocale|SystemLocale|UILanguage|UserLocale)$' {
            if ($null -eq $script:CachedUnattendLocaleOptions) {
                if (Get-Command -Name 'Get-PAWUnattendLocaleOptions' -ErrorAction SilentlyContinue) {
                    $script:CachedUnattendLocaleOptions = @(Get-PAWUnattendLocaleOptions)
                }
                else {
                    $script:CachedUnattendLocaleOptions = @()
                }
            }

            if ($script:CachedUnattendLocaleOptions.Count -eq 0) {
                return $null
            }

            return $script:CachedUnattendLocaleOptions
        }
        '^VHDFile$' {
            if ([string]::IsNullOrWhiteSpace($script:ResolvedVhdFolder)) {
                return $null
            }
            if (-not (Test-Path -LiteralPath $script:ResolvedVhdFolder -PathType Container)) {
                return $null
            }
            try {
                $vhdxFiles = @(Get-ChildItem -LiteralPath $script:ResolvedVhdFolder -Filter '*.vhdx' -File -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object)
                if (@($vhdxFiles).Count -eq 0) {
                    return $null
                }
                return $vhdxFiles
            }
            catch {
                Write-PAWLog -Level 'WARN' -Message ("Failed to read VHDX files from VHDFolder '{0}': {1}" -f $script:ResolvedVhdFolder, $_.Exception.Message) -LogPath $LogPath
                return $null
            }
        }
        '^RunScript$' {
            if ([string]::IsNullOrWhiteSpace($script:ResolvedCustomScriptsFolder)) {
                return @('NA')
            }
            if (-not (Test-Path -LiteralPath $script:ResolvedCustomScriptsFolder -PathType Container)) {
                return @('NA')
            }
            try {
                $scriptFiles = @(Get-ChildItem -LiteralPath $script:ResolvedCustomScriptsFolder -Filter '*.ps1' -File -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object)
                return @('NA') + @($scriptFiles | Where-Object { $_ -ne 'NA' })
            }
            catch {
                Write-PAWLog -Level 'WARN' -Message ("Failed to read script files from CustomScripts folder '{0}': {1}" -f $script:ResolvedCustomScriptsFolder, $_.Exception.Message) -LogPath $LogPath
                return @('NA')
            }
        }
        '^SecurityBaselineLocation$' {
            if ([string]::IsNullOrWhiteSpace($script:ResolvedSecurityBaselineFolder)) {
                return @('NA')
            }
            if (-not (Test-Path -LiteralPath $script:ResolvedSecurityBaselineFolder -PathType Container)) {
                return @('NA')
            }
            try {
                $baselineFolders = @(Get-ChildItem -LiteralPath $script:ResolvedSecurityBaselineFolder -Directory -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object)
                return @('NA') + @($baselineFolders | Where-Object { $_ -ne 'NA' })
            }
            catch {
                Write-PAWLog -Level 'WARN' -Message ("Failed to read baseline folders from SecurityBaseLineFolder '{0}': {1}" -f $script:ResolvedSecurityBaselineFolder, $_.Exception.Message) -LogPath $LogPath
                return @('NA')
            }
        }
        '^VMSwitch$' {
            # Get-VMSwitch requires an elevated session; fall back to a plain text cell otherwise.
            if (-not (Test-PAWIsElevated)) {
                return $null
            }
            try {
                $vmSwitchNames = @(Get-VMSwitch -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object -Unique)
                if ($vmSwitchNames.Count -eq 0) {
                    return $null
                }
                return $vmSwitchNames
            }
            catch {
                Write-PAWLog -Level 'WARN' -Message ("Failed to read Hyper-V virtual switches: {0}" -f $_.Exception.Message) -LogPath $LogPath
                return $null
            }
        }
        default {
            return $null
        }
    }
}

function Select-PAWTemplateDialog {
    $table = Get-PAWTemplateTableFromGrid
    if ((Get-PAWTemplateRowCount -InputObject $table) -eq 0) {
        return -1
    }

    $dialog = New-Object System.Windows.Forms.Form
    $dialog.Text = 'Select Template'
    $dialog.StartPosition = 'CenterParent'
    $dialog.ClientSize = New-Object System.Drawing.Size(760, 480)
    $dialog.MinimumSize = $dialog.Size
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $dialog.Font = $Font1
    $dialog.BackColor = $Palette.Background

    $list = New-Object System.Windows.Forms.ListBox
    $list.Location = New-Object System.Drawing.Point(12, 12)
    $list.Size = New-Object System.Drawing.Size(736, 414)
    $list.Anchor = 'Top, Bottom, Left, Right'
    $list.IntegralHeight = $false
    $list.HorizontalScrollbar = $true
    $list.Font = $FontData
    $list.ItemHeight = $FontData.Height + 6
    foreach ($row in @($table.Rows)) {
        $templateName = [string]$row['Name']
        [void]$list.Items.Add($templateName)
        $textWidth = [System.Windows.Forms.TextRenderer]::MeasureText($templateName, $list.Font).Width
        $list.HorizontalExtent = [Math]::Max($list.HorizontalExtent, $textWidth)
    }
    if ($list.Items.Count -gt 0) {
        $list.SelectedIndex = 0
    }
    $dialog.Controls.Add($list)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'OK'
    $btnOk.Location = New-Object System.Drawing.Point(336, 438)
    $btnOk.Size = New-Object System.Drawing.Size(200, 30)
    $btnOk.Anchor = 'Bottom, Right'
    $btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
    Set-PAWThemedButton -Button $btnOk
    $dialog.Controls.Add($btnOk)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(548, 438)
    $btnCancel.Size = New-Object System.Drawing.Size(200, 30)
    $btnCancel.Anchor = 'Bottom, Right'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    Set-PAWThemedButton -Button $btnCancel
    $dialog.Controls.Add($btnCancel)

    $dialog.AcceptButton = $btnOk
    $dialog.CancelButton = $btnCancel

    Set-PAWUiTheme -Control $dialog
    $result = $dialog.ShowDialog($form)
    if ($result -ne [System.Windows.Forms.DialogResult]::OK -or $list.SelectedIndex -lt 0) {
        return -1
    }

    return $list.SelectedIndex
}
function Update-PAWSelectedTemplateToGrid {
    [void]$gridTemplateSettings.EndEdit()
    $table = Get-PAWTemplateTableFromGrid
    if ($script:SelectedTemplateRowIndex -lt 0 -or $script:SelectedTemplateRowIndex -ge $table.Rows.Count) {
        throw 'No template selected.'
    }

    $settings = Resolve-PAWTemplateTable -InputObject $gridTemplateSettings.DataSource
    if ($null -eq $settings) {
        throw 'Template settings editor is not initialized.'
    }

    $newName = [string]$txtSelectedTemplate.Text
    $newName = $newName.Trim()
    if ([string]::IsNullOrWhiteSpace($newName)) {
        throw 'Selected template name cannot be empty.'
    }

    for ($i = 0; $i -lt $table.Rows.Count; $i++) {
        if ($i -eq $script:SelectedTemplateRowIndex) {
            continue
        }
        if ([string]::Equals([string]$table.Rows[$i]['Name'], $newName, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Template '$newName' already exists."
        }
    }

    $null = ($table.Rows[$script:SelectedTemplateRowIndex]['Name'] = $newName)

    foreach ($settingsRow in @($settings.Rows)) {
        $settingName = [string]$settingsRow['Setting']
        if ($settingName -eq 'Name') {
            continue
        }
        if ($table.Columns.Contains($settingName)) {
            $null = ($table.Rows[$script:SelectedTemplateRowIndex][$settingName] = [string]$settingsRow['Value'])
        }
    }
}

function Select-PAWTemplateByIndex {
    param([int]$Index)

    $table = Get-PAWTemplateTableFromGrid
    if ($Index -lt 0 -or $Index -ge (Get-PAWTemplateRowCount -InputObject $table)) {
        return
    }

    $script:SelectedTemplateRowIndex = $Index
    $selectedRow = $table.Rows[$Index]
    $txtSelectedTemplate.Text = [string]$selectedRow['Name']
    $settingsTable = New-PAWTemplateSettingsTable -TemplateRow $selectedRow -TemplateTable $table
    $gridTemplateSettings.DataSource = $settingsTable

   Add-PAWTemplateSettingsEditorDropDowns -Grid $gridTemplateSettings -AllowedValuesProvider {
        param($settingName)
        Get-PAWTemplateSettingAllowedValues -SettingName $settingName
    }
    Set-PAWTemplateEditorColumnWidths -Grid $gridTemplateSettings -KeyWidth 300 -ValueWidth 900

    if ($gridTemplateSettings.Rows.Count -gt 0) {
        $gridTemplateSettings.ClearSelection()
        $gridTemplateSettings.FirstDisplayedScrollingRowIndex = 0
        if ($gridTemplateSettings.Columns.Contains('Value')) {
            $gridTemplateSettings.CurrentCell = $gridTemplateSettings.Rows[0].Cells['Value']
        }
        else {
            $gridTemplateSettings.CurrentCell = $gridTemplateSettings.Rows[0].Cells[0]
        }
    }

}


$script:EditorUiState = Import-PAWEditorUiSettings


$btnReload.Add_Click({
    try {
        Write-PAWLog -Message 'Reload requested.' -LogPath $LogPath
        $script:ConfigJson = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        Import-PAWUiFromJson -JsonData $script:ConfigJson
        $table = Get-PAWTemplateTableFromGrid
        if ((Get-PAWTemplateRowCount -InputObject $table) -gt 0) {
            Select-PAWTemplateByIndex -Index 0
        }
    }
    catch {
        Show-PAWUiError -Title 'Reload Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

function Save-PAWEditorTheme {
    param(
        [Parameter(Mandatory = $true)][string]$ConfigPath,
        [Parameter(Mandatory = $true)][ValidateSet('Dark', 'Light')][string]$Theme
    )
    $path = $ConfigPath
    $config = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $config.Settings.Configuration | Add-Member -NotePropertyName UITheme -NotePropertyValue $Theme -Force
    $config | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8 -ErrorAction Stop
}

$btnSave.Add_Click({
    try {
        Write-PAWLog -Message 'Save requested.' -LogPath $LogPath

        Save-PAWConfigFromUi -JsonData $script:ConfigJson `
            -TxtOrgName $txtOrgName `
            -TxtFullName $txtFullName `
            -TxtVmFolder $txtVmFolder `
            -TxtInstallFolder $txtInstallFolder `
            -TxtVhdFolder $txtVhdFolder `
            -TxtSecurityBaselineFolder $txtSecurityBaselineFolder `
            -OutputPath $ConfigPath

        if ($null -ne $themeSelect.SelectedItem) {
            Save-PAWEditorTheme -ConfigPath $ConfigPath -Theme ([string]$themeSelect.SelectedItem)
            $script:ConfigJson.Settings.Configuration | Add-Member -NotePropertyName UITheme -NotePropertyValue ([string]$themeSelect.SelectedItem) -Force
        }
        Write-PAWLog -Message 'Config.json saved successfully.' -LogPath $LogPath
        [System.Windows.Forms.MessageBox]::Show('Config.json saved successfully.', 'PAWConfigEditor', 'OK', 'Information') | Out-Null
    }
    catch {
        Show-PAWUiError -Title 'Save Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$btnSelectTemplate.Add_Click({
    try {
        Write-PAWLog -Message 'Select Template requested.' -LogPath $LogPath
        $selectedIndex = Select-PAWTemplateDialog
        if ($selectedIndex -lt 0) {
            return
        }

        if ($script:SelectedTemplateRowIndex -ge 0) {
            Update-PAWSelectedTemplateToGrid
        }

        Select-PAWTemplateByIndex -Index $selectedIndex
        $groupTemplate.Text = "Template Settings  "
    }
    catch {
        Show-PAWUiError -Title 'Select Template Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$btnAddTemplate.Add_Click({
    try {
        Write-PAWLog -Message 'Add Template requested.' -LogPath $LogPath
        if ($script:SelectedTemplateRowIndex -ge 0) {
            Update-PAWSelectedTemplateToGrid
        }

        $templateName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter new template name:', 'Add Template', '')
        $templateName = [string]$templateName
        $templateName = $templateName.Trim()

        if ([string]::IsNullOrWhiteSpace($templateName)) {
            return
        }

        $table = Get-PAWTemplateTableFromGrid
        foreach ($existingRow in @($table.Rows)) {
            if ([string]::Equals([string]$existingRow['Name'], $templateName, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Template '$templateName' already exists."
            }
        }

        $newRow = $table.NewRow()
        $null = ($newRow['Name'] = $templateName)
        [void]$table.Rows.Add($newRow)
        Select-PAWTemplateByIndex -Index ($table.Rows.Count - 1)
        Write-PAWLog -Message "Template '$templateName' added." -LogPath $LogPath
    }
    catch {
        Show-PAWUiError -Title 'Add Template Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$btnRemoveTemplate.Add_Click({
    try {
        Write-PAWLog -Message 'Remove Template requested.' -LogPath $LogPath
        $table = Get-PAWTemplateTableFromGrid
        $tableRowCount = Get-PAWTemplateRowCount -InputObject $table
        if ($tableRowCount -eq 0 -or $script:SelectedTemplateRowIndex -lt 0 -or $script:SelectedTemplateRowIndex -ge $tableRowCount) {
            return
        }

        $templateName = [string]$table.Rows[$script:SelectedTemplateRowIndex]['Name']
        $confirmMessage = "You are about to delete following Template $templateName, are you sure?"
        $result = [System.Windows.Forms.MessageBox]::Show($confirmMessage, 'Confirm Remove Template', 'YesNo', 'Question')
        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
            return
        }

        $templateJsonPathToDelete = $null
        if ($script:TemplateFilePathsByName.ContainsKey($templateName)) {
            $templateJsonPathToDelete = [string]$script:TemplateFilePathsByName[$templateName]
        }

        $removeIndex = $script:SelectedTemplateRowIndex
        $table.Rows.RemoveAt($removeIndex)
        if ($script:TemplateFilePathsByName.ContainsKey($templateName)) {
            [void]$script:TemplateFilePathsByName.Remove($templateName)
        }

        if (-not [string]::IsNullOrWhiteSpace($templateJsonPathToDelete) -and (Test-Path -LiteralPath $templateJsonPathToDelete -PathType Leaf)) {
            Remove-Item -LiteralPath $templateJsonPathToDelete -Force
            Write-PAWLog -Message "Removed template file '$templateJsonPathToDelete'." -LogPath $LogPath
        }

        $script:SelectedTemplateRowIndex = -1
        if ((Get-PAWTemplateRowCount -InputObject $table) -gt 0) {
            $nextIndex = [Math]::Min($removeIndex, (Get-PAWTemplateRowCount -InputObject $table) - 1)
            Select-PAWTemplateByIndex -Index $nextIndex
        }
        else {
            $txtSelectedTemplate.Text = ''
            $gridTemplateSettings.DataSource = $null
            Write-PAWLog -Message "Template '$templateName' removed. No templates left." -LogPath $LogPath
        }

        if (-not [string]::IsNullOrWhiteSpace($templateJsonPathToDelete)) {
            if (Test-Path -LiteralPath $templateJsonPathToDelete -PathType Leaf) {
                Write-PAWLog -Level 'WARN' -Message "Template '$templateName' removed from list, but file delete failed: $templateJsonPathToDelete" -LogPath $LogPath
            }
            else {
                Write-PAWLog -Message "Template '$templateName' removed and file deleted." -LogPath $LogPath
            }
        }
        else {
            Write-PAWLog -Level 'WARN' -Message "Template '$templateName' removed from list, but no backing JSON file mapping was found." -LogPath $LogPath
        }
    }
    catch {
        Show-PAWUiError -Title 'Remove Template Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$btnCopyTemplate.Add_Click({
    try {
        Write-PAWLog -Message 'Clone Template requested.' -LogPath $LogPath
        $table = Get-PAWTemplateTableFromGrid
        $rowCount = Get-PAWTemplateRowCount -InputObject $table
        if ($rowCount -eq 0 -or $script:SelectedTemplateRowIndex -lt 0 -or $script:SelectedTemplateRowIndex -ge $rowCount) {
            throw 'Select a template before cloning.'
        }

        Update-PAWSelectedTemplateToGrid

        $sourceRow = $table.Rows[$script:SelectedTemplateRowIndex]
        $sourceName = [string]$sourceRow['Name']
        $defaultCloneName = if ([string]::IsNullOrWhiteSpace($sourceName)) { 'New Template Clone' } else { "$sourceName - Clone" }

        $newTemplateName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter name for cloned template:', 'Clone Template', $defaultCloneName)
        $newTemplateName = [string]$newTemplateName
        $newTemplateName = $newTemplateName.Trim()

        if ([string]::IsNullOrWhiteSpace($newTemplateName)) {
            return
        }

        foreach ($existingRow in @($table.Rows)) {
            if ([string]::Equals([string]$existingRow['Name'], $newTemplateName, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Template '$newTemplateName' already exists."
            }
        }

        $newRow = $table.NewRow()
        foreach ($column in @($table.Columns)) {
            $columnName = [string]$column.ColumnName
            if ($columnName -eq 'Name') {
                $null = ($newRow['Name'] = $newTemplateName)
            }
            else {
                $null = ($newRow[$columnName] = [string]$sourceRow[$columnName])
            }
        }

        [void]$table.Rows.Add($newRow)
        Select-PAWTemplateByIndex -Index ($table.Rows.Count - 1)
        Write-PAWLog -Message "Template '$newTemplateName' cloned from '$sourceName'." -LogPath $LogPath
    }
    catch {
        Show-PAWUiError -Title 'Clone Template Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

$btnSaveTemplate.Add_Click({
    try {
        Write-PAWLog -Message 'Save Template requested.' -LogPath $LogPath
        Save-PAWSelectedTemplateToJson
        [System.Windows.Forms.MessageBox]::Show('Template JSON saved successfully.', 'PAWConfigEditor', 'OK', 'Information') | Out-Null
    }
    catch {
        Show-PAWUiError -Title 'Save Template Failed' -ErrorRecord $_ -LogPath $LogPath
    }
})

function Update-PAWTemplateTransferList {
    $folder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path
    $saved = Get-PAWTemplateFileCollection -TemplateFolder $folder
    $transferTemplates.Items.Clear()
    foreach ($template in $saved) { [void]$transferTemplates.Items.Add($template) }
}

function Invoke-PAWTemplateImportDialog {
    $picker = New-Object System.Windows.Forms.OpenFileDialog
    $picker.Title = 'Import template JSON files'
    $picker.Filter = 'Template JSON (*.json)|*.json'
    $picker.Multiselect = $true
    $attempted = $false
    try {
        if ($picker.ShowDialog($form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $validated = @($picker.FileNames | ForEach-Object { Get-PAWValidatedTemplate -Path $_ -ErrorAction Stop -WarningAction SilentlyContinue })
        $folder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path
        $saved = Get-PAWTemplateFileCollection -TemplateFolder $folder
        $conflicts = @($validated | Where-Object { $saved.Name -contains $_.Name })
        $replace = $false
        if ($conflicts.Count) {
            $answer = [System.Windows.Forms.MessageBox]::Show($form,
                "Replace these existing templates?`n$($conflicts.Name -join "`n")",
                'Confirm template replacement', 'YesNo', 'Warning')
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            $replace = $true
        }
        $answer = [System.Windows.Forms.MessageBox]::Show($form,
            'Import refreshes the Templates tab and discards unsaved template edits. Save them first if needed. Continue?',
            'Confirm template import', 'YesNo', 'Warning')
        if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $attempted = $true
        $tool = Join-Path $PSScriptRoot 'Import-PAWTemplate.ps1'
        $result = @(& $tool -Path $picker.FileNames -ConfigPath $ConfigPath -Replace:$replace -Confirm:$false -ErrorAction Stop)
        [void][System.Windows.Forms.MessageBox]::Show($form,
            "Imported templates:`n$($result.Name -join "`n")", 'Import complete', 'OK', 'Information')
        $valueWarnings = @($result | ForEach-Object { $_.Warnings })
        if ($valueWarnings.Count) {
            [void][System.Windows.Forms.MessageBox]::Show($form,
                ($valueWarnings -join "`n`n"), 'Imported with warnings - correct settings and save', 'OK', 'Warning')
        }
    }
    catch { Show-PAWUiError -Title 'Template Import Failed' -ErrorRecord $_ -LogPath $LogPath }
    finally {
        $picker.Dispose()
        if ($attempted) {
            try {
                $script:TemplateTable = New-PAWTemplateTableFromJsonFolder -TemplateFolderPath $folder
                $gridTemplates.DataSource = $script:TemplateTable
                $script:SelectedTemplateRowIndex = -1
                $gridTemplateSettings.DataSource = $null
                $txtSelectedTemplate.Text = ''
                if ($script:TemplateTable.Rows.Count) { Select-PAWTemplateByIndex -Index 0 }
                Update-PAWTemplateTransferList
            }
            catch { Show-PAWUiError -Title 'Template Refresh Failed' -ErrorRecord $_ -LogPath $LogPath }
        }
        $form.Text = $script:PAWToolTitle
    }
}

function Invoke-PAWTemplateExportDialog {
    try {
        $selected = @($transferTemplates.SelectedItems)
        if (-not $selected.Count) { throw 'Select one or more saved templates to export.' }
        $destination = Select-PAWFolderPath -Description 'Select template export folder'
        if ([string]::IsNullOrWhiteSpace($destination)) { return }
        $conflicts = @($selected | Where-Object { Test-Path -LiteralPath (Join-Path $destination $_.FileName) -ErrorAction Stop })
        $replace = $false
        if ($conflicts.Count) {
            $answer = [System.Windows.Forms.MessageBox]::Show($form,
                "Replace these export files?`n$($conflicts.FileName -join "`n")",
                'Confirm export replacement', 'YesNo', 'Warning')
            if ($answer -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            $replace = $true
        }
        $tool = Join-Path $PSScriptRoot 'Export-PAWTemplate.ps1'
        $result = @(& $tool -Name $selected.Name -ConfigPath $ConfigPath -DestinationFolder $destination -Replace:$replace -Confirm:$false -ErrorAction Stop)
        if ($result.Count -ne $selected.Count) { throw 'Export did not return a file for every selected template.' }
        foreach ($exported in $result) {
            if ([string]::IsNullOrWhiteSpace([string]$exported.Destination) -or
                -not (Test-Path -LiteralPath $exported.Destination -PathType Leaf -ErrorAction Stop)) {
                throw "Exported template file was not found: '$($exported.Destination)'."
            }
        }
        [void][System.Windows.Forms.MessageBox]::Show($form,
            "Exported templates:`n$($result.Destination -join "`n")", 'Export complete', 'OK', 'Information')
    }
    catch { Show-PAWUiError -Title 'Template Export Failed' -ErrorRecord $_ -LogPath $LogPath }
    finally { $form.Text = $script:PAWToolTitle }
}

$btnImportTemplates.Add_Click({ Invoke-PAWTemplateImportDialog })
$btnExportTemplates.Add_Click({ Invoke-PAWTemplateExportDialog })
$btnRefreshTransfer.Add_Click({
    try { Update-PAWTemplateTransferList }
    catch { Show-PAWUiError -Title 'Template List Failed' -ErrorRecord $_ -LogPath $LogPath }
})
$editorTabs.Add_SelectedIndexChanged({
    if ($editorTabs.SelectedTab -eq $transferTab) {
        try { Update-PAWTemplateTransferList }
        catch { Show-PAWUiError -Title 'Template List Failed' -ErrorRecord $_ -LogPath $LogPath }
    }
})

$btnClose.Add_Click({
    Write-PAWLog -Message 'Editor closed by user.' -LogPath $LogPath
    $form.Close()
})
Add-PAWUiRibbon -Form $form -ScriptPath $PSCommandPath -CloseButton $btnClose

try {
    Import-PAWUiFromJson -JsonData $script:ConfigJson
    $table = Get-PAWTemplateTableFromGrid
    if ((Get-PAWTemplateRowCount -InputObject $table) -gt 0) {
        $selectedIndex = 0
        if (($null -ne $script:EditorUiState) -and $script:EditorUiState.PSObject.Properties['SelectedTemplate']) {
            $savedTemplate = [string]$script:EditorUiState.SelectedTemplate
            for ($i = 0; $i -lt $table.Rows.Count; $i++) {
                if ([string]::Equals([string]$table.Rows[$i]['Name'], $savedTemplate, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $selectedIndex = $i
                    break
                }
            }
        }
        Select-PAWTemplateByIndex -Index $selectedIndex
    }
}
catch {
    Write-PAWLog -Level 'ERROR' -Message ('Initial template load failed: ' + $_.Exception.Message) -Exception $_.Exception -LogPath $LogPath
    if (-not [string]::IsNullOrWhiteSpace($_.ScriptStackTrace)) {
        Write-PAWLog -Level 'ERROR' -Message ("Initial template load failed ScriptStack:`r`n" + $_.ScriptStackTrace) -LogPath $LogPath
    }
}

$form.Add_FormClosing({
    Save-PAWEditorUiSettings
})

if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
    $form.StartPosition = 'Manual'
    $form.Location = New-Object System.Drawing.Point($WindowX, $WindowY)
}
$form.Text = $script:PAWToolTitle
$form.Add_Shown({ Set-PAWWindowForeground -Form $form })
try { [void]$form.ShowDialog() }
finally {
    $form.Icon.Dispose()
    $form.Dispose()
}
