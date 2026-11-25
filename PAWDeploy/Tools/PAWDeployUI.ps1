<#
.SYNOPSIS
    Graphical front-end for configuring and launching Privileged Access Workstation (PAW) VM deployments.

.DESCRIPTION
    PAWDeployUI.ps1 presents a Windows Forms interface that lets operators configure and
    launch a PAW VM deployment without using the command line.

    The form reads all active templates from the template JSON files in the Config folder
    configured in Config.json and populates a dropdown so the operator can select a
    deployment profile. Templates with Active set to False are skipped. Choosing a template
    auto-fills most fields. The tool also restores the most recently used UI selections from
    a per-user settings file (%TEMP%\PAWDeploySettings\PAWDeployUI.settings) and saves
    updated selections as the operator changes template and toggle values.

    When the operator clicks Build, all required fields are validated. Missing or invalid
    inputs are highlighted in orange and a Fix validation errors label is shown. When
    other inputs are valid, the VM name is checked against local Hyper-V VMs. An
    existing name or failed Hyper-V query keeps the form open; change the highlighted
    VM name and click Build again.
    Existing target VM directories (even empty ones) also block Build. Configuration
    and filesystem query failures are logged and keep the form open.
    Once validation passes, the tool assembles the full parameter set and launches New-PAWVM.ps1
    in a new classic PowerShell console, aligned with the lower half of the form:
    same width and screen, half the height, with the bottom edges aligned.
    New-PAWVM.ps1 writes structured deployment entries to
    %TEMP%\PAWDeploy\New-PAWVM.log. The form closes
    after the build is started. Copy CMD copies the equivalent New-PAWVM.ps1 command line
    to the clipboard instead. Both actions use the same quoted command, including
    Show Verbose and all selected Skip overrides. Copied commands remain usable
    after closing the form; passwords are not put in clipboard or command history.

    Fields exposed in the UI:
      Left column  (virtual machine settings):
        - Template selection (active templates beside Config.json)
        - VM Name (auto-generated from template; editable)
        - Hyper-V VM Switch (populated from local Hyper-V configuration)
        - VLAN ID (optional)
        - Disk Mode (Diff / Copy)
        - Optional VHD(X) override (blank uses the template)
        - Skip Shielding toggle (defaults off)
        - Skip Link toggle (defaults off; skips the VM Connect shortcut)
        - Domain join credentials and OU (visible for domain-joined templates)

      Right column (guest OS settings):
        - Local Administrator password
        - Override ComputerName toggle and name field
        - Optional folder to copy into the VM
        - Optional post-deployment run command
        - Skip Baseline toggle (defaults off)
        - Skip Application toggle (defaults off)
        - Skip Disk Encryption toggle (defaults off)
        - Skip RunScript toggle (defaults off)
        - Show Verbose toggle (persists across launches)
        - Use DHCP toggle (defaults on)
        - Static IP fields (IP address, subnet, DNS, gateway; visible when DHCP is off)

    Menu launches use a hidden PowerShell host and place the form over the menu.

    This script is the graphical equivalent of New-PAWVM.ps1 and is typically launched
    via the PAW Deploy UI shortcut (or PAW Menu) that Install-PAWDeploy.ps1 creates in the
    install folder.

.EXAMPLE
    .\Tools\PAWDeployUI.ps1

    Opens the deployment form. Run from an elevated PowerShell session.

.PARAMETER PAWDebug
    Enables diagnostic startup and Hyper-V switch loading timings. An inherited
    $PAWDebug = $true enables them unless the switch is explicitly set to false.

.NOTES
    Version : 2.0.0.38
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+, Hyper-V module, local Administrator privileges.
    Files   : New-PAWVM.ps1, Config and Functions must be in the parent installation folder.
    Data    : UI settings are stored in %TEMP%\PAWDeploySettings\PAWDeployUI.settings.
    Log file: %TEMP%\PAWDeploy\PAWDeployUI.log.
    Templates: A deployment requires at least one active template in Config
               (Active not set, or set to True).
#>
[CmdletBinding()]
param(
    [int]$WindowX,
    [int]$WindowY,
    [switch]$PAWDebug = (Get-Variable -Name PAWDebug -ValueOnly -ErrorAction SilentlyContinue)
)

$startupClock = if ($PAWDebug) { [Diagnostics.Stopwatch]::StartNew() } else { $null }

# Edition branding (logo); Build rewrites this value for the Community package.
$script:PAWEdition = 'Community'

$RootFolder = Split-Path -Parent $PSScriptRoot

$PawUtilityManifest = Join-Path $RootFolder 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUtilityManifest"
}
Import-Module -Name $PawUtilityManifest -Force -ErrorAction Stop
if (-not (Test-PAWIsElevated)) {
    Add-Type -AssemblyName System.Windows.Forms
    [void][System.Windows.Forms.MessageBox]::Show(
        'Run this tool from an elevated PowerShell session as a local administrator.',
        'New PAW', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    throw 'PAWDeployUI.ps1 requires an elevated local administrator.'
}
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$PawUiUtilityManifest = Join-Path $RootFolder 'Functions\PAWUIUtility\PAWUIUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUiUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUiUtilityManifest"
}
Import-Module -Name $PawUiUtilityManifest -Force -ErrorAction Stop
$Script:SettingsDirectory = Join-Path $env:TEMP 'PAWDeploySettings'
$Script:SettingsFile = Join-Path $Script:SettingsDirectory 'PAWDeployUI.settings'
$Script:ToolName = "PAWDeployUI"
$Script:ToolTitle = "PAW Deployment Toolkit" #'PAWDeploy - New PAW'
$Script:RunUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Get Data
$XMLDatafile = "$RootFolder\Config\Config.json"
$XMLData = Get-Content -Path "$XMLDatafile" -Raw | ConvertFrom-Json
$Script:LogFolder = Resolve-PAWLogFolder
$Script:LogPath = Join-Path $Script:LogFolder 'PAWDeployUI.log'
$Script:UILogFile = $Script:LogPath

#Get Templates
$TemplateFolder = Split-Path -Parent (Resolve-Path -LiteralPath $XMLDatafile -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $TemplateFolder -PathType Container)) {
    throw "Template folder not found: $TemplateFolder"
}

$Templates = @()
foreach ($TemplateFile in (Get-ChildItem -LiteralPath $TemplateFolder -Filter '*.json' -File | Where-Object Name -ne 'Config.json' | Sort-Object Name)) {
    $TemplateObject = Get-Content -LiteralPath $TemplateFile.FullName -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$TemplateObject.Name)) {
        $TemplateObject | Add-Member -NotePropertyName Name -NotePropertyValue $TemplateFile.BaseName -Force
    }
    $Templates += $TemplateObject
}

$Templates = @(
    $Templates | Where-Object {
        if ($null -eq $_.Active) {
            $true
        }
        elseif ($_.Active -is [bool]) {
            $_.Active
        }
        else {
            [string]$_.Active -eq 'True'
        }
    }
)

$script:TemplateData = $null
$TemplatesSelection = @($Templates | ForEach-Object { $_.Name })

#Generate Randomname
$chars = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
$RandomName = [string](($chars[0..25] | Get-Random) + (($chars | Get-Random -Count 3) -join ""))

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Font1 = [System.Drawing.Font]::new("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$FontHeading1 = [System.Drawing.Font]::new("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
$FontHeading2 = [System.Drawing.Font]::new("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$FontHeading3 = [System.Drawing.Font]::new("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$FontData = [System.Drawing.Font]::new("Segoe UI", 10)
$Palette = Get-PAWUiPalette

#region begin GUI{

$Form = New-Object system.Windows.Forms.Form
$Form.Size = New-Object System.Drawing.Size(1344, 756)
$Form.MinimumSize = New-Object System.Drawing.Size(1344, 756)
$Form.MaximumSize = New-Object System.Drawing.Size(1344, 756)
$Form.MaximizeBox = $false
$Form.StartPosition = 'CenterScreen'
$Form.text = $Script:ToolTitle
$Form.TopMost = $false
$form.BackColor = $Palette.Background

# Set the Icon for the GUI
$Form.Icon = Get-PAWWindowIcon

$InfoLogo = Get-PAWImage -Name InfoIcon

$PictureBox3 = New-Object system.Windows.Forms.PictureBox
$PictureBox3.width = 14
$PictureBox3.height = 14
$PictureBox3.location = New-Object System.Drawing.Point(782, 283)
$PictureBox3.image = $InfoLogo
$PictureBox3.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
$PictureBox3.BringToFront()

$PictureBox4 = New-Object system.Windows.Forms.PictureBox
$PictureBox4.width = 14
$PictureBox4.height = 14
$PictureBox4.location = New-Object System.Drawing.Point(772, 313)
$PictureBox4.image = $InfoLogo
$PictureBox4.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
$PictureBox4.BringToFront()


$ExtraFolderToolTip = New-Object system.Windows.Forms.ToolTip
$ExtraFolderToolTip.AutoPopDelay = 3000
$ExtraFolderToolTip.InitialDelay = 300
$ExtraFolderToolTip.ReshowDelay = 300
$ExtraFolderToolTip.ShowAlways = $true;
$ExtraFolderToolTip.SetToolTip($PictureBox3, 'The folder you select will be copied to C:\ as a folder with the same name.');


$RunCommandInfoToolTip = New-Object system.Windows.Forms.ToolTip
$RunCommandInfoToolTip.AutoPopDelay = 3000
$RunCommandInfoToolTip.InitialDelay = 300
$RunCommandInfoToolTip.ReshowDelay = 300
$RunCommandInfoToolTip.ShowAlways = $true;
$RunCommandInfoToolTip.SetToolTip($PictureBox4, 'Select a script from Resources\CustomScripts, or select NA to not run a script.')


$TemplateLabel = New-Object system.Windows.Forms.Label
$TemplateLabel.text = "Template"
$TemplateLabel.AutoSize = $true
$TemplateLabel.width = 25
$TemplateLabel.height = 10
$TemplateLabel.location = New-Object System.Drawing.Point(20, 190)
$TemplateLabel.Font = $Font1

$TemplateListbox = New-Object system.Windows.Forms.ComboBox
$TemplateListbox.DropDownStyle = 'DropDownList'
$TemplateListbox.text = $null
$TemplateListbox.width = 300
$TemplateListbox.height = 70
$TemplateListbox.location = New-Object System.Drawing.Point(200, 190)
$TemplateListbox.Font = $FontData

$TemplateStatusLabel = New-Object System.Windows.Forms.Label
$TemplateStatusLabel.Name = 'TemplateStatus'
$TemplateStatusLabel.Text = 'No active templates. Create or activate a template in Templates, then reopen New PAW.'
$TemplateStatusLabel.Location = New-Object System.Drawing.Point(20, 86)
$TemplateStatusLabel.Size = New-Object System.Drawing.Size(1250, 40)
$TemplateStatusLabel.Font = $Font1
$TemplateStatusLabel.ForeColor = $Palette.Accent
$TemplateStatusLabel.Visible = $false

$ApplicationBundleLabel = New-Object System.Windows.Forms.Label
$ApplicationBundleLabel.Text = 'Application Bundle'
$ApplicationBundleLabel.AutoSize = $true
$ApplicationBundleLabel.Location = New-Object System.Drawing.Point(692, 190)
$ApplicationBundleLabel.Font = $Font1
$ApplicationBundleSelect = New-Object System.Windows.Forms.ComboBox
$ApplicationBundleSelect.DropDownStyle = 'DropDownList'
$ApplicationBundleSelect.Font = $FontData
$ApplicationBundleSelect.Size = New-Object System.Drawing.Size(300, 25)
$ApplicationBundleSelect.Location = New-Object System.Drawing.Point(892, 187)
$ApplicationManagerCommand = Join-Path $RootFolder 'Tools\Invoke-PAWApplicationManager.ps1'
$ApplicationBundleSelect.DisplayMember = 'Name'
$null = $ApplicationBundleSelect.Items.Add([pscustomobject]@{ Name = '(Template default)'; BundleId = $null })
foreach ($bundle in @(& $ApplicationManagerCommand -Action ListBundles)) {
    $null = $ApplicationBundleSelect.Items.Add($bundle)
}
$ApplicationBundleSelect.SelectedIndex = 0
$Form.Controls.AddRange(@($ApplicationBundleLabel, $ApplicationBundleSelect))

$VMLabel = New-Object system.Windows.Forms.Label
$VMLabel.text = "Virtual Machine"
$VMLabel.AutoSize = $true
$VMLabel.width = 25
$VMLabel.height = 10
$VMLabel.location = New-Object System.Drawing.Point(20, 150)
$VMLabel.Font = $FontHeading2

$VMnameLabel = New-Object system.Windows.Forms.Label
$VMnameLabel.text = "VM Name"
$VMnameLabel.AutoSize = $true
$VMnameLabel.width = 25
$VMnameLabel.height = 10
$VMnameLabel.location = New-Object System.Drawing.Point(20, 220)
$VMnameLabel.Font = $Font1

$VMnameTextBox = New-Object system.Windows.Forms.TextBox
$VMnameTextBox.multiline = $false
$VMnameTextBox.width = 300
$VMnameTextBox.height = 20
$VMnameTextBox.location = New-Object System.Drawing.Point(200, 220)
$VMnameTextBox.Font = $FontData
$VMnameTextBox.Text = $null

$VMSwitchLabel = New-Object system.Windows.Forms.Label
$VMSwitchLabel.text = "VM Switch"
$VMSwitchLabel.AutoSize = $true
$VMSwitchLabel.width = 25
$VMSwitchLabel.height = 10
$VMSwitchLabel.location = New-Object System.Drawing.Point(20, 250)
$VMSwitchLabel.Font = $Font1

$VMSwitchSelect = New-Object system.Windows.Forms.ComboBox
$VMSwitchSelect.width = 300
$VMSwitchSelect.location = New-Object System.Drawing.Point(200, 250)
$VMSwitchSelect.Font = $FontData
$VMSwitchSelect.Enabled = $false

$VMSwitchRefresh = New-Object System.Windows.Forms.LinkLabel
$VMSwitchRefresh.Text = 'Refresh'
$VMSwitchRefresh.AccessibleName = 'Refresh Hyper-V switches'
$VMSwitchRefresh.Location = New-Object System.Drawing.Point(145, 253)
$VMSwitchRefresh.AutoSize = $true
$VMSwitchRefresh.LinkColor = $Palette.Accent
$VMSwitchRefresh.ActiveLinkColor = $Palette.Accent
$VMSwitchRefresh.Enabled = $false

$VlanLabel = New-Object system.Windows.Forms.Label
$VlanLabel.text = "VlanID"
$VlanLabel.AutoSize = $true
$VlanLabel.width = 25
$VlanLabel.height = 10
$VlanLabel.location = New-Object System.Drawing.Point(20, 280)
$VlanLabel.Font = $Font1

$VlanTextBox = New-Object system.Windows.Forms.TextBox
$VlanTextBox.multiline = $false
$VlanTextBox.width = 50
$VlanTextBox.height = 20
$VlanTextBox.location = New-Object System.Drawing.Point(200, 280)
$VlanTextBox.Font = $FontData
$VlanTextBox.Text = $null

$DiskModeLabel = New-Object system.Windows.Forms.Label
$DiskModeLabel.text = "Disk Mode"
$DiskModeLabel.AutoSize = $true
$DiskModeLabel.width = 25
$DiskModeLabel.height = 10
$DiskModeLabel.location = New-Object System.Drawing.Point(20, 310)
$DiskModeLabel.Font = $Font1

$DiskModeSelect = New-Object System.Windows.Forms.ComboBox
$DiskModeSelect.Location = New-Object System.Drawing.Point(200, 310)
$DiskModeSelect.Visible = $true
$DiskModeSelect.width = 300
$DiskModeSelect.Font = $FontData

$VMNameShieldedCheckBoxLabel = New-Object system.Windows.Forms.Label
$VMNameShieldedCheckBoxLabel.text = "Skip Shielding"
$VMNameShieldedCheckBoxLabel.AutoSize = $true
$VMNameShieldedCheckBoxLabel.width = 25
$VMNameShieldedCheckBoxLabel.height = 10
$VMNameShieldedCheckBoxLabel.location = New-Object System.Drawing.Point(20, 370)
$VMNameShieldedCheckBoxLabel.Font = $Font1

$VMNameShieldedCheckBox = New-Object System.Windows.Forms.CheckBox
$VMNameShieldedCheckBox.Checked = $false
$VMNameShieldedCheckBox.Location = New-Object System.Drawing.Point(200, 370)
$VMNameShieldedCheckBox.Visible = $true

$SkipLinkCheckBoxLabel = New-Object System.Windows.Forms.Label
$SkipLinkCheckBoxLabel.Text = "Skip Link"
$SkipLinkCheckBoxLabel.AutoSize = $true
$SkipLinkCheckBoxLabel.Location = New-Object System.Drawing.Point(20, 400)
$SkipLinkCheckBoxLabel.Font = $Font1

$SkipLinkCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipLinkCheckBox.Checked = $false
$SkipLinkCheckBox.Location = New-Object System.Drawing.Point(200, 400)
$SkipLinkCheckBox.Visible = $true

$VHDXOverrideLabel = New-Object System.Windows.Forms.Label
$VHDXOverrideLabel.Text = 'VHD(X) override'
$VHDXOverrideLabel.AutoSize = $true
$VHDXOverrideLabel.Location = New-Object System.Drawing.Point(20, 340)
$VHDXOverrideLabel.Font = $Font1

$VHDXOverrideTextBox = New-Object System.Windows.Forms.TextBox
$VHDXOverrideTextBox.Location = New-Object System.Drawing.Point(200, 340)
$VHDXOverrideTextBox.Width = 300
$VHDXOverrideTextBox.Font = $FontData

$VHDXOverrideBrowse = New-Object System.Windows.Forms.LinkLabel
$VHDXOverrideBrowse.Text = 'Browse'
$VHDXOverrideBrowse.AccessibleName = 'Browse for VHD(X) override'
$VHDXOverrideBrowse.Location = New-Object System.Drawing.Point(145, 343)
$VHDXOverrideBrowse.AutoSize = $true
$VHDXOverrideBrowse.LinkColor = $Palette.Accent
$VHDXOverrideBrowse.ActiveLinkColor = $Palette.Accent

$DJoinLabel = New-Object system.Windows.Forms.Label
$DJoinLabel.text = "Domain Credentials"
$DJoinLabel.AutoSize = $true
$DJoinLabel.width = 25
$DJoinLabel.height = 10
$DJoinLabel.location = New-Object System.Drawing.Point(20, 460)
$DJoinLabel.Font = $FontHeading2
$DJoinLabel.Visible = $false

$DJANameLabel = New-Object system.Windows.Forms.Label
$DJANameLabel.text = "Username"
$DJANameLabel.AutoSize = $true
$DJANameLabel.width = 25
$DJANameLabel.height = 10
$DJANameLabel.location = New-Object System.Drawing.Point(20, 490)
$DJANameLabel.Font = $Font1
$DJANameLabel.Visible = $false

$DJANameTextBox = New-Object system.Windows.Forms.TextBox
$DJANameTextBox.multiline = $false
$DJANameTextBox.width = 300
$DJANameTextBox.height = 20
$DJANameTextBox.location = New-Object System.Drawing.Point(200, 490)
$DJANameTextBox.Font = $FontData
$DJANameTextBox.Text = $null
$DJANameTextBox.Visible = $false

$DJAPasswordLabel = New-Object system.Windows.Forms.Label
$DJAPasswordLabel.text = "Password"
$DJAPasswordLabel.AutoSize = $true
$DJAPasswordLabel.width = 25
$DJAPasswordLabel.height = 10
$DJAPasswordLabel.location = New-Object System.Drawing.Point(20, 520)
$DJAPasswordLabel.Font = $Font1
$DJAPasswordLabel.Visible = $false

$DJAPasswordTextBox = New-Object system.Windows.Forms.TextBox
$DJAPasswordTextBox.multiline = $false
$DJAPasswordTextBox.width = 300
$DJAPasswordTextBox.height = 20
$DJAPasswordTextBox.location = New-Object System.Drawing.Point(200, 520)
$DJAPasswordTextBox.Font = $FontData
$DJAPasswordTextBox.PasswordChar = "*"
$DJAPasswordTextBox.Text = $null
$DJAPasswordTextBox.Visible = $false

$DJOULabel = New-Object system.Windows.Forms.Label
$DJOULabel.text = "OU"
$DJOULabel.AutoSize = $true
$DJOULabel.width = 25
$DJOULabel.height = 10
$DJOULabel.location = New-Object System.Drawing.Point(20, 550)
$DJOULabel.Font = $Font1
$DJOULabel.Visible = $false

$DJOUTextBox = New-Object system.Windows.Forms.TextBox
$DJOUTextBox.multiline = $false
$DJOUTextBox.width = 300
$DJOUTextBox.height = 20
$DJOUTextBox.location = New-Object System.Drawing.Point(200, 550)
$DJOUTextBox.Font = $FontData
$DJOUTextBox.Text = $null
$DJOUTextBox.Visible = $false


$VMGuesLabel = New-Object system.Windows.Forms.Label
$VMGuesLabel.text = "Guest OS"
$VMGuesLabel.AutoSize = $true
$VMGuesLabel.width = 25
$VMGuesLabel.height = 10
$VMGuesLabel.location = New-Object System.Drawing.Point(692, 150)
$VMGuesLabel.Font = $FontHeading2

$LPasswordLabel = New-Object system.Windows.Forms.Label
$LPasswordLabel.text = "Administrator Password"
$LPasswordLabel.AutoSize = $true
$LPasswordLabel.width = 25
$LPasswordLabel.height = 10
$LPasswordLabel.location = New-Object System.Drawing.Point(692, 220)
$LPasswordLabel.Font = $Font1

$LPasswordTextBox = New-Object system.Windows.Forms.TextBox
$LPasswordTextBox.multiline = $false
$LPasswordTextBox.width = 300
$LPasswordTextBox.height = 20
$LPasswordTextBox.location = New-Object System.Drawing.Point(892, 220)
$LPasswordTextBox.Font = $FontData
$LPasswordTextBox.PasswordChar = "*"
$LPasswordTextBox.Text = $null

$VMNameCheckBoxLabel = New-Object system.Windows.Forms.Label
$VMNameCheckBoxLabel.text = "Override ComputerName"
$VMNameCheckBoxLabel.AutoSize = $true
$VMNameCheckBoxLabel.location = New-Object System.Drawing.Point(692, 252)
$VMNameCheckBoxLabel.Font = $Font1

$VMNameCheckBox = New-Object System.Windows.Forms.CheckBox
$VMNameCheckBox.Checked = $false
$VMNameCheckBox.Location = New-Object System.Drawing.Point(872, 250)
$VMNameCheckBox.Visible = $true
$VMNameCheckBox.width = 15

$OSDComputerNameTextBox = New-Object system.Windows.Forms.TextBox
$OSDComputerNameTextBox.multiline = $false
$OSDComputerNameTextBox.width = 300
$OSDComputerNameTextBox.height = 20
$OSDComputerNameTextBox.location = New-Object System.Drawing.Point(892, 250)
$OSDComputerNameTextBox.Font = $FontData
$OSDComputerNameTextBox.MaxLength = 15
$OSDComputerNameTextBox.Text = $null
$OSDComputerNameTextBox.enabled = $false


$ExtraFolderLabel = New-Object system.Windows.Forms.Label
$ExtraFolderLabel.text = "Copy Folder"
$ExtraFolderLabel.AutoSize = $true
$ExtraFolderLabel.width = 25
$ExtraFolderLabel.height = 10
$ExtraFolderLabel.location = New-Object System.Drawing.Point(692, 280)
$ExtraFolderLabel.Font = $Font1

$ExtraFolderTextBox = New-Object system.Windows.Forms.TextBox
$ExtraFolderTextBox.multiline = $false
$ExtraFolderTextBox.width = 300
$ExtraFolderTextBox.height = 20
$ExtraFolderTextBox.location = New-Object System.Drawing.Point(892, 280)
$ExtraFolderTextBox.Font = $FontData
$ExtraFolderTextBox.Text = $null

$ExtraFolderBrowse = New-Object System.Windows.Forms.LinkLabel
$ExtraFolderBrowse.Text = 'Browse'
$ExtraFolderBrowse.AccessibleName = 'Browse for Copy Folder'
$ExtraFolderBrowse.Location = New-Object System.Drawing.Point(837, 283)
$ExtraFolderBrowse.AutoSize = $true
$ExtraFolderBrowse.LinkColor = $Palette.Accent
$ExtraFolderBrowse.ActiveLinkColor = $Palette.Accent


$RunCommandLabel = New-Object system.Windows.Forms.Label
$RunCommandLabel.text = "Run Script"
$RunCommandLabel.AutoSize = $true
$RunCommandLabel.width = 25
$RunCommandLabel.height = 10
$RunCommandLabel.location = New-Object System.Drawing.Point(692, 310)
$RunCommandLabel.Font = $Font1

$RunCommandTextBox = New-Object system.Windows.Forms.ComboBox
$RunCommandTextBox.DropDownStyle = 'DropDownList'
$RunCommandTextBox.width = 300
$RunCommandTextBox.height = 20
$RunCommandTextBox.location = New-Object System.Drawing.Point(892, 310)
$RunCommandTextBox.Font = $FontData
$RunCommandTextBox.Text = $null

$RunScriptRefresh = New-Object System.Windows.Forms.LinkLabel
$RunScriptRefresh.Text = 'Refresh'
$RunScriptRefresh.AccessibleName = 'Refresh Run Script choices'
$RunScriptRefresh.Location = New-Object System.Drawing.Point(837, 313)
$RunScriptRefresh.AutoSize = $true
$RunScriptRefresh.LinkColor = $Palette.Accent
$RunScriptRefresh.ActiveLinkColor = $Palette.Accent

$WDACPolicyLabel = New-Object System.Windows.Forms.Label
$WDACPolicyLabel.Text = 'WDAC Policy'
$WDACPolicyLabel.AutoSize = $true
$WDACPolicyLabel.Location = New-Object System.Drawing.Point(692, 340)
$WDACPolicyLabel.Font = $Font1

$WDACPolicySelect = New-Object System.Windows.Forms.ComboBox
$WDACPolicySelect.DropDownStyle = 'DropDownList'
$WDACPolicySelect.Location = New-Object System.Drawing.Point(892, 340)
$WDACPolicySelect.Width = 300
$WDACPolicySelect.Font = $FontData

$WDACRefresh = New-Object System.Windows.Forms.LinkLabel
$WDACRefresh.Text = 'Refresh'
$WDACRefresh.AccessibleName = 'Refresh WDAC policies'
$WDACRefresh.Location = New-Object System.Drawing.Point(837, 343)
$WDACRefresh.AutoSize = $true
$WDACRefresh.LinkColor = $Palette.Accent
$WDACRefresh.ActiveLinkColor = $Palette.Accent

$SkipWDACCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipWDACCheckBox.Width = 25
$SkipWDACCheckBox.Location = New-Object System.Drawing.Point(1100, 630)
$SkipWDACCheckBox.Font = $Font1

$SkipWDACLabel = New-Object System.Windows.Forms.Label
$SkipWDACLabel.Text = 'Skip WDAC'
$SkipWDACLabel.AutoSize = $true
$SkipWDACLabel.Location = New-Object System.Drawing.Point(992, 630)
$SkipWDACLabel.Font = $Font1

$SkipASRCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipASRCheckBox.Width = 25
$SkipASRCheckBox.Location = New-Object System.Drawing.Point(1100, 600)
$SkipASRCheckBox.Font = $Font1

$SkipASRLabel = New-Object System.Windows.Forms.Label
$SkipASRLabel.Text = 'Skip ASR'
$SkipASRLabel.AutoSize = $true
$SkipASRLabel.Location = New-Object System.Drawing.Point(992, 600)
$SkipASRLabel.Font = $Font1

$SecurityBaseLineCheckBoxLabel = New-Object system.Windows.Forms.Label
$SecurityBaseLineCheckBoxLabel.text = "Skip Baseline"
$SecurityBaseLineCheckBoxLabel.AutoSize = $true
$SecurityBaseLineCheckBoxLabel.width = 25
$SecurityBaseLineCheckBoxLabel.height = 10
$SecurityBaseLineCheckBoxLabel.location = New-Object System.Drawing.Point(692, 570)
$SecurityBaseLineCheckBoxLabel.Font = $Font1

$SecurityBaseLineCheckBox = New-Object System.Windows.Forms.CheckBox
$SecurityBaseLineCheckBox.Width = 25
$SecurityBaseLineCheckBox.Checked = $false
$SecurityBaseLineCheckBox.Location = New-Object System.Drawing.Point(872, 570)
$SecurityBaseLineCheckBox.Visible = $true

$SkipApplicationCheckBoxLabel = New-Object system.Windows.Forms.Label
$SkipApplicationCheckBoxLabel.text = "Skip Application"
$SkipApplicationCheckBoxLabel.AutoSize = $true
$SkipApplicationCheckBoxLabel.width = 25
$SkipApplicationCheckBoxLabel.height = 10
$SkipApplicationCheckBoxLabel.location = New-Object System.Drawing.Point(692, 600)
$SkipApplicationCheckBoxLabel.Font = $Font1

$SkipApplicationCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipApplicationCheckBox.Width = 25
$SkipApplicationCheckBox.Checked = $false
$SkipApplicationCheckBox.Location = New-Object System.Drawing.Point(872, 600)
$SkipApplicationCheckBox.Visible = $true

$SkipDiskEncryptionCheckBoxLabel = New-Object system.Windows.Forms.Label
$SkipDiskEncryptionCheckBoxLabel.text = "Skip Disk Encryption"
$SkipDiskEncryptionCheckBoxLabel.AutoSize = $true
$SkipDiskEncryptionCheckBoxLabel.width = 25
$SkipDiskEncryptionCheckBoxLabel.height = 10
$SkipDiskEncryptionCheckBoxLabel.location = New-Object System.Drawing.Point(692, 630)
$SkipDiskEncryptionCheckBoxLabel.Font = $Font1

$SkipDiskEncryptionCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipDiskEncryptionCheckBox.Width = 25
$SkipDiskEncryptionCheckBox.Checked = $false
$SkipDiskEncryptionCheckBox.Location = New-Object System.Drawing.Point(872, 630)
$SkipDiskEncryptionCheckBox.Visible = $true

$SkipRunScriptCheckBoxLabel = New-Object system.Windows.Forms.Label
$SkipRunScriptCheckBoxLabel.text = "Skip RunScript"
$SkipRunScriptCheckBoxLabel.AutoSize = $true
$SkipRunScriptCheckBoxLabel.width = 25
$SkipRunScriptCheckBoxLabel.height = 10
$SkipRunScriptCheckBoxLabel.location = New-Object System.Drawing.Point(992, 570)
$SkipRunScriptCheckBoxLabel.Font = $Font1

$SkipRunScriptCheckBox = New-Object System.Windows.Forms.CheckBox
$SkipRunScriptCheckBox.Width = 25
$SkipRunScriptCheckBox.Checked = $false
$SkipRunScriptCheckBox.Location = New-Object System.Drawing.Point(1100, 570)
$SkipRunScriptCheckBox.Visible = $true


$DHCPCheckBoxLabel = New-Object system.Windows.Forms.Label
$DHCPCheckBoxLabel.text = "Use DHCP"
$DHCPCheckBoxLabel.AutoSize = $true
$DHCPCheckBoxLabel.width = 25
$DHCPCheckBoxLabel.height = 10
$DHCPCheckBoxLabel.location = New-Object System.Drawing.Point(692, 380)
$DHCPCheckBoxLabel.Font = $Font1

$DHCPCheckBox = New-Object System.Windows.Forms.CheckBox
$DHCPCheckBox.Width = 25
$DHCPCheckBox.Checked = $true
$DHCPCheckBox.Location = New-Object System.Drawing.Point(872, 380)
$DHCPCheckBox.Visible = $true

$ShowVerboseCheckBoxLabel = New-Object system.Windows.Forms.Label
$ShowVerboseCheckBoxLabel.text = "Show Verbose"
$ShowVerboseCheckBoxLabel.AutoSize = $true
$ShowVerboseCheckBoxLabel.width = 25
$ShowVerboseCheckBoxLabel.height = 10
$ShowVerboseCheckBoxLabel.location = New-Object System.Drawing.Point(20, 430)
$ShowVerboseCheckBoxLabel.Font = $Font1


$ShowVerboseCheckBox = New-Object System.Windows.Forms.CheckBox
$ShowVerboseCheckBox.Checked = $false
$ShowVerboseCheckBox.Width = 25
$ShowVerboseCheckBox.Location = New-Object System.Drawing.Point(200, 430)
$ShowVerboseCheckBox.Visible = $true

$IPAddressLabel = New-Object system.Windows.Forms.Label
$IPAddressLabel.text = "IPAddress"
$IPAddressLabel.AutoSize = $true
$IPAddressLabel.width = 25
$IPAddressLabel.height = 10
$IPAddressLabel.location = New-Object System.Drawing.Point(692, 410)
$IPAddressLabel.Font = $Font1
$IPAddressLabel.Visible = $false

$IPAddressTextBox = New-Object system.Windows.Forms.TextBox
$IPAddressTextBox.multiline = $false
$IPAddressTextBox.width = 150
$IPAddressTextBox.height = 20
$IPAddressTextBox.location = New-Object System.Drawing.Point(892, 410)
$IPAddressTextBox.Font = $FontData
$IPAddressTextBox.Text = 'DHCP'
$IPAddressTextBox.Visible = $false

$SubnetLabel = New-Object system.Windows.Forms.Label
$SubnetLabel.text = "Subnet"
$SubnetLabel.AutoSize = $true
$SubnetLabel.width = 25
$SubnetLabel.height = 10
$SubnetLabel.location = New-Object System.Drawing.Point(692, 440)
$SubnetLabel.Font = $Font1
$SubnetLabel.Visible = $false

$SubnetTextBox = New-Object system.Windows.Forms.TextBox
$SubnetTextBox.multiline = $false
$SubnetTextBox.width = 150
$SubnetTextBox.height = 20
$SubnetTextBox.location = New-Object System.Drawing.Point(892, 440)
$SubnetTextBox.Font = $FontData
$SubnetTextBox.Text = 'DHCP'
$SubnetTextBox.Visible = $false

$DNS1Label = New-Object system.Windows.Forms.Label
$DNS1Label.text = "DNS1"
$DNS1Label.AutoSize = $true
$DNS1Label.width = 25
$DNS1Label.height = 10
$DNS1Label.location = New-Object System.Drawing.Point(692, 470)
$DNS1Label.Font = $Font1
$DNS1Label.Visible = $false

$DNS1TextBox = New-Object system.Windows.Forms.TextBox
$DNS1TextBox.multiline = $false
$DNS1TextBox.width = 150
$DNS1TextBox.height = 20
$DNS1TextBox.location = New-Object System.Drawing.Point(892, 470)
$DNS1TextBox.Font = $FontData
$DNS1TextBox.Text = 'DHCP'
$DNS1TextBox.Visible = $false

$DNS2Label = New-Object system.Windows.Forms.Label
$DNS2Label.text = "DNS2"
$DNS2Label.AutoSize = $true
$DNS2Label.width = 25
$DNS2Label.height = 10
$DNS2Label.location = New-Object System.Drawing.Point(692, 500)
$DNS2Label.Font = $Font1
$DNS2Label.Visible = $false

$DNS2TextBox = New-Object system.Windows.Forms.TextBox
$DNS2TextBox.multiline = $false
$DNS2TextBox.width = 150
$DNS2TextBox.height = 20
$DNS2TextBox.location = New-Object System.Drawing.Point(892, 500)
$DNS2TextBox.Font = $FontData
$DNS2TextBox.Text = 'DHCP'
$DNS2TextBox.Visible = $false

$GatewayLabel = New-Object system.Windows.Forms.Label
$GatewayLabel.text = "Gateway"
$GatewayLabel.AutoSize = $true
$GatewayLabel.width = 25
$GatewayLabel.height = 10
$GatewayLabel.location = New-Object System.Drawing.Point(692, 530)
$GatewayLabel.Font = $Font1
$GatewayLabel.Visible = $false

$GatewayTextBox = New-Object system.Windows.Forms.TextBox
$GatewayTextBox.multiline = $false
$GatewayTextBox.width = 150
$GatewayTextBox.height = 20
$GatewayTextBox.location = New-Object System.Drawing.Point(892, 530)
$GatewayTextBox.Font = $FontData
$GatewayTextBox.Text = 'DHCP'
$GatewayTextBox.Visible = $false

$ValidationLabel1 = New-Object system.Windows.Forms.Label
$ValidationLabel1.text = "*"
$ValidationLabel1.AutoSize = $true
$ValidationLabel1.width = 8
$ValidationLabel1.height = 10
$ValidationLabel1.location = New-Object System.Drawing.Point(692, 656)
$ValidationLabel1.Font = $FontHeading2
$ValidationLabel1.Visible = $false
$ValidationLabel1.ForeColor = $Palette.Accent

$ValidationLabel2 = New-Object system.Windows.Forms.Label
$ValidationLabel2.text = " Fix validation errors"
$ValidationLabel2.AutoSize = $true
$ValidationLabel2.width = 350
$ValidationLabel2.height = 10
$ValidationLabel2.location = New-Object System.Drawing.Point(712, 659)
$ValidationLabel2.Font = $Font1
$Validationlabel2.Visible = $false




$CopyCMDButton = New-Object system.Windows.Forms.Button
$CopyCMDButton.text = "Copy CMD"
$CopyCMDButton.width = 200
$CopyCMDButton.height = 30
$CopyCMDButton.location = New-Object System.Drawing.Point(898, 680)
$CopyCMDButton.Font = $FontHeading3
$CopyCMDButton.BackColor = $Palette.Accent
$CopyCMDButton.ForeColor = $Palette.AccentText
$CopyCMDButton.FlatStyle = "Flat"
$CopyCMDButton.FlatAppearance.BorderSize = 0;
$CopyCMDButton.Visible = $false
$CopyCMDButton.Enabled = $false

$OkButton = New-Object system.Windows.Forms.Button
$OkButton.text = "Build"
$OkButton.width = 200
$OkButton.height = 30
$OkButton.location = New-Object System.Drawing.Point(1108, 680)
$OkButton.Font = $FontHeading3
$OkButton.BackColor = $Palette.Accent
$OkButton.ForeColor = $Palette.AccentText
$OkButton.FlatStyle = "Flat"
$OkButton.FlatAppearance.BorderSize = 0;
$OkButton.Enabled = $false

$CancelButton = New-Object system.Windows.Forms.Button
$CancelButton.text = "Close"
$CancelButton.width = 60
$CancelButton.height = 30
$CancelButton.location = New-Object System.Drawing.Point(1260, 680)
$CancelButton.Font = $FontHeading3
$CancelButton.BackColor = $Palette.Panel
$CancelButton.ForeColor = $Palette.Text
$CancelButton.FlatStyle = "Flat"
$CancelButton.FlatAppearance.BorderSize = 0;




foreach ($item in $TemplatesSelection) {
    [void] $TemplateListbox.Items.Add($item)
}

[void]$DiskModeSelect.Items.Add("Diff")
[void]$DiskModeSelect.Items.Add("Copy")

$Form.controls.AddRange(@(


        $TemplateListbox,
        $TemplateStatusLabel,
        $VMnameTextBox,
        $VMSwitchSelect,
        $VMSwitchRefresh,
        $VlanTextBox,
        $DiskModeSelect,
        $VMNameShieldedCheckBox,
        $VHDXOverrideLabel,
        $VHDXOverrideTextBox,
        $VHDXOverrideBrowse,

        $LPasswordTextBox,
        $OSDComputerNameTextBox,
        $VMNameCheckBox,
        $ExtraFolderTextBox,
        $ExtraFolderBrowse,
        $RunCommandTextBox,
        $RunScriptRefresh,
        $WDACPolicyLabel,
        $WDACPolicySelect,
        $WDACRefresh,
        $SkipWDACCheckBox,
        $SkipASRCheckBox,
        $SkipASRLabel,
        $SkipWDACLabel,
        $SecurityBaseLineCheckBox,
        $SkipApplicationCheckBox,
        $SkipDiskEncryptionCheckBox,
        $SkipRunScriptCheckBox,
        $SkipLinkCheckBox,
        $DHCPCheckBox,
        $ShowVerboseCheckBox,
        $IPAddressTextBox,
        $SubnetTextBox,
        $DNS1TextBox,
        $DNS2TextBox,
        $GatewayTextBox,
        $DJANameTextBox,
        $DJAPasswordTextBox,
        $DJOUTextBox,

        $CopyCMDButton,
        $OkButton,
        $CancelButton,

        $TemplateLabel,
        $RunCommandLabel,
        $VMLabel,
        $DJoinLabel,
        $DHCPCheckBoxLabel,
        $VMNameCheckBoxLabel,
        $ShowVerboseCheckBoxLabel,
        $IPAddressLabel,
        $SubnetLabel,
        $DNS1Label,
        $DNS2Label,
        $GatewayLabel,
        $VlanLabel,
        $PictureBox3,
        $PictureBox4,
        $VMnameLabel,
        $DJANameLabel,
        $DJAPasswordLabel,
        $LPasswordLabel,
        $DiskModeLabel,
        $VMNameShieldedCheckBoxLabel,
        $DJOULabel,
        $VMSwitchLabel,
        $VMGuesLabel,
        $ExtraFolderLabel,
        $ExtraFolderLabel,
        $SecurityBaseLineCheckBoxLabel,
        $SkipApplicationCheckBoxLabel,
        $SkipDiskEncryptionCheckBoxLabel,
        $SkipRunScriptCheckBoxLabel,
        $SkipLinkCheckBoxLabel,
        $ValidationLabel1,
        $ValidationLabel2

    )
)

function Add-PAWDeploySections {
    param([Parameter(Mandatory)][System.Windows.Forms.Form]$Form)
    foreach ($section in @(
        @{ Name = 'PAWVirtualMachineSection'; Left = 8; Width = 640 },
        @{ Name = 'PAWGuestOSSection'; Left = 680; Width = 640 }
    )) {
        $panel = New-Object System.Windows.Forms.Panel
        $panel.Name = $section.Name
        $panelTop = 150
        $panel.Location = New-Object System.Drawing.Point($section.Left, $panelTop)
        $panel.Size = New-Object System.Drawing.Size($section.Width, (654 - $panelTop))
        $panel.Padding = New-Object System.Windows.Forms.Padding(12)
        $members = @($Form.Controls | Where-Object {
            $_.Top -ge $panelTop -and $_.Top -lt 650 -and
            $_.Left -ge $panel.Left -and $_.Right -le $panel.Right
        })
        $Form.Controls.Add($panel)
        foreach ($control in $members) {
            $location = New-Object System.Drawing.Point(($control.Left - $panel.Left), ($control.Top - $panel.Top))
            $panel.Controls.Add($control)
            $control.Location = $location
        }
    }
}

Add-PAWDeploySections -Form $Form

#region gui events {
$OkButton.Add_Click({ Invoke-PAWValidateInput })
$CancelButton.Add_Click({ Exit-PAWDeploy })
$SwitchStatusLabel = New-Object System.Windows.Forms.Label
$SwitchStatusLabel.Text = 'Loading Hyper-V switches...'
Add-PAWUiRibbon -Form $Form -ScriptPath $PSCommandPath -CloseButton $CancelButton -StatusLabel $SwitchStatusLabel
$TemplateListbox.Add_SelectedValueChanged({ Set-PAWDeployTemplate; Save-PAWUISettings })

$DHCPCheckBox.Add_Click({ Invoke-PAWDeployToggleDHCP -Status $DHCPCheckBox.Checked; Save-PAWUISettings })
$VMNameCheckBox.Add_Click({ Invoke-PAWDeployOverrideComputerName -Status $VMNameCheckBox.Checked; Save-PAWUISettings })
$SkipRunScriptCheckBox.Add_Click({ Invoke-PAWDeployToggleRunScript -Status $SkipRunScriptCheckBox.Checked; Save-PAWUISettings })
$SkipWDACCheckBox.Add_Click({
    $WDACPolicySelect.Enabled = -not $SkipWDACCheckBox.Checked
    $WDACRefresh.Enabled = -not $SkipWDACCheckBox.Checked
    Save-PAWUISettings
})
$SkipASRCheckBox.Add_Click({ Save-PAWUISettings })
$WDACPolicySelect.Add_SelectionChangeCommitted({ Save-PAWUISettings })
$WDACRefresh.Add_LinkClicked({
    try { Update-PAWWDACSelection }
    catch { Write-PAWDeployUILog -Level ERROR -Message "WDAC policy list failed: $($_.Exception.Message)"; [void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'WDAC list failed', 'OK', 'Error') }
})
$VMNameShieldedCheckBox.Add_Click({ Save-PAWUISettings })
$SecurityBaseLineCheckBox.Add_Click({ Save-PAWUISettings })
$SkipApplicationCheckBox.Add_CheckedChanged({
    $ApplicationBundleSelect.Enabled = -not $SkipApplicationCheckBox.Checked
})
$SkipApplicationCheckBox.Add_Click({ Save-PAWUISettings })
$ShowVerboseCheckBox.Add_Click({ Save-PAWUISettings; Write-PAWDeployUILog -Message ("ShowVerbose changed: {0}" -f $ShowVerboseCheckBox.Checked) })

$CopyCMDButton.Add_Click({ Invoke-PAWCopyDeploymentCommand })
$VHDXOverrideBrowse.Add_LinkClicked({
    try {
        $selectedFile = Select-PAWFilePath -InitialPath $VHDXOverrideTextBox.Text -Filter 'Virtual hard disks (*.vhd;*.vhdx)|*.vhd;*.vhdx'
        if (-not [string]::IsNullOrWhiteSpace($selectedFile)) {
            $VHDXOverrideTextBox.Text = $selectedFile
        }
    }
    catch {
        Write-PAWDeployUILog -Level ERROR -Message "Cannot select VHD(X) override: $($_.Exception.Message)"
        [void][System.Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, 'VHD(X) selection failed', 'OK', 'Error')
    }
})
$ExtraFolderBrowse.Add_LinkClicked({
    try {
        $selectedFolder = Select-PAWFolderPath -InitialPath $ExtraFolderTextBox.Text -Description 'Select folder to copy into the PAW'
        if (-not [string]::IsNullOrWhiteSpace($selectedFolder)) {
            $ExtraFolderTextBox.Text = $selectedFolder
        }
    }
    catch {
        Write-PAWDeployUILog -Level ERROR -Message "Cannot select Copy Folder: $($_.Exception.Message)"
        [void][System.Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, 'Folder selection failed', 'OK', 'Error')
    }
})
$RunScriptRefresh.Add_LinkClicked({
    try { Invoke-PAWBrowseRunScript }
    catch {
        Write-PAWDeployUILog -Level ERROR -Message "Cannot select Run Script: $($_.Exception.Message)"
        [void][System.Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, 'Script selection failed', 'OK', 'Error')
    }
})
#endregion events }

#endregion GUI }


Function Invoke-PAWDeployOverrideComputerName ($Status) {

    If ($status -eq $false) {
        $OSDComputerNameTextBox.enabled = $false
    }
    else {
        $OSDComputerNameTextBox.enabled = $true
    }

}

Function Invoke-PAWDeployToggleDHCP ($Status) {

    If ($status -eq $false) {
        $Visible = $true
        $DNS1TextBox.Text = ""
        $DNS2TextBox.Text = ""
        $IPAddressTextBox.Text = ""
        $SubnetTextBox.Text = ""
        $GatewayTextBox.Text = ""

    }
    else {
        $Visible = $false
        $DNS1TextBox.Text = "DHCP"
        $DNS2TextBox.Text = "DHCP"
        $IPAddressTextBox.Text = "DHCP"
        $SubnetTextBox.Text = "DHCP"
        $GatewayTextBox.Text = "DHCP"
    }

    $IPAddressLabel.Visible = $Visible
    $DNS1Label.Visible = $Visible
    $DNS1TextBox.Visible = $Visible
    $DNS2Label.Visible = $Visible
    $DNS2TextBox.Visible = $Visible
    $IPAddressTextBox.Visible = $Visible
    $SubnetLabel.Visible = $Visible
    $SubnetTextBox.Visible = $Visible
    $GatewayLabel.Visible = $Visible
    $GatewayTextBox.Visible = $Visible
    $skipTop = if ($Visible) { $GatewayTextBox.Top + 40 } else { $DHCPCheckBox.Top + 30 }
    foreach ($control in @($SecurityBaseLineCheckBoxLabel, $SecurityBaseLineCheckBox, $SkipRunScriptCheckBoxLabel, $SkipRunScriptCheckBox)) {
        $control.Top = $skipTop
    }
    foreach ($control in @($SkipApplicationCheckBoxLabel, $SkipApplicationCheckBox, $SkipASRLabel, $SkipASRCheckBox)) {
        $control.Top = $skipTop + 30
    }
    foreach ($control in @($SkipDiskEncryptionCheckBoxLabel, $SkipDiskEncryptionCheckBox, $SkipWDACLabel, $SkipWDACCheckBox)) {
        $control.Top = $skipTop + 60
    }

}

function Invoke-PAWBrowseRunScript {
    $options = @(Get-PAWRunScriptOptions -InstallFolderPath $RootFolder -ErrorAction Stop)
    $previous = $RunCommandTextBox.Text
    $RunCommandTextBox.Items.Clear()
    [void]$RunCommandTextBox.Items.Add('NA')
    if ($options.Count) { $RunCommandTextBox.Items.AddRange([object[]]$options) }
    $RunCommandTextBox.SelectedItem = if ($options -contains $previous) { $previous } else { 'NA' }
}

function Update-PAWWDACSelection {
    $previous = $WDACPolicySelect.Text
    $options = @(Get-PAWWDACPolicyOptions -InstallFolderPath $RootFolder -ErrorAction Stop)
    $WDACPolicySelect.Items.Clear()
    [void]$WDACPolicySelect.Items.Add('NA')
    if ($options.Count) { $WDACPolicySelect.Items.AddRange([object[]]$options) }
    if ($previous -and $previous -ne 'NA' -and $options -notcontains $previous) {
        [void]$WDACPolicySelect.Items.Add($previous)
        Write-PAWDeployUILog -Level WARN -Message "Selected WDAC policy '$previous' is unavailable. Import it, choose another policy, or select Skip WDAC."
    }
    $WDACPolicySelect.SelectedItem = if ($previous) { $previous } else { 'NA' }
}

function Get-PAWDeploySecurityArguments {
    $arguments = ''
    if ($SkipASRCheckBox.Checked) { $arguments += ' -SkipASR' }
    if ($SkipWDACCheckBox.Checked) { $arguments += ' -SkipWDAC' }
    else { $arguments += " -WDACPolicy '$($WDACPolicySelect.Text.Replace("'", "''"))'" }
    $arguments
}

function Update-PAWDeployASRSelection {
    $templateASR = $TemplateData.PSObject.Properties['ASR']
    $enabled = $true
    if ($null -ne $templateASR) {
        $enabled = (ConvertTo-PAWTemplateValue -SettingName ASR -Value $templateASR.Value) -eq 'True'
    }
    $SkipASRCheckBox.Checked = -not $enabled
    $SkipASRCheckBox.Enabled = $true
}

Function Invoke-PAWDeployToggleRunScript ($Status) {
    $RunScriptRefresh.Enabled = -not $Status

    If ($status -eq $true) {
        $RunCommandTextBox.enabled = $false
        $RunCommandTextBox.BackColor = (Get-PAWUiPalette).ReadOnly
        $RunCommandLabel.ForeColor = (Get-PAWUiPalette).MutedText
    }
    else {
        $RunCommandTextBox.enabled = $true
        $RunCommandTextBox.BackColor = (Get-PAWUiPalette).Field
        $RunCommandLabel.ForeColor = (Get-PAWUiPalette).Text
    }

}


Function Invoke-PAWCopyDeploymentCommand {
    try {
        Get-PAWDeployCommand | Set-Clipboard -ErrorAction Stop
    }
    catch {
        Write-PAWDeployUILog -Level ERROR -Message "Failed to copy deployment command: $($_.Exception.Message)"
        throw
    }
}

function Get-PAWDeployCommand {
    $values = [ordered]@{
        Template = [string]$TemplateListbox.SelectedItem
        VMName = $VMnameTextBox.Text
        OSDAdapter0IPAddressList = $IPAddressTextBox.Text
        OSDAdapter0Gateways = $GatewayTextBox.Text
        OSDAdapter0DNS1 = $DNS1TextBox.Text
        OSDAdapter0DNS2 = $DNS2TextBox.Text
        OSDAdapter0SubnetMaskPrefix = $SubnetTextBox.Text
        VMSwitchName = [string]$VMSwitchSelect.SelectedItem
        DiskMode = [string]$DiskModeSelect.SelectedItem
    }
    if (-not [string]::IsNullOrWhiteSpace($VlanTextBox.Text)) { $values.VlanID = $VlanTextBox.Text }
    if (-not [string]::IsNullOrWhiteSpace($OSDComputerNameTextBox.Text)) { $values.OSDComputerName = $OSDComputerNameTextBox.Text }
    if ($DJAPasswordTextBox.Visible) {
        $values.DomainJoinAccount = $DJANameTextBox.Text
        $machineObjectOU = ([string]$DJOUTextBox.Text).Trim()
        if ($machineObjectOU -ne ([string]$TemplateData.MachineObjectOU).Trim()) {
            $values.MachineObjectOU = $machineObjectOU
        }
    }
    if ($RunCommandTextBox.Text -ne '' -and -not $SkipRunScriptCheckBox.Checked) { $values.RunScript = $RunCommandTextBox.Text }
    if ($ExtraFolderTextBox.Text -ne '') { $values.ExtraFolder = $ExtraFolderTextBox.Text }
    if (-not [string]::IsNullOrWhiteSpace($VHDXOverrideTextBox.Text)) { $values.VHDX = $VHDXOverrideTextBox.Text }
    if ($ApplicationBundleSelect.SelectedIndex -gt 0) { $values.ApplicationBundle = [string]$ApplicationBundleSelect.SelectedItem.BundleId }

    $arguments = @(
        foreach ($entry in $values.GetEnumerator()) {
            "-$($entry.Key) '$(([string]$entry.Value).Replace("'", "''"))'"
        }
    )
    $switches = [ordered]@{
        SkipShielding = $VMNameShieldedCheckBox.Checked
        SkipSecurityBaseLine = $SecurityBaseLineCheckBox.Checked
        SkipApplication = $SkipApplicationCheckBox.Checked
        SkipDiskEncryption = $SkipDiskEncryptionCheckBox.Checked
        SkipRunScript = $SkipRunScriptCheckBox.Checked
        SkipLink = $SkipLinkCheckBox.Checked
        Verbose = $ShowVerboseCheckBox.Checked
    }
    foreach ($entry in $switches.GetEnumerator()) {
        if ($entry.Value) { $arguments += "-$($entry.Key)" }
    }
    $escapedScriptPath = (Join-Path $RootFolder 'New-PAWVM.ps1').Replace("'", "''")
    "& '$escapedScriptPath' $($arguments -join ' ')$(Get-PAWDeploySecurityArguments)"
}


Function Set-PAWDeployTemplate {
    #Get Templates
    $SelectedTemplate = $($TemplateListbox.SelectedItem)
    if ($null -eq $SelectedTemplate) {
        $script:TemplateData = $null
        $OkButton.Enabled = $false
        $CopyCMDButton.Enabled = $false
        $CopyCMDButton.Visible = $false
        return
    }
    $script:TemplateData = $Templates | Where-Object Name -EQ $SelectedTemplate | Select-Object -First 1
    $ApplicationBundleSelect.SelectedIndex = 0
    if ($null -eq $script:TemplateData) {
        throw "Template '$SelectedTemplate' was not found in folder '$TemplateFolder'."
    }

    # Populate form from the template
    $VMnameTextBox.Text = $TemplateData.NamePrefix + "-" + $TemplateData.NameSuffix + $RandomName
    $OSDComputerNameTextBox.Text = $TemplateData.NamePrefix + "-" + $TemplateData.NameSuffix + $RandomName
    $VlanTextBox.Text = $TemplateData.vlanid
    Invoke-PAWBrowseRunScript
    $templateScript = if (-not [string]::IsNullOrWhiteSpace([string]$TemplateData.RunScript)) {
        [string]$TemplateData.RunScript
    } else { [string]$TemplateData.ExpansionScript }
    if ($RunCommandTextBox.Items.Contains($templateScript)) {
        $RunCommandTextBox.SelectedItem = $templateScript
    }
    else {
        if ($templateScript -and $templateScript -ne 'NA') {
            Write-PAWDeployUILog -Level WARN -Message "Template RunScript '$templateScript' is not a filename in configured CustomScripts. Select an imported script."
        }
        $RunCommandTextBox.SelectedItem = 'NA'
    }
    $ExtraFolderTextBox.Text = $TemplateData.ExtraFolder
    $DJOUTextBox.Text = $TemplateData.MachineObjectOU
    Update-PAWWDACSelection
    $templatePolicy = [string]$TemplateData.WDACPolicyFile
    if ($WDACPolicySelect.Items.Contains($templatePolicy)) { $WDACPolicySelect.SelectedItem = $templatePolicy }
    else {
        $WDACPolicySelect.SelectedItem = 'NA'
        if ($templatePolicy -and $templatePolicy -ne 'NA') {
            [void]$WDACPolicySelect.Items.Add($templatePolicy)
            $WDACPolicySelect.SelectedItem = $templatePolicy
            Write-PAWDeployUILog -Level WARN -Message "Template WDACPolicyFile '$templatePolicy' is unavailable in Resources\WDACPolicies. Import a policy or select Skip WDAC."
        }
    }

    $DiskModeSelect.SelectedItem = $TemplateData.DiskMode
    Update-PAWDeployASRSelection
    foreach ($control in @($VMNameShieldedCheckBox, $SecurityBaseLineCheckBox, $SkipApplicationCheckBox,
        $SkipDiskEncryptionCheckBox, $SkipRunScriptCheckBox, $SkipLinkCheckBox, $SkipWDACCheckBox)) {
        $control.Enabled = $true
    }

    If ($TemplateData.Shielded -eq "True") {
        $VMNameShieldedCheckBox.Checked = $false
    }
    else {
        $VMNameShieldedCheckBox.Checked = $true
    }

    If ($TemplateData.ApplySecurityBaseline -eq "True" -and
        -not [string]::IsNullOrWhiteSpace([string]$TemplateData.SecurityBaselineLocation) -and
        ([string]$TemplateData.SecurityBaselineLocation).Trim() -ne 'NA') {
        $SecurityBaseLineCheckBox.Checked = $false
        $SecurityBaseLineCheckBox.Enabled = $true
    }
    else {
        $SecurityBaseLineCheckBox.Checked = $true
    }

    If ($TemplateData.Application -eq "True") {
        $SkipApplicationCheckBox.Checked = $false
    }
    else {
        $SkipApplicationCheckBox.Checked = $true
    }

    If ($TemplateData.BitLocker -eq "True") {
        $SkipDiskEncryptionCheckBox.Checked = $false
    }
    else {
        $SkipDiskEncryptionCheckBox.Checked = $true
    }

    if ([string]::IsNullOrWhiteSpace($TemplateData.RunScript) -or $TemplateData.RunScript -eq "NA") {
        $SkipRunScriptCheckBox.Checked = $true        
    }
    else {
        $SkipRunScriptCheckBox.Checked = $false
    }

    Invoke-PAWDeployToggleRunScript -Status $SkipRunScriptCheckBox.Checked
    Invoke-PAWDeployToggleDHCP -Status $DHCPCheckBox.Checked


    # Hide or show domain credential part depending on selected template
    If ($TemplateData.DomainOrWorkGroup -match "workgroup") {
        $DJANameLabel.Visible = $false
        $DJANameTextBox.Visible = $false
        $DJAPasswordLabel.Visible = $false
        $DJAPasswordTextBox.Visible = $false
        $DJoinLabel.Visible = $false
        $DJOULabel.Visible = $false
        $DJOUTextBox.Visible = $false
    }
    else {
        $DJANameLabel.Visible = $true
        $DJANameTextBox.Visible = $true
        $DJAPasswordLabel.Visible = $true
        $DJAPasswordTextBox.Visible = $true
        $DJoinLabel.Visible = $true
        $DJOULabel.Visible = $true
        $DJOUTextBox.Visible = $true
    }

    # Check if the Switch in the xml exists, if not, set it to null
    $VMSwitchSelect.SelectedItem = $VMSwitchSelect.Items | Where-Object { $_ -eq $TemplateData.VMSwitch } | Select-Object -First 1

    $CopyCMDButton.Visible = $true
    $OkButton.Enabled = $VMSwitchSelect.Enabled -and $VMSwitchSelect.Items.Count -gt 0
    $CopyCMDButton.Enabled = $OkButton.Enabled
}
function Exit-PAWDeploy() {
    $Form.close()
}

Function Write-PAWDeployUILog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    try {
        Write-PAWLog -Message $Message -Level $Level -LogPath $Script:LogPath
    }
    catch {
        # silently ignore logging failures
    }
}

Function Invoke-PAWValidateInput {

    $ValidationError = $false

    # Validate input
    $fieldColor = (Get-PAWUiPalette).Field
    $TemplateListbox.BackColor = $fieldColor
    $VMSwitchSelect.BackColor = $fieldColor
    $LPasswordTextBox.BackColor = $fieldColor
    $OSDComputerNameTextBox.BackColor = $fieldColor
    $DJANameTextBox.BackColor = $fieldColor
    $DJAPasswordTextBox.BackColor = $fieldColor
    $VMnameTextBox.BackColor = $fieldColor
    $VHDXOverrideTextBox.BackColor = $fieldColor

    $ValidationLabel1.Visible = $false
    $ValidationLabel2.Visible = $false
    $ValidationLabel2.Text = " Fix validation errors"

    if ([string]::IsNullOrWhiteSpace($VMnameTextBox.Text)) {
        $ValidationError = $true
        $VMnameTextBox.BackColor = $Palette.Accent
    }
    elseif ($VMnameTextBox.Text -ne [System.IO.Path]::GetFileName($VMnameTextBox.Text) -or
        $VMnameTextBox.Text -in @('.', '..')) {
        $ValidationError = $true
        $VMnameTextBox.BackColor = $Palette.Accent
    }

    If ($null -eq $TemplateListbox.SelectedItem) {
        $ValidationError = $true
        $TemplateListbox.BackColor = $Palette.Accent
    }

    If ($null -eq $VMSwitchSelect.SelectedItem) {
        $ValidationError = $true
        $VMSwitchSelect.BackColor = $Palette.Accent
    }
    If ($LPasswordTextBox.text -eq "") {
        $ValidationError = $true
        $LPasswordTextBox.BackColor = $Palette.Accent
    }

    If ($VMNameCheckBox.Checked -eq $true) {
        If ($OSDComputerNameTextBox.text -eq "") {
            $ValidationError = $true
            $OSDComputerNameTextBox.BackColor = $Palette.Accent
        }

    }
    if ($OSDComputerNameTextBox.Text.Length -gt 15) {
        $ValidationError = $true
        $OSDComputerNameTextBox.BackColor = $Palette.Accent
    }

    if ($DJAPasswordTextBox.Visible) {
        if ($DJAPasswordTextBox.text -eq "") {
            $ValidationError = $true
            $DJAPasswordTextBox.BackColor = $Palette.Accent
        }
    }
    if ($DJANameTextBox.Visible) {
        if ($DJANameTextBox.text -eq "") {
            $ValidationError = $true
            $DJANameTextBox.BackColor = $Palette.Accent
        }
    }

    if (-not $ValidationError) {
        $vhdValue = if ([string]::IsNullOrWhiteSpace($VHDXOverrideTextBox.Text)) {
            [string]$TemplateData.VHDFile
        } else { $VHDXOverrideTextBox.Text }
        $isVHDOverride = -not [string]::IsNullOrWhiteSpace($VHDXOverrideTextBox.Text)
        $ResolvedTemplateVHDFile = $null
        try {
            $ResolvedTemplateVHDFile = Resolve-PAWVHDFilePath -ConfigPath $XMLDatafile -VHDFileValue $vhdValue
        }
        catch {
            Write-PAWDeployUILog -Level ERROR -Message "Failed to resolve VHDFile '$vhdValue': $($_.Exception.Message)"
        }
        If ([string]::IsNullOrWhiteSpace($ResolvedTemplateVHDFile) -or ((Test-Path -LiteralPath $ResolvedTemplateVHDFile -PathType Leaf) -eq $false)) {
            $ValidationError = $true
            if ($isVHDOverride) {
                $VHDXOverrideTextBox.BackColor = $Palette.Accent
                $ValidationLabel2.Text = ' Override VHD(X) not found. See log.'
            }
            else {
                $TemplateListbox.BackColor = $Palette.Accent
                $ValidationLabel2.Text = ' Template VHD(X) not found. See log.'
            }
            Write-PAWDeployUILog -Level ERROR -Message "VHDFile not found: $vhdValue (resolved: $ResolvedTemplateVHDFile)"
        }
    }

    if (-not $ValidationError) {
        try {
            $existingVM = @(Get-VM -ErrorAction Stop | Where-Object { $_.Name -eq $VMnameTextBox.Text })
            if ($existingVM.Count -gt 0) {
                $ValidationError = $true
                $VMnameTextBox.BackColor = $Palette.Accent
                $ValidationLabel2.Text = " VM exists. Change VM Name."
                $VMnameTextBox.Focus() | Out-Null
                $VMnameTextBox.SelectAll()
                Write-PAWDeployUILog -Level WARN -Message "VM '$($VMnameTextBox.Text)' already exists on this Hyper-V host. Change VM Name and click Build again."
            }
        }
        catch {
            $ValidationError = $true
            $ValidationLabel2.Text = " Cannot query Hyper-V. See log."
            Write-PAWDeployUILog -Level ERROR -Message "Cannot validate VM name against Hyper-V: $($_.Exception.Message)"
        }
    }

    if (-not $ValidationError) {
        try {
            $buildConfig = Get-Content -LiteralPath $XMLDatafile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $vmLocation = [string]$buildConfig.Settings.HyperV.VMFolder
            if ([string]::IsNullOrEmpty($vmLocation)) {
                $vmLocation = [string]$buildConfig.Settings.HyperV.VMLocation
            }
            if ([string]::IsNullOrEmpty($vmLocation)) { $vmLocation = 'C:\VMs' }
            $vmFolder = Join-Path $vmLocation $VMnameTextBox.Text -ErrorAction Stop
            if (Test-Path -LiteralPath $vmFolder -ErrorAction Stop) {
                $ValidationError = $true
                $VMnameTextBox.BackColor = $Palette.Accent
                $ValidationLabel2.Text = " VM folder exists. Change name."
                $VMnameTextBox.Focus() | Out-Null
                $VMnameTextBox.SelectAll()
                Write-PAWDeployUILog -Level WARN -Message "VM directory '$vmFolder' already exists. Choose another VM name or inspect the existing directory before retrying."
            }
        }
        catch {
            $ValidationError = $true
            $ValidationLabel2.Text = " Cannot check VM folder. See log."
            Write-PAWDeployUILog -Level ERROR -Message "Cannot validate VM directory: $($_.Exception.Message)"
        }
    }

    If ($ValidationError -eq $true) {
        $ValidationLabel1.Visible = $true
        $ValidationLabel2.Visible = $true
        Write-PAWDeployUILog -Message "Validation failed. Please review highlighted fields."
    }
    else {
        Write-PAWDeployUILog -Message "Validation passed. Starting deployment build."
        Invoke-PAWDeployBuild
    }

}


Function Invoke-PAWDeployBuild {
    $Template = $($TemplateListbox.SelectedItem)
    $VMname = $VMnameTextBox.Text
    $ShowVerbose = $ShowVerboseCheckBox.Checked
    $deploymentCommand = Get-PAWDeployCommand

    $DataToExport = @{
        AdminPassword = $LPasswordTextBox.Text
    }
    if ($DJAPasswordTextBox.Visible) {
        $DataToExport.add("DomainJoinAccountPassword", $DJAPasswordTextBox.Text)
    }


    # Create a tempfolder for data
    if ((Test-Path -Path "$env:TEMP\PAWDeploy") -eq $false) {
        New-Item -Path "$env:TEMP\PAWDeploy" -ItemType Directory | Out-Null
    }
    $SecureVariable = ConvertTo-SecureString -String ($DataToExport | ConvertTo-Json ) -AsPlainText -force | ConvertFrom-SecureString
    $SecureVariable | Out-File -FilePath "$env:TEMP\PAWDeploy-$VMName.dat" -Force -Confirm:$false


    $escapedUiManifest = $PawUiUtilityManifest.Replace("'", "''")
    $consoleHeight = [int][Math]::Floor($Form.Height / 2)
    $consoleTop = $Form.Bottom - $consoleHeight
    $command = @"
`$ErrorActionPreference = 'Stop'
Import-Module '$escapedUiManifest' -Force -ErrorAction Stop
Set-PAWConsoleWindow -X $($Form.Left) -Y $consoleTop -Width $($Form.Width) -Height $consoleHeight
`$ErrorActionPreference = 'Continue'
$deploymentCommand
"@
    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

    $PowerShellExecutable = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
    # An explicit console host prevents Windows Terminal from moving the build into a tab.
    $consoleHost = Join-Path $env:SystemRoot 'System32\conhost.exe'
    try {
        Start-Process -FilePath $consoleHost -ArgumentList "`"$PowerShellExecutable`" -NoExit -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand" -WorkingDirectory $RootFolder -ErrorAction Stop -Verbose
    }
    catch {
        Write-PAWDeployUILog -Message "Failed to launch build console: $($_.Exception.Message)"
        throw
    }
    Write-PAWDeployUILog -Message ("Build launched. Template={0}; VM={1}; ShowVerbose={2}; UILog={3}" -f $Template, $VMName, $ShowVerbose, $Script:UILogFile)
    $Form.close()
}

Function Save-PAWUISettings {
    try {
        $settings = [PSCustomObject]@{
            SkipShielding        = $VMNameShieldedCheckBox.Checked
            SkipBaseline         = $SecurityBaseLineCheckBox.Checked
            SkipApplication      = $SkipApplicationCheckBox.Checked
            SkipRunScript        = $SkipRunScriptCheckBox.Checked
            SkipASR              = $SkipASRCheckBox.Checked
            SkipWDAC             = $SkipWDACCheckBox.Checked
            WDACPolicy           = $WDACPolicySelect.Text
            UseDHCP              = $DHCPCheckBox.Checked
            ShowVerbose          = $ShowVerboseCheckBox.Checked
            OverrideComputerName = $VMNameCheckBox.Checked
            Template             = $TemplateListbox.SelectedItem
            WindowWidth          = $Form.Width
            WindowHeight         = $Form.Height
            LocationX            = $Form.Location.X
            LocationY            = $Form.Location.Y
        }

        [void](Save-PAWUiState -SettingsRoot $Script:SettingsDirectory -SettingsFile $Script:SettingsFile -State $settings -Depth 3)
    }
    catch {
        Write-PAWDeployUILog -Level WARN -Message "UI settings could not be saved: $($_.Exception.Message)"
    }
}

Invoke-PAWDeployToggleRunScript -Status $SkipRunScriptCheckBox.Checked
Update-PAWWDACSelection

$uiSettings = Import-PAWUiState -SettingsFile $Script:SettingsFile
if ($null -ne $uiSettings) {
    if ($uiSettings.PSObject.Properties['SkipShielding']) {
        $VMNameShieldedCheckBox.Checked = [bool]$uiSettings.SkipShielding
    }
    if ($uiSettings.PSObject.Properties['SkipBaseline']) {
        $SecurityBaseLineCheckBox.Checked = [bool]$uiSettings.SkipBaseline
    }
    if ($uiSettings.PSObject.Properties['SkipApplication']) {
        $SkipApplicationCheckBox.Checked = [bool]$uiSettings.SkipApplication
    }
    if ($uiSettings.PSObject.Properties['SkipRunScript']) {
        $SkipRunScriptCheckBox.Checked = [bool]$uiSettings.SkipRunScript
        Invoke-PAWDeployToggleRunScript -Status $SkipRunScriptCheckBox.Checked
    }
    if ($uiSettings.PSObject.Properties['UseDHCP']) {
        $DHCPCheckBox.Checked = [bool]$uiSettings.UseDHCP
        Invoke-PAWDeployToggleDHCP -Status $DHCPCheckBox.Checked
    }
    if ($uiSettings.PSObject.Properties['ShowVerbose']) {
        $ShowVerboseCheckBox.Checked = [bool]$uiSettings.ShowVerbose
    }
    if ($uiSettings.PSObject.Properties['OverrideComputerName']) {
        $VMNameCheckBox.Checked = [bool]$uiSettings.OverrideComputerName
        Invoke-PAWDeployOverrideComputerName -Status $VMNameCheckBox.Checked
    }
    if ($uiSettings.PSObject.Properties['Template'] -and ($null -ne $uiSettings.Template)) {
        if ($TemplateListbox.Items.Contains($uiSettings.Template)) {
            $TemplateListbox.SelectedItem = $uiSettings.Template
        }
    }
    if ($uiSettings.PSObject.Properties['SkipASR']) { $SkipASRCheckBox.Checked = [bool]$uiSettings.SkipASR }
    if ($uiSettings.PSObject.Properties['SkipWDAC']) { $SkipWDACCheckBox.Checked = [bool]$uiSettings.SkipWDAC }
    if ($uiSettings.PSObject.Properties['WDACPolicy'] -and $uiSettings.WDACPolicy) {
        if (-not $WDACPolicySelect.Items.Contains([string]$uiSettings.WDACPolicy)) {
            [void]$WDACPolicySelect.Items.Add([string]$uiSettings.WDACPolicy)
        }
        $WDACPolicySelect.SelectedItem = [string]$uiSettings.WDACPolicy
        Update-PAWWDACSelection
    }
}
$WDACPolicySelect.Enabled = -not $SkipWDACCheckBox.Checked
$WDACRefresh.Enabled = -not $SkipWDACCheckBox.Checked
$ApplicationBundleSelect.Enabled = -not $SkipApplicationCheckBox.Checked

if ($Templates.Count -eq 0) {
    $TemplateStatusLabel.Visible = $true
    $Form.Controls['PAWVirtualMachineSection'].Enabled = $false
    $Form.Controls['PAWGuestOSSection'].Enabled = $false
    $CopyCMDButton.Visible = $true
    $SwitchStatusLabel.Text = ''
    Write-PAWDeployUILog -Level WARN -Message "No active templates found in: $TemplateFolder"
}

$Form.Add_FormClosing({
        if ($Templates.Count -gt 0) { Save-PAWUISettings }
        Write-PAWDeployUILog -Message 'UI closed.'
    })

if ($PSBoundParameters.ContainsKey('WindowX') -and $PSBoundParameters.ContainsKey('WindowY')) {
    $Form.StartPosition = 'Manual'
    $Form.Location = New-Object System.Drawing.Point($WindowX, $WindowY)
}
$Form.Text = $script:PAWToolTitle

function Set-PAWSwitchLoadError {
    param([string]$Message)

    $SwitchStatusLabel.Text = ''
    $VMSwitchSelect.Items.Clear()
    $VMSwitchSelect.Text = 'Unable to load switches. Click Refresh to retry.'
    $VMSwitchRefresh.Enabled = $true
    Write-PAWDeployUILog -Level ERROR -Message "Failed to load Hyper-V switches: $Message"
}

function Start-PAWSwitchLoad {
    if ($script:SwitchLoad) { return }
    $clock = if ($PAWDebug) { [Diagnostics.Stopwatch]::StartNew() } else { $null }
    $selection = [string]$VMSwitchSelect.SelectedItem
    $template = $script:TemplateData
    $VMSwitchSelect.Enabled = $false
    $SwitchStatusLabel.Text = 'Loading Hyper-V switches...'
    $VMSwitchSelect.Text = ''
    $VMSwitchRefresh.Enabled = $false
    $OkButton.Enabled = $false
    $CopyCMDButton.Enabled = $false
    try {
        if (-not $script:SwitchQuery) {
            $script:SwitchQuery = [PowerShell]::Create()
            [void]$script:SwitchQuery.AddScript('Hyper-V\Get-VMSwitch -ErrorAction Stop | Select-Object -ExpandProperty Name')
        }
        $script:SwitchQuery.Streams.Error.Clear()
        $script:SwitchLoad = @{
            Result = $script:SwitchQuery.BeginInvoke(); Clock = $clock
            Selection = $selection; Template = $template
        }
        $switchTimer.Start()
    }
    catch {
        $script:SwitchLoad = $null
        if ($script:SwitchQuery) { $script:SwitchQuery.Dispose(); $script:SwitchQuery = $null }
        Set-PAWSwitchLoadError -Message $_.Exception.Message
    }
}

function Complete-PAWSwitchLoad {
    $load = $script:SwitchLoad
    if (-not $load -or -not $load.Result.IsCompleted) { return }
    $switchTimer.Stop()
    $script:SwitchLoad = $null
    $SwitchStatusLabel.Text = ''
    try {
        $names = @($script:SwitchQuery.EndInvoke($load.Result) | ForEach-Object { [string]$_ })
        $VMSwitchSelect.Items.Clear()
        $VMSwitchSelect.Text = ''
        if ($names.Count -gt 0) {
            $VMSwitchSelect.Items.AddRange($names)
            $preferred = if ($load.Selection -and $load.Template -eq $script:TemplateData -and $load.Selection -in $names) {
                $load.Selection
            } elseif ($null -ne $script:TemplateData) { [string]$script:TemplateData.VMSwitch } else { '' }
            $VMSwitchSelect.SelectedItem = $names | Where-Object { $_ -eq $preferred } | Select-Object -First 1
            $VMSwitchSelect.Enabled = $true
            $OkButton.Enabled = $null -ne $TemplateListbox.SelectedItem -and $null -ne $script:TemplateData
            $CopyCMDButton.Enabled = $OkButton.Enabled
        }
        else {
            $VMSwitchSelect.Text = 'No Hyper-V switches found. Click Refresh to retry.'
        }
        $VMSwitchRefresh.Enabled = $true
        if ($PAWDebug) {
            Write-PAWDeployUILog -Message ("Hyper-V switch list ready: {0} switch(es) in {1:N2}s." -f $names.Count, $load.Clock.Elapsed.TotalSeconds)
        }
        else {
            Write-PAWDeployUILog -Message ("Hyper-V switch list ready: {0} switch(es)." -f $names.Count)
        }
    }
    catch {
        Set-PAWSwitchLoadError -Message $_.Exception.Message
    }
}

$script:SwitchLoad = $null
$script:SwitchQuery = $null
$switchTimer = [System.Windows.Forms.Timer]::new()
$switchTimer.Interval = 100
$switchTimer.Add_Tick({ Complete-PAWSwitchLoad })
$VMSwitchRefresh.Add_LinkClicked({ Start-PAWSwitchLoad })
$Form.Add_Shown({ Set-PAWWindowForeground -Form $Form })
$Form.Add_Shown({
        if ($PAWDebug) {
            Write-PAWDeployUILog -Message ("UI shown after {0:N2}s. SettingsFile={1}; UILog={2}" -f $startupClock.Elapsed.TotalSeconds, $Script:SettingsFile, $Script:UILogFile)
        }
        if ($Templates.Count -gt 0) { Start-PAWSwitchLoad }
    })
try { [void]$Form.ShowDialog() }
finally {
    $switchTimer.Dispose()
    $Form.Icon.Dispose()
    $Form.Dispose()
    if ($null -ne $InfoLogo) { $InfoLogo.Dispose() }
    if ($script:SwitchQuery) { $script:SwitchQuery.Dispose() }
}
