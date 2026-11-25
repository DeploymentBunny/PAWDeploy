<#
.SYNOPSIS
    PAWDeploy Community Edition menu GUI.

.DESCRIPTION
    PAWMenuCommunity.ps1 is the Community Edition variant of the PAWDeploy launcher.
    The build copies it into the Community package as PAWMenu.ps1.

    The form provides New PAW, Configuration, Templates, Applications/Bundles
    and an elevated PowerShell Prompt, with Logs, Help and Close.

    Community users can edit settings, templates and applications in the UI or
    with Invoke-PAWConfigurationSettings.ps1, Invoke-PAWTemplateSettings.ps1 and
    Invoke-PAWApplicationSettings.ps1.

.EXAMPLE
    .\PAWMenu.ps1

    Opens the Community Edition menu (the installed file name of this script).

.NOTES
    Version : 2.0.0.17
    Author  : The Fantastic PAWDeploy Team
    Purpose : GUI launcher for the Community Edition tools.
#>

# Edition branding (logo); this script is the Community menu.
$script:PAWEdition = 'Community'

# PAWUIUtility provides Get-PAWImage and Get-PAWWindowIcon for all graphics.
$PawUiUtilityManifest = Join-Path $PSScriptRoot 'Functions\PAWUIUtility\PAWUIUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUiUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUiUtilityManifest"
}
Import-Module -Name $PawUiUtilityManifest -Force -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath
$script:LogPath = Join-Path (Resolve-PAWLogFolder) 'PAWMenuCommunity.log'
Write-PAWLog -Message 'PAW Menu starting (Community).' -LogPath $script:LogPath

$DLL = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
Add-Type -MemberDefinition $DLL -name NativeMethods -namespace Win32
#Get-Process PowerShell | Select MainWindowTitle
$windowHandle = [IntPtr]::Zero


Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$FontData = 'Segoe UI,10'
$FontHeading2 = [System.Drawing.Font]::new("Segoe UI", 24, [System.Drawing.FontStyle]::Bold)
$FontButton = [System.Drawing.Font]::new("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$Palette = Get-PAWUiPalette

#region begin GUI{ 

$Form = New-Object system.Windows.Forms.Form
$Form.Size = New-Object System.Drawing.Size(1344, 756)
$Form.MinimumSize = New-Object System.Drawing.Size(1344, 756)
$Form.MaximumSize = New-Object System.Drawing.Size(1344, 756)
$Form.MaximizeBox = $false
$Form.TopMost = $false
$Form.Text = 'Truesec PAW Deployment Toolkit - Community Edition'
$Form.StartPosition = "CenterScreen"
$form.ForeColor = $Palette.Text

$form.BackColor = $Palette.Background
$BackgroundImg = $null
if (-not [string]::IsNullOrWhiteSpace($Palette.BackgroundImage)) {
    $BackgroundImg = Get-PAWImage -Name $Palette.BackgroundImage
    $form.BackgroundImage = $BackgroundImg
    $form.BackgroundImageLayout = 'Stretch'
}

 
$Close = New-Object system.Windows.Forms.Button
$Close.text = "Close"
$Close.width = 90
$Close.height = 30
$Close.location = New-Object System.Drawing.Point(1218, 665)
$Close.Font = $FontButton
$Close.BackColor = $Palette.Panel
$Close.ForeColor = $Palette.Text
$Close.FlatStyle = "Flat"
$Close.FlatAppearance.BorderSize = 0;
 

$PAW = New-Object system.Windows.Forms.Button
$PAW.text = "New PAW"
$PAW.width = 200
$PAW.height = 40
$PAW.location = New-Object System.Drawing.Point(50, 160)
$PAW.Font = $FontButton
$PAW.BackColor = $Palette.Accent
$PAW.ForeColor = $Palette.AccentText
$PAW.FlatStyle = "Flat"
$PAW.FlatAppearance.BorderSize = 0;

$Config = New-Object system.Windows.Forms.Button
$Config.text = "Configuration"
$Config.width = 200
$Config.height = 40
$Config.location = New-Object System.Drawing.Point(50, 220)
$Config.Font = $FontButton
$Config.BackColor = $Palette.Accent
$Config.ForeColor = $Palette.AccentText
$Config.FlatStyle = "Flat"
$Config.FlatAppearance.BorderSize = 0;

# Set the Icon for the GUI
$Form.Icon = Get-PAWWindowIcon

$Help = New-Object System.Windows.Forms.Button
$Help.Text = 'Help'
$Help.Size = New-Object System.Drawing.Size(90, 30)
$Help.Location = New-Object System.Drawing.Point(1118, 665)
$Help.Font = $FontButton
$Help.BackColor = $Palette.Panel
$Help.ForeColor = $Palette.Text
$Help.FlatStyle = 'Flat'
$Help.FlatAppearance.BorderSize = 0
$Help.Add_Click({ Open-PAWGUI -ScriptName 'PAWHelpUI' })
$PowerShellPrompt = New-Object System.Windows.Forms.Button
$PowerShellPrompt.Text = 'PowerShell Prompt'
$PowerShellPrompt.Size = New-Object System.Drawing.Size(200, 40)
$PowerShellPrompt.Location = New-Object System.Drawing.Point(50, 400)
$PowerShellPrompt.Font = $FontButton
$PowerShellPrompt.BackColor = $Palette.Accent
$PowerShellPrompt.ForeColor = $Palette.AccentText
$PowerShellPrompt.FlatStyle = 'Flat'
$PowerShellPrompt.FlatAppearance.BorderSize = 0
$PowerShellPrompt.Add_Click({
    try {
        $consoleHeight = [int][Math]::Floor($Form.Height / 2)
        Start-PAWElevatedPowerShell -RootFolder $PSScriptRoot -Version (($script:PAWToolTitle -split ' - ')[1]) `
            -X $Form.Left -Y ($Form.Bottom - $consoleHeight) -Width $Form.Width -Height $consoleHeight
    }
    catch {
        [void][System.Windows.Forms.MessageBox]::Show($Form, $_.Exception.Message, 'PowerShell launch failed', 'OK', 'Error')
    }
})
$TemplateEditor = New-PAWUiButton -Text 'Templates' -X 50 -Y 280 -Width 200 -Height 40 -Accent
$TemplateEditor.Add_Click({ Open-PAWGUI -ScriptName 'PAWTemplateEditorUI' })
$ApplicationManager = New-PAWUiButton -Text 'Applications/Bundles' -X 50 -Y 340 -Width 200 -Height 40 -Accent
$ApplicationManager.Add_Click({ Open-PAWGUI -ScriptName 'PAWApplicationManagerUI' })
$LogViewer = New-PAWUiButton -Text 'Logs' -X 1018 -Y 665 -Width 90 -Height 30
$LogViewer.Add_Click({ Open-PAWGUI -ScriptName 'PAWLogsUI' })
$LaunchStatusLabel = New-Object System.Windows.Forms.Label
$Form.controls.AddRange(@($Config, $TemplateEditor, $PAW, $ApplicationManager, $LogViewer, $PowerShellPrompt, $Close, $Help))
Add-PAWUiRibbon -Form $Form -ScriptPath $PSCommandPath -Menu -Edition $script:PAWEdition -StatusLabel $LaunchStatusLabel

#region gui events {
$Close.Add_Click({ Close-PAWUI })





#endregion events }

#endregion GUI }
$PAW.Add_Click({
        Open-PAWGUI -ScriptName 'PAWDeployUI'
    })
$config.Add_Click({
        Open-PAWGUI -ScriptName 'PAWConfigEditorUI'
    })
Function Open-PAWGUI ($ScriptName) {
    Start-PAWUiTool -Form $Form -StatusLabel $LaunchStatusLabel -RootFolder $PSScriptRoot -ScriptName $ScriptName -LogPath $script:LogPath
}

Function Close-PAWUI {
    $Form.Close()
}

$Form.Add_FormClosing({
    })

$Form.Text = $script:PAWToolTitle
try { [void]$Form.ShowDialog() }
finally {
    $Form.Icon.Dispose()
    $Form.Dispose()
    if ($null -ne $BackgroundImg) { $BackgroundImg.Dispose() }
}
