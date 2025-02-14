<#
 # This script will give you the option to change the SKU.
 # The script detects the Server OS version and present a list of other SKU's that the current version can be converted into
 # Version 2.0
 # Added Selfelevating : Script "borrowed" from Ben Armstrong - https://blogs.msdn.microsoft.com/virtual_pc_guy/2010/09/23/a-self-elevating-powershell-script/
 # Added support for Windows Server 2016
#>

$DLL = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
Add-Type -MemberDefinition $DLL -name NativeMethods -namespace Win32
$Process = (Get-Process PowerShell | Where-Object MainWindowTitle -like '*VM Deploy*').MainWindowHandle
# Minimize window
[Win32.NativeMethods]::ShowWindowAsync($Process, 2)

#Get Env:
$RootFolder = $MyInvocation.MyCommand.Path | Split-Path -Parent

#Get LData
$XMLLDatafile = "$RootFolder\lConfig.XML"
[XML]$XMLLData = Get-Content -Path $XMLLDatafile

switch ($XMLLData.Settings.Source)
{
    'local' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = Get-Content -Path "$RootFolder\$XMLDatafile"
    }
    'http' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = (New-Object System.Net.WebClient).DownloadString($XMLDatafile)
    }
    'unc' {
        #Get Data
        $XMLDatafile = $XMLLData.Settings.XMLFile
        [XML]$XMLData = (New-Object System.Net.WebClient).DownloadString($XMLDatafile)
    }
    Default {}
}

#Get Templates
$Templates = $XMLData.Settings.Templates.Template | Where-Object Active -EQ $True
$TemplatesSelection = $Templates.name

#Generate Randomname
$chars = [char[]]"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
$RandomName = [string](($chars[0..25]|Get-Random)+(($chars|Get-Random -Count 3) -join ""))

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$Font = 'Consolas,10'

#region begin GUI{ 

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = '800,600'
$Form.text                       = "VM Deploy 1.0"
$Form.TopMost                    = $false

$PictureBox1                     = New-Object system.Windows.Forms.PictureBox
$PictureBox1.width               = 150
$PictureBox1.height              = 150
$PictureBox1.location            = New-Object System.Drawing.Point(630,0)
$PictureBox1.imageLocation       = "$RootFolder\image.png"
$PictureBox1.SizeMode            = [System.Windows.Forms.PictureBoxSizeMode]::zoom

$OkButton                        = New-Object system.Windows.Forms.Button
$OkButton.text                   = "Build"
$OkButton.width                  = 60
$OkButton.height                 = 30
$OkButton.location               = New-Object System.Drawing.Point(630,550)
$OkButton.Font                   = $Font

$CancelButton                    = New-Object system.Windows.Forms.Button
$CancelButton.text               = "Close"
$CancelButton.width              = 60
$CancelButton.height             = 30
$CancelButton.location           = New-Object System.Drawing.Point(720,550)
$CancelButton.Font               = $Font

$SorceServerLabel                = New-Object system.Windows.Forms.Label
$SorceServerLabel.text           = "Source"
$SorceServerLabel.AutoSize       = $true
$SorceServerLabel.width          = 25
$SorceServerLabel.height         = 10
$SorceServerLabel.location       = New-Object System.Drawing.Point(20,10)
$SorceServerLabel.Font           = $Font

$TemplateLabel                   = New-Object system.Windows.Forms.Label
$TemplateLabel.text              = "Template"
$TemplateLabel.AutoSize          = $true
$TemplateLabel.width             = 25
$TemplateLabel.height            = 10
$TemplateLabel.location          = New-Object System.Drawing.Point(20,30)
$TemplateLabel.Font              = $Font

$TemplateListbox                 = New-Object system.Windows.Forms.ListBox
$TemplateListbox.text            = "TemplateSelection"
$TemplateListbox.width           = 350
$TemplateListbox.height          = 70
$TemplateListbox.location        = New-Object System.Drawing.Point(100,30)

$VMnameLabel                     = New-Object system.Windows.Forms.Label
$VMnameLabel.text                = "VMname"
$VMnameLabel.AutoSize            = $true
$VMnameLabel.width               = 25
$VMnameLabel.height              = 10
$VMnameLabel.location            = New-Object System.Drawing.Point(20,250)
$VMnameLabel.Font                = $Font

$VMnameTextBox                   = New-Object system.Windows.Forms.TextBox
$VMnameTextBox.multiline         = $false
$VMnameTextBox.width             = 150
$VMnameTextBox.height            = 20
$VMnameTextBox.location          = New-Object System.Drawing.Point(100,250)
$VMnameTextBox.Font              = $Font
$VMnameTextBox.Text              = $null

$DJANameLabel                    = New-Object system.Windows.Forms.Label
$DJANameLabel.text               = "D Account"
$DJANameLabel.AutoSize           = $true
$DJANameLabel.width              = 25
$DJANameLabel.height             = 10
$DJANameLabel.location           = New-Object System.Drawing.Point(20,280)
$DJANameLabel.Font               = $Font

$DJANameTextBox                  = New-Object system.Windows.Forms.TextBox
$DJANameTextBox.multiline        = $false
$DJANameTextBox.width            = 150
$DJANameTextBox.height           = 20
$DJANameTextBox.location         = New-Object System.Drawing.Point(100,280)
$DJANameTextBox.Font             = $Font
$DJANameTextBox.Text             = $null

$DJAPasswordLabel                = New-Object system.Windows.Forms.Label
$DJAPasswordLabel.text           = "D Password"
$DJAPasswordLabel.AutoSize       = $true
$DJAPasswordLabel.width          = 25
$DJAPasswordLabel.height         = 10
$DJAPasswordLabel.location       = New-Object System.Drawing.Point(20,310)
$DJAPasswordLabel.Font           = $Font

$DJAPasswordTextBox              = New-Object system.Windows.Forms.TextBox
$DJAPasswordTextBox.multiline    = $false
$DJAPasswordTextBox.width        = 150
$DJAPasswordTextBox.height       = 20
$DJAPasswordTextBox.location     = New-Object System.Drawing.Point(100,310)
$DJAPasswordTextBox.Font         = $Font
$DJAPasswordTextBox.PasswordChar = "*"
$DJAPasswordTextBox.Text         = $null

$LPasswordLabel                  = New-Object system.Windows.Forms.Label
$LPasswordLabel.text             = "L Password"
$LPasswordLabel.AutoSize         = $true
$LPasswordLabel.width            = 25
$LPasswordLabel.height           = 10
$LPasswordLabel.location         = New-Object System.Drawing.Point(20,340)
$LPasswordLabel.Font             = $Font

$LPasswordTextBox                = New-Object system.Windows.Forms.TextBox
$LPasswordTextBox.multiline      = $false
$LPasswordTextBox.width          = 150
$LPasswordTextBox.height         = 20
$LPasswordTextBox.location       = New-Object System.Drawing.Point(100,340)
$LPasswordTextBox.Font           = $Font
$LPasswordTextBox.PasswordChar = "*"
$LPasswordTextBox.Text           = $null

$IPAddressLabel                  = New-Object system.Windows.Forms.Label
$IPAddressLabel.text             = "IPAddress"
$IPAddressLabel.AutoSize         = $true
$IPAddressLabel.width            = 25
$IPAddressLabel.height           = 10
$IPAddressLabel.location         = New-Object System.Drawing.Point(20,400)
$IPAddressLabel.Font             = $Font

$IPAddressTextBox                = New-Object system.Windows.Forms.TextBox
$IPAddressTextBox.multiline      = $false
$IPAddressTextBox.width          = 150
$IPAddressTextBox.height         = 20
$IPAddressTextBox.location       = New-Object System.Drawing.Point(100,400)
$IPAddressTextBox.Font           = $Font
$IPAddressTextBox.Text           = 'DHCP'

$SubnetLabel                     = New-Object system.Windows.Forms.Label
$SubnetLabel.text                = "Subnet"
$SubnetLabel.AutoSize            = $true
$SubnetLabel.width               = 25
$SubnetLabel.height              = 10
$SubnetLabel.location            = New-Object System.Drawing.Point(20,430)
$SubnetLabel.Font                = $Font

$SubnetTextBox                   = New-Object system.Windows.Forms.TextBox
$SubnetTextBox.multiline         = $false
$SubnetTextBox.width             = 150
$SubnetTextBox.height            = 20
$SubnetTextBox.location          = New-Object System.Drawing.Point(100,430)
$SubnetTextBox.Font              = $Font
$SubnetTextBox.Text              = 'DHCP'

$DNS1Label                       = New-Object system.Windows.Forms.Label
$DNS1Label.text                  = "DNS1"
$DNS1Label.AutoSize              = $true
$DNS1Label.width                 = 25
$DNS1Label.height                = 10
$DNS1Label.location              = New-Object System.Drawing.Point(20,460)
$DNS1Label.Font                  = $Font

$DNS1TextBox                     = New-Object system.Windows.Forms.TextBox
$DNS1TextBox.multiline           = $false
$DNS1TextBox.width               = 150
$DNS1TextBox.height              = 20
$DNS1TextBox.location            = New-Object System.Drawing.Point(100,460)
$DNS1TextBox.Font                = $Font
$DNS1TextBox.Text                = 'DHCP'

$DNS2Label                       = New-Object system.Windows.Forms.Label
$DNS2Label.text                  = "DNS2"
$DNS2Label.AutoSize              = $true
$DNS2Label.width                 = 25
$DNS2Label.height                = 10
$DNS2Label.location              = New-Object System.Drawing.Point(20,490)
$DNS2Label.Font                  = $Font

$DNS2TextBox                     = New-Object system.Windows.Forms.TextBox
$DNS2TextBox.multiline           = $false
$DNS2TextBox.width               = 150
$DNS2TextBox.height              = 20
$DNS2TextBox.location            = New-Object System.Drawing.Point(100,490)
$DNS2TextBox.Font                = $Font
$DNS2TextBox.Text                = 'DHCP'

$GatewayLabel                    = New-Object system.Windows.Forms.Label
$GatewayLabel.text               = "Gateway"
$GatewayLabel.AutoSize           = $true
$GatewayLabel.width              = 25
$GatewayLabel.height             = 10
$GatewayLabel.location           = New-Object System.Drawing.Point(20,520)
$GatewayLabel.Font               = $Font

$GatewayTextBox                  = New-Object system.Windows.Forms.TextBox
$GatewayTextBox.multiline        = $false
$GatewayTextBox.width            = 150
$GatewayTextBox.height           = 20
$GatewayTextBox.location         = New-Object System.Drawing.Point(100,520)
$GatewayTextBox.Font             = $Font
$GatewayTextBox.Text             = 'DHCP'

$VlanLabel                       = New-Object system.Windows.Forms.Label
$VlanLabel.text                  = "VLANID"
$VlanLabel.AutoSize              = $true
$VlanLabel.width                 = 25
$VlanLabel.height                = 10
$VlanLabel.location              = New-Object System.Drawing.Point(20,550)
$VlanLabel.Font                  = $Font

$VlanTextBox                     = New-Object system.Windows.Forms.TextBox
$VlanTextBox.multiline           = $false
$VlanTextBox.width               = 150
$VlanTextBox.height              = 20
$VlanTextBox.location            = New-Object System.Drawing.Point(100,550)
$VlanTextBox.Font                = $Font
$VlanTextBox.Text                = $null

$result                          = New-Object system.Windows.Forms.TextBox
$result.multiline                = $true
$result.width                    = 480
$result.height                   = 180
$result.location                 = New-Object System.Drawing.Point(300,250)
$result.Font                     = $Font

foreach($item in $TemplatesSelection){
    [void] $TemplateListbox.Items.Add($item)
}

$Form.controls.AddRange(@($OkButton,$CancelButton,$SorceServerLabel,$TemplateLabel,$IPAddressLabel,$SubnetLabel,$DNS1Label,$DNS2Label,$GatewayLabel,$VlanLabel,$TemplateListbox,$IPAddressTextBox,$SubnetTextBox,$DNS1TextBox,$DNS2TextBox,$GatewayTextBox,$VlanTextBox,$result,$PictureBox1,$VMnameLabel,$VMnameTextBox,$DJANameLabel,$DJANameTextBox,$DJAPasswordLabel,$DJAPasswordTextBox,$LPasswordLabel,$LPasswordTextBox))

#region gui events {
$OkButton.Add_Click({ OkButtonSelected })
$CancelButton.Add_Click({ CancelButtonSelected })
$TemplateListbox.Add_SelectedValueChanged({TemplateListboxChanged})
#endregion events }

#endregion GUI }
Function TemplateListboxChanged
{
    #Get Data
    
    #Get Templates
    $SelectedTemplate = $($TemplateListbox.SelectedItem)
    $TemplateData = $XMLData.Settings.Templates.Template | Where-Object Name -EQ $SelectedTemplate

    $result.text = "Selected Template is $SelectedTemplate"
    $result.text += "`r`n" + "MachineObjectOU is now $($TemplateData.MachineObjectOU)"
    $result.text += "`r`n" + "NameSuffix is now $($TemplateData.NameSuffix)"

    $VMnameTextBox.Text = $env:COMPUTERNAME + "-" + $TemplateData.NameSuffix + $RandomName
    $VlanTextBox.Text = $TemplateData.vlanid

}
function CancelButtonSelected()
{
    $Form.close()
}
Function OkButtonSelected
{
    $result.text = "Starting the build..."
    #$result.text += "$($TemplateListbox.SelectedItem)"
    #$result.text += "$($DevEnvListbox.SelectedItem)"
    #$result.text += "$($IPAddressTextBox.Text)"
    #$result.text += "$($GatewayTextBox.Text)"
    #$result.text += "$($DNS1TextBox.Text)"
    #$result.text += "$($DNS2TextBox.Text)"
    #$result.text += "$($SubnetTextBox.Text)"
    #$result.text += "$($DJANameTextBox.Text)"
    #$result.text += "$($VlanTextBox.Text)"
    
    $Template = $($TemplateListbox.SelectedItem)
    $VMname = $VMnameTextBox.Text
    $OSDAdapter0IPAddressList = $($IPAddressTextBox.Text)
    $OSDAdapter0Gateways = $($GatewayTextBox.Text)
    $OSDAdapter0DNS1 = $($DNS1TextBox.Text)
    $OSDAdapter0DNS2 = $($DNS2TextBox.Text)
    $OSDAdapter0SubnetMaskPrefix = $($SubnetTextBox.Text)
    $AdminPassword = $($LPasswordTextBox.text)
    $DomainAdmin = $($DJANameTextBox.Text)
    $DomainAdminPassword = $($DJAPasswordTextBox.text)
    $vlanid = $($VlanTextBox.Text)

    $DataToExport = @{
        AdminPassword=$AdminPassword
        DomainAdminPassword=$DomainAdminPassword
    }
    $DataToExport | Export-Clixml -Path "$env:TEMP\vmdeploy.xml"



    if($DomainAdmin -eq ""){
        $ScriptArguments = "-Template `'$Template`' -RootFolder NA -VMName $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -vlanid $vlanid -DataFromFile"
    }
    else{
        $ScriptArguments = "-Template `'$Template`' -RootFolder NA -VMName $VMName -OSDAdapter0IPAddressList $OSDAdapter0IPAddressList -OSDAdapter0Gateways $OSDAdapter0Gateways -OSDAdapter0DNS1 $OSDAdapter0DNS1 -OSDAdapter0DNS2 $OSDAdapter0DNS2 -OSDAdapter0SubnetMaskPrefix $OSDAdapter0SubnetMaskPrefix -vlanid $vlanid -DomainAdmin $DomainAdmin -DataFromFile"
    }

    $ScriptToRun = "$RootFolder\VMDeploy.ps1"
    $Argument = "-NoExit $ScriptToRun $ScriptArguments"
    
    Start-Process PowerShell -ArgumentList "$Argument" -Verbose
    $Form.close()
}
[void]$Form.ShowDialog()