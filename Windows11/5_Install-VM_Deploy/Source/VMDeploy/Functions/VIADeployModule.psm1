Function New-VIAUnattendXML
{
    <#
     ##################################################################################
     #  Script name: Create-UnattendXML.ps1
     #  Created:		2013-09-02
     #  version:		v1.0
     #  Author:      Mikael Nystrom
     #  Homepage:    http://deploymentbunny.com/
     ##################################################################################
 
     ##################################################################################
     #  Disclaimer:
     #  -----------
     #  This script is provided "AS IS" with no warranties, confers no rights and 
     #  is not supported by the authors or DeploymentBunny.
     ##################################################################################
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Computername,
    
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $OSDAdapter0IPAddressList,
    
        [parameter(mandatory=$false)]
        [ValidateSet("Domain","Workgroup")]
        $DomainOrWorkGroup,

        [parameter(mandatory=$false)]
        $ProductKey = 'NONE',

        [parameter(mandatory=$false)]
        $AdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $OrgName = "ViaMonstra",

        [parameter(mandatory=$false)]
        $Fullname = "ViaMonstra",

        [parameter(mandatory=$false)]
        $TimeZoneName = "Pacific Standard Time",

        [parameter(mandatory=$false)]
        $InputLocale = "en-US",

        [parameter(mandatory=$false)]
        $SystemLocale = "en-US",

        [parameter(mandatory=$false)]
        $UILanguage = "en-US",

        [parameter(mandatory=$false)]
        $UserLocale = "en-US",

        [parameter(mandatory=$false)]
        $OSDAdapter0Gateways = "192.168.1.1",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS1 = "192.168.1.200",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS2 = "192.168.1.201",

        [parameter(mandatory=$false)]
        $OSDAdapter0SubnetMaskPrefix = "24",

        [parameter(mandatory=$false)]
        $DNSDomain = "corp.viamonstra.com",

        [parameter(mandatory=$false)]
        $DomainNetBios = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $DomainAdmin = "Administrator",

        [parameter(mandatory=$false)]
        $DomainAdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $DomainAdminDomain = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $MachineObjectOU = "NA",

        [parameter(mandatory=$false)]
        $JoinWorkgroup = "WORKGROUP",

        [parameter(mandatory=$false)]
        [ValidateSet("1","2","3")]
        $ProtectYourPC = "3"
    )

    if((Test-Path -Path .\Unattend.xml) -eq $true)
    {
        Remove-Item -Path .\Unattend.xml
    }

    Write-Verbose "IP is $OSDAdapter0IPAddressList"
    $unattendFile = New-Item -Path "Unattend.xml" -type File
    Set-Content $unattendFile '<?xml version="1.0" encoding="utf-8"?>'
    Add-Content $unattendFile '<unattend xmlns="urn:schemas-microsoft-com:unattend">'
    Add-Content $unattendFile '    <settings pass="specialize">'
    
    Switch ($DomainOrWorkGroup){
        DOMAIN
        {
            Write-Verbose "Configure for domain mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile '                <Credentials>'
            Add-Content $unattendFile "                    <Username>$DomainAdmin</Username>"
            Add-Content $unattendFile "                    <Domain>$DomainAdminDomain</Domain>"
            Add-Content $unattendFile "                    <Password>$DomainAdminPassword</Password>"
            Add-Content $unattendFile '                </Credentials>'
            Add-Content $unattendFile "                <JoinDomain>$DNSDomain</JoinDomain>"
            If(!($MachineObjectOU -eq 'NA'))
            {
                Write-Verbose "OU is set to $MachineObjectOU"
                Add-Content $unattendFile "                <MachineObjectOU>$MachineObjectOU</MachineObjectOU>"
            }
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        WORKGROUP
        {
            Write-Verbose "Configure unattend.xml for workgroup mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile "                <JoinWorkgroup>$JoinWorkgroup</JoinWorkgroup>"
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        Default
        {
            Write-Verbose "Epic Fail, exit..."
            Exit
        }
    }
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile "            <ComputerName>$ComputerName</ComputerName>"

    If($ProductKey -eq 'NONE')
    {
        Write-Verbose "No Productkey"
    }
    else
    {
        Write-Verbose "Adding Productkey $ProductKey"
        Add-Content $unattendFile "            <ProductKey>$ProductKey</ProductKey>"
    }
        Add-Content $unattendFile "            <RegisteredOrganization>$OrgName</RegisteredOrganization>"
        Add-Content $unattendFile "            <RegisteredOwner>$Fullname</RegisteredOwner>"
        Add-Content $unattendFile '            <DoNotCleanTaskBar>true</DoNotCleanTaskBar>'
        Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
        Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
        Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
        Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
        Add-Content $unattendFile '        </component>'
    if ($OSDAdapter0IPAddressList -contains "DHCP")
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for DHCP"
    }
    else
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for Static IP"
        Add-Content $unattendFile '        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <DNSServerSearchOrder>'
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0DNS1</IpAddress>"
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"2`">$OSDAdapter0DNS2</IpAddress>"
        Add-Content $unattendFile '                    </DNSServerSearchOrder>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <Ipv4Settings>'
        Add-Content $unattendFile '                        <DhcpEnabled>false</DhcpEnabled>'
        Add-Content $unattendFile '                    </Ipv4Settings>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                    <UnicastIpAddresses>'
        Add-Content $unattendFile "                       <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0IPAddressList/$OSDAdapter0SubnetMaskPrefix</IpAddress>"
        Add-Content $unattendFile '                    </UnicastIpAddresses>'
        Add-Content $unattendFile '                    <Routes>'
        Add-Content $unattendFile '                        <Route wcm:action="add">'
        Add-Content $unattendFile '                            <Identifier>0</Identifier>'
        Add-Content $unattendFile "                            <NextHopAddress>$OSDAdapter0Gateways</NextHopAddress>"
        Add-Content $unattendFile "                            <Prefix>0.0.0.0/0</Prefix>"
        Add-Content $unattendFile '                        </Route>'
        Add-Content $unattendFile '                    </Routes>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
    }
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '    <settings pass="oobeSystem">'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile '            <UserAccounts>'
    Add-Content $unattendFile '                <AdministratorPassword>'
    Add-Content $unattendFile "                    <Value>$AdminPassword</Value>"
    Add-Content $unattendFile '                    <PlainText>True</PlainText>'
    Add-Content $unattendFile '                </AdministratorPassword>'
    Add-Content $unattendFile '            </UserAccounts>'
    Add-Content $unattendFile '            <OOBE>'
    Add-Content $unattendFile '                <HideEULAPage>true</HideEULAPage>'
    Add-Content $unattendFile '                <NetworkLocation>Work</NetworkLocation>'
    Add-Content $unattendFile "                <ProtectYourPC>$ProtectYourPC</ProtectYourPC>"
    Add-Content $unattendFile '            </OOBE>'
    Add-Content $unattendFile "            <RegisteredOrganization>$Orgname</RegisteredOrganization>"
    Add-Content $unattendFile "            <RegisteredOwner>$FullName</RegisteredOwner>"
    Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
    Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
    Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
    Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '</unattend>'
    Return $unattendFile
}
Function New-VIAUnattendXMLClient
{
    <#
     ##################################################################################
     #  Script name: Create-UnattendXML.ps1
     #  Created:		2013-09-02
     #  version:		v1.0
     #  Author:      Mikael Nystrom
     #  Homepage:    http://deploymentbunny.com/
     ##################################################################################
 
     ##################################################################################
     #  Disclaimer:
     #  -----------
     #  This script is provided "AS IS" with no warranties, confers no rights and 
     #  is not supported by the authors or DeploymentBunny.
     ##################################################################################
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Computername,
    
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $OSDAdapter0IPAddressList,
    
        [parameter(mandatory=$false)]
        [ValidateSet("Domain","Workgroup")]
        $DomainOrWorkGroup,

        [parameter(mandatory=$false)]
        $ProductKey = 'NONE',

        [parameter(mandatory=$false)]
        $AdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $OrgName = "ViaMonstra",

        [parameter(mandatory=$false)]
        $Fullname = "ViaMonstra",

        [parameter(mandatory=$false)]
        $TimeZoneName = "Pacific Standard Time",

        [parameter(mandatory=$false)]
        $InputLocale = "en-US",

        [parameter(mandatory=$false)]
        $SystemLocale = "en-US",

        [parameter(mandatory=$false)]
        $UILanguage = "en-US",

        [parameter(mandatory=$false)]
        $UserLocale = "en-US",

        [parameter(mandatory=$false)]
        $OSDAdapter0Gateways = "192.168.1.1",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS1 = "192.168.1.200",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS2 = "192.168.1.201",

        [parameter(mandatory=$false)]
        $OSDAdapter0SubnetMaskPrefix = "24",

        [parameter(mandatory=$false)]
        $DNSDomain = "corp.viamonstra.com",

        [parameter(mandatory=$false)]
        $DomainNetBios = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $DomainAdmin = "Administrator",

        [parameter(mandatory=$false)]
        $DomainAdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $DomainAdminDomain = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $MachineObjectOU = "NA",

        [parameter(mandatory=$false)]
        $JoinWorkgroup = "WORKGROUP",

        [parameter(mandatory=$false)]
        [ValidateSet("1","2","3")]
        $ProtectYourPC = "3"
    )

    if((Test-Path -Path .\Unattend.xml) -eq $true)
    {
        Remove-Item -Path .\Unattend.xml
    }

    Write-Verbose "IP is $OSDAdapter0IPAddressList"
    $unattendFile = New-Item -Path "Unattend.xml" -type File
    Set-Content $unattendFile '<?xml version="1.0" encoding="utf-8"?>'
    Add-Content $unattendFile '<unattend xmlns="urn:schemas-microsoft-com:unattend">'
    Add-Content $unattendFile '    <settings pass="specialize">'
    
    Switch ($DomainOrWorkGroup){
        DOMAIN
        {
            Write-Verbose "Configure for domain mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile '                <Credentials>'
            Add-Content $unattendFile "                    <Username>$DomainAdmin</Username>"
            Add-Content $unattendFile "                    <Domain>$DomainAdminDomain</Domain>"
            Add-Content $unattendFile "                    <Password>$DomainAdminPassword</Password>"
            Add-Content $unattendFile '                </Credentials>'
            Add-Content $unattendFile "                <JoinDomain>$DNSDomain</JoinDomain>"
            If(!($MachineObjectOU -eq 'NA'))
            {
                Write-Verbose "OU is set to $MachineObjectOU"
                Add-Content $unattendFile "                <MachineObjectOU>$MachineObjectOU</MachineObjectOU>"
            }
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        WORKGROUP
        {
            Write-Verbose "Configure unattend.xml for workgroup mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile "                <JoinWorkgroup>$JoinWorkgroup</JoinWorkgroup>"
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        Default
        {
            Write-Verbose "Epic Fail, exit..."
            Exit
        }
    }
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile "            <ComputerName>$ComputerName</ComputerName>"

    If($ProductKey -eq 'NONE')
    {
        Write-Verbose "No Productkey"
    }
    else
    {
        Write-Verbose "Adding Productkey $ProductKey"
        Add-Content $unattendFile "            <ProductKey>$ProductKey</ProductKey>"
    }
        Add-Content $unattendFile "            <RegisteredOrganization>$OrgName</RegisteredOrganization>"
        Add-Content $unattendFile "            <RegisteredOwner>$Fullname</RegisteredOwner>"
        Add-Content $unattendFile '            <DoNotCleanTaskBar>true</DoNotCleanTaskBar>'
        Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <RunSynchronous>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>EnableAdmin</Description>'
        Add-Content $unattendFile '                    <Order>1</Order>'
        Add-Content $unattendFile '                    <Path>cmd /c net user Administrator /active:yes</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>UnfilterAdministratorToken</Description>'
        Add-Content $unattendFile '                    <Order>2</Order>'
        Add-Content $unattendFile '                    <Path>cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 0 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>disable user account page</Description>'
        Add-Content $unattendFile '                    <Order>3</Order>'
        Add-Content $unattendFile '                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\OOBE /v UnattendCreatedUser /t REG_DWORD /d 1 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>disable async RunOnce</Description>'
        Add-Content $unattendFile '                    <Order>4</Order>'
        Add-Content $unattendFile '                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer /v AsyncRunOnce /t REG_DWORD /d 0 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '            </RunSynchronous>'
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
        Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
        Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
        Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
        Add-Content $unattendFile '        </component>'
    if ($OSDAdapter0IPAddressList -contains "DHCP")
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for DHCP"
    }
    else
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for Static IP"
        Add-Content $unattendFile '        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <DNSServerSearchOrder>'
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0DNS1</IpAddress>"
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"2`">$OSDAdapter0DNS2</IpAddress>"
        Add-Content $unattendFile '                    </DNSServerSearchOrder>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <Ipv4Settings>'
        Add-Content $unattendFile '                        <DhcpEnabled>false</DhcpEnabled>'
        Add-Content $unattendFile '                    </Ipv4Settings>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                    <UnicastIpAddresses>'
        Add-Content $unattendFile "                       <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0IPAddressList/$OSDAdapter0SubnetMaskPrefix</IpAddress>"
        Add-Content $unattendFile '                    </UnicastIpAddresses>'
        Add-Content $unattendFile '                    <Routes>'
        Add-Content $unattendFile '                        <Route wcm:action="add">'
        Add-Content $unattendFile '                            <Identifier>0</Identifier>'
        Add-Content $unattendFile "                            <NextHopAddress>$OSDAdapter0Gateways</NextHopAddress>"
        Add-Content $unattendFile "                            <Prefix>0.0.0.0/0</Prefix>"
        Add-Content $unattendFile '                        </Route>'
        Add-Content $unattendFile '                    </Routes>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
    }
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '    <settings pass="oobeSystem">'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile '            <UserAccounts>'
    Add-Content $unattendFile '                <AdministratorPassword>'
    Add-Content $unattendFile "                    <Value>$AdminPassword</Value>"
    Add-Content $unattendFile '                    <PlainText>True</PlainText>'
    Add-Content $unattendFile '                </AdministratorPassword>'
    Add-Content $unattendFile '            </UserAccounts>'
    Add-Content $unattendFile '            <OOBE>'
    Add-Content $unattendFile '                <HideEULAPage>true</HideEULAPage>'
    Add-Content $unattendFile '                <HideLocalAccountScreen>true</HideLocalAccountScreen>'
    Add-Content $unattendFile '                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>'
    Add-Content $unattendFile '                <NetworkLocation>Work</NetworkLocation>'
    Add-Content $unattendFile "                <ProtectYourPC>$ProtectYourPC</ProtectYourPC>"
    Add-Content $unattendFile '            </OOBE>'
    Add-Content $unattendFile "            <RegisteredOrganization>$Orgname</RegisteredOrganization>"
    Add-Content $unattendFile "            <RegisteredOwner>$FullName</RegisteredOwner>"
    Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
    Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
    Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
    Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '</unattend>'
    Return $unattendFile
}
Function New-VIAUnattendXMLClientfor1709
{
    <#
     ##################################################################################
     #  Script name: Create-UnattendXML.ps1
     #  Created:		2013-09-02
     #  version:		v1.0
     #  Author:      Mikael Nystrom
     #  Homepage:    http://deploymentbunny.com/
     ##################################################################################
 
     ##################################################################################
     #  Disclaimer:
     #  -----------
     #  This script is provided "AS IS" with no warranties, confers no rights and 
     #  is not supported by the authors or DeploymentBunny.
     ##################################################################################
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $Computername,
    
        [parameter(mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $OSDAdapter0IPAddressList,
    
        [parameter(mandatory=$false)]
        [ValidateSet("Domain","Workgroup")]
        $DomainOrWorkGroup,

        [parameter(mandatory=$false)]
        $ProductKey = 'NONE',

        [parameter(mandatory=$false)]
        $AdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $OrgName = "ViaMonstra",

        [parameter(mandatory=$false)]
        $Fullname = "ViaMonstra",

        [parameter(mandatory=$false)]
        $TimeZoneName = "Pacific Standard Time",

        [parameter(mandatory=$false)]
        $InputLocale = "en-US",

        [parameter(mandatory=$false)]
        $SystemLocale = "en-US",

        [parameter(mandatory=$false)]
        $UILanguage = "en-US",

        [parameter(mandatory=$false)]
        $UserLocale = "en-US",

        [parameter(mandatory=$false)]
        $OSDAdapter0Gateways = "192.168.1.1",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS1 = "192.168.1.200",

        [parameter(mandatory=$false)]
        $OSDAdapter0DNS2 = "192.168.1.201",

        [parameter(mandatory=$false)]
        $OSDAdapter0SubnetMaskPrefix = "24",

        [parameter(mandatory=$false)]
        $DNSDomain = "corp.viamonstra.com",

        [parameter(mandatory=$false)]
        $DomainNetBios = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $DomainAdmin = "Administrator",

        [parameter(mandatory=$false)]
        $DomainAdminPassword = "P@ssw0rd",

        [parameter(mandatory=$false)]
        $DomainAdminDomain = "VIAMONSTRA",

        [parameter(mandatory=$false)]
        $MachineObjectOU = "NA",

        [parameter(mandatory=$false)]
        $JoinWorkgroup = "WORKGROUP",

        [parameter(mandatory=$false)]
        [ValidateSet("1","2","3")]
        $ProtectYourPC = "3"
    )

    if((Test-Path -Path .\Unattend.xml) -eq $true)
    {
        Remove-Item -Path .\Unattend.xml
    }

    Write-Verbose "IP is $OSDAdapter0IPAddressList"
    $unattendFile = New-Item -Path "Unattend.xml" -type File
    Set-Content $unattendFile '<?xml version="1.0" encoding="utf-8"?>'
    Add-Content $unattendFile '<unattend xmlns="urn:schemas-microsoft-com:unattend">'
    Add-Content $unattendFile '    <settings pass="specialize">'
    
    Switch ($DomainOrWorkGroup){
        DOMAIN
        {
            Write-Verbose "Configure for domain mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile '                <Credentials>'
            Add-Content $unattendFile "                    <Username>$DomainAdmin</Username>"
            Add-Content $unattendFile "                    <Domain>$DomainAdminDomain</Domain>"
            Add-Content $unattendFile "                    <Password>$DomainAdminPassword</Password>"
            Add-Content $unattendFile '                </Credentials>'
            Add-Content $unattendFile "                <JoinDomain>$DNSDomain</JoinDomain>"
            If(!($MachineObjectOU -eq 'NA'))
            {
                Write-Verbose "OU is set to $MachineObjectOU"
                Add-Content $unattendFile "                <MachineObjectOU>$MachineObjectOU</MachineObjectOU>"
            }
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        WORKGROUP
        {
            Write-Verbose "Configure unattend.xml for workgroup mode"
            Add-Content $unattendFile '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
            Add-Content $unattendFile '            <Identification>'
            Add-Content $unattendFile "                <JoinWorkgroup>$JoinWorkgroup</JoinWorkgroup>"
            Add-Content $unattendFile '            </Identification>'
            Add-Content $unattendFile '        </component>'
        }
        Default
        {
            Write-Verbose "Epic Fail, exit..."
            Exit
        }
    }
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile "            <ComputerName>$ComputerName</ComputerName>"

    If($ProductKey -eq 'NONE')
    {
        Write-Verbose "No Productkey"
    }
    else
    {
        Write-Verbose "Adding Productkey $ProductKey"
        Add-Content $unattendFile "            <ProductKey>$ProductKey</ProductKey>"
    }
        Add-Content $unattendFile "            <RegisteredOrganization>$OrgName</RegisteredOrganization>"
        Add-Content $unattendFile "            <RegisteredOwner>$Fullname</RegisteredOwner>"
        Add-Content $unattendFile '            <DoNotCleanTaskBar>true</DoNotCleanTaskBar>'
        Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <RunSynchronous>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>EnableAdmin</Description>'
        Add-Content $unattendFile '                    <Order>1</Order>'
        Add-Content $unattendFile '                    <Path>cmd /c net user Administrator /active:yes</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>UnfilterAdministratorToken</Description>'
        Add-Content $unattendFile '                    <Order>2</Order>'
        Add-Content $unattendFile '                    <Path>cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 0 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>disable user account page</Description>'
        Add-Content $unattendFile '                    <Order>3</Order>'
        Add-Content $unattendFile '                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Setup\OOBE /v UnattendCreatedUser /t REG_DWORD /d 1 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '                <RunSynchronousCommand wcm:action="add">'
        Add-Content $unattendFile '                    <Description>disable async RunOnce</Description>'
        Add-Content $unattendFile '                    <Order>4</Order>'
        Add-Content $unattendFile '                    <Path>reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer /v AsyncRunOnce /t REG_DWORD /d 0 /f</Path>'
        Add-Content $unattendFile '                </RunSynchronousCommand>'
        Add-Content $unattendFile '            </RunSynchronous>'
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
        Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
        Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
        Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
        Add-Content $unattendFile '        </component>'
    if ($OSDAdapter0IPAddressList -contains "DHCP")
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for DHCP"
    }
    else
    {
        Write-Verbose "IP is $OSDAdapter0IPAddressList so we prep for Static IP"
        Add-Content $unattendFile '        <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <DNSServerSearchOrder>'
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0DNS1</IpAddress>"
        Add-Content $unattendFile "                        <IpAddress wcm:action=`"add`" wcm:keyValue=`"2`">$OSDAdapter0DNS2</IpAddress>"
        Add-Content $unattendFile '                    </DNSServerSearchOrder>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
        Add-Content $unattendFile '        <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        Add-Content $unattendFile '            <Interfaces>'
        Add-Content $unattendFile '                <Interface wcm:action="add">'
        Add-Content $unattendFile '                    <Ipv4Settings>'
        Add-Content $unattendFile '                        <DhcpEnabled>false</DhcpEnabled>'
        Add-Content $unattendFile '                    </Ipv4Settings>'
        Add-Content $unattendFile '                    <Identifier>Ethernet</Identifier>'
        Add-Content $unattendFile '                    <UnicastIpAddresses>'
        Add-Content $unattendFile "                       <IpAddress wcm:action=`"add`" wcm:keyValue=`"1`">$OSDAdapter0IPAddressList/$OSDAdapter0SubnetMaskPrefix</IpAddress>"
        Add-Content $unattendFile '                    </UnicastIpAddresses>'
        Add-Content $unattendFile '                    <Routes>'
        Add-Content $unattendFile '                        <Route wcm:action="add">'
        Add-Content $unattendFile '                            <Identifier>0</Identifier>'
        Add-Content $unattendFile "                            <NextHopAddress>$OSDAdapter0Gateways</NextHopAddress>"
        Add-Content $unattendFile "                            <Prefix>0.0.0.0/0</Prefix>"
        Add-Content $unattendFile '                        </Route>'
        Add-Content $unattendFile '                    </Routes>'
        Add-Content $unattendFile '                </Interface>'
        Add-Content $unattendFile '            </Interfaces>'
        Add-Content $unattendFile '        </component>'
    }
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '    <settings pass="oobeSystem">'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'
    Add-Content $unattendFile '            <UserAccounts>'
    Add-Content $unattendFile '                <AdministratorPassword>'
    Add-Content $unattendFile "                    <Value>$AdminPassword</Value>"
    Add-Content $unattendFile '                    <PlainText>True</PlainText>'
    Add-Content $unattendFile '                </AdministratorPassword>'
    Add-Content $unattendFile '            </UserAccounts>'
    Add-Content $unattendFile '            <AutoLogon>'
    Add-Content $unattendFile '             <Enabled>true</Enabled>'
    Add-Content $unattendFile '             <Username>Administrator</Username>'
    Add-Content $unattendFile '             <Domain>.</Domain>'
    Add-Content $unattendFile '             <Password>'
    Add-Content $unattendFile "              <Value>$AdminPassword</Value>"
    Add-Content $unattendFile '              <PlainText>true</PlainText>'
    Add-Content $unattendFile '             </Password>'
    Add-Content $unattendFile '             <LogonCount>1</LogonCount>'
    Add-Content $unattendFile '            </AutoLogon>'
    Add-Content $unattendFile '            <OOBE>'
    Add-Content $unattendFile '                <HideEULAPage>true</HideEULAPage>'
    Add-Content $unattendFile '                <HideLocalAccountScreen>true</HideLocalAccountScreen>'
    Add-Content $unattendFile '                <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>'
    Add-Content $unattendFile '                <HideOnlineAccountScreens>true</HideOnlineAccountScreens>'
    Add-Content $unattendFile '                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>'
    Add-Content $unattendFile "                <ProtectYourPC>$ProtectYourPC</ProtectYourPC>"
    Add-Content $unattendFile '            </OOBE>'
    Add-Content $unattendFile "            <RegisteredOrganization>$Orgname</RegisteredOrganization>"
    Add-Content $unattendFile "            <RegisteredOwner>$FullName</RegisteredOwner>"
    Add-Content $unattendFile "            <TimeZone>$TimeZoneName</TimeZone>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    Add-Content $unattendFile "            <InputLocale>$InputLocale</InputLocale>"
    Add-Content $unattendFile "            <SystemLocale>$SystemLocale</SystemLocale>"
    Add-Content $unattendFile "            <UILanguage>$UILanguage</UILanguage>"
    Add-Content $unattendFile "            <UserLocale>$UserLocale</UserLocale>"
    Add-Content $unattendFile '        </component>'
    Add-Content $unattendFile '    </settings>'
    Add-Content $unattendFile '</unattend>'
    Return $unattendFile
}
Function New-VIASetupCompletecmd
{
<#
.Synopsis
   Short description
.DESCRIPTION
   Long description
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
#>
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $Command
    )

    if((Test-Path -Path .\SetupComplete.cmd) -eq $true)
    {
        Remove-Item -Path .\SetupComplete.cmd
    }

    $unattendFile = New-Item -Path "SetupComplete.cmd" -type File
    Set-Content $unattendFile '@Echo off'
    Add-Content $unattendFile "$Command"
    Return $unattendFile
}
Function New-VIAISOImage
{
    Param(
    $SourceFolder,
    $Destinationfile
    )
    $Arguments = "-u2 ""$SourceFolder"" ""$Destinationfile"""
    Invoke-VIAExe -Executable 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe' -Arguments $Arguments
}
