Function Get-TSxTest
{
    Return "OK"
}

Function Get-VIAOSVersion([ref]$OSv)
{
    $OS = Get-WmiObject -Class Win32_OperatingSystem | Select *
    Switch -Regex ($OS.Version)
    {
    "6.1"
        {If($OS.ProductType -eq 1)
            {$OSv.value = "Windows 7 SP1"}
                Else
            {$OSv.value = "Windows Server 2008 R2"}
        }
    "6.2"
        {If($OS.ProductType -eq 1)
            {$OSv.value = "Windows 8"}
                Else
            {$OSv.value = "Windows Server 2012"}
        }
    "6.3"
        {If($OS.ProductType -eq 1)
            {$OSv.value = "Windows 8.1"}
                Else
            {$OSv.value = "Windows Server 2012 R2"}
        }
    "10.0.14"
        {If($OS.ProductType -eq 1)
            {$OSv.value = "Windows 10 1607"}
                Else
            {$OSv.value = "Windows Server 2016"}
        }
    "10.0.17"
        {If($OS.ProductType -eq 1)
            {$OSv.value = "Windows 10 1809"}
                Else
            {$OSv.value = "Windows Server 2019"}
        }
    DEFAULT { "Version not listed" }
    } 
}
Function Get-OSSKU
{
    $Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels\'
    if(Test-Path -Path $Path)
    {
        $Test = Get-ItemProperty -Path $Path
        if(($Test.'ServerCore' -eq 1) -and ($Test.'Server-Gui-Shell' -eq 1)){$OSSKU = "DesktopExperience"}
        if(($Test.'ServerCore' -eq 1) -and ($Test.'Server-Gui-Shell' -ne 1)){$OSSKU = "Core"}
        Return $OSSKU
    }
    else
    {
        Return "Unknown"
    }
}
Function Invoke-VIAExe
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    param(
        [parameter(mandatory=$true,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Executable,

        [parameter(mandatory=$false,position=1)]
        [string]
        $Arguments
    )

    if($Arguments -eq "")
    {
        Write-Verbose "Running Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru"
        $ReturnFromEXE = Start-Process -FilePath $Executable -NoNewWindow -Wait -Passthru
    }else{
        Write-Verbose "Running Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru"
        $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru
    }
    Write-Verbose "Returncode is $($ReturnFromEXE.ExitCode)"
    Return $ReturnFromEXE.ExitCode
}
Function Start-Log
{
[CmdletBinding()]
    param (
    [ValidateScript({ Split-Path $_ -Parent | Test-Path })]
               [string]$FilePath
    )
               
    try
    {
        if (!(Test-Path $FilePath))
               {
                   ## Create the log file
                   New-Item $FilePath -Type File | Out-Null
               }
                              
               ## Set the global variable to be used as the FilePath for all subsequent Write-Log
               ## calls in this session
               $global:ScriptLogFilePath = $FilePath
    }
    catch
    {
        Write-Error $_.Exception.Message
    }
}
Function Write-Log
{
               param (
                              [Parameter(Mandatory = $true)]
                              [string]$Message,
                                             
                              [Parameter()]
                              [ValidateSet(1, 2, 3)]
                              [string]$LogLevel = 1
               )

    $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
    #$LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf)", $LogLevel
    $Line = $Line -f $LineFormat
    Add-Content -Value $Line -Path $ScriptLogFilePath

    if($writetoscreen -eq $true){
        switch ($LogLevel)
        {
            '1'{
                Write-Host $Message -ForegroundColor Gray
                }
            '2'{
                Write-Host $Message -ForegroundColor Yellow
                }
            '3'{
                Write-Host $Message -ForegroundColor Red
                }
            Default {}
        }
    }
}
Function Set-OSCVirtualMemory
{
<#
 	.SYNOPSIS
        Set-OSCVirtualMemory is an advanced function which can be used to adjust virtual memory page file size.
    .DESCRIPTION
        Set-OSCVirtualMemory is an advanced function which can be used to adjust virtual memory page file size.
    .PARAMETER  <InitialSize>
		Setting the paging file's initial size.
	.PARAMETER  <MaximumSize>
		Setting the paging file's maximum size.
	.PARAMETER  <DriveLetter>
		Specifies the drive letter you want to configure.
	.PARAMETER  <SystemManagedSize>
		Allow Windows to manage page files on this computer.
	.PARAMETER  <None>		
		Disable page files setting.
	.PARAMETER  <Reboot>		
		Reboot the computer so that configuration changes take effect.
	.PARAMETER  <AutoConfigure>
		Automatically configure the initial size and maximumsize.
    .EXAMPLE
        C:\PS> Set-OSCVirtualMemory -InitialSize 1024 -MaximumSize 2048 -DriveLetter "C:","D:"

		Execution Results: Set page file size on "C:" successful.
		Execution Results: Set page file size on "D:" successful.

		Name            InitialSize(MB) MaximumSize(MB)
		----            --------------- ---------------
		C:\pagefile.sys            1024            2048
		D:\pagefile.sys            1024            2048
		E:\pagefile.sys            2048            2048
	.LINK
		Get-WmiObject
		http://technet.microsoft.com/library/hh849824.aspx
#>
	[cmdletbinding(SupportsShouldProcess=$true,DefaultParameterSetName="SetPageFileSize")]
	Param
	(
		[Parameter(Mandatory=$true,Position=0,ParameterSetName="SetPageFileSize")]
		[Alias('is')]
		[Int32]$InitialSize,
		[Parameter(Mandatory=$true,Position=1,ParameterSetName="SetPageFileSize")]
		[Alias('ms')]
		[Int32]$MaximumSize,
		[Parameter(Mandatory=$true,Position=2)]
		[Alias('dl')]
		[String[]]$DriveLetter,
		[Parameter(Mandatory=$true,Position=3,ParameterSetName="None")]
		[Switch]$None,
		[Parameter(Mandatory=$true,Position=4,ParameterSetName="SystemManagedSize")]
		[Switch]$SystemManagedSize,
		[Parameter(Mandatory=$false,Position=5)]
		[Switch]$Reboot,
		[Parameter(Mandatory=$true,Position=6,ParameterSetName="AutoConfigure")]
		[Alias('auto')]
		[Switch]$AutoConfigure
	)
	
	If($PSCmdlet.ShouldProcess("Setting the virtual memory page file size"))
	{
		Foreach($DL in $DriveLetter)
		{		
			If($None)
			{
				$PageFile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name='$DL\\pagefile.sys'" -EnableAllPrivileges
				If($PageFile -ne $null)
				{
					$PageFile.Delete()
				}
				Else
				{
					Write-Warning """$DL"" is already set None!"
				}
			}
			ElseIf($SystemManagedSize)
			{
				$InitialSize = 0
				$MaximumSize = 0
				
				Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
			}						
			ElseIf($AutoConfigure)
			{
				$InitialSize = 0
				$MaximumSize = 0
				
				#Getting total physical memory size
				Get-WmiObject -Class Win32_PhysicalMemory | Where-Object{$_.DeviceLocator -ne "SYSTEM ROM"} | `
				ForEach-Object{$TotalPhysicalMemorySize += [Double]($_.Capacity)/1GB}
				
				<#
				By default, the minimum size on a 32-bit (x86) system is 1.5 times the amount of physical RAM if physical RAM is less than 1 GB, 
				and equal to the amount of physical RAM plus 300 MB if 1 GB or more is installed. The default maximum size is three times the amount of RAM, 
				regardless of how much physical RAM is installed. 
				#>
				If($TotalPhysicalMemorySize -lt 1)
				{
					$InitialSize = 1.5*1024
					$MaximumSize = 1024*3
					Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
				}
				Else
				{
					$InitialSize = 1024+300
					$MaximumSize = 1024*3
					Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
				}
			}
			Else
			{
				Set-PageFileSize -DL $DL -InitialSize $InitialSize -MaximumSize $MaximumSize
			}
			
			If($Reboot)
			{
				Restart-Computer -ComputerName $Env:COMPUTERNAME -Force
			}
		}
		
		#get current page file size information
		Get-WmiObject -Class Win32_PageFileSetting -EnableAllPrivileges|Select-Object Name, `
		@{Name="InitialSize(MB)";Expression={if($_.InitialSize -eq 0){"System Managed"}else{$_.InitialSize}}}, `
		@{Name="MaximumSize(MB)";Expression={if($_.MaximumSize -eq 0){"System Managed"}else{$_.MaximumSize}}}| `
		Format-Table -AutoSize
	}
}
Function Set-PageFileSize
{
	Param($DL,$InitialSize,$MaximumSize)
	
	#The AutomaticManagedPagefile property determines whether the system managed pagefile is enabled. 
	#This capability is not available on windows server 2003,XP and lower versions.
	#Only if it is NOT managed by the system and will also allow you to change these.
	$IsAutomaticManagedPagefile = Get-WmiObject -Class Win32_ComputerSystem |Foreach-Object{$_.AutomaticManagedPagefile}
	If($IsAutomaticManagedPagefile)
	{
		#We must enable all the privileges of the current user before the command makes the WMI call.
		$SystemInfo=Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
		$SystemInfo.AutomaticManagedPageFile = $false
		[Void]$SystemInfo.Put()
	}
	
	Write-Verbose "Setting pagefile on $DL"
	
	#configuring the page file size
	$PageFile = Get-WmiObject -Class Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $DL'"
	
	Try
	{
		If($PageFile -ne $null)
		{
			$PageFile.Delete()
		}
			Set-WmiInstance -Class Win32_PageFileSetting -Arguments @{name="$DL\pagefile.sys"; InitialSize = 0; MaximumSize = 0} `
			-EnableAllPrivileges |Out-Null
			
			$PageFile = Get-WmiObject Win32_PageFileSetting -Filter "SettingID='pagefile.sys @ $DL'"
			
			$PageFile.InitialSize = $InitialSize
			$PageFile.MaximumSize = $MaximumSize
			[Void]$PageFile.Put()
			
			Write-Host  "Execution Results: Set page file size on ""$DL"" successful."
			Write-Warning "Pagefile configuration changed on computer '$Env:COMPUTERNAME'. The computer must be restarted for the changes to take effect."
	}
	Catch
	{
		Write-Host "Execution Results: No Permission - Failed to set page file size on ""$DL"""
	}
}