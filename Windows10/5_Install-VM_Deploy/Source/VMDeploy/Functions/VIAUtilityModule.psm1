<#
.Synopsis
   VIAUtility.psm1
.DESCRIPTION
   VIAUtility.psm1
.EXAMPLE
   Example of how to use this cmdlet
#>

function Convert-VIADStoFQDN
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    
    param(
        [parameter(mandatory=$true,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DS
    )
    (($DS.replace("dc=",".")).replace(",","")).substring(1)
}
function Convert-VIAFQDNtoDS
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    
    param(
        [parameter(mandatory=$true,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FQDN
    )
    "dc=" + ($FQDN.replace(".",",dc="))
}
Function Invoke-VIAExe
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    param(
        [parameter(mandatory=$true,position=0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Executable,

        [parameter(mandatory=$true,position=1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Arguments,

        [parameter(mandatory=$false,position=2)]
        [ValidateNotNullOrEmpty()]
        [int]
        $SuccessfulReturnCode = 0
    )

    Write-Verbose "Running $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru"
    $ReturnFromEXE = Start-Process -FilePath $Executable -ArgumentList $Arguments -NoNewWindow -Wait -Passthru

    Write-Verbose "Returncode is $($ReturnFromEXE.ExitCode)"

    if(!($ReturnFromEXE.ExitCode -eq $SuccessfulReturnCode)) {
        throw "$Executable failed with code $($ReturnFromEXE.ExitCode)"
    }
}
Function Convert-Subnet
{
    <#
    .SYNOPSIS
    Converts between PrefixLength and subnet mask. 


    .DESCRIPTION
    This script converts between PrefixLength and subnet mask parameters, these parameters define the size of a subnet for IPv4 addresses.  
    This script assumes valid subnet mask input and does not support scenarios such as non-contiguous subnet masks. 


    .INPUTS
    None

    .OUTPUTS
    The script outputs a PrefixLength if SubnetMask was entered, or a SubnetMask if a PrefixLength was entered.

    .NOTES
    Requires Windows 8 or later.

    #>

    [CmdletBinding(SupportsShouldProcess=$true)]

    Param( 
        [Parameter(ParameterSetName="SubnetMask",Mandatory=$True)]
        [string]
        $SubnetMask, 
        
        [Parameter(ParameterSetName="PrefixLength",Mandatory=$True)]
        [int]
        $PrefixLength
    )

    ####################################
    #User provided a prefix
    if ($PrefixLength)
    {
        $PrefixLengthReturn = $PrefixLength
        if ($PrefixLength -gt 32) 
        { 
            Write-Warning "Invalid input, prefix length must be less than 32"
            exit(1)
        }
               
        $bitArray=""
        for($bitCount = 0; $PrefixLength -ne "0"; $bitCount++) 
        {
            $bitArray += '1'
            $PrefixLength = $PrefixLength - 1;
        }
    
        ####################################                       
        #Fill in the rest with zeroes
        While ($bitCount -ne 32) 
        {
            $bitArray += '0'
            $bitCount++ 
        }
        ####################################
        #Convert the bit array into subnet mask
        $ClassAAddress = $bitArray.SubString(0,8)
        $ClassAAddress = [Convert]::ToUInt32($ClassAAddress, 2)
        $ClassBAddress = $bitArray.SubString(8,8)
        $ClassBAddress = [Convert]::ToUInt32($ClassBAddress, 2)
        $ClassCAddress = $bitArray.SubString(16,8)
        $ClassCAddress = [Convert]::ToUInt32($ClassCAddress, 2)
        $ClassDAddress = $bitArray.SubString(24,8)           
        $ClassDAddress = [Convert]::ToUInt32($ClassDAddress, 2)
 
        $SubnetMaskReturn =  "$ClassAAddress.$ClassBAddress.$ClassCAddress.$ClassDAddress"
    }

    ####################################
    ##User provided a subnet mask
    if ($SubnetMask)
    {
	    ####################################
        #Ensure valid IP address input.  Note this does not check for non-contiguous subnet masks!
        $Address=[System.Net.IPaddress]"0.0.0.0"
        Try
        {
            $IsValidInput=[System.Net.IPaddress]::TryParse($SubnetMask, [ref]$Address)
        }
        Catch 
        {

        }
        Finally
        {

        }    

        if ($IsValidInput -eq $False)
        {
            Write-Warning "Invalid Input. Please enter a properly formatted subnet mask."
            Exit(1)
        }

        ####################################
        #Convert subnet mask to prefix length
        If($IsValidInput)
        {
            $PrefixArray=@()
            $PrefixLength = 0
            $ByteArray = $SubnetMask.Split(".")
        
            ####################################        
            #This loop converts the bytes to bits, add zeroes when necessary
            for($byteCount = 0; $byteCount-lt 4; $byteCount++) 
            {
                $bitVariable = $ByteArray[$byteCount]
                $bitVariable = [Convert]::ToString($bitVariable, 2)
            
                if($bitVariable.Length -lt 8)
                {
                  $NumOnes=$bitVariable.Length
                  $NumZeroes=8-$bitVariable.Length

                  for($bitCount=0; $bitCount -lt $NumZeroes; $bitCount++) 
                  {
                    $Temp=$Temp+"0"
                  }
              
                  $bitVariable=$Temp+$bitVariable
                }
            
                ####################################
                #This loop counts the bits in the prefix
                for($bitCount=0; $bitCount -lt 8; $bitCount++) 
                {
                    if ($bitVariable[$bitCount] -eq "1")
                    {
                        $PrefixLength++ 
                    }

                    $PrefixArray=$PrefixArray + ($bitVariable[$bitCount])

                }
            }
        
            ####################################
            #Check if the subnet mask was contiguous, fail if it wasn't.
            $Mark=$False

            foreach ($bit in $PrefixArray) 
            {
                if($bit -eq "0")
                {
                    if($Mark -eq $False)
                    {
                        $Mark=$True
                    }
                }
                if($bit -eq "1")
                {
                    if($Mark -eq $True)
                    {
                        Write-Warning "Invalid Input. Please enter a properly formatted subnet mask."
                        Exit(1)
                    }    
                }
                
            }

	        $SubnetMaskReturn = $SubnetMask
	        $PrefixLengthReturn = $PrefixLength
	    }
    }
    ##Create the object to be returned to the console
    $Return = new-object Object
    Add-Member -InputObject $Return -Name PrefixLength -Value $PrefixLengthReturn -Type NoteProperty
    Add-Member -InputObject $Return -Name SubnetMask -Value  $SubnetMaskReturn -Type NoteProperty
    $Return
}
Function Compress-VIADeDupDrive
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        $DriveLetter
    )
    Foreach($Item in $DriveLetter){
        $Drive = $DriveLetter + ":"
        Start-DedupJob $Drive -Type Optimization -Priority High -Memory 75 -Wait
        Start-DedupJob $Drive -Type GarbageCollection -Priority High -Memory 75 -Wait
        Start-DedupJob $Drive -Type Scrubbing -Priority High -Memory 75 -Wait
    }
}
Function Enable-VIACredSSP
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        $Connection
    )

    #Enable CredSSP on Client
    Enable-WSManCredSSP -Role Client -DelegateComputer $Connection -Force -ErrorAction Stop
    Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $true -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force -Concatenate
}
Function Get-VIAOSVersion
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
    )
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $OSversion = [System.Environment]::OSVersion.Version
    $OSversionComplete = "$($version.major).$($version.Minor).$($version.build)"
    $OSversionMajorMinor = "$($version.major).$($version.Minor)"
    $OSversionMajor = "$($version.major).$($version.Minor)"


    Switch ($OSversionMajor)
    {
    "6.1"
    {
        If($OS.ProductType -eq 1){$OSv = "W7"}Else{$OSv = "WS2008R2"}
    }
    "6.2"
    {
        If($OS.ProductType -eq 1){$OSv = "W8"}Else{$OSv = "WS2012"}
    }
    "6.3"
    {
        If($OS.ProductType -eq 1){$OSv = "W81"}Else{$OSv = "WS2012R2"}
    }
    "10.0"
    {
        If($OS.ProductType -eq 1){$OSv = "W10"}Else{$OSv = "WS2016"}
    }
        DEFAULT {$OSv="Unknown"}
    } 
    Return $OSV
}
Function Install-VIASNMP
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
            $ComputerName
    )
    Foreach($Item in $ComputerName){
        Invoke-Command -ComputerName $Item -ScriptBlock {
            Add-WindowsFeature -Name SNMP-Service -IncludeAllSubFeature -IncludeManagementTools
        }
    }
}
Function Install-VIADCB
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
        $ComputerName
    )
    Foreach($Item in $ComputerName){
        Invoke-Command -ComputerName $Item -ScriptBlock {
            Add-WindowsFeature -Name Data-Center-Bridging -IncludeAllSubFeature -IncludeManagementTools
        }
    }
}
Function Restart-VIAComputer
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
        $ComputerName
    )
    Foreach($Item in $ComputerName){
        Restart-Computer -ComputerName $ComputerName -Force -AsJob
    }
}
Function Show-VIAText
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
        $Text,
        $Color
    )
    
    Write-Host $Text -ForegroundColor $Color
}
Function New-VIARandomPassword
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
        [int]$PasswordLength,
        [boolean]$Complex
    )

    #Characters to use based
    $strSimple = "A","B","C","D","E","F","G","H","J","K","L","M","N","P","Q","R","S","T","U","V","W","X","Y","Z","1","2","3","4","5","6","7","8","9","0","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z” 
    $strComplex = "A","B","C","D","E","F","G","H","J","K","L","M","N","P","Q","R","S","T","U","V","W","X","Y","Z","1","2","3","4","5","6","7","8","9","0","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z”,"!","_" 
    $strNumbers = "2","3","4","5","6","7","8","9","0"
     
    #Check to see if password contains at least 1 digit
    $bolHasNumber = $false
    $pass = $null
     
    #Sets which Character Array to use based on $Complex
    if ($Complex){$strCharacters = $strComplex}else{$strCharacters = $strSimple}
   
    #Loop to actually generate the password
    for ($i=0;$i -lt $PasswordLength; $i++){$c = Get-Random -InputObject $strCharacters
     if ([char]::IsDigit($c)){$bolHasNumber = $true}$pass += $c}
    
    #Check to see if a Digit was seen, if not, fixit
    if ($bolHasNumber)
        {
            return $pass
        }
        else
        {
            $pos = Get-Random -Maximum $PasswordLength
            $n = Get-Random -InputObject $strNumbers
            $pwArray = $pass.ToCharArray()
            $pwArray[$pos] = $n
            $pass = ""
            foreach ($s in $pwArray)
            {
                $pass += $s
            }
        return $pass
    }
}
Function Update-VIALog
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
    [Parameter(
        Mandatory=$true, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0
    )]
    [string]$Data,

    [Parameter(
        Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0
    )]
    [string]$Solution = $Solution,

    [Parameter(
        Mandatory=$false, 
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1
    )]
    [validateset('Information','Warning','Error')]
    [string]$Class = "Information"

    )
    $LogString = "$Solution, $Data, $Class, $(Get-Date)"
    $HostString = "$Solution, $Data, $(Get-Date)"
    
    Add-Content -Path $LogPath -Value $LogString
    switch ($Class)
    {
        'Information'{
            Write-Host $HostString -ForegroundColor Gray
            }
        'Warning'{
            Write-Host $HostString -ForegroundColor Yellow
            }
        'Error'{
            Write-Host $HostString -ForegroundColor Red
            }
        Default {}
    }
}
Function Suspend-VIAScript
{
    [CmdletBinding(SupportsShouldProcess=$true)]

    Param(
        $Message = "Press any key to continue . . . "
    )

    If ($psISE) {
        # The "ReadKey" functionality is not supported in Windows PowerShell ISE.
        $Shell = New-Object -ComObject "WScript.Shell"
        $Button = $Shell.Popup("Click OK to continue.", 0, "Script Paused", 0)
        Return
    }
 
    Write-Host -NoNewline $Message
    $Ignore =
        16,  # Shift (left or right)
        17,  # Ctrl (left or right)
        18,  # Alt (left or right)
        20,  # Caps lock
        91,  # Windows key (left)
        92,  # Windows key (right)
        93,  # Menu key
        144, # Num lock
        145, # Scroll lock
        166, # Back
        167, # Forward
        168, # Refresh
        169, # Stop
        170, # Search
        171, # Favorites
        172, # Start/Home
        173, # Mute
        174, # Volume Down
        175, # Volume Up
        176, # Next Track
        177, # Previous Track
        178, # Stop Media
        179, # Play
        180, # Mail
        181, # Select Media
        182, # Application 1
        183  # Application 2
 
    While ($KeyInfo.VirtualKeyCode -Eq $Null -Or $Ignore -Contains $KeyInfo.VirtualKeyCode) {
        $KeyInfo = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown")
    }
 
    Write-Host
}
Function Clear-VIAVolume
{
    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
        $VolumeLabel
    )
    Get-Volume -FileSystemLabel $VolumeLabel -ErrorAction SilentlyContinue| Get-Partition | Get-Disk | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
}
Function Start-VIASoundNotify
{

    [cmdletbinding(SupportsShouldProcess=$True)]

    Param(
    )

    $sound = new-Object System.Media.SoundPlayer;
    $sound.SoundLocation="c:\WINDOWS\Media\notify.wav";
    $sound.Play();
}
Function Wait-VIAServiceToRun
{
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param(
        $ServiceName = 'LanmanWorkstation',
        $VMname,
        $Credentials
    )
    Write-Verbose "Waiting for $ServiceName to start on $VMname"
    Invoke-Command -VMName $VMname -ScriptBlock {
        Param($ServiceName)
        do{
            Write-Verbose "Waiting for $ServiceName to start"
            Get-Service -Name $ServiceName
        }until((Get-Service -Name $ServiceName).Status -eq 'Running' )
    } -Credential $Credentials -ArgumentList $ServiceName
}

