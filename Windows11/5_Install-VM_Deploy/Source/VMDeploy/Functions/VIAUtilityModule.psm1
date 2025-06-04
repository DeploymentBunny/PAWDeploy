<#
.Synopsis
   VIAUtility.psm1
.DESCRIPTION
   VIAUtility.psm1
.EXAMPLE
   Example of how to use this cmdlet
#>

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

