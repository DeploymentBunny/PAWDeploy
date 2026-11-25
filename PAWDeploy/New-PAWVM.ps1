<#
.SYNOPSIS
    Deploys a Privileged Access Workstation (PAW) as a Hyper-V virtual machine.

.DESCRIPTION
    New-PAWVM.ps1 automates the end-to-end provisioning of a PAW VM on a Hyper-V host.
    Optional application/download, encryption, RunScript, shielding, baseline and
    shortcut failures are warned/logged and summarized without aborting subsequent
    stages. A completed run with such failures is not verified as fully hardened.
    VM creation, required guest readiness and secret-cleanup failures still abort;
    failure cleanup retains the VM and its disks.
    The script performs the following steps in order:

      1. Reads deployment settings from Config.json (customer data and Hyper-V defaults)
          and template definitions from JSON files in the Templates folder.

     2. Builds dynamic parameters at runtime:
         - Template values from Config\*.json (excluding Config.json).
         - VMSwitchName values from available Hyper-V switches (when discoverable).
         Resolves remaining parameters and prompts interactively for any required
         credentials (local Administrator password and, for domain-joined VMs, domain
         administrator credentials) that were not supplied on the command line.

     3. Creates the VM folder structure and the Hyper-V virtual machine via New-PAWHyperVVM.

     4. Mounts the template VHDX and injects:
         - A Windows unattend.xml (generated for Client or Server OS classes).
         - A SetupComplete.cmd that signals OS deployment completion via a KVP registry key.
         - An optional extra folder (user-supplied scripts/data).
         - Security baseline files (copied from SecurityBaselineLocation in the template).
         During staging, the script requires clean Panther and Setup\Scripts paths in the
         offline image to avoid reusing stale deployment artifacts.

     5. Dismounts the VHDX and starts the VM.

     6. Waits for the VM to be fully operational (Integration Components, IP address,
         PowerShell Direct connectivity, and KVP deployment-done marker).

     7. Through PowerShell Direct, hardens the new VM:
         - Clears and initialises the virtual TPM.
         - Enables BitLocker on C: with TPM protector (AES-256).
         - Enables Virtualization-Based Security (VBS) and Credential Guard via
            registry keys (DeviceGuard VBS + LsaCfgFlags).
         - Enables temporary autologon for the local Administrator account to support
            first-boot post-configuration.
         Restarts the VM, reconnects via PowerShell Direct, then waits for BitLocker
         to reach full encryption (100%) on C: before continuing.

     8. Optionally applies the Shielded VM security policy.

     9. Optionally executes a RunScript filename located in CustomScripts and logs
         a warning if it returns a non-zero exit code.

     10. Optionally installs the enabled applications in the selected Application Bundle
         from Resources independently of ExtraFolder; only selected application files are
         staged into the guest; one at a
         time, in bundle order, from the source-specific staged payloads before
         the VM is completed.

     11. Optionally applies Microsoft Security Baselines (OS and, when present, Edge)
         from C:\SECBL inside the VM, using the Windows 11 -Win11DomainJoined or
         -Win11NonDomainJoined switch. The baseline is reported as not applied if the
         switch is not supported by the baseline script or a baseline script returns
         a non-zero exit code.

     12. Stops the VM and creates a Hyper-V VM Connect shortcut on the All Users
          desktop under %ALLUSERSPROFILE%\Desktop\PAW Links.

    Requires PowerShell 5.1 or later and must be run as Administrator.
    All activity is logged to %TEMP%\PAWDeploy\New-PAWVM.log.

.PARAMETER Template
    (Dynamic – mandatory) Name of the deployment template defined in Config\*.json (excluding Config.json).
    The ValidateSet is populated at runtime from JSON files in the Templates folder.

.PARAMETER VMname
    Optional display name of the Hyper-V virtual machine.
    If omitted, a name is generated automatically using the template's NamePrefix and
    NameSuffix values combined with a random segment from New-PAWVMname.

.PARAMETER VMSwitchName
    (Dynamic – optional) Name of the Hyper-V virtual switch to attach the VM NIC to.
    The ValidateSet is populated at runtime from the switches present on the host.

.PARAMETER VMLocation
    File-system path where the VM configuration folder will be created.
    Defaults to C:\VMs if not specified.

.PARAMETER OSDAdapter0IPAddressList
    IP address for the first network adapter.  Defaults to 'DHCP' if not provided.
    When this parameter is omitted all four network parameters (IP, gateway, DNS, mask)
    default to 'DHCP'.

.PARAMETER OSDAdapter0Gateways
    Default gateway for the first network adapter.  Defaults to 'DHCP'.

.PARAMETER OSDAdapter0DNS1
    Primary DNS server for the first network adapter.  Defaults to 'DHCP'.

.PARAMETER OSDAdapter0DNS2
    Secondary DNS server for the first network adapter.  Defaults to 'DHCP'.

.PARAMETER OSDAdapter0SubnetMaskPrefix
    Subnet mask prefix length (e.g. 24) for the first network adapter.
    Defaults to 'DHCP'.

.PARAMETER AdminPassword
    SecureString containing the local Administrator password to set inside the VM.
    If not supplied, the script prompts interactively.

.PARAMETER DomainJoinAccount
    Domain administrator username used to join the VM to a domain.
    Do not include domain qualifiers (for example: no Domain\Username, user@domain,
    or values containing '/').
    Required when the selected template specifies DomainOrWorkGroup = "Domain".
    Prompted interactively if omitted.

.PARAMETER DomainJoinAccountPassword
    SecureString containing the password for the DomainJoinAccount account.
    Required for domain-joined deployments; prompted interactively if omitted.

.PARAMETER MachineObjectOU
    Distinguished name of the OU the computer account is created in when the VM joins
    the domain. Overrides the MachineObjectOU value in the template if specified.
    Ignored for workgroup deployments.

.PARAMETER VlanID
    802.1q VLAN ID (0–4095) to configure on the VM's network adapter.
    Defaults to the VLanID value defined in the template.

.PARAMETER SkipShielding
    When specified, the VM's security policy is NOT set to Shielded after BitLocker encryption.
    Without this switch, shielding follows the template value in the selected template JSON
    (<Shielded>True/False</Shielded>).

.PARAMETER ExtraFolder
    Path to a local folder whose contents are copied into the root of the VM's VHDX
    during image injection. No additional folder is copied unless this parameter is specified.

.PARAMETER RunScript
    Filename of a PowerShell script in Resources\CustomScripts to execute
    via PowerShell Direct after all other configuration steps have completed.
    Overrides the RunScript value in the template if specified.

.PARAMETER SkipRunScript
    When specified, skips RunScript execution even if RunScript is provided either
    from command line or the selected template JSON.

.PARAMETER VHDX
    Path to an alternative VHDX file that overrides the VHDFile value defined in the
    template.  The file must exist at the specified path; the script exits with an error
    if it cannot be found.

.PARAMETER SkipSecurityBaseLine
    When specified, the Microsoft Security Baseline files are NOT copied from the host
    into the VM image during injection.
    By default (without this switch), the baselines are always copied from the
    SecurityBaselineLocation path defined in the template, provided that path is
    accessible on the host.

.PARAMETER OSDComputerName
    Windows computer name to assign to the VM (3–15 characters).
    Defaults to the VMName value if not specified.

.PARAMETER DiskMode
    Accepted values: "Diff" (differencing disk) or "Copy" (full copy of the VHDX).
    Defaults to "Diff" unless overridden by the template or command line.

.PARAMETER SkipApplication
    When specified, skips PAWAppInstall execution inside the VM.
    By default (without this switch), applications are always installed.

.PARAMETER ApplicationBundle
    Bundle name or ID overriding the template's ApplicationBundle for this build only.
    Tab completion shows names; ambiguous names are completed as IDs. SkipApplication
    and template Application=False still disable application installation. NA (in the
    template or here) also disables application installation.

.PARAMETER SkipDiskEncryption
    When specified, skips all BitLocker encryption steps during deployment.
    This skips both enabling BitLocker on C: and waiting for encryption to reach
    100% completion.

.PARAMETER SkipASR
    Skips guest Attack Surface Reduction even when template ASR is True.
    Template ASR=False also skips configuration. Older templates without ASR
    retain enabled-by-default behavior.

.PARAMETER WDACPolicy
    XML filename directly in Resources\WDACPolicies. Overrides template
    WDACPolicyFile. Empty/NA skips WDAC when explicitly supplied.

.PARAMETER SkipWDAC
    Skips WDAC compilation/installation. Otherwise the selected policy is staged
    after cleanup for activation at the next VM boot, retaining Audit/Enforced mode.

.PARAMETER SkipLink
    When specified, skips creation of the VM Connect shortcut on the All Users desktop.
    By default (without this switch), a shortcut is created under
    %ALLUSERSPROFILE%\Desktop\PAW Links.

.PARAMETER SkipGuestFolderCleanup
    When specified, skips the final guest cleanup that removes C:\SECBL and
    C:\PAWFiles before the VM is shut down.
    By default (without this switch), both folders are removed if they exist.
    Autologon values and staged setup files are always removed and verified.
    On failure the VM and these diagnostic folders are retained regardless of
    this switch; reachable guest autologon/setup files are still cleaned.

.PARAMETER Validate
    When specified, enables verbose output for the deployment run and plays a
    notification sound when the script enters the final phase before the last
    VM shutdown.

.PARAMETER PreflightOnly
    Checks host RAM/disk and deployment resources without creating a VM,
    staging files, downloading applications or prompting for credentials.
    Returns the resource plan, including blocking errors and pending downloads.
    Does not validate template format. Validate retains its existing behavior.

.PARAMETER StartPAW
    When specified, starts the VM after PAWDeploy completes successfully.
    By default (without this switch), the VM remains stopped after deployment.

.PARAMETER ConnectPAW
    When specified, launches VMConnect.exe and connects to the deployed VM after
    PAWDeploy completes successfully. Implies -StartPAW (the VM will be started).
    By default (without this switch), no automatic connection is made.

.PARAMETER NoLaps
    When specified, skips creation of the PreventLAPS.txt marker file.
    The marker file is only created for domain-joined deployments and only when
    this switch is NOT specified.

.EXAMPLE
    .\New-PAWVM.ps1 -Template Win11PAW -VMSwitchName "External Switch"

    Deploys a PAW VM using the Win11PAW template, attached to the "External Switch"
    Hyper-V switch.  All optional settings are taken from the selected template JSON.  The script
    prompts for the local Administrator password.

.EXAMPLE
    .\New-PAWVM.ps1 -Template Win11PAW -VMSwitchName "External Switch" `
                    -VMname "PAW-MYPC-001" -VMLocation "D:\VMs" `
                    -AdminPassword (Read-Host -AsSecureString)

    Deploys a PAW VM with an explicit VM name and storage location, supplying the
    Administrator password securely.

.EXAMPLE
    .\New-PAWVM.ps1 -Template Win11PAWDomain -VMSwitchName "Corp Switch" `
                    -OSDAdapter0IPAddressList "10.0.0.50" `
                    -OSDAdapter0Gateways "10.0.0.1" `
                    -OSDAdapter0DNS1 "10.0.0.10" `
                    -OSDAdapter0SubnetMaskPrefix "24" `
                    -DomainJoinAccount "svcDeploy"

    Deploys a domain-joined PAW VM with a static IP configuration.

.NOTES
    Version : 2.0.0.22
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+, Hyper-V module, local Administrator privileges.
    Log file: %TEMP%\PAWDeploy\New-PAWVM.log
              (the script folder if none is configured); appended on each run.

    The PAWUtility module (Functions\PAWUtility) must be present relative to the
    script root – it provides all New-PAW*, Test-PAW*, Wait-PAW*, and related helpers.
#>
[cmdletbinding(SupportsShouldProcess = $true)]
Param
(
    [Parameter(Position = 1, Mandatory = $true)]
    [Alias('Templaate')]
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

            $scriptRoot = $PSScriptRoot
            if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
                if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
                    $scriptRoot = Split-Path -Parent $PSCommandPath
                }
                else { $scriptRoot = (Get-Location).Path }
            }
            $manifest = Join-Path $scriptRoot 'Functions\PAWUtility\PAWUtility.psd1'
            if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "PAWUtility module not found under '$scriptRoot'." }
            Import-Module -Name $manifest -Scope Local -ErrorAction Stop
            Get-PAWTemplateArgumentCompletion -ParameterName Name -WordToComplete $wordToComplete -ScriptFolder $scriptRoot
        })]

    [ValidateNotNullOrEmpty()]
    [string]
    $Template,

    [parameter(Position = 2, mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $VMname,

    [parameter(Position = 3, mandatory = $False)]
    [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            try {
                foreach ($switchName in @(Get-VMSwitch -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object -Unique)) {
                    if ([string]$switchName -like "$wordToComplete*") {
                        [System.Management.Automation.CompletionResult]::new("'$switchName'", [string]$switchName, 'ParameterValue', [string]$switchName)
                    }
                }
            }
            catch {
            }
        })]
    [ValidateNotNullOrEmpty()]
    [String]
    $VMSwitchName,

    [parameter(Position = 4, mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $VMLocation,

    [parameter(Position = 5, mandatory = $False)]
    [String]
    $OSDAdapter0IPAddressList,

    [parameter(Position = 6, mandatory = $False)]
    [String]
    $OSDAdapter0Gateways,

    [parameter(Position = 7, mandatory = $False)]
    [String]
    $OSDAdapter0DNS1,

    [parameter(Position = 8, mandatory = $False)]
    [String]
    $OSDAdapter0DNS2,

    [parameter(Position = 9, mandatory = $False)]
    [String]
    $OSDAdapter0SubnetMaskPrefix,

    [parameter(Position = 10, mandatory = $False)]
    [SecureString]
    $AdminPassword,

    [parameter(Position = 11, mandatory = $False)]
    [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw "DomainJoinAccount cannot be empty. Use only the account name (for example: admminy)."
            }
            if ($_ -match '[@\\/]') {
                throw "DomainJoinAccount must be username only. Use only the account name (for example: admminy), and do not include domain prefix/suffix such as DOMAIN\\user, user@domain, or / separators."
            }
            $true
        })]
    [String]
    $DomainJoinAccount,

    [parameter(Position = 12, mandatory = $False)]
    [SecureString]
    $DomainJoinAccountPassword,

    [parameter(mandatory = $False)]
    [String]
    $MachineObjectOU,

    [parameter(Position = 13, mandatory = $False)]
    [ValidateRange(0, 4095)]
    [string]
    $VlanID,

    [parameter(Position = 14, mandatory = $False)]
    [Switch]
    $SkipShielding,

    [parameter(Position = 15, mandatory = $False)]
    $ExtraFolder,

    [parameter(Position = 16, mandatory = $False)]
    $RunScript,

    [parameter(Position = 17, mandatory = $False)]
    [String]
    $VHDX,

    [parameter(Position = 18, mandatory = $False)]
    [Switch]
    $SkipSecurityBaseLine,

    [parameter(Position = 19, mandatory = $False)]
    [ValidateLength(3, 15)]
    [String]
    $OSDComputerName,

    [parameter(Position = 20, mandatory = $False)]
    [ValidateSet("Diff", "Copy")]
    [String]
    $DiskMode,

    [parameter(Position = 21, mandatory = $False)]
    [switch]
    $SkipApplication,

    [parameter(mandatory = $False)]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $command = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } |
            ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $command) { throw 'Could not resolve the deployment script for application bundle completion.' }
        $root = Split-Path -Parent $command.Path
        $manifest = Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "PAWUtility module not found under '$root'." }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWApplicationArgumentCompletion -ParameterName ApplicationBundle -WordToComplete $wordToComplete -ScriptFolder $root
    })]
    [ValidateNotNullOrEmpty()]
    [string]$ApplicationBundle,

    [parameter(Position = 22, mandatory = $False)]
    [switch]
    $SkipDiskEncryption,

    [parameter(Position = 23, mandatory = $False)]
    [switch]
    $SkipRunScript,

    [parameter(Position = 24, mandatory = $False)]
    [switch]
    $SkipLink,

    [parameter(Position = 25, mandatory = $False)]
    [switch]
    $StartPAW,

    [parameter(Position = 26, mandatory = $False)]
    [switch]
    $ConnectPAW,

    [parameter(Position = 27, mandatory = $False)]
    [switch]
    $NoLaps,

    [parameter(Position = 28, mandatory = $False)]
    [switch]
    $SkipGuestFolderCleanup,

    [parameter(Position = 29, mandatory = $False)]
    [switch]
    $Validate,

    [switch]$PreflightOnly,

    [switch]$SkipASR,

    [switch]$SkipWDAC,

    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $command = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } |
            ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $command) { throw 'Could not resolve the deployment script for WDAC completion.' }
        $root = Split-Path -Parent $command.Path
        $manifest = Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { throw "PAWUtility module not found under '$root'." }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName WDACPolicyFile -WordToComplete $wordToComplete -ScriptFolder $root
    })]
    [string]$WDACPolicy
)

#Requires -Version 5.1

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'New-PAWVM.ps1 must be run as Administrator.'
}

if ($PSBoundParameters['Verbose']) {
    $VerbosePreference = "Continue"
}
if ($PSBoundParameters['Debug']) {
    $DebugPreference = "Continue"
}
if ($PSBoundParameters['ErrorAction']) {
    $ErrorActionPreference = $PSBoundParameters['ErrorAction']
}
else {
    $ErrorActionPreference = "Continue"
}
if ($PSBoundParameters['WarningAction']) {
    $WarningPreference = $PSBoundParameters['WarningAction']
}
else {
    $WarningPreference = "Continue"
}
if ($PSBoundParameters['InformationAction']) {
    $InformationPreference = $PSBoundParameters['InformationAction']
}
else {
    $InformationPreference = "Continue"
}
if ($PSBoundParameters['Confirm']) {
    $ConfirmPreference = $PSBoundParameters['Confirm']
}
else {
    $ConfirmPreference = "High"
}
if ($PSBoundParameters['WhatIf']) {
    $WhatIfPreference = $PSBoundParameters['WhatIf']
}
else {
    $WhatIfPreference = $false
}

if ($Validate.IsPresent) {
    $VerbosePreference = 'Continue'
}


# PAWUtility provides all New-PAW*, Test-PAW*, Wait-PAW*, Invoke-PAWPSDirect, Resolve-*,
# Get-PAWTemplateCollection, ConvertTo-PAW*OrNull, etc. used below.
Import-Module -Global (Join-Path $PSScriptRoot 'Functions\PAWUtility') -ErrorAction Stop -Force
$LogFolder = Resolve-PAWLogFolder
$LogPath = Join-Path $LogFolder 'New-PAWVM.log'
Write-PAWLog -Message 'Deployment startup: reading script metadata.' -LogPath $LogPath
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$SolutionVersion = '2.0.0.22'
$BuildStartTime = Get-Date
$ConfigDataFile = Join-Path $PSScriptRoot 'Config\Config.json'
try {
    if (-not $PreflightOnly -and -not $WhatIfPreference) {
        Restore-PAWInterruptedDeployment -JournalFolder (Join-Path $LogFolder 'Recovery') -InstallRoot $PSScriptRoot -LogPath $LogPath -CurrentVMName $VMName -Confirm:$false -ErrorAction Stop
    }
    Write-PAWLog -Message 'Deployment startup: loading templates.' -LogPath $LogPath
    $preflightTemplates = Get-PAWTemplateCollection -TemplateFolder (Split-Path -Parent $ConfigDataFile)
    $preflightTemplate = $preflightTemplates | Where-Object Name -EQ $Template | Select-Object -First 1
    if ($null -eq $preflightTemplate) {
        $availableTemplates = @($preflightTemplates | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        throw "Template '$Template' was not found in folder '$(Split-Path -Parent $ConfigDataFile)'. Available templates: $($availableTemplates -join ', ')."
    }
    Write-PAWLog -Message 'Deployment startup: checking deployment resources.' -LogPath $LogPath
    $preflight = Test-PAWDeployment -ConfigPath $ConfigDataFile -TemplateData $preflightTemplate -Overrides $PSBoundParameters -AllowPendingDownloads
    Write-PAWLog -Message "Deployment preflight completed. CanPrepare=$($preflight.CanPrepare); CanDeploy=$($preflight.CanDeploy)." -LogPath $LogPath
}
catch {
    Write-PAWLog -Level ERROR -Message "Deployment startup failed: $($_.Exception.Message)" -Exception $_.Exception -LogPath $LogPath
    throw
}
if ($PreflightOnly) {
    foreach ($issue in $preflight.Errors) { Write-Warning "$($issue.Name): $($issue.Message)" }
    return $preflight
}

$CleanupState = @{}
$PSDirectContext = @{}
if ($VMName -and $VMName -eq [System.IO.Path]::GetFileName($VMName) -and $VMName -notin @('.', '..')) {
    $CleanupState.CredentialFile = Join-Path $env:TEMP "PAWDeploy-$VMName.dat"
}
$DeploymentFailed = $false
$OptionalFailures = New-Object 'System.Collections.Generic.List[object]'
$DiskEncryptionStarted = $false
$PAWResourcesRoot = $null
$PAWApplicationDownloadsRoot = $null
$PAWAppInstallHostScript = $null
$ApplicationFilesStaged = $false
$CustomScriptsStaged = $false
function Write-PAWOptionalFailure {
    param([string]$Step, [string]$Reason)
    $OptionalFailures.Add([pscustomobject]@{ Step = $Step; Reason = $Reason })
    Write-PAWLog -Level WARN -Message "${Step}: $Reason" -LogPath $LogPath -OutputMode Warning
}
$Cred = $null
try {
    foreach ($check in $preflight.Checks) {
        $level = if ($check.Passed) { 'INFO' } else { 'ERROR' }
        Write-PAWLog -Level $level -Message "Preflight $($check.Name): $($check.Message) AvailableBytes=$($check.AvailableBytes); RequiredBytes=$($check.RequiredBytes)" -LogPath $LogPath -OutputMode Console
    }
    foreach ($setting in $preflight.Settings.PSObject.Properties) {
        Write-PAWLog -Message "Preflight setting $($setting.Name)=$($setting.Value.Value) (source: $($setting.Value.Source))." -LogPath $LogPath -OutputMode Console
    }
    foreach ($step in $preflight.Steps.PSObject.Properties) {
        $action = if ($step.Value) { 'Run' } else { 'Skip' }
        Write-PAWLog -Message "Preflight step $($step.Name): $action." -LogPath $LogPath -OutputMode Console
    }
    foreach ($warning in $preflight.Warnings) { Write-PAWLog -Level WARN -Message "Preflight: $warning" -LogPath $LogPath -OutputMode Warning }
    if ($preflight.PendingDownloads.Count) {
        Write-PAWLog -Message "Preflight preparation required: $($preflight.PendingDownloads -join ', '). Application cache will be checked after preparation, before VM creation." -LogPath $LogPath -OutputMode Console
    }
    if (-not $preflight.CanPrepare) {
        $blockingDetails = @($preflight.Errors | ForEach-Object { "- $($_.Name): $($_.Message)" })
        throw "Deployment resource preflight failed with $($preflight.Errors.Count) blocking error(s):`n$($blockingDetails -join "`n")`nCorrect the resources or skip the affected steps."
    }
    # Init section
    Write-PAWConsoleLog -Message  "Starting {0} script version {1}" -Type Info -Value "PAWDeploy", "$SolutionVersion"

    Write-PAWLog -Message "#########################################" -LogPath $LogPath
    Write-PAWLog -Message "## PAWDeploy script started at $(Get-Date) ##" -LogPath $LogPath
    Write-PAWLog -Message "#########################################" -LogPath $LogPath
    
    Write-PAWLog -Message "Starting PAWDeploy script - Version $SolutionVersion" -LogPath $LogPath
    Write-PAWLog -Message "LogPath='$LogPath'" -LogPath $LogPath
    Write-PAWLog -Message "Running on $($env:COMPUTERNAME) with PowerShell version $($PSVersionTable.PSVersion)" -LogPath $LogPath
    

    Write-PAWLog -Message "Structured deployment logging is enabled at $LogPath" -LogPath $LogPath



    # Get Data
    $ConfigData = Get-Content -Path "$ConfigDataFile" -Raw | ConvertFrom-Json
    $TemplateFolder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigDataFile -ErrorAction Stop).Path
    $TemplateCollection = Get-PAWTemplateCollection -TemplateFolder $TemplateFolder


    $CustomerData = $ConfigData.Settings.CustomerData
    $HyperVData = $ConfigData.Settings.HyperV
    $OperatingSystemConfiguration = $ConfigData.Settings.OperatingSystemConfiguration
    $TemplateData = $TemplateCollection | Where-Object Name -EQ $Template | Select-Object -First 1
    if ($null -eq $TemplateData) {
        $availableTemplates = @($TemplateCollection | ForEach-Object { [string]$_.Name } | Sort-Object -Unique)
        Write-PAWLog -Level 'ERROR' -Message "Template '$Template' was not found in folder '$TemplateFolder'. Available templates: $($(( $availableTemplates | ForEach-Object { "'$_'" } ) -join ', '))" -LogPath $LogPath
        throw "Template '$Template' was not found in folder '$TemplateFolder'. Available templates: $($(( $availableTemplates | ForEach-Object { "'$_'" } ) -join ', '))"
    }

    #region Warnings
    
    # Resolve shielding from template unless explicitly overridden by -SkipShielding.
    $TemplateShieldingValue = if ([string]::IsNullOrWhiteSpace([string]$TemplateData.Shielding)) {
        [string]$TemplateData.Shielded
    }
    else {
        [string]$TemplateData.Shielding
    }
    $EnableShieldingRequested = -not $SkipShielding.IsPresent -and $TemplateShieldingValue.Trim().ToLowerInvariant() -eq 'true'

    if ($SkipShielding.IsPresent) {
        Write-PAWLog -Level 'WARN' -Message "Shielding is disabled (-SkipShielding was specified)" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
    }
    elseif ($TemplateShieldingValue.Trim().ToLowerInvariant() -eq 'false') {
        Write-PAWLog -Level 'WARN' -Message "Shielding is disabled (template shielding is set to False)" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
    }
    elseif ($EnableShieldingRequested) {
        Write-PAWLog -Message "Shielding is enabled (template shielding is set to True)" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    else {
        $EnableShieldingRequested = $true
        Write-PAWLog -Message "Shielding is enabled (template default)" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }


    $TemplateDisablesDiskEncryption = ([string]$TemplateData.BitLocker).Trim().ToLowerInvariant() -eq 'false'
    $SkipDiskEncryptionRequested = $SkipDiskEncryption.IsPresent -or $TemplateDisablesDiskEncryption

    if ($SkipDiskEncryption.IsPresent) {
        Write-PAWLog -Level 'WARN' -Message "SkipDiskEncryption is set; disk encryption will be skipped" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
    }

    if ($TemplateDisablesDiskEncryption) {
        Write-PAWLog -Level 'WARN' -Message "Template BitLocker is set to False; disk encryption will be skipped" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
    }

    if ($SkipDiskEncryptionRequested) {
        Write-PAWLog -Level 'WARN' -Message "SkipDiskEncryption is set; skipping disk encryption wait" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
    }



    # --- Security Baseline Copy: now occurs after VM creation and mounting ---
    $SecurityBaselineCopiedToImage = $false
    $ResolvedSecurityBaselineLocation = $null

    if ($SkipSecurityBaseLine -or [string]::IsNullOrWhiteSpace([string]$TemplateData.SecurityBaselineLocation) -or
        ([string]$TemplateData.SecurityBaselineLocation).Trim() -eq 'NA') {
        Write-PAWLog -Message 'Skipping copy of security baselines (SkipSecurityBaseLine or SecurityBaselineLocation is empty/NA)' -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    #endregion


    #region Validate VMLocation
    if ($PSBoundParameters.ContainsKey('VMLocation') -eq $True) {
        if (!(Test-Path -Path $VMLocation)) {
            Write-Warning "VMLocation '$VMLocation' does not exist"
            throw "PAWDeploy terminated due to previous error."
        }
        else {
            Write-Verbose "VMLocation '$VMLocation' exists, using it"
        }
    }
    elseif (-not [string]::IsNullOrEmpty($HyperVData.VMFolder)) {
        $VMLocation = $HyperVData.VMFolder
        Write-Verbose "VMLocation not provided, using HyperV VMFolder from config: $VMLocation"
        if (!(Test-Path -Path $VMLocation)) {
            Write-Warning "Config VMFolder '$VMLocation' does not exist"
            throw "PAWDeploy terminated due to previous error."
        }
    }
    elseif (-not [string]::IsNullOrEmpty($HyperVData.VMLocation)) {
        $VMLocation = $HyperVData.VMLocation
        Write-Verbose "VMLocation not provided, using legacy HyperV VMLocation from config: $VMLocation"
        if (!(Test-Path -Path $VMLocation)) {
            Write-Warning "Template VMLocation '$VMLocation' does not exist"
            throw "PAWDeploy terminated due to previous error."
        }
    }
    else {
        $VMLocation = "C:\VMs"
        Write-Verbose "VMLocation not provided and not set in template, using default: $VMLocation"
        if (!(Test-Path -Path $VMLocation)) {            
            Write-PAWConsoleLog -Message "Default VMLocation {0} does not exist, creating it" -Type Info -Value $VMLocation
            try { 
                New-Item -Path $VMLocation -ItemType Directory -ErrorAction Stop | Out-Null
            }
            catch {
                Write-PAWConsoleLog -Message "Failed to create default VMLocation '{0}'. $($_.Exception.Message)" -Type Error -Value $VMLocation
                throw "PAWDeploy terminated due to previous error."
            }
        }
    }
    Write-PAWConsoleLog -Message "VMLocation is now {0}" -Type Info -Value $VMLocation
    #endregion Validate VMLocation



    #region Validate VMSwitch
    # Early VMSwitch preflight: fail fast before prompting for credentials or starting deployment work.
    $preflightVMSwitchNames = @()
    try {
        $preflightVMSwitchNames = @(Get-VMSwitch -ErrorAction Stop | Select-Object -ExpandProperty Name | Sort-Object -Unique)
    }
    catch {
        Write-PAWLog -Level 'ERROR' -Message "Unable to enumerate Hyper-V switches during preflight. $($_.Exception.Message)" -LogPath $LogPath
        Write-PAWConsoleLog -Message "Unable to enumerate Hyper-V switches during preflight. {0}" -Type Error -Value $($_.Exception.Message)
        throw "Unable to enumerate Hyper-V switches during preflight. $($_.Exception.Message)"
    }

    $preflightSwitchName = $null
    if ($PSBoundParameters.ContainsKey('VMSwitchName') -and -not [string]::IsNullOrWhiteSpace([string]$VMSwitchName)) {
        $preflightSwitchName = Resolve-PAWVMSwitchName -SwitchValue $VMSwitchName
    }
    else {
        $preflightSwitchName = Resolve-PAWVMSwitchName -SwitchValue $TemplateData.VMSwitch
    }

    if ([string]::IsNullOrWhiteSpace($preflightSwitchName)) {
        Write-PAWConsoleLog -Message "VMSwitch is not provided and template '{0}' does not define VMSwitch." -Type Warn -Value $Template
        Write-PAWConsoleLog -Message "Available Hyper-V switches:" -Type Info
        for ($switchIndex = 0; $switchIndex -lt $preflightVMSwitchNames.Count; $switchIndex++) {
            Write-PAWConsoleLog -Message "[{0}] {1}" -Type Info -Value ($switchIndex + 1), $preflightVMSwitchNames[$switchIndex]
        }

        $preflightSelectedSwitchIndex = $null
        do {
            $preflightSelectionInput = Read-Host -Prompt ("Select VMSwitch by number (1-{0})" -f $preflightVMSwitchNames.Count)
            $preflightParsedSelection = 0
            if ([int]::TryParse([string]$preflightSelectionInput, [ref]$preflightParsedSelection) -and $preflightParsedSelection -ge 1 -and $preflightParsedSelection -le $preflightVMSwitchNames.Count) {
                $preflightSelectedSwitchIndex = $preflightParsedSelection - 1
            }
            else {
                Write-Warning "Invalid selection '$preflightSelectionInput'. Enter a number between 1 and $($preflightVMSwitchNames.Count)."
            }
        }
        while ($null -eq $preflightSelectedSwitchIndex)

        $preflightSwitchName = $preflightVMSwitchNames[$preflightSelectedSwitchIndex]
        Write-PAWConsoleLog -Message "Selected preflight VMSwitchName {0}" -Type Info -Value $preflightSwitchName
    }

    if (-not ($preflightVMSwitchNames -contains $preflightSwitchName)) {
        Write-PAWLog -Level 'ERROR' -Message "VMSwitch $preflightSwitchName was not found on this host during preflight. Available switches: $($preflightVMSwitchNames -join ', ')" -LogPath $LogPath
        Write-PAWConsoleLog -Message "VMSwitch '{0}' was not found on this host during preflight" -Type Error -Value $preflightSwitchName
        Write-PAWConsoleLog -Message "Available switches: {0}" -Type Info -Value ($preflightVMSwitchNames -join ', ')
        throw "The entered VMSwitch $($preflightSwitchName) was not found on this host"
    }

    $VMSwitchName = $preflightSwitchName
    Write-PAWConsoleLog -Message "Preflight VMSwitchName resolved to {0}" -Type Info -Value $VMSwitchName

    # Early VHDX preflight: construct full path using Config.json + VHD filename and validate before build work continues.
    if ($PSBoundParameters.ContainsKey('VHDX') -eq $True) {
        $resolvedOverrideVHDPath = Resolve-PAWVHDFilePath -ConfigPath $ConfigDataFile -VHDFileValue $PSBoundParameters['VHDX']
        if ([string]::IsNullOrWhiteSpace($resolvedOverrideVHDPath) -or -not (Test-Path -LiteralPath $resolvedOverrideVHDPath -PathType Leaf)) {
            Write-PAWLog -Level 'ERROR' -Message "Could not find the file $($PSBoundParameters['VHDX'])" -LogPath $LogPath -OutputMode Warning
            Write-PAWLog -Level 'ERROR' -Message "Resolved VHDX path: $resolvedOverrideVHDPath" -LogPath $LogPath -OutputMode Warning
            throw "PAWDeploy terminated due to previous error."
        }

        $TemplateData.VHDFile = $resolvedOverrideVHDPath
        Write-PAWLog -Message "VHDX parameter is set; resolved VHDX path: $($TemplateData.VHDFile)" -LogPath $LogPath -OutputMode Verbose
    }
    else {
        $resolvedTemplateVHDPath = Resolve-PAWVHDFilePath -ConfigPath $ConfigDataFile -VHDFileValue ([string]$TemplateData.VHDFile)
        if ([string]::IsNullOrWhiteSpace($resolvedTemplateVHDPath) -or -not (Test-Path -LiteralPath $resolvedTemplateVHDPath -PathType Leaf)) {
            Write-PAWLog -Level 'ERROR' -Message "Could not find the file $($TemplateData.VHDFile)" -LogPath $LogPath -OutputMode Warning
            Write-PAWLog -Level 'ERROR' -Message "Resolved VHDX path: $resolvedTemplateVHDPath" -LogPath $LogPath -OutputMode Warning
            throw "PAWDeploy terminated due to previous error."
        }

        $TemplateData.VHDFile = $resolvedTemplateVHDPath
        Write-PAWLog -Message "Preflight VHDX path resolved to '$($TemplateData.VHDFile)'" -LogPath $LogPath -OutputMode Verbose
    }
    #endregion


    #region Validate Temp folder

    $PAWTempFolder = Join-Path $env:TEMP ("PAWDeploy-" + [guid]::NewGuid().ToString('N'))
    $recoveryFolder = Join-Path $LogFolder 'Recovery'
    $null = New-Item -Path $recoveryFolder -ItemType Directory -Force -ErrorAction Stop
    $CleanupState.RunId = [guid]::NewGuid().ToString('N')
    $CleanupState.JournalPath = [IO.Path]::GetFullPath((Join-Path $recoveryFolder "$($CleanupState.RunId).clixml"))
    $CleanupState.ProcessId = $PID
    $CleanupState.ProcessStartTicks = (Get-Process -Id $PID -ErrorAction Stop).StartTime.ToUniversalTime().Ticks
    $CleanupState.RunspaceId = [runspace]::DefaultRunspace.InstanceId
    $CleanupState.InstallRoot = [IO.Path]::GetFullPath($PSScriptRoot)
    $CleanupState.SourceVHD = $TemplateData.VHDFile
    $CleanupState.TempFolder = $PAWTempFolder
    Save-PAWDeploymentState -State $CleanupState
    $null = New-Item -Path $PAWTempFolder -ItemType Directory -ErrorAction Stop
    Set-Content -LiteralPath (Join-Path $PAWTempFolder '.pawdeploy-owner') -Value $CleanupState.RunId -Encoding ASCII -ErrorAction Stop
    $MountFolder = Join-Path $PAWTempFolder 'Mount'
    Write-PAWLog -Message "Created deployment-owned staging folder $PAWTempFolder" -LogPath $LogPath

    #endregion

    #region Validate Parameters
    
    # Restore automatic VM name generation if not provided
    if (-not $VMName) {
        $prefix = [string]$TemplateData.NamePrefix
        if ([string]::IsNullOrWhiteSpace($prefix)) {
            $prefix = New-PAWVMNamePrefix
        }

        $suffix = [string]$TemplateData.NameSuffix
        if ([string]::IsNullOrWhiteSpace($suffix)) {
            $suffix = New-PAWVMNameSuffix
        }

        $random = New-PAWVMname
        $VMName = "$prefix-$random-$suffix"
        Write-PAWLog -Message "VMName not provided, generated: $VMName" -LogPath $LogPath -OutputMode Console -ConsoleType Info -Value $VMName -ConsoleMessage "VMName not provided, generated: {0}"
    }

    if ($VMName -ne [System.IO.Path]::GetFileName($VMName) -or $VMName -in @('.', '..')) {
        throw 'VMName must be a single directory name.'
    }
    $CleanupState.CredentialFile = Join-Path $env:TEMP "PAWDeploy-$VMName.dat"
    Save-PAWDeploymentState -State $CleanupState

    if ([string]::IsNullOrWhiteSpace([string]$OSDComputerName)) {
        $OSDComputerName = $VMName
        Write-PAWLog -Message "OSDComputerName not provided, using VMName: $OSDComputerName" -LogPath $LogPath -OutputMode Console -ConsoleType Info -Value $OSDComputerName -ConsoleMessage "OSDComputerName not provided, using VMName {0}"
    }



    # check if template is set for a run command
    if ("" -ne $TemplateData.RunScript) {
        Write-PAWLog -Message "Template is set for RunScript: $($TemplateData.RunScript)" -LogPath $LogPath -OutputMode Verbose
        if ($PSBoundParameters.ContainsKey('RunScript') -eq $True) {
            Write-PAWLog -Message "RunScript parameter is set to $($PSBoundParameters['RunScript'])" -LogPath $LogPath -OutputMode Verbose
            $RunScript = $PSBoundParameters['RunScript']
        }
        else {
            $RunScript = $TemplateData.RunScript
        }
    }
    else {
        Write-PAWLog -Level 'WARN' -Message "RunScript is not set in the template" -LogPath $LogPath -OutputMode Console -ConsoleType Info
        if ($PSBoundParameters.ContainsKey('RunScript') -eq $True) {
            Write-PAWLog -Message "RunScript parameter is set to $($PSBoundParameters['RunScript'])" -LogPath $LogPath -OutputMode Verbose
            $RunScript = $PSBoundParameters['RunScript']
        }
        else {
            $RunScript = "NA"
            Write-PAWLog -Message "RunScript parameter is set to NA" -LogPath $LogPath -OutputMode Verbose
        }
    }

    # Normalize RunScript so both command-line and template value "NA" mean explicit skip.
    if ([string]::IsNullOrWhiteSpace([string]$RunScript) -or ([string]$RunScript).Trim().ToUpperInvariant() -eq 'NA') {
        $RunScript = 'NA'
        Write-PAWLog -Level 'WARN' -Message 'RunScript resolved to NA; runscript execution will be skipped' -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }

    $diskParameters = @{
        Name = 'DiskMode'; Kind = 'DiskMode'; TemplateValue = $TemplateData.DiskMode
        ConfigValue = $HyperVData.DiskMode; DefaultValue = 'Diff'; LogPath = $LogPath
        DefaultOutputMode = 'Console'
    }
    if ($PSBoundParameters.ContainsKey('DiskMode')) { $diskParameters.CommandLineValue = $DiskMode }
    $ResolvedDiskMode = (Resolve-PAWSetting @diskParameters).Value
    $ResolvedVMGeneration = (Resolve-PAWSetting -Name VMGen -Kind VMGen -TemplateValue $TemplateData.VMGen -ConfigValue $HyperVData.VMGen -DefaultValue 2 -LogPath $LogPath -DefaultOutputMode Console).Value
    $ResolvedNoCPU = (Resolve-PAWSetting -Name NoCPU -Kind PositiveInt -TemplateValue $TemplateData.NoCPU -ConfigValue $HyperVData.NoCPU -DefaultValue 2 -LogPath $LogPath).Value
    $ResolvedMemoryMB = (Resolve-PAWSetting -Name Memory -Kind PositiveInt -TemplateValue $TemplateData.Memory -ConfigValue $HyperVData.Memory -DefaultValue 3072 -LogPath $LogPath).Value
    $ResolvedDynamicMem = (Resolve-PAWSetting -Name DynamicMem -Kind Boolean -TemplateValue $TemplateData.DynamicMem -ConfigValue $HyperVData.DynamicMem -DefaultValue $false -LogPath $LogPath).Value
    $ResolvedDomainOrWorkGroup = (Resolve-PAWSetting -Name DomainOrWorkGroup -Kind DomainOrWorkGroup -TemplateValue $TemplateData.DomainOrWorkGroup -ConfigValue $OperatingSystemConfiguration.DomainOrWorkGroup -DefaultValue Workgroup -LogPath $LogPath).Value
    $ResolvedTimeZoneName = (Resolve-PAWSetting -Name TimeZoneName -Kind String -TemplateValue $TemplateData.TimeZoneName -ConfigValue $OperatingSystemConfiguration.TimeZoneName -LogPath $LogPath).Value
    $ResolvedInputLocale = (Resolve-PAWSetting -Name InputLocale -Kind String -TemplateValue $TemplateData.InputLocale -ConfigValue $OperatingSystemConfiguration.InputLocale -LogPath $LogPath).Value
    $ResolvedSystemLocale = (Resolve-PAWSetting -Name SystemLocale -Kind String -TemplateValue $TemplateData.SystemLocale -ConfigValue $OperatingSystemConfiguration.SystemLocale -LogPath $LogPath).Value
    $ResolvedUILanguage = (Resolve-PAWSetting -Name UILanguage -Kind String -TemplateValue $TemplateData.UILanguage -ConfigValue $OperatingSystemConfiguration.UILanguage -LogPath $LogPath).Value
    $ResolvedUserLocale = (Resolve-PAWSetting -Name UserLocale -Kind String -TemplateValue $TemplateData.UserLocale -ConfigValue $OperatingSystemConfiguration.UserLocale -LogPath $LogPath).Value

    if ($SkipRunScript) {
        $RunScript = 'NA'
        Write-PAWLog -Level 'WARN' -Message 'SkipRunScript is set; runscript execution will be skipped' -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    if (-not $PSBoundParameters.ContainsKey('WDACPolicy')) {
        $WDACPolicy = [string]$TemplateData.WDACPolicyFile
    }
    $WDACPolicy = $WDACPolicy.Trim()
   
    # Copy only an explicitly selected extra folder.
    if ($PSBoundParameters.ContainsKey('ExtraFolder') -and -not [string]::IsNullOrWhiteSpace([string]$PSBoundParameters['ExtraFolder'])) {
        $ExtraFolder = [string]$PSBoundParameters['ExtraFolder']
        Write-PAWLog -Message "ExtraFolder parameter is set to $ExtraFolder" -LogPath $LogPath -OutputMode Verbose
    }
    else {
        $ExtraFolder = $null
        Write-PAWLog -Message 'No additional folder configured; skipping ExtraFolder copy.' -LogPath $LogPath -OutputMode Verbose
    }



    # Honor Application template setting: if template sets Application=False, treat as -SkipApplication.
    if (-not $SkipApplication -and $TemplateData.Application -eq 'False') {
        $SkipApplication = $true
        Write-PAWLog -Level 'WARN' -Message "Template Application is set to False; application installation will be skipped" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    elseif (-not $SkipApplication -and ([string]$(if ($PSBoundParameters.ContainsKey('ApplicationBundle')) { $ApplicationBundle } else { $TemplateData.ApplicationBundle })).Trim() -eq 'NA') {
        $SkipApplication = $true
        Write-PAWLog -Level 'WARN' -Message "ApplicationBundle is set to NA; application installation will be skipped" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    elseif ($SkipApplication) {
        Write-PAWLog -Level 'WARN' -Message "SkipApplication is set; application installation will be skipped" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    }
    else {
        Write-PAWLog -Message "Application installation is enabled (default)" -LogPath $LogPath -OutputMode Verbose
    }

    Write-Verbose "Resolved deployment configuration:"
    Write-Verbose "  Template         : $Template"
    Write-Verbose "  VMName           : $VMName"
    Write-Verbose "  OSDComputerName  : $OSDComputerName"
    Write-Verbose "  VMSwitch         : $VMSwitchName"
    Write-Verbose "  VHDX             : $($TemplateData.VHDFile)"
    Write-Verbose "  DiskMode         : $ResolvedDiskMode"
    Write-Verbose "  VMGen            : $ResolvedVMGeneration"
    Write-Verbose "  NoCPU            : $ResolvedNoCPU"
    Write-Verbose "  Memory           : $ResolvedMemoryMB MB"
    Write-Verbose "  DynamicMem       : $ResolvedDynamicMem"
    Write-Verbose "  DomainOrWorkGroup: $ResolvedDomainOrWorkGroup"
    Write-Verbose "  TimeZone         : $ResolvedTimeZoneName"
    Write-Verbose "  InputLocale      : $ResolvedInputLocale"
    Write-Verbose "  SystemLocale     : $ResolvedSystemLocale"
    Write-Verbose "  UILanguage       : $ResolvedUILanguage"
    Write-Verbose "  UserLocale       : $ResolvedUserLocale"
    Write-Verbose "  RunScript        : $RunScript"
    Write-Verbose "  ExtraFolder      : $ExtraFolder"
    Write-Verbose "  Shielding        : $EnableShieldingRequested"
    Write-Verbose "  DiskEncryption   : $(-not $SkipDiskEncryptionRequested)"
    Write-Verbose "  Application      : $(-not $SkipApplication)"

    #endregion

    #region Credentials

    # Check if $CredFromFile in use
    if ((Test-Path "$env:temp\PAWDeploy-$VMName.dat") -eq $true) {
        $obj = Get-Content "$env:temp\PAWDeploy-$VMName.dat" | ConvertTo-SecureString
        $credentialBuffer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($obj)
        try {
            $SecureVariable = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($credentialBuffer) | ConvertFrom-Json
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialBuffer)
        }
        $AdminPassword = ($SecureVariable.AdminPassword | ConvertTo-SecureString -AsPlainText -Force)

        if ($SecureVariable.DomainJoinAccountPassword) {
            $DomainJoinAccountPassword = ($SecureVariable.DomainJoinAccountPassword | ConvertTo-SecureString -AsPlainText -Force)
        }
        Write-PAWLog -Message "Loaded credentials from $env:temp\PAWDeploy-$VMName.dat" -LogPath $LogPath
        Remove-Item -LiteralPath $CleanupState.CredentialFile -Force -ErrorAction Stop
        $CleanupState.CredentialFile = $null
        $SecureVariable = $null
    }
    else {
        # check if admin password is provided, if not prompt for it
        if ($PSBoundParameters.ContainsKey('AdminPassword') -eq $False) {
            Write-PAWLog -Level 'WARN' -Message "AdminPassword is not provided, prompting for it" -LogPath $LogPath -OutputMode Console -ConsoleType Warning -ConsoleMessage "AdminPassword is not provided"
            $AdminPassword = Read-Host -Prompt "Please enter the Local Administrator password" -AsSecureString
        }
    }

    if ($ResolvedDomainOrWorkGroup -eq "Domain") {
        if ($PSBoundParameters.ContainsKey('DomainJoinAccount') -eq $False) {
            Write-PAWLog -Level 'WARN' -Message "DomainJoinAccount is not provided, prompting for it" -LogPath $LogPath -OutputMode Console -ConsoleType Warning -ConsoleMessage "DomainJoinAccount is not provided"
            # Prompt for the username only (no domain prefix/suffix).
            do {
                $DomainJoinAccount = Read-Host -Prompt "Please enter the Domain Join Account username (username only)"
                if ([string]::IsNullOrWhiteSpace($DomainJoinAccount) -or ($DomainJoinAccount -match '[@\\/]')) {
                    Write-PAWLog -Level 'ERROR' -Message "DomainJoinAccount must be username only and cannot contain @, \\ or /." -LogPath $LogPath -OutputMode Console -ConsoleType Error -ConsoleMessage "DomainJoinAccount must be username only and cannot contain @, \ or /."
                    $DomainJoinAccount = $null
                }
            }
            while ([string]::IsNullOrWhiteSpace($DomainJoinAccount))
        }
    }


    if ($ResolvedDomainOrWorkGroup -eq "Domain") {
        if ($null -ne $DomainJoinAccountPassword) {
            Write-PAWLog -Message "Domain Join Password provided from GUI" -LogPath $LogPath -OutputMode Verbose
        }
        else {
            if ($PSBoundParameters.ContainsKey('DomainJoinAccountPassword') -eq $False) {
                Write-PAWLog -Level 'WARN' -Message "DomainJoinAccountPassword is not provided, prompting for it" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
                # Show the resolved account/domain context before prompting for the secure password.
                Write-PAWLog -Message "Template domain: $($TemplateData.DNSDomain)" -LogPath $LogPath -OutputMode Verbose
                Write-PAWLog -Message "DomainJoinAccount in use: $DomainJoinAccount" -LogPath $LogPath -OutputMode Verbose
                $DomainJoinAccountPassword = Read-Host -Prompt "Please enter the password for DomainJoinAccount '$DomainJoinAccount'" -AsSecureString
            }
        }
    }

    #endregion

    # Set default values for the network adapter parameters if not provided
    if ($PSBoundParameters.ContainsKey('OSDAdapter0IPAddressList') -eq $False ) {
        $OSDAdapter0IPAddressList = 'DHCP'
        $OSDAdapter0Gateways = 'DHCP'
        $OSDAdapter0DNS1 = 'DHCP'
        $OSDAdapter0DNS2 = 'DHCP'
        $OSDAdapter0SubnetMaskPrefix = 'DHCP'
        Write-PAWLog -Message "Network parameters not provided, defaulting all to DHCP" -LogPath $LogPath
    }

   
    # Late sanity check for VHD path previously resolved during early preflight.
    if (-not (Test-Path -LiteralPath $TemplateData.VHDFile -PathType Leaf)) {
        Write-PAWConsoleLog -Message "Could not find the file {0}" -Type Error -Value "$($TemplateData.VHDFile)"
        throw "PAWDeploy terminated due to previous error."
    }

    #region PAWAppInstall

    # Download only the selected applications into Resources before the VM build.
    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($SkipApplication) {
            Write-PAWConsoleLog -Message "SkipApplication is set; skipping application download stage" -Type Info
        }
        else {
            $PAWApplicationDownloadScriptPath = Join-Path $PSScriptRoot 'Tools\Invoke-PAWApplicationDownload.ps1'
            $PAWResourcesRoot = Join-Path $PSScriptRoot 'Resources'
            $PAWApplicationDownloadsRoot = Join-Path $PAWResourcesRoot 'ApplicationDownloads'
            $PAWAppInstallHostScript = Join-Path $PAWResourcesRoot 'Applications\Invoke-PAWInstallApplications.ps1'

            if (-not (Test-Path -LiteralPath $PAWAppInstallHostScript -PathType Leaf)) {
                throw "Application installer not found: $PAWAppInstallHostScript"
            }
            elseif (-not (Test-Path -Path $PAWApplicationDownloadScriptPath -PathType Leaf)) {
                throw "Application download tool not found: $PAWApplicationDownloadScriptPath"
            }
            elseif ($WhatIfPreference -eq $true) {
                Write-PAWConsoleLog -Message "WhatIf is enabled; skipping application download stage" -Type Info
            }
            else {
                Write-Verbose "Running Invoke-PAWApplicationDownload.ps1 before VM build"
                Write-Verbose "Application download cache root: $PAWApplicationDownloadsRoot"
                try {
                    & $PAWApplicationDownloadScriptPath -ApplicationPlan $preflight.ApplicationPlan -ErrorAction Stop | Out-Null
                }
                catch {
                    throw
                }
            }
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Application download' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    #endregion

    #region Create VM
    $finalPreflightOverrides = @{}
    foreach ($key in $PSBoundParameters.Keys) { $finalPreflightOverrides[$key] = $PSBoundParameters[$key] }
    $finalPreflightOverrides.VMName = $VMName
    $finalPreflightOverrides.VMSwitchName = $VMSwitchName
    $finalPreflight = Test-PAWDeployment -ConfigPath $ConfigDataFile -TemplateData $TemplateData -Overrides $finalPreflightOverrides -ApplicationPlan $preflight.ApplicationPlan
    foreach ($issue in $finalPreflight.Errors) {
        Write-PAWLog -Level ERROR -Message "Final preflight $($issue.Name): $($issue.Message) AvailableBytes=$($issue.AvailableBytes); RequiredBytes=$($issue.RequiredBytes)" -LogPath $LogPath -OutputMode Console
    }
    if (-not $finalPreflight.CanDeploy -or @($OptionalFailures | Where-Object Step -eq 'Application download').Count) {
        $blockingDetails = @($finalPreflight.Errors | ForEach-Object { "- $($_.Name): $($_.Message)" })
        $blockingDetails += @($OptionalFailures | Where-Object Step -eq 'Application download' | ForEach-Object { "- $($_.Step): $($_.Reason)" })
        if ($finalPreflight.PendingDownloads.Count) {
            $blockingDetails += "- Application preparation pending: $($finalPreflight.PendingDownloads -join ', ')."
        }
        throw "Final deployment resource preflight failed:`n$($blockingDetails -join "`n")`nNo VM was created; correct the application cache/resources or skip the affected steps."
    }
    Write-PAWConsoleLog -Message "Creating VM {0}" -Type Change -Value $VMname
    $VM = New-PAWHyperVVM -VMName $VMName -VMMem ($ResolvedMemoryMB * 1024 * 1024) -VMvCPU $ResolvedNoCPU -VMLocation $VMlocation -DiskMode $ResolvedDiskMode -VMSwitchName $VMSwitchName -VMGeneration $ResolvedVMGeneration -VHDFile $TemplateData.VHDFile -CleanupState $CleanupState -ErrorAction Stop

    # Check if the VM was created successfully
    Write-PAWConsoleLog -Message "Check if {0} exist" -Type Info -Value $VM.Name
    If ((Test-PAWVMExists -VMname $VMName) -eq $False) {
        Write-PAWConsoleLog -Message "{0} does not exist" -Type Error -Value $VMName
        throw "PAWDeploy terminated due to previous error."
    }

    Write-Verbose "Adding Virtual Machine Note"
    $VMNotes = '###PAW42###'
    if (-not [string]::IsNullOrEmpty([string]$TemplateData.vmnotes)) {
        $VMNotes += ' ' + [string]$TemplateData.vmnotes
    }
    Set-VM -VMName $VMName -Notes $VMNotes -ErrorAction Stop

    # We need to convert the secure string admin password to plain text for the unattend.xml
    if ($AdminPassword -is [System.Security.SecureString]) {
        Write-Verbose "Converting AdminPassword to plain text"
        $adminBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
        try { $NonSecureAdminPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($adminBuffer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($adminBuffer) }
    }
    else {
        Write-PAWLog -Level 'WARN' -Message "AdminPassword is not a secure string, using as-is" -LogPath $LogPath
        $NonSecureAdminPassword = $AdminPassword
    }


    # check if we are using domain or workgroup
    if ($ResolvedDomainOrWorkGroup -ne 'Workgroup') {
        Write-Verbose "DomainOrWorkGroup is set to Domain, DomainJoinAccount is provided, converting to plain text"
        # We need to convert the secure string domain admin password to plain text for the unattend.xml
        if ($DomainJoinAccountPassword -is [System.Security.SecureString]) {
            Write-Verbose "Converting DomainJoinAccountPassword to plain text"
            $domainBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainJoinAccountPassword)
            try { $NonSecureDomainJoinAccountPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($domainBuffer) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($domainBuffer) }
        }
        else {
            Write-PAWLog -Level 'WARN' -Message "DomainJoinAccountPassword is not a secure string, skipping conversion" -LogPath $LogPath
        }
    }


    $ResolvedMachineObjectOU = [string]$TemplateData.MachineObjectOU
    if ($PSBoundParameters.ContainsKey('MachineObjectOU')) {
        $ResolvedMachineObjectOU = $MachineObjectOU
        Write-PAWLog -Message "MachineObjectOU overridden by parameter: $ResolvedMachineObjectOU" -LogPath $LogPath
    }

    # Create unattend xml
    $unattendParameters = @{
        Computername = $OSDComputerName
        OSDAdapter0IPAddressList = $OSDAdapter0IPAddressList
        DomainOrWorkGroup = $ResolvedDomainOrWorkGroup
        ProtectYourPC = 3
        OSDAdapter0Gateways = $OSDAdapter0Gateways
        OSDAdapter0DNS1 = $OSDAdapter0DNS1
        OSDAdapter0DNS2 = $OSDAdapter0DNS2
        OSDAdapter0SubnetMaskPrefix = $OSDAdapter0SubnetMaskPrefix
        OrgName = $CustomerData.OrgName
        Fullname = $CustomerData.FullName
        TimeZoneName = $ResolvedTimeZoneName
        DNSDomain = $($TemplateData.DNSDomain)
        DomainJoinAccount = $DomainJoinAccount
        DomainJoinAccountPassword = $NonSecureDomainJoinAccountPassword
        DomainName = $TemplateData.DNSDomain
        MachineObjectOU = $ResolvedMachineObjectOU
        AdminPassword = $NonSecureAdminPassword
        ProductKey = $ProductKey
        Path = "$PAWTempFolder\Unattend.xml"
        InputLocale = $ResolvedInputLocale
        SystemLocale = $ResolvedSystemLocale
        UILanguage = $ResolvedUILanguage
        UserLocale = $ResolvedUserLocale
    }
    try {
        switch ($TemplateData.OSClass) {
            'Client' { $PAWUnattendXML = New-PAWUnattendXMLClient @unattendParameters }
            'Server' { $PAWUnattendXML = New-PAWUnattendXMLServer @unattendParameters }
            default  { $PAWUnattendXML = New-PAWUnattendXMLClient @unattendParameters }
        }
    }
    finally {
        $unattendParameters.Clear()
        $unattendParameters = $null
        $NonSecureDomainJoinAccountPassword = $null
    }
    Write-Verbose "Created $($PAWUnattendXML.FullName)"
    $PAWSetupCompletecmdCommand = "cmd.exe /c PowerShell.exe -Command New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest' -Name OSDeployment -Value Done -PropertyType String"
    $PAWSetupCompletecmd = New-PAWSetupCompleteCMD -Path $PAWTempFolder -Command $PAWSetupCompletecmdCommand
    Write-Verbose "Created $($PAWSetupCompletecmd.FullName)"

    $VMDisks = @(Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop)
    if ($VMDisks.Count -ne 1) { throw 'Expected exactly one deployment disk.' }
    $VMVHDFile = $VMDisks[0]
    if ((Get-DiskImage -ImagePath $VMVHDFile.Path -ErrorAction Stop).Attached) {
        throw 'Deployment disk is already mounted; refusing to claim its mount.'
    }
    $CleanupState.MountedVHD = $VMVHDFile.Path
    Save-PAWDeploymentState -State $CleanupState
    Mount-PAWVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder -ErrorAction Stop
    Write-PAWConsoleLog -Message "Mounted {0} in {1}" -Type Info -Value $VMVHDFile.Path, $MountFolder

    # Check if Extrafolder is provided, if not ignore it, if provided, create the folder and copy the files
    if ($Null -ne $ExtraFolder) {
        $ExtraFolderName = $ExtraFolder | Split-Path -Leaf
        Write-Verbose "ExtraFolder is set to $ExtraFolder"
        if (Test-Path -path "$MountFolder\$ExtraFolderName") {
            Write-Warning "Folder $MountFolder\$ExtraFolderName already exists"
            throw "PAWDeploy terminated due to previous error."
        }
        else {
            $Result = New-Item -Path "$MountFolder\$ExtraFolderName" -ItemType Directory
            Write-Verbose "Folder $($Result.FullName) was created"

            # Check if the ExtraFolder contains files to copy
            if (Test-Path -Path "$ExtraFolder") {
                Write-Verbose "Copying files from $ExtraFolder to $MountFolder\$ExtraFolderName"
                Copy-PAWDirectory -Source $ExtraFolder -Destination "$MountFolder\$ExtraFolderName" -LogPath $LogPath -ErrorAction Stop
                Write-Verbose "Files copied to $MountFolder\$ExtraFolderName"

                $PAWUtilityModuleSource = Join-Path $PSScriptRoot 'Functions\PAWUtility'
                $PAWUtilityModuleDestination = "$MountFolder\$ExtraFolderName\Functions\PAWUtility"
                if (Test-Path -Path $PAWUtilityModuleSource) {
                    Write-Verbose "Copying PAWUtility module to $PAWUtilityModuleDestination"
                    Copy-PAWDirectory -Source $PAWUtilityModuleSource -Destination $PAWUtilityModuleDestination -LogPath $LogPath -ErrorAction Stop
                }
                else {
                    Write-Warning "Could not find PAWUtility module at $PAWUtilityModuleSource"
                }
            }
            else {
                Write-Warning "No files found in $ExtraFolder, skipping copy"
            }
        }
    }
    else {
        Write-PAWConsoleLog -Message "No ExtraFolder provided, skipping" -Type Info
    }

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if (-not $SkipApplication) {
            if (-not $PAWResourcesRoot -or -not (Test-Path -LiteralPath $PAWResourcesRoot -PathType Container)) {
                throw 'Application Resources folder could not be resolved or does not exist.'
            }
            $applicationDestination = Join-Path $MountFolder 'PAWFiles\AppInstall'
            $applicationModuleSource = Join-Path $PSScriptRoot 'Functions\PAWUtility'
            $applicationModuleDestination = Join-Path $MountFolder 'PAWFiles\Functions\PAWUtility'
            foreach ($destination in @($applicationDestination, $applicationModuleDestination)) {
                if (Test-Path -LiteralPath $destination) {
                    throw "Application staging destination already exists; refusing to overwrite unrelated Copy Folder/image content: $destination"
                }
            }
            $null = New-Item -Path (Split-Path -Parent $applicationDestination) -ItemType Directory -Force
            $null = New-Item -Path $applicationDestination -ItemType Directory -Force
            Copy-Item -LiteralPath $PAWAppInstallHostScript -Destination $applicationDestination -Force -ErrorAction Stop
            $null = New-Item -Path (Split-Path -Parent $applicationModuleDestination) -ItemType Directory -Force
            Copy-PAWDirectory -Source $applicationModuleSource -Destination $applicationModuleDestination -LogPath $LogPath -ErrorAction Stop

            $selectedApplications = @($preflight.ApplicationPlan.Applications | Where-Object InstallEnabled)
            $installFileSourceRoot = Join-Path $PAWResourcesRoot 'Applications\InstallFiles'
            $installFileDestinationRoot = Join-Path $applicationDestination 'Applications'
            $installFileApplications = @($selectedApplications | Where-Object Source -in @('WinGet', 'Local'))
            if ($installFileApplications.Count -gt 0) {
                $null = New-Item -Path $installFileDestinationRoot -ItemType Directory -Force
                foreach ($application in $installFileApplications) {
                    $sourceInstallFile = Get-PAWApplicationInstallFilePath -InstallRoot $installFileSourceRoot -Name $application.Name
                    if (-not (Test-Path -LiteralPath $sourceInstallFile -PathType Leaf)) {
                        throw "Application install file was not found: $sourceInstallFile"
                    }
                    Copy-Item -LiteralPath $sourceInstallFile -Destination $installFileDestinationRoot -Force -ErrorAction Stop
                }
            }

            foreach ($application in $selectedApplications) {
                switch ($application.Source) {
                    'WinGet' {
                        $sourceCache = Get-PAWWinGetCacheFolder -CacheRoot $PAWApplicationDownloadsRoot -Name $application.Name
                        $destinationCache = Get-PAWWinGetCacheFolder -CacheRoot (Join-Path $applicationDestination 'Downloads') -Name $application.Name
                        Copy-PAWDirectory -Source $sourceCache -Destination $destinationCache -LogPath $LogPath -ErrorAction Stop
                    }
                    'Local' {
                        $sourceLocal = Get-PAWLocalApplicationFolder -LocalRoot (Join-Path $PAWApplicationDownloadsRoot 'Local') -Name $application.Name
                        $destinationLocal = Get-PAWLocalApplicationFolder -LocalRoot (Join-Path $applicationDestination 'Local') -Name $application.Name
                        Copy-PAWDirectory -Source $sourceLocal -Destination $destinationLocal -LogPath $LogPath -ErrorAction Stop
                    }
                }
            }

            $moduleApplications = @($selectedApplications | Where-Object { $_.Source -eq 'PSGallery' -and $null -eq $_.Options })
            if ($moduleApplications.Count -gt 0) {
                $moduleCacheRoot = Join-Path $PAWApplicationDownloadsRoot 'Modules'
                $moduleQueue = New-Object 'System.Collections.Generic.Queue[string]'
                foreach ($application in $moduleApplications) { $moduleQueue.Enqueue([string]$application.Id) }
                $moduleFolders = @{}
                while ($moduleQueue.Count -gt 0) {
                    $moduleName = $moduleQueue.Dequeue()
                    if ($moduleFolders.ContainsKey($moduleName)) { continue }
                    $moduleFolder = Join-Path $moduleCacheRoot $moduleName
                    $versionFolder = Get-ChildItem -LiteralPath $moduleFolder -Directory -ErrorAction Stop |
                        Where-Object { $_.Name -as [version] } |
                        Sort-Object { [version]$_.Name } -Descending |
                        Select-Object -First 1
                    if ($null -eq $versionFolder) { throw "Cached PowerShell module '$moduleName' was not found under '$moduleFolder'." }
                    $manifestPath = Join-Path $versionFolder.FullName "$moduleName.psd1"
                    $manifest = Import-PowerShellDataFile -LiteralPath $manifestPath -ErrorAction Stop
                    $moduleFolders[$moduleName] = $versionFolder
                    foreach ($dependency in @($manifest.RequiredModules)) {
                        $dependencyName = if ($dependency -is [System.Collections.IDictionary]) { [string]$dependency.ModuleName } else { [string]$dependency }
                        if (-not [string]::IsNullOrWhiteSpace($dependencyName)) { $moduleQueue.Enqueue($dependencyName) }
                    }
                }
                foreach ($versionFolder in $moduleFolders.Values) {
                    $relativeModulePath = $versionFolder.FullName.Substring($moduleCacheRoot.Length).TrimStart('\')
                    $destinationModule = Join-Path (Join-Path $applicationDestination 'Downloads\Modules') $relativeModulePath
                    Copy-PAWDirectory -Source $versionFolder.FullName -Destination $destinationModule -LogPath $LogPath -ErrorAction Stop
                }
            }

            $stagedPackagesRoot = Join-Path $applicationDestination 'Packages'
            $selectedTypedApplications = @($preflight.ApplicationPlan.Applications | Where-Object {
                $_.InstallEnabled -and ($_.Source -in @('Classic', 'WindowsComponent') -or
                    ($_.Source -eq 'PSGallery' -and $null -ne $_.Options))
            })
            if ($selectedTypedApplications.Count -gt 0) {
                $null = New-Item -Path $stagedPackagesRoot -ItemType Directory -Force
                foreach ($application in $selectedTypedApplications) {
                    $sourcePackage = Join-Path $PAWResourcesRoot "Applications\Packages\$($application.ApplicationId)"
                    if (Test-Path -LiteralPath $sourcePackage -PathType Container) {
                        Copy-PAWDirectory -Source $sourcePackage -Destination (Join-Path $stagedPackagesRoot ([string]$application.ApplicationId)) -LogPath $LogPath -ErrorAction Stop
                    }
                    else {
                        $null = New-Item -Path (Join-Path $stagedPackagesRoot ([string]$application.ApplicationId)) -ItemType Directory -Force
                    }
                }
            }
            $applicationSnapshot = [ordered]@{
                BundleId = $preflight.ApplicationPlan.BundleId
                Applications = @($preflight.ApplicationPlan.Applications)
            }
            foreach ($application in $installFileApplications) {
                $installFile = Get-PAWApplicationInstallFilePath -InstallRoot $installFileDestinationRoot -Name $application.Name
                $installData = Get-Content -LiteralPath $installFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $installData.Settings = $preflight.ApplicationPlan.Settings[$application.Name]
                [IO.File]::WriteAllText($installFile, ($installData | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
            }
            [IO.File]::WriteAllText((Join-Path $applicationDestination 'Applications.json'),
                ($applicationSnapshot | ConvertTo-Json -Depth 20), (New-Object Text.UTF8Encoding($false)))
            foreach ($requiredFile in @(
                (Join-Path $applicationDestination 'Invoke-PAWInstallApplications.ps1'),
                (Join-Path $applicationDestination 'Applications.json'),
                (Join-Path $applicationModuleDestination 'PAWUtility.psd1')
            )) {
                if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
                    throw "Required staged application file is missing: $requiredFile"
                }
            }
            $ApplicationFilesStaged = $true
            Write-PAWConsoleLog -Message 'Selected application payload staged in C:\PAWFiles\AppInstall' -Type Info
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Application staging' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        $customScriptsSource = Resolve-PAWCustomScriptsFolder -InstallFolderPath $PSScriptRoot
        $customScriptsDestination = Join-Path $MountFolder 'PAWFiles\CustomScripts'
        if (-not (Test-Path -LiteralPath $customScriptsSource -PathType Container)) {
            throw "CustomScripts folder does not exist: $customScriptsSource"
        }
        if (Test-Path -LiteralPath $customScriptsDestination) {
            throw "CustomScripts staging destination already exists; refusing unrelated content: $customScriptsDestination"
        }
        $null = New-Item -Path (Split-Path -Parent $customScriptsDestination) -ItemType Directory -Force
        Copy-PAWDirectory -Source $customScriptsSource -Destination $customScriptsDestination -LogPath $LogPath -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $customScriptsDestination -PathType Container)) {
            throw "CustomScripts staging was not verified: $customScriptsDestination"
        }
        $CustomScriptsStaged = $true
    }
    catch { Write-PAWOptionalFailure -Step 'RunScript staging' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    # Create PreventLAPS.txt only for domain-joined deployments when -NoLaps is not set.
    $CreatePreventLAPSMarker = ($ResolvedDomainOrWorkGroup -eq 'Domain') -and (-not $NoLaps.IsPresent)
    if ($CreatePreventLAPSMarker) {
        $PreventLAPSFile = New-Item -Path "$MountFolder\PreventLAPS.txt" -ItemType File -Value "This is a PAW VM, do not install LAPS on this machine"
        Write-Verbose "Created $($PreventLAPSFile.FullName)"
    }
    else {
        if ($ResolvedDomainOrWorkGroup -ne 'Domain') {
            Write-PAWConsoleLog -Message "Workgroup deployment detected; skipping PreventLAPS.txt creation" -Type Info
        }
        elseif ($NoLaps.IsPresent) {
            Write-PAWConsoleLog -Message "NoLaps is set; skipping PreventLAPS.txt creation" -Type Info
        }
    }

    # Ensure the offline image has a clean staging path for unattend injection.
    # If Panther already exists we stop to avoid overwriting a previous or partial deployment state.
    if (Test-Path -path "$MountFolder\Windows\Panther") {
        Write-PAWConsoleLog -Message "Folder $MountFolder\Windows\Panther already exists" -Type Warning
        throw "PAWDeploy terminated due to previous error."
    }
    else {
        $Result = New-Item -Path "$MountFolder\Windows\Panther" -ItemType Directory
        Write-Verbose "Folder $($Result.FullName) was created"
    }

    if (Test-Path -path "$MountFolder\Windows\Setup\Scripts") {
        Write-Warning "Folder $MountFolder\Windows\Setup\Scripts"
        throw "PAWDeploy terminated due to previous error."
    }
    else {
        $Result = New-Item -Path "$MountFolder\Windows\Setup\Scripts" -ItemType Directory
        Write-Verbose "Folder $($Result.FullName) was created"
    }

    $CleanupState.OfflineSetupFiles = @(
        "$MountFolder\Windows\Panther\$($PAWUnattendXML.Name)",
        "$MountFolder\Windows\Setup\Scripts\$($PAWSetupCompletecmd.Name)"
    )
    Copy-Item -Path $PAWUnattendXML.FullName -Destination "$MountFolder\Windows\Panther\$($PAWUnattendXML.Name)" -ErrorAction Stop
    Write-Verbose "$($PAWUnattendXML.FullName) was copied to $MountFolder\Windows\Panther\$($PAWUnattendXML.Name)"

    Copy-Item -Path $PAWSetupCompletecmd.FullName -Destination "$MountFolder\Windows\Setup\Scripts\$($PAWSetupCompletecmd.Name)" -ErrorAction Stop
    Write-Verbose "$($PAWSetupCompletecmd.FullName) was copied to $MountFolder\Windows\Setup\Scripts\$($PAWSetupCompletecmd.Name)"

    # --- Security Baseline Copy: now occurs after VM creation and mounting ---
    $SecurityBaselineCopiedToImage = $false
    $ResolvedSecurityBaselineLocation = $null

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($SkipSecurityBaseLine -or [string]::IsNullOrWhiteSpace([string]$TemplateData.SecurityBaselineLocation) -or
            ([string]$TemplateData.SecurityBaselineLocation).Trim() -eq 'NA') {
            $SecurityBaselineCopiedToImage = $false
            $ResolvedSecurityBaselineLocation = $null
        }
        else {
            try {
                $ResolvedSecurityBaselineLocation = Resolve-PAWSecurityBaselinePath -ConfigPath $ConfigDataFile -SecurityBaselineLocationValue ([string]$TemplateData.SecurityBaselineLocation)
            }
            catch {
                throw
            }
            if ((Test-Path -Path $ResolvedSecurityBaselineLocation) -eq $true) {
                Write-PAWLog -Message "Copying Security Baselines from $ResolvedSecurityBaselineLocation" -LogPath $LogPath -OutputMode Console -ConsoleType Info -Value $ResolvedSecurityBaselineLocation -ConsoleMessage "Copying Security Baselines from {0}"
                Copy-PAWDirectory -Source $ResolvedSecurityBaselineLocation -Destination "$MountFolder\SECBL" -LogPath $LogPath -ErrorAction Stop
                $SecurityBaselineCopiedToImage = $true
            }
            else {
                throw "Security baseline directory not found: $ResolvedSecurityBaselineLocation"
            }
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Security baseline copy' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }
    Write-PAWConsoleLog -Message "Dismounting VHD file" -Type Info
    Dismount-PAWVHDInFolder -VHDfile $VMVHDFile.Path -MountFolder $MountFolder
    if ((Get-DiskImage -ImagePath $VMVHDFile.Path -ErrorAction Stop).Attached) {
        throw 'Deployment disk remains mounted after staging.'
    }
    $CleanupState.MountedVHD = $null
    $CleanupState.OfflineSetupFiles = $null
    Save-PAWDeploymentState -State $CleanupState

    Write-Verbose "Removing $($PAWUnattendXML.FullName)"
    Remove-Item -Path $PAWUnattendXML.FullName

    Write-Verbose "Removing $($PAWSetupCompletecmd.FullName)"
    Remove-Item -Path $PAWSetupCompletecmd.FullName

    # set VLAN ID for the VM if not provided
    if ($PSBoundParameters.ContainsKey('VlanID') -eq $False) {
        $VLanID = $TemplateData.VLanID
    }

    #Set VLANid for NIC01
    Write-Verbose "Setting VLAN $VLanID"
    Set-VMNetworkAdapterVlan -VMName $VMName -VlanId $VLanID -Access

    #Adjust memory
    if ($ResolvedDynamicMem) {
        Write-Verbose "Enable Dynamic Memory"
        Set-VMMemory -VMName $VMname -DynamicMemoryEnabled $True
    }

    # Disable AutomaticCheckpointsEnabled
    if ((Get-VM $VMName).AutomaticCheckpointsEnabled -eq $true) {
        Write-Verbose "Disable AutomaticCheckpointsEnabled"
        Get-VM -Name $VMname | Set-VM -AutomaticCheckpointsEnabled 0 -ErrorAction SilentlyContinue
    }

    # Set BatteryPassthroughEnabled
    Write-Verbose "Set BatteryPassthroughEnabled"
    Get-VM -Name $VMname | Set-VM -BatteryPassthroughEnabled $true

    # Create VM Protector for the VM and enable TPM
    Write-Verbose "Create VM Protector for the VM and enable TPM"
    Set-VMKeyProtector -VMName $VMname -NewLocalKeyProtector
    Get-VM -Name $VMname | Enable-VMTPM

    # Set-VMProcessor -ExposeVirtualizationExtensions
    Write-Verbose "Enable ExposeVirtualizationExtensions on VM"
    Set-VMProcessor -ExposeVirtualizationExtensions $True -VMName $VMname

    #endregion

    #region Deploy VM

    #Deploy VM    
    Write-PAWConsoleLog -Message "Starting {0}" -Type Info -Value "$VMname"
    Start-VM -VMname $VMname -ErrorAction Inquire
    Wait-PAWVMIsRunning -VMname $VMname

    # Generate credentials for the VM
    Write-Verbose "Generate credentials for the VM"
    $Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ".\Administrator", $AdminPassword

    # Wait for the VM to start
    Write-PAWConsoleLog -Message "Wait for the VM to have IC loaded" -Type Wait
    Wait-PAWVMHaveICLoaded -VMname $VMname
    Write-PAWConsoleLog -Message "Wait for the VM to have an IP address" -Type Wait
    Wait-PAWVMHaveIP -VMname $VMname
    Write-PAWConsoleLog -Message "Wait for the VM to write complete in KVP" -Type Wait
    Wait-PAWVMDeployment -VMname $VMName
    Write-PAWConsoleLog -Message "Wait for the VM accept PowerShell Direct" -Type Wait
    Wait-PAWVMHavePSDirect -VMname $VMName -Credentials $Cred   
    Write-PAWConsoleLog -Message "Wait for the VM to complete OOBE" -Type Wait
    Wait-PAWVMCompleteOOBE -VMname $VMname -Credentials $Cred   

    Write-PAWConsoleLog -Message "Waiting is over, moving on" -Type Info

    Write-PAWConsoleLog -Message "Pausing Windows Update during deployment" -Type Info
    $null = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMName -Credential $Cred -ScriptBlock {
        $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        if (-not (Test-Path $auPath)) { New-Item -Path $auPath -Force | Out-Null }
        Set-ItemProperty -Path $auPath -Name NoAutoUpdate -Value 1 -Type DWord
        Set-ItemProperty -Path $auPath -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord
        Stop-Service -Name wuauserv, UsoSvc -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }


    # Connect and clear vTPM
    Write-PAWConsoleLog -Message "Connect and clear vTPM" -Type Info
    $ScriptBlock = {
        Initialize-Tpm -AllowClear -WarningAction SilentlyContinue
    }
    Write-PAWConsoleLog -Message "Clearing vTPM" -Type Info
    $Result = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred
    Write-PAWConsoleLog -Message "Status for vTPM: $($Result.tpmready)" -Type Info


    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if (-not $SkipDiskEncryptionRequested) {
            Write-PAWLog -Message "Disk encryption is enabled (default)" -LogPath $LogPath -OutputMode Console -ConsoleType Info
    
            # Connect and enable bitlocker
            Write-PAWConsoleLog -Message "Connect and enable bitlocker" -Type Info
            $ScriptBlock = {
                $bitLockerWarnings = @()
                $failure = $null
                try {
                    $null = Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -TPMProtector -UsedSpaceOnly `
                        -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable bitLockerWarnings
                }
                catch { $failure = $_.Exception.Message }
                [pscustomobject]@{
                    Warnings = @($bitLockerWarnings | ForEach-Object { $_.Message })
                    Failure = $failure
                }
            }
            Write-PAWConsoleLog -Message "Enable Bitlocker" -Type Info
            $bitLockerResult = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred
            if ($null -eq $bitLockerResult -or $null -eq $bitLockerResult.PSObject.Properties['Warnings'] -or
                $null -eq $bitLockerResult.PSObject.Properties['Failure']) {
                throw 'BitLocker did not return a valid result from the guest.'
            }
            foreach ($warning in @($bitLockerResult.Warnings)) {
                $warningText = ([string]$warning -replace '\s+', ' ').Trim()
                Write-PAWLog -Level WARN -Message "BitLocker: $warningText" -LogPath $LogPath -OutputMode Console -ConsoleType Warning
            }
            if ($null -ne $bitLockerResult.Failure) {
                if ([string]::IsNullOrWhiteSpace([string]$bitLockerResult.Failure)) {
                    throw 'BitLocker failed in the guest without an error message.'
                }
                throw [string]$bitLockerResult.Failure
            }
            $DiskEncryptionStarted = $true
            Write-PAWConsoleLog -Message "Bitlocker enabled on C: drive" -Type Info
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Disk encryption enable' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    # Connect and enable VBS
    Write-PAWConsoleLog -Message "Connect and Virtual Based Security" -Type Info
    $ScriptBlock = {
        $Null = Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart -WarningAction SilentlyContinue
        $Null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
        $Null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1
        $Null = Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1
    }
    Write-PAWConsoleLog -Message "Enable Virtual Based Security" -Type Info
    $Null = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred
    Write-PAWConsoleLog -Message "Virtual Based Security is enabled" -Type Info

    # Add logic to enable autologon in the VM at next startup, this is needed to apply the shielded policy without having to log in to the VM first and to avoid dual logons at first usage.
    $ScriptBlock = {
        param($NonSecureAdminPassword)
        #Write-Host -ForegroundColor Green "Enabling autologon for the local administrator account"
        $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        Set-ItemProperty -Path $RegPath -Name "AutoAdminLogon" -Value "1" -Type String
        Set-ItemProperty -Path $RegPath -Name "DefaultUsername" -Value "Administrator" -Type String
        Set-ItemProperty -Path $RegPath -Name "DefaultPassword" -Value $NonSecureAdminPassword -Type String
    }
    Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred -ArgumentList $NonSecureAdminPassword 6>$null
    $NonSecureAdminPassword = $null

    # Restart the VM
    Write-PAWConsoleLog -Message "Restarting {0}" -Type Info -Value $VMname
    Close-PAWPSDirectSessionContext -SessionContext $PSDirectContext
    Stop-PAWVM -VMName $VMname
    Start-VM -Name $VMname -ErrorAction Stop

    # Wait for the VM to start
    Write-PAWConsoleLog -Message  "Wait for the VM to have IC loaded" -Type Wait
    Wait-PAWVMHaveICLoaded -VMname $VMname
    Write-PAWConsoleLog -Message "Wait for the VM to have an IP address" -Type Wait
    Wait-PAWVMHaveIP -VMname $VMname
    Write-PAWConsoleLog -Message "Wait for the VM accept PowerShell Direct" -Type Wait
    Wait-PAWVMHavePSDirect -VMname $VMName -Credentials $Cred
    Write-PAWConsoleLog -Message "Wait for the VM to complete OOBE" -Type Wait
    Wait-PAWVMCompleteOOBE -VMname $VMname -Credentials $Cred 
    Write-PAWConsoleLog -Message "Waiting is over, moving on" -Type Info

    # A pending feature/update restart would otherwise be taken by the guest itself later in the deployment.
    Write-PAWConsoleLog -Message "Checking {0} for pending restarts" -Type Info -Value $VMname
    $null = Restart-PAWVMIfRebootPending -VMName $VMname -Credential $Cred

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($DiskEncryptionStarted) {
            # Connect and enable bitlocker
            Write-PAWConsoleLog -Message "Connect and encrypt disk" -Type Info
            $ScriptBlock = {
                $deadline = [Diagnostics.Stopwatch]::StartNew()
                do {
                    $volume = Get-BitLockerVolume -MountPoint C: -ErrorAction Stop
                    if ($volume.VolumeStatus -eq 'FullyEncrypted') { break }
                    if ($volume.VolumeStatus -ne 'EncryptionInProgress') {
                        throw "Disk encryption is not progressing. State: $($volume.VolumeStatus); protection: $($volume.ProtectionStatus)."
                    }
                    if ($deadline.Elapsed.TotalHours -ge 2) { throw 'Disk encryption did not complete within two hours.' }
                    $EncryptionPercentage = $volume.EncryptionPercentage
                
                
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor DarkGray
                    Write-Host -ForegroundColor Gray "Percentage of disk encrypted: $EncryptionPercentage"

                    Start-Sleep -Seconds 15
                }
                until ($false)
                $EncryptionPercentage = $volume.EncryptionPercentage
                Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor DarkGray
                Write-Host -ForegroundColor Gray "Percentage of disk encrypted: $EncryptionPercentage"
            }
            Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -ScriptBlock $ScriptBlock -Credential $Cred -RetryCommand 6>$null
            Write-PAWConsoleLog -Message "Disk encryption is done" -Type Info
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Disk encryption completion' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    # check if the VM should be shielded
    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($EnableShieldingRequested) {
            Write-PAWConsoleLog -Message "Shielded VM is set to True" -Type Info

            # Stop VM before applying shielded security policy.
            Write-PAWConsoleLog -Message "Stopping VM before applying shielded policy" -Type Info
            Close-PAWPSDirectSessionContext -SessionContext $PSDirectContext
            Stop-PAWVM -VMName $VMname

            # Apply VM shielding policy.
            Write-PAWConsoleLog -Message "Applying shielded security policy" -Type Info
            Get-VM -Name $VMname | Set-VMSecurityPolicy -Shielded $true -ErrorAction Stop

            # Start VM after applying shielding.
            Write-PAWConsoleLog -Message "Starting VM after applying shielded policy" -Type Info
            Start-VM -Name $VMname -ErrorAction Stop

            # Wait for the VM to start
            Write-PAWConsoleLog -Message "Wait for the VM to have IC loaded" -Type Wait
            Wait-PAWVMHaveICLoaded -VMname $VMname
            Write-PAWConsoleLog -Message "Wait for the VM to have an IP address" -Type Wait
            Wait-PAWVMHaveIP -VMname $VMname
            Write-PAWConsoleLog -Message "Wait for the VM accept PowerShell Direct" -Type Wait
            Wait-PAWVMHavePSDirect -VMname $VMName -Credentials $Cred
            Write-PAWConsoleLog -Message "Waiting is over, moving on" -Type Info

        }
        else {
            Write-PAWConsoleLog -Message "Shielded VM is set to False, skipping" -Type Info
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Shielding' -Reason $_.Exception.Message
        try {
            if ([string](Get-VM -Name $VMName -ErrorAction Stop).State -eq 'Off') {
                Start-VM -Name $VMName -ErrorAction Stop
                Wait-PAWVMHavePSDirect -VMname $VMName -Credentials $Cred
            }
        }
        catch { Write-PAWOptionalFailure -Step 'Shielding recovery' -Reason $_.Exception.Message } }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    # Run only a filename from the independently staged CustomScripts directory.
    $PathToExtraFolderInsideVM = 'C:\PAWFiles\CustomScripts'
    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($RunScript -eq 'NA') {
            Write-PAWConsoleLog -Message "RunScript is NA, skipping extra script execution" -Type Warning
        }
        else {
            if (-not $CustomScriptsStaged) { throw 'CustomScripts were not staged; RunScript skipped.' }
            if ($RunScript -ne [IO.Path]::GetFileName($RunScript) -or
                [IO.Path]::GetExtension($RunScript) -ne '.ps1' -or
                $RunScript.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw 'RunScript must be a .ps1 filename in CustomScripts, without directory paths.'
            }
            $runScriptPathInsideVM = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMname -Credential $Cred -ArgumentList $PathToExtraFolderInsideVM, $RunScript -ScriptBlock {
                param($CustomScriptsPath, $ScriptName)
                $candidate = Join-Path $CustomScriptsPath $ScriptName
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return $candidate
                }
            } | Select-Object -Last 1
            $runScriptExists = -not [string]::IsNullOrWhiteSpace([string]$runScriptPathInsideVM)
            if (-not $runScriptExists) {
                $runScriptPathInsideVM = Join-Path $PathToExtraFolderInsideVM $RunScript
            }

            if (-not $runScriptExists) {
                throw "RunScript was not found: $runScriptPathInsideVM"
            }
            else {
                Write-PAWConsoleLog -Message "RunScript {0} exists, running it" -Type Info -Value $runScriptPathInsideVM
                $runScriptResult = Invoke-PAWPSDirect -VMName $VMname -Credential $Cred -ArgumentList $runScriptPathInsideVM -ScriptBlock {
                    param($ScriptPath)
                    $savedPreference = $ErrorActionPreference
                    $savedLocation = Get-Location
                    try {
                        Set-Location -LiteralPath (Split-Path -Parent $ScriptPath) -ErrorAction Stop
                        $ErrorActionPreference = 'Continue'
                        $output = @(& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $ScriptPath 2>&1)
                        $exitCode = $LASTEXITCODE
                    }
                    finally {
                        Set-Location -LiteralPath $savedLocation.Path -ErrorAction Stop
                        $ErrorActionPreference = $savedPreference
                    }
                    [pscustomobject]@{
                        ExitCode = $exitCode
                        HadErrors = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count -gt 0
                        Output = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
                    }
                } | Select-Object -Last 1
                if ($null -eq $runScriptResult -or $runScriptResult.PSObject.Properties.Match('ExitCode').Count -eq 0) {
                    throw 'RunScript did not return a verifiable exit code.'
                }
                $runScriptExitCode = $runScriptResult.ExitCode
                if ($runScriptResult.Output) {
                    Write-PAWLog -Message "RunScript output:`n$($runScriptResult.Output)" -LogPath $LogPath
                }
                if ($runScriptExitCode -eq 0 -and -not $runScriptResult.HadErrors) {
                    Write-PAWLog -Message "RunScript $runScriptPathInsideVM completed with exit code 0" -LogPath $LogPath -OutputMode Console -ConsoleType Info -Value $RunScript -ConsoleMessage "RunScript {0} executed successfully"
                }
                else {
                    throw "RunScript '$runScriptPathInsideVM' failed/reported errors (exit code $runScriptExitCode). $($runScriptResult.Output)"
                }
            }
        }
    }
    catch { Write-PAWOptionalFailure -Step 'RunScript' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }
    #region PAWAppInstall
    # Run PAWAppInstall inside the VM after all security configuration.
    # Host initiates one application at a time and each install runs fully in the guest.
    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if (-not $SkipApplication) {
            if ($ApplicationFilesStaged) {
                $PAWAppInstallCacheInsideVM = 'C:\PAWFiles\AppInstall\Downloads'
                $PAWAppInstallApplicationsInsideVM = 'C:\PAWFiles\AppInstall\Applications.json'
                if (-not (Test-Path -LiteralPath $PAWAppInstallHostScript -PathType Leaf)) {
                    throw "Configured application installer not found: $PAWAppInstallHostScript"
                }

                if ($null -ne $PAWAppInstallHostScript) {
                    Write-PAWConsoleLog -Message "Running PAWAppInstall inside VM (host-initiated per application)" -Type Info
                    Write-PAWConsoleLog -Message "Host script      : {0}" -Type Info -Value $PAWAppInstallHostScript
                    Write-PAWConsoleLog -Message "Application bundle: {0}" -Type Info -Value $preflight.ApplicationPlan.BundleId
                    Write-PAWConsoleLog -Message "CacheRoot in VM  : {0}" -Type Info -Value $PAWAppInstallCacheInsideVM
                    try {
                        $hostApplications = @($preflight.ApplicationPlan.Applications | Where-Object { $_.InstallEnabled })

                        if ($hostApplications.Count -eq 0) {
                            Write-PAWConsoleLog -Message "No enabled applications found. Skipping PAWAppInstall application stage." -Type Warning
                        }

                        $scriptContent = Get-Content -Path $PAWAppInstallHostScript -Raw
                        $remoteInstallScriptBlock = {
                            param($ScriptBody, $CacheRoot, $ApplicationsPath, $ApplicationName)
                            $ErrorActionPreference = 'Stop'
                            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
                            $remoteScriptBlock = [scriptblock]::Create($ScriptBody)
                            & $remoteScriptBlock -CacheRoot $CacheRoot -ApplicationsPath $ApplicationsPath -Name $ApplicationName
                        }

                        $applicationTotal = $hostApplications.Count
                        $applicationIndex = 0
                        foreach ($package in $hostApplications) {
                            $applicationIndex++
                            Write-PAWConsoleLog -Message "[$applicationIndex/$applicationTotal] Initiating application install from host: {0}" -Type Info -Value $package.Name
                            try {
                                Invoke-PAWPSDirect -VMName $VMname -Credential $Cred -ScriptBlock $remoteInstallScriptBlock -ArgumentList $scriptContent, $PAWAppInstallCacheInsideVM, $PAWAppInstallApplicationsInsideVM, $package.Name -RetryCommand |
                                    ForEach-Object {
                                        $text = [string]$_
                                        if (-not [string]::IsNullOrWhiteSpace($text)) {
                                            Write-PAWConsoleLog -Message "[$($package.Name)] {0}" -Type Info -Value $text
                                        }
                                    }
                                Write-PAWConsoleLog -Message "[$applicationIndex/$applicationTotal] Application completed: {0}" -Type Info -Value $package.Name
                                if ($applicationIndex -lt $applicationTotal) {
                                    Write-PAWConsoleLog -Message "Waiting 5 seconds before starting next application..." -Type Wait
                                    Start-Sleep -Seconds 5
                                }
                            }
                            catch {
                                Write-PAWOptionalFailure -Step "Application $($package.Name)" -Reason $_.Exception.Message
                            }
                        }

                        if ($hostApplications.Count -gt 0) {
                            Write-PAWConsoleLog -Message "PAWAppInstall application processing finished" -Type Info
                        }

                    }
                    catch {
                        throw
                    }
                    Write-PAWConsoleLog -Message "PAWAppInstall processing finished; see final report for failures" -Type Info
                }
                else {
                    throw "Configured application installer not found: $PAWAppInstallHostScript"
                }
            }
            else {
                throw 'Application files were not staged into the VM; application installation skipped.'
            }
        }
        else {
            Write-PAWConsoleLog -Message "SkipApplication is set; skipping PAWAppInstall" -Type Info
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Application install' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    #endregion PAWAppInstall

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if (-not $SkipSecurityBaseLine -and $TemplateData.ApplySecurityBaseline -eq "True" -and
            ([string]$TemplateData.SecurityBaselineLocation).Trim() -ne 'NA') {
            if (-not $SecurityBaselineCopiedToImage) {
                throw 'Security baseline files were not copied into the VM image; application skipped.'
            }
            else {
                $SecurityBaselineApplyResult = $null
                $SecurityBaselineApplied = $false
                $SecurityBaselineApplyReason = $null

                $SecurityBaselineScriptBlock = {
                    param($OSBaselineSwitch)
                    foreach ($baselineType in @('OS', 'Edge')) {
                        $baselineScript = "C:\SECBL\$baselineType\Scripts\Baseline-LocalInstall.ps1"
                        $output = @()
                        $applied = $false
                        $reason = $null
                        try {
                            if (-not (Test-Path -LiteralPath $baselineScript -PathType Leaf)) {
                                throw "Baseline script not found: $baselineScript"
                            }
                            $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $baselineScript)
                            if ($baselineType -eq 'OS') {
                                $parseErrors = $null
                                $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($baselineScript, [ref]$null, [ref]$parseErrors)
                                if ($parseErrors.Count) { throw "Baseline script parse error: $($parseErrors -join '; ')" }
                                $parameters = @($scriptAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
                                if ($parameters -notcontains $OSBaselineSwitch) {
                                    throw "OS baseline does not support -$OSBaselineSwitch. Available parameters: $($parameters -join ', ')."
                                }
                                $arguments += "-$OSBaselineSwitch"
                            }
                            Set-Location -Path (Split-Path -Parent $baselineScript) -ErrorAction Stop
                            $savedPreference = $ErrorActionPreference
                            try {
                                # Capture native stderr without converting it into a remoting failure.
                                $ErrorActionPreference = 'Continue'
                                $output = @(& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @arguments 2>&1)
                                $exitCode = $LASTEXITCODE
                            }
                            finally { $ErrorActionPreference = $savedPreference }
                            if ($exitCode -ne 0) { throw "Baseline exited with code $exitCode." }
                            if (@($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count) {
                                throw 'Baseline reported errors despite exit code 0; complete application cannot be verified.'
                            }
                            $applied = $true
                            $reason = 'Baseline script completed without reported errors.'
                        }
                        catch { $reason = $_.Exception.Message }
                        [pscustomobject]@{
                            BaselineType = $baselineType
                            Applied = $applied
                            Reason = $reason
                            Output = (($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine)
                        }
                    }
                }

                $OSBaselineSwitch = $null
                Switch ($ResolvedDomainOrWorkGroup) {
                    'Domain' { $OSBaselineSwitch = 'Win11DomainJoined' }
                    'Workgroup' { $OSBaselineSwitch = 'Win11NonDomainJoined' }
                    Default {
                        throw "Unsupported DomainOrWorkGroup value '$ResolvedDomainOrWorkGroup' for baseline apply."
                    }
                }

                if ($null -ne $OSBaselineSwitch) {
                    $SecurityBaselineApplyResult = Invoke-PAWPSDirect -VMName $VMname -ScriptBlock $SecurityBaselineScriptBlock -ArgumentList $OSBaselineSwitch -Credential $Cred 6>$null
                }

                $baselineResults = @($SecurityBaselineApplyResult)
                if ($baselineResults.Count -ne 2 -or
                    @($baselineResults | Where-Object { $_.PSObject.Properties.Match('Applied').Count -eq 0 }).Count) {
                    throw 'Could not verify OS/Edge baseline results from guest command output.'
                }
                foreach ($baselineResult in $baselineResults) {
                    if ($baselineResult.Output) {
                        Write-PAWLog -Message "$($baselineResult.BaselineType) baseline output:`n$($baselineResult.Output)" -LogPath $LogPath
                    }
                    if ($baselineResult.Applied -eq $true) {
                        Write-PAWLog -Message "$($baselineResult.BaselineType) security baseline script completed" -LogPath $LogPath -OutputMode Console -ConsoleType Info
                    }
                    else {
                        Write-PAWOptionalFailure -Step "$($baselineResult.BaselineType) security baseline" -Reason "$($baselineResult.Reason) $($baselineResult.Output)"
                    }
                }
            }
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Security baseline application' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    Write-PAWConsoleLog -Message "Re-enabling Windows Update" -Type Info
    $null = Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMName -Credential $Cred -ScriptBlock {
        $auPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Remove-ItemProperty -Path $auPath -Name NoAutoUpdate, NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue
    }

    if ($Validate.IsPresent) {
        Write-Verbose 'Validate mode enabled. Entering final deployment phase before the last VM shutdown.'
        Invoke-PAWFinalPhaseNotification
    }

    Write-PAWConsoleLog -Message "Cleaning deployment artifacts and verifying autologon removal" -Type Info
    Invoke-PAWDeploymentCleanup -State $CleanupState -Credential $Cred -CleanupGuest `
        -SkipGuestFolderCleanup -LogPath $LogPath -Confirm:$false -ErrorAction Stop

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        $templateASR = $TemplateData.PSObject.Properties['ASR']
        $enableASR = $true
        if (-not $SkipASR -and $null -ne $templateASR) {
            $enableASR = (ConvertTo-PAWTemplateValue -SettingName ASR -Value $templateASR.Value) -eq 'True'
        }
        if (-not $SkipASR -and $enableASR) {
            $expectedRules = @(Get-PAWASRRule)
            Write-PAWLog -Message "Applying ASR master list version $($expectedRules[0].ProfileVersion) ($($expectedRules.Count) rules)." -LogPath $LogPath -OutputMode Console -ConsoleType Info
            $asrResults = @(Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMName -Credential $Cred `
                -ArgumentList ${function:Enable-PAWASR}.ToString(), $expectedRules -ScriptBlock {
                    param($Definition, $Rules)
                    . ([scriptblock]::Create("function Enable-PAWASR { $Definition }"))
                    Enable-PAWASR -Rules $Rules -Confirm:$false -ErrorAction Stop
                })
            if ($asrResults.Count -ne $expectedRules.Count -or @($asrResults.Id | Sort-Object -Unique).Count -ne $expectedRules.Count -or
                @($expectedRules | Where-Object { $asrResults.Id -notcontains $_.Id }).Count) {
                throw 'ASR did not return a verifiable result for every catalog rule.'
            }
            foreach ($rule in $asrResults) {
                if ($rule.Status -eq 'Failed') { Write-PAWOptionalFailure -Step 'ASR' -Reason "$($rule.Name) [$($rule.Id)]: $($rule.Reason)" }
                elseif ($rule.Status -in @('Enabled', 'Configured', 'NotApplicable')) {
                    Write-PAWLog -Message "ASR $($rule.Status): $($rule.Name) [$($rule.Id)] - $($rule.Reason)" -LogPath $LogPath -OutputMode Console -ConsoleType Info
                }
                else { throw "ASR returned an unknown status for '$($rule.Id)'." }
            }
        }
        else { Write-PAWLog -Message 'ASR configuration skipped (SkipASR or template ASR=False).' -LogPath $LogPath -OutputMode Console -ConsoleType Info }
    }
    catch { Write-PAWOptionalFailure -Step 'ASR' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if (-not $SkipWDAC -and $WDACPolicy -and $WDACPolicy -ne 'NA') {
            if ([IO.Path]::GetFileName($WDACPolicy) -ne $WDACPolicy -or [IO.Path]::GetExtension($WDACPolicy) -ne '.xml' -or
                $WDACPolicy.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw 'WDACPolicy must be an XML filename directly in Resources\WDACPolicies.'
            }
            $policy = Get-PAWWDACPolicy -Path (Join-Path (Join-Path $PSScriptRoot 'Resources\WDACPolicies') $WDACPolicy)
            $wdacResults = @(Invoke-PAWPSDirect -SessionContext $PSDirectContext -VMName $VMName -Credential $Cred `
                -ArgumentList ${function:Get-PAWWDACPolicy}.ToString(), ${function:Install-PAWWDACPolicy}.ToString(), $policy.Xml -ScriptBlock {
                    param($ValidateDefinition, $InstallDefinition, $Xml)
                    . ([scriptblock]::Create("function Get-PAWWDACPolicy { $ValidateDefinition }"))
                    . ([scriptblock]::Create("function Install-PAWWDACPolicy { $InstallDefinition }"))
                    Install-PAWWDACPolicy -XmlContent $Xml -Confirm:$false -ErrorAction Stop
                } 3>&1 | ForEach-Object {
                    if ($_ -is [Management.Automation.WarningRecord]) { Write-PAWOptionalFailure -Step 'WDAC' -Reason (($_.Message -replace '\s+', ' ').Trim()) }
                    else { $_ }
                })
            if ($wdacResults.Count -ne 1) { throw 'WDAC did not return exactly one installation result.' }
            $wdacResult = $wdacResults[0]
            if ($null -eq $wdacResult -or $wdacResult.Verified -ne $true -or $wdacResult.RebootRequired -ne $true) {
                throw 'WDAC policy installation did not return verified next-boot staging.'
            }
            Write-PAWLog -Message "Windows Defender Application Control: '$WDACPolicy' compiled and verified at '$($wdacResult.Destination)' ($($wdacResult.Mode)). Activation requires the next VM boot." -LogPath $LogPath -OutputMode Console -ConsoleType Info
        }
        else { Write-PAWLog -Message 'WDAC skipped (SkipWDAC or no WDAC policy selected).' -LogPath $LogPath -OutputMode Console -ConsoleType Info }
    }
    catch { Write-PAWOptionalFailure -Step 'WDAC' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    Invoke-PAWDeploymentCleanup -State $CleanupState -Credential $Cred -CleanupGuest `
        -SkipGuestFolderCleanup:($SkipGuestFolderCleanup -or $OptionalFailures.Count -gt 0) -LogPath $LogPath -Confirm:$false -ErrorAction Stop

    # Stopping the VM
    Write-PAWConsoleLog -Message "Stopping {0}" -Type Info -Value "$VMname"
    Close-PAWPSDirectSessionContext -SessionContext $PSDirectContext
    Stop-PAWVM -VMName $VMname
    $CleanupState.InstallationComplete = $true
    Save-PAWDeploymentState -State $CleanupState

    #endregion

    #region Post-deployment

    # Keep PreventLAPS.txt in the image (do not remove it post-deployment).

    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        $shortcutFolder = Join-Path $env:ALLUSERSPROFILE 'Desktop\PAW Links'
        If (-not $SkipLink -and (Test-Path -Path $shortcutFolder) -ne $true) {
            Write-PAWConsoleLog -Message "Creating {0}" -Type Info -Value $shortcutFolder
            $null = New-Item -Path $shortcutFolder -Type Directory -Force
        }

        if ($SkipLink) {
            Write-PAWConsoleLog -Message "SkipLink is set; skipping VM Connect shortcut creation" -Type Verbose
        }
        else {
            # Create a short cut for the VM
            $linkName = "Connect to " + $VMName + ".lnk"
            $shortcutPath = Join-Path $shortcutFolder $linkName
            Write-PAWConsoleLog -Message "Creating VMConnect shortcut for {0} at {1}" -Type Info -Value "$VMName", "$shortcutPath"
            $createdShortcut = New-PAWShortCut -SoruceFile vmconnect.exe -DestinationFile $shortcutPath -Arguments "localhost $VMName" -IconDLL "$env:ProgramFiles\hyper-v\snapinabout.dll" -RunAsAdmin
            Write-PAWConsoleLog -Message "Created shortcut: {0}" -Type Change -Value "$($createdShortcut.FullName)"
        }


    }
    catch { Write-PAWOptionalFailure -Step 'Link creation' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }
    # Post-deployment VM start and connect if requested.
    $optionalErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($ConnectPAW.IsPresent -or $StartPAW.IsPresent) {
            if ($ConnectPAW.IsPresent) {
                $StartPAW = $true
                Write-PAWConsoleLog -Message "ConnectPAW is set; the VM will be started and VMConnect will be launched after completion" -Type Info
            }
            elseif ($StartPAW.IsPresent) {
                Write-PAWConsoleLog -Message "StartPAW is set; the VM will be started after successful deployment" -Type Info
            }

            if ($ConnectPAW.IsPresent) {
                Write-PAWConsoleLog -Message "Launching VMConnect to {0}" -Type Info -Value "$VMName"
                Start-VM -Name $VMName -ErrorAction Stop
                Start-Process -FilePath 'vmconnect.exe' -ArgumentList 'localhost', $VMName
            }
            elseif ($StartPAW.IsPresent) {
                Write-PAWConsoleLog -Message "Starting {0}" -Type Info -Value "$VMName"
                Start-VM -Name $VMName -ErrorAction Stop
            }
        }
    }
    catch { Write-PAWOptionalFailure -Step 'Start/Connect PAW' -Reason $_.Exception.Message }
    finally { $ErrorActionPreference = $optionalErrorPreference }

    $BuildDuration = (Get-Date) - $BuildStartTime
    $BuildMinutes = [math]::Round($BuildDuration.TotalMinutes, 2)
    Write-PAWConsoleLog -Message "" -Type Info
    if ($OptionalFailures.Count -gt 0) {
        Write-PAWLog -Level WARN -Message "Deployment finished with $($OptionalFailures.Count) optional-step failure(s) in $BuildMinutes minutes. This PAW is not verified as fully configured/hardened." -LogPath $LogPath -OutputMode Warning
        foreach ($failure in $OptionalFailures) {
            Write-PAWLog -Level WARN -Message "$($failure.Step): $($failure.Reason)" -LogPath $LogPath -OutputMode Warning
        }
    }
    else {
        Write-PAWLog -Message "PAWDeploy completed successfully in $BuildMinutes minutes." -LogPath $LogPath -OutputMode Console -ConsoleType Success -Value "$BuildMinutes" -ConsoleMessage "Deployment done, total duration {0} minutes"
    }
    
    #endregion

}
catch {
    $DeploymentFailed = $true
    Write-PAWLog -Level 'ERROR' -Message "Deployment failed: $($_.Exception.Message)" -Exception $_.Exception -LogPath $LogPath
    throw
}
finally {
    $NonSecureAdminPassword = $null
    $NonSecureDomainJoinAccountPassword = $null
    $SecureVariable = $null
    $sessionCleanupError = $null
    try {
        Close-PAWPSDirectSessionContext -SessionContext $PSDirectContext -ErrorAction Stop
    }
    catch {
        $sessionCleanupError = $_
        Write-PAWLog -Level 'ERROR' -Message "PowerShell Direct session cleanup incomplete: $($_.Exception.Message)" -LogPath $LogPath -OutputMode Warning
    }
    try {
        Invoke-PAWDeploymentCleanup -State $CleanupState -Credential $Cred `
            -CleanupGuest:$DeploymentFailed `
            -SkipGuestFolderCleanup:($SkipGuestFolderCleanup -or $DeploymentFailed -or $OptionalFailures.Count -gt 0) -LogPath $LogPath -Confirm:$false -ErrorAction Stop
    }
    catch {
        Write-PAWLog -Level 'ERROR' -Message "Deployment cleanup incomplete: $($_.Exception.Message)" -LogPath $LogPath -OutputMode Warning
        if (-not $DeploymentFailed) { throw }
    }
    finally {
        if ($CleanupState.JournalPath) {
            $CleanupState.Inactive = $true
            Save-PAWDeploymentState -State $CleanupState
            if ($CleanupState.InstallationComplete -and -not $CleanupState.MountedVHD -and
                -not $CleanupState.TempFolder -and -not $CleanupState.CredentialFile) {
                Remove-Item -LiteralPath $CleanupState.JournalPath -Force -ErrorAction Stop
            }
        }
    }
    if ($null -ne $sessionCleanupError -and -not $DeploymentFailed) { throw $sessionCleanupError }
}
