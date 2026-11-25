<#
.SYNOPSIS
Lists, shows, creates, clones, edits, and removes PAWDeploy deployment templates from the command line.

.DESCRIPTION
Manages the template JSON files stored beside Config\Config.json
below the parent installation folder.
It is the command-line alternative to the template management in PAWConfigEditorUI.ps1
and writes template files in the same format.

Actions:
- -List   (default) Lists all templates.
- -Show   Displays every setting of one template.
- -New    Creates a new template. Unspecified settings use the defaults from Config.json.
- -Clone  Copies an existing template to a new template, optionally changing settings.
- -Edit   Changes settings of an existing template, and optionally renames it with -NewName.
- -Remove Deletes a template file. Prompts for confirmation unless -Force is used.

Every template setting is available as a named parameter. Additional or custom settings
can be supplied with -Setting as a hashtable.

Press Tab to complete values with the same choices as the PAWConfigEditorUI.ps1 template
grid: template names, NoCPU, Memory, TimeZoneName, the locale settings, VHDFile, RunScript,
SecurityBaselineLocation, VMSwitch, and the True/False and list settings.

Values are validated before any file is written:
- True/False, DiskMode, DomainOrWorkGroup, VMGen, NoCPU, Memory, and VLanID accept only supported values.
- TimeZoneName must be a valid Windows time zone ID.
- Locale settings must be valid culture names (InputLocale also accepts keyboard identifiers).
- ProductKey must be empty or use the XXXXX-XXXXX-XXXXX-XXXXX-XXXXX format.
- Template names must be unique (case-insensitive), because deployments select templates by name.

Warnings are shown when a referenced VHDX file, RunScript, security baseline folder,
or Hyper-V switch cannot be found. The template is still saved.

.PARAMETER List
Lists all templates. This is the default action.

.PARAMETER Show
Displays all settings of the template given by -Name.

.PARAMETER New
Creates a new template named -Name.

.PARAMETER Clone
Clones the template given by -Name into a new template named -NewName.

.PARAMETER Edit
Updates the template given by -Name.

.PARAMETER Remove
Deletes the template given by -Name.

.PARAMETER Name
The template name. For -New, the name of the template to create. For the other actions,
the name of an existing template (case-insensitive). Press Tab to complete existing template
names (quoted automatically when needed) for -Show, -Clone, -Edit, and -Remove.

.PARAMETER NewName
For -Clone, the name of the new template (default: "<Name> - Clone").
For -Edit, a new name for the template. The template file name is not changed.

.PARAMETER Force
Removes a template without prompting for confirmation.

.PARAMETER PassThru
Returns the created or updated template as an object. Used with -New, -Clone, and -Edit.

.PARAMETER Setting
Hashtable of additional settings, for example @{ VMNotes = 'Tier 0'; CustomValue = 'X' }.
Standard settings are validated the same way as the named parameters. Unknown settings are
stored as-is with a warning. A setting cannot be given both as a parameter and in -Setting.

.PARAMETER VMNotes
Description stored on the Hyper-V VM.

.PARAMETER VMGen
Hyper-V generation. Only 2 is supported for PAWs (required for vTPM, BitLocker, and Shielded VMs).

.PARAMETER NoCPU
Number of virtual processors.

.PARAMETER Memory
VM memory in MB (minimum 2048).

.PARAMETER DynamicMem
True or False.

.PARAMETER DiskMode
Diff (differencing disk) or Copy (full copy of the reference image).

.PARAMETER Shielded
True or False. Whether the VM is configured as Shielded.

.PARAMETER BitLocker
True or False. Whether BitLocker is enabled inside the VM.

.PARAMETER ASR
True or False. Whether applicable ASR rules are enabled in Block mode inside
the VM. Defaults to True for new templates; deployment SkipASR overrides True.

.PARAMETER Application
True or False. Whether PAWAppInstall applications are installed.

.PARAMETER ApplySecurityBaseline
True or False. Whether the security baseline is applied.

.PARAMETER VHDFile
Reference VHDX file name (resolved against VHDFolder) or full path.

.PARAMETER RunScript
Post-deployment script in Resources\CustomScripts. Use NA or an empty string to skip.

.PARAMETER WDACPolicyFile
XML filename in Resources\WDACPolicies. Use NA or an empty string to skip.

.PARAMETER SecurityBaselineLocation
Security baseline folder name (resolved against SecurityBaseLineFolder) or full path.

.PARAMETER TimeZoneName
Windows time zone ID, for example "W. Europe Standard Time".

.PARAMETER InputLocale
Keyboard layout, for example sv-SE or 041d:0000041d.

.PARAMETER SystemLocale
System locale, for example sv-SE.

.PARAMETER UILanguage
Display language, for example en-US.

.PARAMETER UserLocale
Regional format, for example sv-SE.

.PARAMETER DomainOrWorkGroup
DOMAIN or WORKGROUP.

.PARAMETER DNSDomain
Active Directory DNS domain name. Use NA for workgroup templates.

.PARAMETER MachineObjectOU
Distinguished name of the OU for the computer object. Use NA for workgroup templates.

.PARAMETER NamePrefix
Prefix for generated VM and computer names (letters, digits, and hyphens).

.PARAMETER NameSuffix
Suffix for generated VM and computer names (letters, digits, and hyphens).

.PARAMETER VLanID
VLAN ID for the VM network adapter, 0-4094. 0 means no VLAN.

.PARAMETER VMSwitch
Hyper-V virtual switch name.

.PARAMETER ProductKey
Optional product key. Use an empty string to clear it.

.EXAMPLE
.\Tools\Invoke-PAWTemplateSettings.ps1

Lists all templates.

.EXAMPLE
.\Tools\Invoke-PAWTemplateSettings.ps1 -Show -Name 'Windows 11 x64 PAW for WORKGROUP ON'

Displays all settings of a template.

.EXAMPLE
$params = @{
    New               = $true
    Name              = 'Windows 11 T0 PAW for CORP'
    VHDFile           = 'W1124H2VPAW.vhdx'
    VMSwitch          = 'CorpSwitch'
    DomainOrWorkGroup = 'DOMAIN'
    DNSDomain         = 'corp.contoso.com'
    MachineObjectOU   = 'OU=PAW,OU=Tier0,DC=corp,DC=contoso,DC=com'
    NameSuffix        = 'T0'
}
.\Tools\Invoke-PAWTemplateSettings.ps1 @params

Creates a new domain-joined template.

.EXAMPLE
.\Tools\Invoke-PAWTemplateSettings.ps1 -Clone -Name 'Windows 11 T0 PAW for CORP' -NewName 'Windows 11 T1 PAW for CORP' -NameSuffix 'T1' -VLanID 20

Clones a template and changes the name suffix and VLAN of the copy.

.EXAMPLE
.\Tools\Invoke-PAWTemplateSettings.ps1 -Edit -Name 'Windows 11 T1 PAW for CORP' -Memory 8192 -NoCPU 4 -UILanguage 'en-US' -WhatIf

Shows what would change without writing the template file.

.EXAMPLE
.\Tools\Invoke-PAWTemplateSettings.ps1 -Remove -Name 'Windows 11 T1 PAW for CORP' -Force

Removes a template without prompting.

.NOTES
    Version : 2.0.0.9
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+.
    Safety  : Supports -WhatIf and -Confirm. -Remove prompts unless -Force is used.
    Log file: %TEMP%\PAWDeploy\Invoke-PAWTemplateSettings.log.
#>
[CmdletBinding(DefaultParameterSetName = 'List', SupportsShouldProcess = $true)]
Param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ParameterSetName = 'Show', Mandatory = $true)]
    [switch]$Show,

    [Parameter(ParameterSetName = 'New', Mandatory = $true)]
    [switch]$New,

    [Parameter(ParameterSetName = 'Clone', Mandatory = $true)]
    [switch]$Clone,

    [Parameter(ParameterSetName = 'Edit', Mandatory = $true)]
    [switch]$Edit,

    [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
    [switch]$Remove,

    [Parameter(ParameterSetName = 'Show', Mandatory = $true)]
    [Parameter(ParameterSetName = 'New', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Clone', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Edit', Mandatory = $true)]
    [Parameter(ParameterSetName = 'Remove', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$Name,

    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [string]$NewName,

    [Parameter(ParameterSetName = 'Remove')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [hashtable]$Setting,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$VMNotes,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('2')]
    [string]$VMGen,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateRange(1, 240)]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [int]$NoCPU,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateRange(2048, 1048576)]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [int]$Memory,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$DynamicMem,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('Diff', 'Copy')]
    [string]$DiskMode,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$Shielded,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$BitLocker,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$ASR,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$Application,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [string]$ApplicationBundle,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('True', 'False')]
    [string]$ApplySecurityBaseline,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$VHDFile,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$RunScript,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $command = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } |
            ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $command) { throw 'Could not resolve the template settings script for WDAC completion.' }
        $root = Split-Path -Parent (Split-Path -Parent $command.Path)
        Import-Module -Name (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName WDACPolicyFile -WordToComplete $wordToComplete -ScriptFolder $root -BoundParameters $fakeBoundParameters
    })]
    [string]$WDACPolicyFile,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$SecurityBaselineLocation,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$TimeZoneName,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$InputLocale,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$SystemLocale,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$UILanguage,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$UserLocale,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateSet('DOMAIN', 'WORKGROUP')]
    [string]$DomainOrWorkGroup,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$DNSDomain,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$MachineObjectOU,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$NamePrefix,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$NameSuffix,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateRange(0, 4094)]
    [int]$VLanID,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWTemplateArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string]$VMSwitch,

    [Parameter(ParameterSetName = 'New')]
    [Parameter(ParameterSetName = 'Clone')]
    [Parameter(ParameterSetName = 'Edit')]
    [AllowEmptyString()]
    [string]$ProductKey
)

$PawUtilityManifest = Join-Path (Split-Path -Parent $PSScriptRoot) 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUtilityManifest"
}
Import-Module -Name $PawUtilityManifest -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$TemplateSettingOrder = Get-PAWTemplateSettingOrder

$ConfigPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "Config file not found: $ConfigPath"
}

$LogFolder = Resolve-PAWLogFolder
$LogPath = Join-Path $LogFolder 'Invoke-PAWTemplateSettings.log'

try {
    $Config = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-PAWLog -LogPath $LogPath -Message "Unable to read '$ConfigPath'." -Level 'ERROR' -Exception $_.Exception
    throw "Unable to read '$ConfigPath' as JSON: $($_.Exception.Message)"
}

$ResolvedTemplateFolder = Split-Path -Parent (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).Path

$Action = $PSCmdlet.ParameterSetName

# Collect requested setting changes from named parameters and -Setting.
$RequestedChanges = [ordered]@{}
foreach ($settingName in $TemplateSettingOrder) {
    if ($settingName -ne 'Name' -and $PSBoundParameters.ContainsKey($settingName)) {
        $RequestedChanges[$settingName] = $PSBoundParameters[$settingName]
    }
}
if ($null -ne $Setting) {
    foreach ($key in $Setting.Keys) {
        $keyName = ([string]$key).Trim()
        if ([string]::IsNullOrEmpty($keyName)) {
            throw '-Setting contains an empty setting name.'
        }
        $standardName = $TemplateSettingOrder | Where-Object { $_ -eq $keyName } | Select-Object -First 1
        if ($null -ne $standardName) {
            $keyName = $standardName
        }
        if ($keyName -eq 'Name') {
            throw 'Use -Name or -NewName to set the template name, not -Setting.'
        }
        if ($RequestedChanges.Contains($keyName)) {
            throw "Setting '$keyName' is given both as a parameter and in -Setting."
        }
        if ($null -eq $standardName) {
            Write-Warning "'$keyName' is not a standard template setting; it is stored as-is."
        }
        $RequestedChanges[$keyName] = $Setting[$key]
    }
}

# Validate and normalize every requested value before anything is written.
$NormalizedChanges = [ordered]@{}
foreach ($settingName in $RequestedChanges.Keys) {
    if ($TemplateSettingOrder -contains $settingName) {
        $NormalizedChanges[$settingName] = ConvertTo-PAWTemplateValue -SettingName $settingName -Value $RequestedChanges[$settingName]
    }
    else {
        $NormalizedChanges[$settingName] = $RequestedChanges[$settingName]
    }
}

$Templates = @(Get-PAWTemplateFile -TemplateFolder $ResolvedTemplateFolder)

switch ($Action) {
    'List' {
        if (-not (Test-Path -LiteralPath $ResolvedTemplateFolder -PathType Container)) {
            throw "Template folder not found: $ResolvedTemplateFolder"
        }
        if ($Templates.Count -eq 0) {
            Write-Warning "No templates found in: $ResolvedTemplateFolder"
            return
        }
        $displaySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]@('Name', 'VHDFile', 'DomainOrWorkGroup', 'VMSwitch', 'File'))
        $standardMembers = [System.Management.Automation.PSMemberInfo[]]@($displaySet)
        foreach ($template in $Templates) {
            $item = [PSCustomObject]@{
                Name              = $template.Name
                VHDFile           = $template.Data.VHDFile
                DomainOrWorkGroup = $template.Data.DomainOrWorkGroup
                VMSwitch          = $template.Data.VMSwitch
                UILanguage        = $template.Data.UILanguage
                File              = Split-Path -Leaf $template.FilePath
                FilePath          = $template.FilePath
            }
            $item | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $standardMembers
            $item
        }
        return
    }

    'Show' {
        $template = Find-PAWTemplate -Templates $Templates -TemplateName $Name -TemplateFolder $ResolvedTemplateFolder
        $ordered = ConvertTo-PAWOrderedTemplate -Template $template.Data
        Write-Host "Template file: $($template.FilePath)"
        Format-PAWTemplateSetting -Template $ordered
        return
    }

    'Remove' {
        $template = Find-PAWTemplate -Templates $Templates -TemplateName $Name -TemplateFolder $ResolvedTemplateFolder
        if ($PSCmdlet.ShouldProcess($template.FilePath, "Remove template '$($template.Name)'")) {
            $confirmed = $Force -or $PSBoundParameters.ContainsKey('Confirm') -or $PSCmdlet.ShouldContinue("Remove template '$($template.Name)' and delete '$($template.FilePath)'?", 'Confirm Remove Template')
            if (-not $confirmed) {
                Write-Host 'Remove cancelled.'
                return
            }
            try {
                Remove-Item -LiteralPath $template.FilePath -Force -ErrorAction Stop
            }
            catch {
                Write-PAWLog -LogPath $LogPath -Message "Failed to remove template '$($template.Name)' file '$($template.FilePath)'." -Level 'ERROR' -Exception $_.Exception
                throw "Failed to remove '$($template.FilePath)': $($_.Exception.Message)"
            }
            Write-PAWLog -LogPath $LogPath -Message "Removed template '$($template.Name)' file '$($template.FilePath)'."
            Write-Host "Removed template '$($template.Name)': $($template.FilePath)"
            if ($Templates.Count -le 1) {
                Write-Warning "No templates remain in '$ResolvedTemplateFolder'. Create a template before deploying."
            }
        }
        return
    }
}

# New, Clone, and Edit build a template object, apply the changes, and save it.
$OriginalTemplate = $null
$TargetFilePath = $null
switch ($Action) {
    'New' {
        $TargetName = $Name.Trim()
        $hyperV = $Config.Settings.HyperV
        $osConfig = $Config.Settings.OperatingSystemConfiguration
        $defaults = [ordered]@{
            Name                     = $TargetName
            VMNotes                  = $TargetName
            VMGen                    = '2'
            NoCPU                    = '2'
            Memory                   = '3072'
            DynamicMem               = 'False'
            DiskMode                 = 'Diff'
            Shielded                 = 'True'
            BitLocker                = 'True'
            ASR                      = 'True'
            Application              = 'True'
            ApplicationBundle        = 'cbade470-64cc-4628-9536-b58e3ca3be8d'
            ApplySecurityBaseline    = 'False'
            VHDFile                  = ''
            RunScript                = 'NA'
            SecurityBaselineLocation = ''
            TimeZoneName             = 'W. Europe Standard Time'
            InputLocale              = 'en-US'
            SystemLocale             = 'en-US'
            UILanguage               = 'en-US'
            UserLocale               = 'en-US'
            DomainOrWorkGroup        = 'WORKGROUP'
            DNSDomain                = 'NA'
            MachineObjectOU          = 'NA'
            NamePrefix               = 'PAW'
            NameSuffix               = ''
            VLanID                   = '0'
            VMSwitch                 = ''
            ProductKey               = ''
        }
        # Valid Config.json defaults take precedence over the built-in defaults.
        foreach ($pair in @(@($hyperV, @('VMGen', 'NoCPU', 'Memory', 'DynamicMem', 'DiskMode')), @($osConfig, @('DomainOrWorkGroup', 'TimeZoneName', 'InputLocale', 'SystemLocale', 'UILanguage', 'UserLocale')))) {
            $section = $pair[0]
            if ($null -eq $section) {
                continue
            }
            foreach ($settingName in $pair[1]) {
                $configValue = [string]$section.$settingName
                if ([string]::IsNullOrWhiteSpace($configValue)) {
                    continue
                }
                try {
                    $defaults[$settingName] = ConvertTo-PAWTemplateValue -SettingName $settingName -Value $configValue
                }
                catch {
                    Write-Verbose "Ignoring Config.json default for ${settingName}: $($_.Exception.Message)"
                }
            }
        }
        $WorkingTemplate = $defaults
    }
    'Clone' {
        $source = Find-PAWTemplate -Templates $Templates -TemplateName $Name -TemplateFolder $ResolvedTemplateFolder
        if ($PSBoundParameters.ContainsKey('NewName')) {
            $TargetName = $NewName.Trim()
        }
        else {
            $TargetName = "$($source.Name) - Clone"
        }
        $WorkingTemplate = ConvertTo-PAWOrderedTemplate -Template $source.Data
        $WorkingTemplate['Name'] = $TargetName
    }
    'Edit' {
        $source = Find-PAWTemplate -Templates $Templates -TemplateName $Name -TemplateFolder $ResolvedTemplateFolder
        $TargetFilePath = $source.FilePath
        $OriginalTemplate = ConvertTo-PAWOrderedTemplate -Template $source.Data
        $WorkingTemplate = ConvertTo-PAWOrderedTemplate -Template $source.Data
        $TargetName = $source.Name
        if ($PSBoundParameters.ContainsKey('NewName')) {
            $TargetName = $NewName.Trim()
        }
        if ($NormalizedChanges.Count -eq 0 -and $TargetName -ceq $source.Name) {
            throw 'Nothing to change. Specify one or more template settings or -NewName.'
        }
        $WorkingTemplate['Name'] = $TargetName
    }
}

if ([string]::IsNullOrWhiteSpace($TargetName)) {
    throw 'The template name cannot be empty.'
}

$conflict = $Templates | Where-Object { $_.Name -eq $TargetName -and $_.FilePath -ne $TargetFilePath } | Select-Object -First 1
if ($null -ne $conflict) {
    throw "A template named '$TargetName' already exists: $($conflict.FilePath)"
}

foreach ($settingName in $NormalizedChanges.Keys) {
    $WorkingTemplate[$settingName] = $NormalizedChanges[$settingName]
    if ($TemplateSettingOrder -contains $settingName) {
        Test-PAWTemplateReference -ConfigPath $ConfigPath -SettingName $settingName -Value ([string]$NormalizedChanges[$settingName])
    }
}
$WorkingTemplate = ConvertTo-PAWOrderedTemplate -Template $WorkingTemplate

if ($null -eq $TargetFilePath) {
    $TargetFilePath = Get-PAWUniqueTemplateFilePath -TemplateFolder $ResolvedTemplateFolder -TemplateName $TargetName
}

$ChangeLines = @()
if ($Action -eq 'Edit') {
    foreach ($key in $WorkingTemplate.Keys) {
        $oldValue = $null
        if ($OriginalTemplate.Contains($key)) {
            $oldValue = $OriginalTemplate[$key]
        }
        if (-not ([string]$oldValue -ceq [string]$WorkingTemplate[$key])) {
            $ChangeLines += [PSCustomObject]@{
                Setting  = $key
                OldValue = $oldValue
                NewValue = $WorkingTemplate[$key]
            }
        }
    }
    if ($ChangeLines.Count -eq 0) {
        Write-Host "No changes. Template '$TargetName' already contains the requested values."
        if ($PassThru) {
            [PSCustomObject]$WorkingTemplate
        }
        return
    }
    $operation = "Update template '$($source.Name)': " + (($ChangeLines | ForEach-Object { "$($_.Setting) '$($_.OldValue)' -> '$($_.NewValue)'" }) -join '; ')
}
elseif ($Action -eq 'Clone') {
    $operation = "Clone template '$($source.Name)' to '$TargetName'"
}
else {
    $operation = "Create template '$TargetName'"
}

if ([string]$WorkingTemplate['DomainOrWorkGroup'] -eq 'DOMAIN') {
    foreach ($settingName in @('DNSDomain', 'MachineObjectOU')) {
        $value = [string]$WorkingTemplate[$settingName]
        if ([string]::IsNullOrWhiteSpace($value) -or $value -eq 'NA') {
            Write-Warning "Template '$TargetName' is set to DOMAIN but $settingName is not set."
        }
    }
}
foreach ($settingName in @('VHDFile', 'VMSwitch')) {
    if ([string]::IsNullOrWhiteSpace([string]$WorkingTemplate[$settingName])) {
        Write-Warning "Template '$TargetName' has no $settingName. Set it with -Edit -$settingName before deploying."
    }
}

if ($PSCmdlet.ShouldProcess($TargetFilePath, $operation)) {
    try {
        if (-not (Test-Path -LiteralPath $ResolvedTemplateFolder -PathType Container)) {
            New-Item -Path $ResolvedTemplateFolder -ItemType Directory -Force | Out-Null
        }
        $jsonOutput = $WorkingTemplate | ConvertTo-Json -Depth 20
        Set-Content -LiteralPath $TargetFilePath -Value $jsonOutput -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Write-PAWLog -LogPath $LogPath -Message "Failed to save template '$TargetName' to '$TargetFilePath'." -Level 'ERROR' -Exception $_.Exception
        throw "Failed to save '$TargetFilePath': $($_.Exception.Message)"
    }

    Write-PAWLog -LogPath $LogPath -Message "$operation. File: '$TargetFilePath'."
    if ($ChangeLines.Count -gt 0) {
        $ChangeLines | Format-Table -AutoSize | Out-String | Write-Host
    }
    switch ($Action) {
        'New' { Write-Host "Created template '$TargetName': $TargetFilePath" }
        'Clone' { Write-Host "Cloned template '$($source.Name)' to '$TargetName': $TargetFilePath" }
        'Edit' { Write-Host "Saved template '$TargetName': $TargetFilePath" }
    }

    if ($PassThru) {
        [PSCustomObject]$WorkingTemplate
    }
}
