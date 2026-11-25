<#
.SYNOPSIS
    Command-line entry point for PAW application and bundle management.
.DESCRIPTION
    Returns PowerShell objects for both interactive CLI use and the Application Manager UI.
    ApplicationId and BundleId are stable GUIDs, not display names. Creation
    generates a GUID when the ID is omitted; import/export retain existing GUIDs.
.PARAMETER Action
    Operation to execute. SaveApplication/SaveBundle accept structured InputObject values.
    TestPrerequisites checks optional WinGet discovery requirements without accessing the catalog.
    ListTemplates returns the templates available in the installation's Config folder.
    NewApplication returns an unsaved schema 2 draft; SaveApplication validates and persists it.
    GetApplicationFolder returns the package content folder for an existing Classic application.
    ConvertCatalog explicitly backs up legacy definitions and migrates catalog filenames.
.PARAMETER ConfigPath
    Installation configuration; resolves the application store under Resources.
.PARAMETER InputObject
    Application or bundle document. All values are validated before saving.
.PARAMETER Replace
    Explicitly permits replacing existing definitions or export files.
.PARAMETER RestartRequired
    Metadata for new definitions only. Does not trigger deployment restarts.
.PARAMETER Type
    Type for a NewApplication seed: WinGet, PowerShellModule, Classic or WindowsComponent.
.PARAMETER Configuration
    Optional complete type-specific configuration for NewApplication.
.PARAMETER SourceFolder
    Folder whose contents are copied into a Classic FolderPath or WindowsComponent Source
    package directory when saving. WindowsComponent Configuration.Source must be Source.
.EXAMPLE
    .\Tools\Invoke-PAWApplicationManager.ps1 -Action Search -Query '7-Zip'
.EXAMPLE
    .\Tools\Invoke-PAWApplicationManager.ps1 -Action NewWinGet -Id 7zip.7zip -Architecture x64 -Scope Machine
.EXAMPLE
    .\Tools\Invoke-PAWApplicationManager.ps1 -Action AssignBundle -BundleId cbade470-64cc-4628-9536-b58e3ca3be8d -TemplateName 'Windows 11 x64 PAW for WORKGROUP ON'
.NOTES
    Version : 2.0.0.13
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('ListApplications','ListBundles','Search','NewWinGet','SaveApplication','SaveBundle',
        'Enable','Disable','RemoveApplication','RemoveBundle','Import','ExportApplication','ExportBundle','AssignBundle','ResolveBundle','TestPrerequisites','ListTemplates','ListAssignments','NewApplication','ConvertCatalog','GetApplicationFolder')]
    [string]$Action = 'ListApplications',
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'Config\Config.json'),
    [string]$ApplicationId,
    [string]$BundleId,
    [string]$Id,
    [string]$Query,
    [string]$Name,
    [ValidateSet('WinGet','PowerShellModule','Classic','WindowsComponent')][string]$Type,
    [object]$Configuration,
    [string]$Architecture = 'NA',
    [string]$Scope = 'NA',
    [string]$InstallerType = 'NA',
    [bool]$RestartRequired = $false,
    [string]$Path,
    [string]$TemplateName,
    [object]$InputObject,
    [string]$SourceFolder,
    [switch]$Replace,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
Import-Module (Join-Path $root 'Functions\PAWApplicationManager\PAWApplicationManager.psd1') -ErrorAction Stop
$null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
try {
    if (-not $WhatIfPreference) {
        Write-PAWLog -Message "Application Manager action: $Action." -LogPath (Join-Path (Resolve-PAWLogFolder) 'PAWApplicationManager.log')
    }
    if ($Action -eq 'TestPrerequisites') {
        Test-PAWApplicationManagerPrerequisite
        return
    }
    if ($Action -eq 'ListTemplates') {
        $templates = Get-PAWTemplateCollection -TemplateFolder (Split-Path -Parent $ConfigPath)
        $templates | Sort-Object Name
        return
    }
    $store = Join-Path (Split-Path -Parent (Split-Path -Parent $ConfigPath)) 'Resources'
    switch ($Action) {
        'ListApplications' { Get-PAWApplicationCatalog -Root $store }
        'ListBundles' { Get-PAWApplicationBundle -Root $store }
        'ListAssignments' { Get-PAWApplicationAssignment -Root $store -ConfigPath $ConfigPath }
        'Search' {
            if ($Id) { Find-PAWWinGetApplication -Id $Id }
            else { Find-PAWWinGetApplication -Query $Query }
        }
        'ResolveBundle' { Resolve-PAWApplicationBundle -Root $store -BundleId $BundleId }
        'GetApplicationFolder' {
            $app = @(Get-PAWApplicationCatalog -Root $store | Where-Object ApplicationId -eq $ApplicationId)
            if ($app.Count -ne 1 -or $app[0].Type -ne 'Classic' -or
                $null -eq $app[0].Definition.Configuration.PSObject.Properties['FolderPath']) {
                throw 'GetApplicationFolder requires an existing Classic application with FolderPath.'
            }
            $package = Resolve-PAWApplicationPayloadPath -PackageRoot $store -RelativePath "Applications\Packages\$($app[0].ApplicationId)"
            Resolve-PAWApplicationPayloadPath -PackageRoot $package -RelativePath $app[0].Definition.Configuration.FolderPath
        }
        'NewApplication' {
            if (-not $Type -or -not $Name) { throw 'NewApplication requires Type and Name. Save the returned definition using SaveApplication.' }
            New-PAWManagedApplication -Type $Type -Name $Name -Configuration $Configuration -RestartRequired $RestartRequired
        }
        default {
            if (-not $PSCmdlet.ShouldProcess($store, "$Action ($ApplicationId$BundleId$Path$TemplateName)")) { return }
            if ($Action -in 'RemoveApplication','RemoveBundle' -and -not $Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
                $message = if ($Action -eq 'RemoveApplication') {
                    "Remove application $ApplicationId and its membership in all bundles? Cached installers are retained."
                } else { "Remove bundle $BundleId? Cached installers are retained." }
                if (-not $PSCmdlet.ShouldContinue($message, 'Application Manager')) { return }
            }
            switch ($Action) {
                'ConvertCatalog' { Convert-PAWApplicationCatalog -Root $store -Confirm:$false }
                'NewWinGet' { New-PAWWinGetApplication -Root $store -ApplicationId $ApplicationId -Id $Id -Name $Name -Architecture $Architecture -Scope $Scope -InstallerType $InstallerType -RestartRequired $RestartRequired -Confirm:$false }
                'SaveApplication' { Save-PAWManagedApplication -Root $store -Application $InputObject -SourceFolder $SourceFolder -Replace:$Replace -Confirm:$false }
                'SaveBundle' { Save-PAWApplicationBundle -Root $store -Bundle $InputObject -Replace:$Replace -Confirm:$false }
                { $_ -in 'Enable','Disable' } {
                    $app = @(Get-PAWApplicationCatalog -Root $store | Where-Object ApplicationId -eq $ApplicationId)
                    if ($app.Count -ne 1) { throw "Application '$ApplicationId' not found." }
                    $app[0].Enabled = $Action -eq 'Enable'
                    Save-PAWManagedApplication -Root $store -Application $app[0] -Replace -Confirm:$false
                }
                'RemoveApplication' { Remove-PAWManagedApplication -Root $store -ApplicationId $ApplicationId -Confirm:$false }
                'RemoveBundle' { Remove-PAWApplicationBundle -Root $store -BundleId $BundleId -ConfigPath $ConfigPath -Confirm:$false }
                'Import' { Import-PAWApplicationPackage -Root $store -Path $Path -Replace:$Replace -Confirm:$false }
                'ExportApplication' { Export-PAWApplicationPackage -Root $store -Path $Path -ApplicationId $ApplicationId -Replace:$Replace -Confirm:$false }
                'ExportBundle' { Export-PAWApplicationPackage -Root $store -Path $Path -BundleId $BundleId -Replace:$Replace -Confirm:$false }
                'AssignBundle' { Set-PAWTemplateApplicationBundle -Root $store -BundleId $BundleId -ConfigPath $ConfigPath -TemplateName $TemplateName -Confirm:$false }
            }
        }
    }
}
catch {
    Write-PAWLog -Level ERROR -Message "Application Manager $Action failed: $($_.Exception.Message)" -LogPath (Join-Path (Resolve-PAWLogFolder) 'PAWApplicationManager.log') -OutputMode Warning
    throw
}
