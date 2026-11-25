@{
    RootModule = 'PAWApplicationManager.psm1'
    ModuleVersion = '2.0.0.20'
    GUID = '01bdb9ec-f115-4dad-8a3d-760fbfa33acc'
    Author = 'The Fantastic PAWDeploy Team'
    CompanyName = 'Truesec'
    Copyright = '(c) 2026 Truesec. All rights reserved.'
    Description = 'Application catalog, bundles and portable application definitions for PAWDeploy.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-PAWApplicationCatalog', 'Get-PAWApplication', 'Get-PAWCachedApplication',
        'Get-PAWApplicationBundle', 'New-PAWApplicationBundle', 'Add-PAWApplicationToBundle', 'Save-PAWManagedApplication',
        'Remove-PAWApplication', 'Remove-PAWApplicationFromBundle', 'Remove-PAWCachedApplication',
        'Import-PAWApplication', 'Import-PAWApplicationBundle', 'Import-PAWCachedApplication',
        'Export-PAWApplication', 'Export-PAWApplicationBundle', 'Export-PAWCachedApplication',
        'Save-PAWApplicationBundle', 'Remove-PAWManagedApplication', 'Remove-PAWApplicationBundle',
        'Resolve-PAWApplicationBundle', 'Find-PAWWinGetApplication', 'New-PAWWinGetApplication',
        'Export-PAWApplicationPackage', 'Import-PAWApplicationPackage', 'Set-PAWTemplateApplicationBundle',
        'Test-PAWApplicationManagerPrerequisite', 'Get-PAWApplicationAssignment',
        'New-PAWManagedApplication', 'Convert-PAWApplicationCatalog'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
