<#
.SYNOPSIS
    Precaches enabled catalog applications or prepares a selected build bundle.

.DESCRIPTION
    Without a bundle or plan, prepares every enabled application in the canonical
    Catalog under Resources\ApplicationCatalog, including unassigned applications.
    An explicit ApplicationBundle limits preparation to that bundle.
    New-PAWVM passes its already resolved ApplicationPlan so preparation and both
    preflight gates use the same selection. Globally disabled applications are excluded.
    Enabled controls preparation; InstallEnabled controls guest installation only.

    WinGet applications are downloaded with 'winget download'. WinGet saves
    the installer together with its manifest (.yaml), which contains the
    silent install switches (InstallerSwitches). Both files are kept, and a
    PAWApplication.json summary with the version, installer file and silent
    switches is written next to them for the install step.

    Legacy PSGallery applications are downloaded with Save-Module into the
    Modules cache. Typed PowerShellModule applications are saved at their
    selected exact version, with dependencies, under Packages\<ApplicationId>.
    Classic and WindowsComponent payloads are validated locally; online
    WindowsComponent operations are deferred to the guest OS.

    Local applications are not downloaded. Place the installer (exactly one
    file)     in Resources\ApplicationDownloads\Local\<Application name>; the
    script checks the folder and creates or updates the install file. For an
    exe installer, set SilentArguments in Settings in the install file.

    Only the latest version matching the requested installer filters is kept.
    Older versions are checked when the latest has no applicable installer;
    downloads are pinned to the selected version without relaxing filters.
    An application is skipped when the cached
    version already matches the latest available version; use -Force to
    download it again. When the latest version cannot be checked (for example
    when the host is offline) and the application is already cached, the
    cached version is used and the status is Cached.

    Applications.json is generated only in the staged guest payload. For every
    WinGet and Local application an install file is created or updated in
    Applications\InstallFiles\<Application name>.json.
    The Installer section is refreshed from the WinGet manifest (or the local
    installer file) on every run;
    the Settings section comes from the persistent catalog definition.

    Folder layout:

        Resources\ApplicationCatalog\<SafeName>--<ApplicationId>.json - persistent definitions and Settings
        Resources\ApplicationBundles\<BundleId>.json                    - ordered application references
        Resources\Applications\Packages\<ApplicationId>\                - typed module and installer payloads
        Resources\ApplicationDownloads\WinGet\<Name>\                   - installer, manifest, PAWApplication.json
        Resources\ApplicationDownloads\Modules\<Module>\<Ver>\          - PowerShell modules
        Resources\Applications\InstallFiles\<Name>.json                 - install file per WinGet or Local application
        Resources\ApplicationDownloads\Local\<Name>\                    - installer of a Local application (placed by you)

    Use -WhatIf to see what would be downloaded without changing the cache or
    writing the log.

.PARAMETER Name
    Download only these enabled applications by Name, within the catalog or selected
    bundle/plan. Press Tab to complete names. Disabled applications cannot be selected.

.PARAMETER Force
    Download the applications again even when the cached version is the latest.

.PARAMETER ApplicationBundle
    Bundle GUID to prepare instead of precaching all enabled catalog applications.
    Cannot be combined with ApplicationPlan. NA means no applications: the script
    reports that there is nothing to download and completes successfully.

.PARAMETER ApplicationPlan
    Resolved deployment snapshot supplied by New-PAWVM.

.EXAMPLE
    .\Tools\Invoke-PAWApplicationDownload.ps1
    Downloads the latest version of every enabled application.

.EXAMPLE
    .\Tools\Invoke-PAWApplicationDownload.ps1 -Name '7-Zip', 'KeePass'
    Downloads only 7-Zip and KeePass.

.EXAMPLE
    .\Tools\Invoke-PAWApplicationDownload.ps1 -WhatIf
    Shows which applications would be downloaded without changing the cache.

.EXAMPLE
    .\Tools\Invoke-PAWApplicationDownload.ps1 -Name 'PowerShell 7' -Force
    Downloads PowerShell 7 again even if the cached version is the latest.

.NOTES
    Version : 2.0.0.12
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1+, WinGet (App Installer) 1.8 or later for WinGet applications,
              PowerShellGet for PSGallery applications, Internet access.
    Files   : Config\Config.json and resources below the parent installation folder.
    Log file: %TEMP%\PAWDeploy\Invoke-PAWApplicationDownload.log.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ArgumentCompleter({
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        # Import PAWUtility into the completer scope only; the caller's session is not changed.
        $scriptCommand = @($commandAst.GetCommandName(), $commandName) | Where-Object { $_ } | ForEach-Object { Get-Command -Name $_ -CommandType ExternalScript -ErrorAction SilentlyContinue } | Select-Object -First 1
        if ($null -eq $scriptCommand) { return }
        $scriptFolder = Split-Path -Parent (Split-Path -Parent $scriptCommand.Path)
        $manifest = Join-Path $scriptFolder 'Functions\PAWUtility\PAWUtility.psd1'
        if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
        Import-Module -Name $manifest -Scope Local -ErrorAction Stop
        Get-PAWApplicationArgumentCompletion -ParameterName $parameterName -WordToComplete $wordToComplete -ScriptFolder $scriptFolder -BoundParameters $fakeBoundParameters
    })]
    [string[]]$Name,

    [switch]$Force,
    [string]$ApplicationBundle,
    [psobject]$ApplicationPlan
)

$ErrorActionPreference = 'Stop'

# $PSScriptRoot is not reliably populated in all execution hosts and copied deployment folders.
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $scriptRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}
else {
    $scriptRoot = Split-Path -Parent $PSScriptRoot
}

$PawUtilityManifest = Join-Path $scriptRoot 'Functions\PAWUtility\PAWUtility.psd1'
if (-not (Test-Path -LiteralPath $PawUtilityManifest -PathType Leaf)) {
    throw "Required module not found: $PawUtilityManifest"
}
Import-Module -Name $PawUtilityManifest -Force -ErrorAction Stop
$script:PAWToolTitle = Set-PAWScriptTitle -ScriptPath $PSCommandPath

$ConfigPath = Join-Path $scriptRoot 'Config\Config.json'

$ResourcesRoot = Join-Path $scriptRoot 'Resources'
$CacheRoot = Join-Path $ResourcesRoot 'ApplicationDownloads'
$WinGetRoot = Join-Path $CacheRoot 'WinGet'
$ModuleRoot = Join-Path $CacheRoot 'Modules'
$ApplicationsPath = Join-Path $ResourcesRoot 'ApplicationCatalog'
# Install files are kept when a new version is downloaded.
$InstallRoot = Join-Path $ResourcesRoot 'Applications\InstallFiles'
$LocalRoot = Join-Path $CacheRoot 'Local'

$script:LogPath = $null
if (-not $WhatIfPreference) {
    $LogFolder = Resolve-PAWLogFolder
    $script:LogPath = Join-Path $LogFolder 'Invoke-PAWApplicationDownload.log'
}

function Write-PAWDownloadLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [string]$Level = 'INFO'
    )

    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Write-PAWLog -Message $Message -Level $Level -LogPath $script:LogPath
    }
}

function Get-PAWWinGetFilterArguments {
    param($Application)

    $filterArguments = @()
    # NA in Applications.json means that WinGet selects the installer.
    if ($Application.Architecture -ne 'NA') { $filterArguments += @('--architecture', $Application.Architecture) }
    if ($Application.InstallerType -ne 'NA') { $filterArguments += @('--installer-type', $Application.InstallerType) }
    if ($Application.Scope -ne 'NA') { $filterArguments += @('--scope', ([string]$Application.Scope).ToLowerInvariant()) }
    $filterArguments
}

function Get-PAWLocalMsiProperties {
    param([string]$Path)

    $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
    $database = $windowsInstaller.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $windowsInstaller, @($Path, 0))
    $properties = @{}
    foreach ($propertyName in 'ProductCode', 'ProductVersion') {
        $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @("SELECT Value FROM Property WHERE Property = '$propertyName'"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        $properties[$propertyName] = if ($null -ne $record) { [string]$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1) } else { '' }
        $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($view) | Out-Null
    }
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null
    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
    [PSCustomObject]$properties
}

function Get-PAWWinGetLatestVersion {
    param($Application)

    $baseArguments = @('show', '--id', $Application.Id, '--exact', '--source', 'winget', '--accept-source-agreements', '--disable-interactivity')
    $showArguments = $baseArguments + @(Get-PAWWinGetFilterArguments -Application $Application)
    $output = @(& winget @showArguments 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and $exitCode -ne -1978335216) {
        $detail = ($output | Where-Object { $_ -match '\w' } | Select-Object -Last 2) -join ' '
        throw "winget show failed for '$($Application.Id)' (exit code $exitCode). $detail"
    }

    $versionLine = $output | Where-Object { $_ -match '^Version:\s*(\S+)' } | Select-Object -First 1
    $latestVersion = if ($versionLine -match '^Version:\s*(\S+)') { $Matches[1] } else { $null }
    if ($exitCode -eq 0 -and $output -match '^\s*Installer Url:\s*\S+') {
        if (-not $latestVersion) { throw "WinGet did not report a version for '$($Application.Id)'." }
        return $latestVersion
    }
    if ($exitCode -eq 0 -and -not ($output -match 'No applicable installer found')) {
        throw "WinGet did not report applicable installer metadata for '$($Application.Id)'."
    }

    $message = "$($Application.Name): latest version has no installer matching the requested filters; checking earlier versions without changing architecture, scope or installer type."
    Write-PAWDownloadLog -Level WARN -Message $message
    Write-PAWConsoleLog -Type Warning -Message $message
    $versionsArguments = $baseArguments + @('--versions')
    $versionsOutput = @(& winget @versionsArguments 2>&1 | ForEach-Object { [string]$_ })
    if ($LASTEXITCODE -ne 0) {
        throw "Could not list WinGet versions for '$($Application.Id)' (exit code $LASTEXITCODE). $($versionsOutput -join ' ')"
    }
    $inVersions = $false
    $versions = @(foreach ($line in $versionsOutput) {
        if ($line -match '^\s*-{3,}\s*$') { $inVersions = $true; continue }
        if ($inVersions -and $line -match '^\s*(\S+)\s*$') { $Matches[1] }
    })
    if (-not $versions.Count) { throw "WinGet returned no version list for '$($Application.Id)'." }
    foreach ($candidate in $versions) {
        if ($candidate -eq $latestVersion) { continue }
        $candidateArguments = $showArguments + @('--version', $candidate)
        $candidateOutput = @(& winget @candidateArguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq -1978335216 -or ($exitCode -eq 0 -and $candidateOutput -match 'No applicable installer found')) { continue }
        if ($exitCode -ne 0) {
            throw "Could not check WinGet version '$candidate' for '$($Application.Id)' (exit code $exitCode). $($candidateOutput -join ' ')"
        }
        if (-not ($candidateOutput -match '^\s*Installer Url:\s*\S+')) {
            throw "WinGet did not report installer metadata for '$($Application.Id)' version '$candidate'."
        }
        $candidateVersionLine = $candidateOutput | Where-Object { $_ -match '^Version:\s*(\S+)' } | Select-Object -First 1
        if ($candidateVersionLine -notmatch '^Version:\s*(\S+)' -or $Matches[1] -ne $candidate) {
            throw "WinGet did not confirm requested version '$candidate' for '$($Application.Id)'."
        }
        Write-PAWDownloadLog -Message "Selected compatible version $candidate for '$($Application.Id)' with unchanged installer filters."
        Write-PAWConsoleLog -Type Info -Message "Selected {0} version {1} with unchanged installer filters" -Value $Application.Name, $candidate
        return $candidate
    }
    throw "No WinGet version of '$($Application.Id)' has an installer matching the requested architecture, scope and installer type."
}

function Get-PAWCachedWinGetApplication {
    param(
        $Application,
        [string]$TargetFolder
    )

    $summaryPath = Join-Path $TargetFolder 'PAWApplication.json'
    if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
        return $null
    }

    try {
        $summary = Get-Content -LiteralPath $summaryPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-PAWDownloadLog -Level WARN -Message "Invalid cache metadata for '$($Application.Name)' at '$summaryPath': $($_.Exception.Message). Download the application again."
        return $null
    }

    # A change of Id or installer filters in Applications.json makes the cached download stale.
    # NA and an empty value (older caches) both mean "not set".
    foreach ($property in 'Id', 'Architecture', 'InstallerType', 'Scope') {
        $cachedValue = ([string]$summary.Requested.$property) -replace '^NA$', ''
        $requestedValue = ([string]$Application.$property) -replace '^NA$', ''
        if ($cachedValue -ne $requestedValue) {
            return $null
        }
    }

    foreach ($fileName in @($summary.InstallerFile, $summary.ManifestFile)) {
        if ([string]::IsNullOrWhiteSpace([string]$fileName) -or -not (Test-Path -LiteralPath (Join-Path $TargetFolder $fileName) -PathType Leaf)) {
            Write-PAWDownloadLog -Level WARN -Message "Cache rejected for '$($Application.Name)': installer or manifest '$fileName' is missing in '$TargetFolder'. Run Invoke-PAWApplicationDownload.ps1 -Name '$($Application.Name)' -Force on the host."
            return $null
        }
    }

    try {
        Assert-PAWInstallerHash -Path (Join-Path $TargetFolder $summary.InstallerFile) -ExpectedHash $summary.InstallerSha256 -ApplicationName $Application.Name
    }
    catch {
        Write-PAWDownloadLog -Level WARN -Message "Cache rejected: $($_.Exception.Message)"
        Write-PAWConsoleLog -Type Warning -Message "Cache rejected: {0}" -Value $_.Exception.Message
        return $null
    }
    $summary
}

function Save-PAWWinGetApplication {
    param(
        $Application,
        [string]$TargetFolder,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Version
    )

    $stagingFolder = Join-Path $WinGetRoot ('.staging-' + (Split-Path -Leaf $TargetFolder))
    if (Test-Path -LiteralPath $stagingFolder) {
        Remove-Item -LiteralPath $stagingFolder -Recurse -Force
    }
    New-Item -Path $stagingFolder -ItemType Directory -Force | Out-Null

    try {
        $downloadArguments = @('download', '--id', $Application.Id, '--exact', '--source', 'winget', '--version', $Version, '--download-directory', $stagingFolder, '--accept-source-agreements', '--accept-package-agreements', '--disable-interactivity') + @(Get-PAWWinGetFilterArguments -Application $Application)
        Write-PAWDownloadLog -Message "Running: winget $($downloadArguments -join ' ')"
        $output = @(& winget @downloadArguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        foreach ($line in $output) {
            # Skip progress-bar redraw lines.
            if ($line -match '[A-Za-z]{3}' -and $line -notmatch '[\u2580-\u259F]') {
                Write-PAWDownloadLog -Message "winget: $($line.Trim())"
            }
        }
        if ($exitCode -ne 0) {
            $detail = ($output | Where-Object { $_ -match '[A-Za-z]{3}' -and $_ -notmatch '[\u2580-\u259F]' } | Select-Object -Last 2) -join ' '
            throw "winget download failed for '$($Application.Id)' (exit code $exitCode). $detail"
        }

        $manifestFile = Get-ChildItem -LiteralPath $stagingFolder -File | Where-Object { $_.Extension -in '.yaml', '.yml' } | Select-Object -First 1
        $installerFile = Get-ChildItem -LiteralPath $stagingFolder -File | Where-Object { $_.Extension -notin '.yaml', '.yml' } | Sort-Object Length -Descending | Select-Object -First 1
        if ($null -eq $manifestFile -or $null -eq $installerFile) {
            throw "winget download for '$($Application.Id)' did not produce both an installer and a manifest in $stagingFolder."
        }

        $manifestInfo = Get-PAWWinGetManifestInfo -Path $manifestFile.FullName
        if ([string]$manifestInfo.PackageVersion -ne $Version) {
            throw "Downloaded manifest version '$($manifestInfo.PackageVersion)' does not match requested version '$Version' for '$($Application.Id)'."
        }
        $summary = [PSCustomObject]@{
            Name              = $Application.Name
            Source            = 'WinGet'
            Id                = $Application.Id
            Version           = $manifestInfo.PackageVersion
            InstallerType     = $manifestInfo.InstallerType
            NestedInstallerType = $manifestInfo.NestedInstallerType
            Scope             = $manifestInfo.Scope
            Architecture      = $manifestInfo.Architecture
            ProductCode       = $manifestInfo.ProductCode
            InstallerFile     = $installerFile.Name
            InstallerSha256   = (Get-FileHash -LiteralPath $installerFile.FullName -Algorithm SHA256).Hash
            ManifestFile      = $manifestFile.Name
            InstallerSwitches = $manifestInfo.InstallerSwitches
            Requested         = [PSCustomObject]@{
                Id            = $Application.Id
                Architecture  = $Application.Architecture
                InstallerType = $Application.InstallerType
                Scope         = $Application.Scope
            }
            DownloadedAt      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        }
        $summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stagingFolder 'PAWApplication.json') -Encoding UTF8

        # Keep only the latest version: replace the previous download.
        if (Test-Path -LiteralPath $TargetFolder) {
            Remove-Item -LiteralPath $TargetFolder -Recurse -Force
        }
        Move-Item -LiteralPath $stagingFolder -Destination $TargetFolder
        $summary
    }
    finally {
        if (Test-Path -LiteralPath $stagingFolder) {
            Remove-Item -LiteralPath $stagingFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Save-PAWTypedModulePayload {
    param($Application, [switch]$WhatIf)

    $packageRoot = Join-Path $ResourcesRoot "Applications\Packages\$($Application.ApplicationId)"
    if ($Application.Options.Origin -eq 'Local') {
        return (Test-PAWApplicationResources -Application $Application -AppInstallRoot $ResourcesRoot)
    }
    $requestedVersion = [string]$Application.Options.Version
    if ($requestedVersion -eq 'Latest') {
        try { $module = Find-Module -Name $Application.Id -Repository PSGallery -ErrorAction Stop }
        catch {
            $lookupError = $_
            if (-not $Force) {
                try {
                    $cached = Test-PAWApplicationResources -Application $Application -AppInstallRoot $ResourcesRoot
                    $cachedModule = @($cached.Modules | Where-Object { $_.Parent.Name -eq $Application.Id } |
                        Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1)
                    if ($cachedModule.Count -gt 0) {
                        return [pscustomobject]@{
                            Ready = $true; Pending = $false; Cached = $true; PackageRoot = $packageRoot
                            Version = $cachedModule[0].Name
                            Message = "PSGallery is unavailable; using verified cached version $($cachedModule[0].Name)."
                        }
                    }
                }
                catch { }
            }
            throw $lookupError
        }
        $requestedVersion = [string]$module.Version
    }
    $alreadyReady = $false
    try {
        $checkApplication = $Application.PSObject.Copy()
        $checkApplication.Options = $Application.Options.PSObject.Copy()
        $checkApplication.Options.Version = $requestedVersion
        $null = Test-PAWApplicationResources -Application $checkApplication -AppInstallRoot $ResourcesRoot
        $alreadyReady = $true
    }
    catch { }
    if (-not $Force -and $alreadyReady) {
        return [pscustomobject]@{ Ready = $true; Pending = $false; PackageRoot = $packageRoot; Message = "Version $requestedVersion is already staged." }
    }
    if ($WhatIf) {
        return [pscustomobject]@{ Ready = $false; Pending = $true; WhatIf = $true; PackageRoot = $packageRoot; Message = "Would download and verify version $requestedVersion." }
    }
    $stagingRoot = Join-Path (Join-Path $ResourcesRoot 'Applications\Packages') ('.staging-' + [string]$Application.ApplicationId)
    $stagedPackageRoot = $null
    $candidatePackageRoot = $null
    if (Test-Path -LiteralPath $stagingRoot) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force }
    $null = New-Item -Path $stagingRoot -ItemType Directory -Force
    try {
        Save-Module -Name $Application.Id -RequiredVersion $requestedVersion -Path $stagingRoot -Repository PSGallery -Force -ErrorAction Stop
        $stagedApplication = $Application.PSObject.Copy()
        $stagedApplication.ApplicationId = [guid]::NewGuid().ToString()
        $stagedRoot = Join-Path (Join-Path $ResourcesRoot 'Applications\Packages') ([string]$stagedApplication.ApplicationId)
        $stagedPackageRoot = $stagedRoot
        if (Test-Path -LiteralPath $stagedRoot) { Remove-Item -LiteralPath $stagedRoot -Recurse -Force }
        $null = New-Item -Path $stagedRoot -ItemType Directory -Force
        Move-Item -LiteralPath (Join-Path $stagingRoot $Application.Id) -Destination $stagedRoot -Force
        $validateApplication = $Application.PSObject.Copy()
        $validateApplication.Options = $Application.Options.PSObject.Copy()
        $validateApplication.Options.Version = $requestedVersion
        $validateApplication.ApplicationId = $stagedApplication.ApplicationId
        $null = Test-PAWApplicationResources -Application $validateApplication -AppInstallRoot $ResourcesRoot

        # Validate the combined package before committing; other pinned versions remain available.
        $candidateId = [guid]::NewGuid().ToString()
        $candidatePackageRoot = Join-Path (Join-Path $ResourcesRoot 'Applications\Packages') $candidateId
        $null = New-Item -Path $candidatePackageRoot -ItemType Directory -Force
        foreach ($sourceRoot in @($packageRoot, $stagedRoot)) {
            if (Test-Path -LiteralPath $sourceRoot -PathType Container) {
                Get-ChildItem -LiteralPath $sourceRoot -Force | Copy-Item -Destination $candidatePackageRoot -Recurse -Force
            }
        }
        $validateApplication.ApplicationId = $candidateId
        $null = Test-PAWApplicationResources -Application $validateApplication -AppInstallRoot $ResourcesRoot

        if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
            $null = New-Item -Path $packageRoot -ItemType Directory -Force
        }
        Get-ChildItem -LiteralPath $stagedRoot -Force | Copy-Item -Destination $packageRoot -Recurse -Force
        $expectedManifest = Join-Path (Join-Path (Join-Path $packageRoot $Application.Id) $requestedVersion) "$($Application.Id).psd1"
        if (-not (Test-Path -LiteralPath $expectedManifest -PathType Leaf)) {
            $packageContents = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName)
            throw "Downloaded module '$($Application.Id)' is missing expected manifest '$expectedManifest' after staging. Found: $($packageContents -join ', ')."
        }
        $validateApplication.ApplicationId = $Application.ApplicationId
        $null = Test-PAWApplicationResources -Application $validateApplication -AppInstallRoot $ResourcesRoot
        return [pscustomobject]@{ Ready = $true; Pending = $false; PackageRoot = $packageRoot; Message = "Version $requestedVersion downloaded and verified." }
    }
    finally {
        if (Test-Path -LiteralPath $stagingRoot) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue }
        if ($stagedPackageRoot -and (Test-Path -LiteralPath $stagedPackageRoot)) {
            Remove-Item -LiteralPath $stagedPackageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($candidatePackageRoot -and (Test-Path -LiteralPath $candidatePackageRoot)) {
            Remove-Item -LiteralPath $candidatePackageRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($PSBoundParameters.ContainsKey('ApplicationBundle') -and $PSBoundParameters.ContainsKey('ApplicationPlan')) {
    throw 'Specify ApplicationBundle or ApplicationPlan, not both.'
}
if ($PSBoundParameters.ContainsKey('ApplicationPlan') -and $null -eq $ApplicationPlan) {
    throw 'ApplicationPlan must not be null.'
}
if ($PSBoundParameters.ContainsKey('ApplicationBundle') -and ([string]$ApplicationBundle).Trim() -eq 'NA') {
    Write-PAWConsoleLog -Message 'ApplicationBundle is NA; there are no applications to download.' -Type Success
    Write-PAWDownloadLog -Message 'ApplicationBundle is NA; there are no applications to download. Finished.'
    return
}
if ($null -eq $ApplicationPlan -and $PSBoundParameters.ContainsKey('ApplicationBundle')) {
    $ApplicationPlan = Resolve-PAWDeploymentApplications -ConfigPath $ConfigPath -TemplateData ([pscustomobject]@{
        Application = 'True'; ApplicationBundle = $ApplicationBundle
    })
}
elseif ($null -eq $ApplicationPlan) {
    Import-Module (Join-Path $scriptRoot 'Functions\PAWApplicationManager\PAWApplicationManager.psd1') -ErrorAction Stop
    $catalog = @(Get-PAWApplicationCatalog -Root $ResourcesRoot | Where-Object Enabled)
    $settings = @{}
    foreach ($app in $catalog) { $settings[$app.Definition.Name] = $app.Settings }
    $ApplicationPlan = [pscustomobject]@{
        BundleId = $null
        Applications = @($catalog | ForEach-Object { ConvertTo-PAWApplicationRuntimeDefinition -Application $_ })
        Settings = $settings
    }
}
$applications = @($ApplicationPlan.Applications)
if ($PSBoundParameters.ContainsKey('Name')) {
    $unknownNames = @($Name | Where-Object { $applications.Name -notcontains $_ })
    if ($unknownNames.Count -gt 0) {
        throw "Application(s) not found in ${ApplicationsPath}: $($unknownNames -join ', '). Available: $($applications.Name -join ', ')"
    }
    $applications = @($applications | Where-Object { $Name -contains $_.Name })
}
if ($ApplicationPlan.BundleId) {
    Write-PAWConsoleLog -Message "Application bundle: {0}" -Type Info -Value $ApplicationPlan.BundleId
}
else { Write-PAWConsoleLog -Message 'Precache: all enabled catalog applications' -Type Info }
Write-PAWConsoleLog -Message "Cache root: {0}" -Type Info -Value $CacheRoot
Write-PAWConsoleLog -Message "Applications to process: {0}" -Type Info -Value $applications.Count
Write-PAWDownloadLog -Message "Started. Applications: $($applications.Name -join ', '). Cache root: $CacheRoot. Force: $($Force.IsPresent)"

if (@($applications | Where-Object Source -EQ 'WinGet').Count -gt 0 -and -not (Get-Command -Name winget -CommandType Application -ErrorAction SilentlyContinue)) {
    throw 'winget was not found. Install or update App Installer (WinGet 1.8 or later) from the Microsoft Store and try again.'
}
if (@($applications | Where-Object Source -EQ 'PSGallery').Count -gt 0) {
    # Required by older Windows PowerShell hosts to reach PSGallery over TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$results = New-Object System.Collections.Generic.List[object]
foreach ($application in $applications) {
    $status = $null
    $version = $null
    $message = $null
    $localManifest = $null
    $localInstallerFile = $null

    try {
        switch ($application.Source) {
            'WinGet' {
                $targetFolder = Get-PAWWinGetCacheFolder -CacheRoot $CacheRoot -Name $application.Name
                Write-PAWConsoleLog -Message "Checking {0} ({1})" -Type Info -Value $application.Name, $application.Id
                $cached = Get-PAWCachedWinGetApplication -Application $application -TargetFolder $targetFolder
                try {
                    $latestVersion = Get-PAWWinGetLatestVersion -Application $application
                }
                catch {
                    if ($null -eq $cached) { throw }
                    # Offline or WinGet source unavailable: keep using the cached download.
                    $latestVersion = $null
                    $version = [string]$cached.Version
                    $status = 'Cached'
                    $message = "Could not check for a newer version, using cached version $version. $($_.Exception.Message)"
                    Write-PAWConsoleLog -Message "{0}: could not check for a newer version, using cached version {1}" -Type Warning -Value $application.Name, $version
                    break
                }
                $version = $latestVersion

                if (-not $Force -and $null -ne $cached -and $null -ne $latestVersion -and [string]$cached.Version -eq $latestVersion) {
                    $status = 'UpToDate'
                    $message = "Version $latestVersion is already cached in $targetFolder"
                    Write-PAWConsoleLog -Message "{0} {1} is already the latest version. Skipping." -Type Success -Value $application.Name, $latestVersion
                }
                elseif ($PSCmdlet.ShouldProcess($targetFolder, "Download $($application.Name) $latestVersion with winget")) {
                    Write-PAWConsoleLog -Message "Downloading {0} {1}" -Type Wait -Value $application.Name, $latestVersion
                    $summary = Save-PAWWinGetApplication -Application $application -TargetFolder $targetFolder -Version $latestVersion
                    $version = $summary.Version
                    $status = 'Downloaded'
                    $message = "$($summary.InstallerFile) (Silent: $($summary.InstallerSwitches.Silent))"
                    Write-PAWConsoleLog -Message "Downloaded {0} {1}: {2}" -Type Success -Value $application.Name, $summary.Version, $summary.InstallerFile
                    if ([string]::IsNullOrWhiteSpace([string]$summary.InstallerSwitches.Silent) -and $summary.InstallerType -notin 'msi', 'wix', 'msix', 'zip', 'portable') {
                        Write-PAWConsoleLog -Message "{0} manifest has no Silent switch; the installer type default will be needed" -Type Warning -Value $application.Name
                        Write-PAWDownloadLog -Level 'WARN' -Message "$($application.Name) manifest has no InstallerSwitches.Silent (InstallerType: $($summary.InstallerType))."
                    }
                }
                else {
                    $status = 'WhatIf'
                }
            }
            'Local' {
                $localFolder = Get-PAWLocalApplicationFolder -LocalRoot $LocalRoot -Name $application.Name
                Write-PAWConsoleLog -Message "Checking local application {0}" -Type Info -Value $application.Name
                if (-not (Test-Path -LiteralPath $localFolder -PathType Container)) {
                    throw "Local application folder not found: $localFolder. Create it and place the installer for $($application.Name) in it."
                }
                $localFiles = @(Get-ChildItem -LiteralPath $localFolder -File)
                if ($localFiles.Count -ne 1) {
                    throw "Local application folder $localFolder must contain exactly one installer file (found $($localFiles.Count))."
                }
                $localInstallerFile = $localFiles[0]
                $version = ([string]$localInstallerFile.VersionInfo.ProductVersion).Trim()
                $productCode = ''
                if ($localInstallerFile.Extension -eq '.msi') {
                    try {
                        $msiProperties = Get-PAWLocalMsiProperties -Path $localInstallerFile.FullName
                        $version = [string]$msiProperties.ProductVersion
                        $productCode = [string]$msiProperties.ProductCode
                    }
                    catch {
                        Write-PAWDownloadLog -Level 'WARN' -Message "Could not read the MSI properties of $($localInstallerFile.FullName). $($_.Exception.Message)"
                    }
                }
                $localManifest = [PSCustomObject]@{
                    PackageVersion        = $version
                    InstallerType         = $application.InstallerType
                    NestedInstallerType   = ''
                    NestedInstallerFiles  = @()
                    ProductCode           = $productCode
                    InstallerSwitches     = [PSCustomObject]@{ Silent = ''; Custom = '' }
                    InstallerSuccessCodes = @()
                    ExpectedReturnCodes   = @()
                }
                $status = 'Local'
                $message = $localInstallerFile.FullName
                Write-PAWConsoleLog -Message "Found local installer {0}" -Type Success -Value $localInstallerFile.Name
            }
            'PSGallery' {
                if ($null -ne $application.Options) {
                    if ($application.Options.Origin -eq 'Local') {
                        $resource = Test-PAWApplicationResources -Application $application -AppInstallRoot $ResourcesRoot
                        $status = 'Local'
                        $version = [string]$application.Options.Version
                        $message = "Verified local module payload at $($resource.PackageRoot)"
                    }
                    else {
                        Write-PAWConsoleLog -Message "Preparing module {0} for {1}" -Type Info -Value $application.Id, $application.Options.Runtime
                        $resource = Save-PAWTypedModulePayload -Application $application -WhatIf:$WhatIfPreference
                        $status = if ($resource.WhatIf) { 'WhatIf' } elseif ($resource.Cached) { 'Cached' } elseif ($resource.Message -match 'already staged') { 'UpToDate' } else { 'Downloaded' }
                        $version = if ($resource.Version) { [string]$resource.Version } else { [string]$application.Options.Version }
                        $message = $resource.Message
                    }
                    Write-PAWConsoleLog -Message "Verified module package {0}" -Type Success -Value $application.Id
                    break
                }
                Write-PAWConsoleLog -Message "Checking module {0}" -Type Info -Value $application.Id
                $moduleFolder = Join-Path $ModuleRoot $application.Id
                try {
                    $latestModule = Find-Module -Name $application.Id -Repository PSGallery -ErrorAction Stop
                }
                catch {
                    $cachedModule = Get-ChildItem -LiteralPath $moduleFolder -Directory -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -as [version] } |
                        Sort-Object { [version]$_.Name } -Descending |
                        Select-Object -First 1
                    if ($null -eq $cachedModule) { throw }
                    # Offline or PSGallery unavailable: keep using the cached module.
                    $version = $cachedModule.Name
                    $status = 'Cached'
                    $message = "Could not check for a newer version, using cached version $version. $($_.Exception.Message)"
                    Write-PAWConsoleLog -Message "{0}: could not check for a newer version, using cached version {1}" -Type Warning -Value $application.Id, $version
                    break
                }
                $version = [string]$latestModule.Version
                $versionFolder = Join-Path $moduleFolder $version

                if (-not $Force -and (Test-Path -LiteralPath $versionFolder -PathType Container)) {
                    $status = 'UpToDate'
                    $message = "Version $version is already cached in $versionFolder"
                    Write-PAWConsoleLog -Message "{0} {1} is already the latest version. Skipping." -Type Success -Value $application.Id, $version
                }
                elseif ($PSCmdlet.ShouldProcess($moduleFolder, "Download module $($application.Id) $version from PSGallery")) {
                    Write-PAWConsoleLog -Message "Downloading module {0} {1} and dependencies" -Type Wait -Value $application.Id, $version
                    if (-not (Test-Path -LiteralPath $ModuleRoot)) {
                        New-Item -Path $ModuleRoot -ItemType Directory -Force | Out-Null
                    }
                    Save-Module -Name $application.Id -RequiredVersion $version -Path $ModuleRoot -Repository PSGallery -Force -ErrorAction Stop
                    # Keep only the latest version of this module.
                    Get-ChildItem -LiteralPath $moduleFolder -Directory | Where-Object Name -NE $version | ForEach-Object {
                        Remove-Item -LiteralPath $_.FullName -Recurse -Force
                        Write-PAWDownloadLog -Message "Removed older module version $($_.FullName)"
                    }
                    $status = 'Downloaded'
                    $message = $versionFolder
                    Write-PAWConsoleLog -Message "Downloaded module {0} {1}" -Type Success -Value $application.Id, $version
                }
                else {
                    $status = 'WhatIf'
                }
            }
            { $_ -in 'Classic', 'WindowsComponent' } {
                $resource = Test-PAWApplicationResources -Application $application -AppInstallRoot $ResourcesRoot
                $status = 'PendingGuest'
                $version = ''
                if ($application.Source -eq 'WindowsComponent' -and [string]::IsNullOrWhiteSpace([string]$application.Options.Source)) {
                    $message = 'No host download. Component availability and installation will be checked in the guest OS.'
                }
                else {
                    $message = "Verified staged payload at $($resource.PackageRoot); installation is a guest operation."
                }
                Write-PAWConsoleLog -Message "Application {0} is staged for guest installation" -Type Info -Value $application.Name
            }
        }
    }
    catch {
        $status = 'Failed'
        $message = $_.Exception.Message
        Write-PAWConsoleLog -Message "Failed to download {0}: {1}" -Type Error -Value $application.Name, $message
    }

    if ($application.Source -eq 'WinGet' -and $status -in 'Downloaded', 'UpToDate', 'Cached') {
        try {
            $installFilePath = Get-PAWApplicationInstallFilePath -InstallRoot $InstallRoot -Name $application.Name
            $cacheFolder = Get-PAWWinGetCacheFolder -CacheRoot $CacheRoot -Name $application.Name
            $cachedSummary = Get-Content -LiteralPath (Join-Path $cacheFolder 'PAWApplication.json') -Raw | ConvertFrom-Json
            $cachedManifest = Get-PAWWinGetManifestInfo -Path (Join-Path $cacheFolder $cachedSummary.ManifestFile)
            $installFileResult = Update-PAWApplicationInstallFile -Path $installFilePath -Application $application -ManifestInfo $cachedManifest -InstallerFile $cachedSummary.InstallerFile -ManifestFile $cachedSummary.ManifestFile -ManagedSettings $ApplicationPlan.Settings[$application.Name] -WhatIf:$WhatIfPreference
            if ($null -ne $installFileResult -and $installFileResult.Status -ne 'Unchanged') {
                Write-PAWConsoleLog -Message "Install file {0}: {1}" -Type Info -Value $installFileResult.Status, $installFilePath
                Write-PAWDownloadLog -Message "$($application.Name) install file $($installFileResult.Status): $installFilePath"
            }
        }
        catch {
            $status = 'Failed'
            $message = "Could not update the install file: $($_.Exception.Message)"
            Write-PAWConsoleLog -Message "Failed to update the install file for {0}: {1}" -Type Error -Value $application.Name, $_.Exception.Message
        }
    }
    elseif ($application.Source -eq 'Local' -and $status -eq 'Local') {
        try {
            $installFilePath = Get-PAWApplicationInstallFilePath -InstallRoot $InstallRoot -Name $application.Name
            $installFileResult = Update-PAWApplicationInstallFile -Path $installFilePath -Application $application -ManifestInfo $localManifest -InstallerFile $localInstallerFile.Name -ManagedSettings $ApplicationPlan.Settings[$application.Name] -WhatIf:$WhatIfPreference
            if ($null -ne $installFileResult -and $installFileResult.Status -ne 'Unchanged') {
                Write-PAWConsoleLog -Message "Install file {0}: {1}" -Type Info -Value $installFileResult.Status, $installFilePath
                Write-PAWDownloadLog -Message "$($application.Name) install file $($installFileResult.Status): $installFilePath"
            }
            if ($application.InstallerType -eq 'exe' -and (Test-Path -LiteralPath $installFilePath -PathType Leaf)) {
                $installSettings = (Get-Content -LiteralPath $installFilePath -Raw | ConvertFrom-Json).Settings
                if ([string]::IsNullOrWhiteSpace([string]$installSettings.SilentArguments)) {
                    Write-PAWConsoleLog -Message "{0}: set catalog Settings.SilentArguments using Application Manager before installing" -Type Warning -Value $application.Name
                    Write-PAWDownloadLog -Level 'WARN' -Message "$($application.Name) is an exe without catalog Settings.SilentArguments. Update it using Application Manager."
                }
            }
        }
        catch {
            $status = 'Failed'
            $message = "Could not update the install file: $($_.Exception.Message)"
            Write-PAWConsoleLog -Message "Failed to update the install file for {0}: {1}" -Type Error -Value $application.Name, $_.Exception.Message
        }
    }

    $level = if ($status -eq 'Failed') { 'ERROR' } else { 'INFO' }
    Write-PAWDownloadLog -Level $level -Message "$($application.Name) [$($application.Source) $($application.Id)] $status $version $message"
    $results.Add([PSCustomObject]@{
            Name    = $application.Name
            Source  = $application.Source
            Id      = $application.Id
            Version = $version
            Status  = $status
            Message = $message
        })
}

$failed = @($results | Where-Object Status -EQ 'Failed')

$summaryText = 'Downloaded: {0}  Up to date: {1}  Cached (offline): {2}  Local: {3}  Failed: {4}' -f @($results | Where-Object Status -EQ 'Downloaded').Count, @($results | Where-Object Status -EQ 'UpToDate').Count, @($results | Where-Object Status -EQ 'Cached').Count, @($results | Where-Object Status -EQ 'Local').Count, $failed.Count
Write-PAWConsoleLog -Message $summaryText -Type $(if ($failed.Count -gt 0) { 'Warning' } else { 'Success' })
Write-PAWDownloadLog -Level $(if ($failed.Count -gt 0) { 'WARN' } else { 'INFO' }) -Message "Finished. $summaryText"

$results

if ($failed.Count -gt 0) {
    Write-Error "Download failed for: $($failed.Name -join ', '). See $($script:LogPath) for details."
}
