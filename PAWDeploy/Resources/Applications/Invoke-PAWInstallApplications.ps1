<#
.SYNOPSIS
    Installs PAW applications and PowerShell modules from the local download cache.

.DESCRIPTION
    Reads the runtime application plan (Applications.json) and installs enabled
    applications from the cache created by Invoke-PAWApplicationDownload.ps1:

        CacheRoot\..\Applications.json         - the application list
        CacheRoot\WinGet\<Application name>\   - installer, WinGet manifest, PAWApplication.json
        CacheRoot\Modules\<Module>\<Version>\  - PowerShell modules
        AppInstall\Packages\<ApplicationId>\    - typed module, classic, or component payloads
        CacheRoot\..\Applications\<Name>.json  - install file per WinGet or Local application
        CacheRoot\..\Local\<Name>\             - installer of a Local application

    WinGet and Local applications are installed silently as described in their install
    file: Settings.SilentArguments when set, otherwise the switches from the
    WinGet manifest (or the installer type default for Local) stored in the Installer section. See
    Get-PAWWinGetInstallCommand for the rules. Applications that are already
    installed (Settings.InstallCheckPaths, or Installer.ProductCode in the
    Uninstall registry) are skipped.

    Legacy PSGallery applications are copied from CacheRoot\Modules.
    Typed PSGallery modules and Classic applications are installed from their
    selected Packages\<ApplicationId> payloads. WindowsComponent applications
    use the guest OS component cmdlets and never request an automatic restart.

    This script does not download anything and throws when cached content is
    missing. It runs inside the PAW and is started by New-PAWVM.ps1.
    WinGet installer SHA256 must match its download metadata before execution.
    Missing or invalid integrity metadata requires a new host download and copy.

.PARAMETER CacheRoot
    Root folder of the download cache. Defaults to the Downloads folder next to
    this script (C:\PAWFiles\AppInstall\Downloads inside the PAW).

.PARAMETER ApplicationsPath
    Path to Applications.json. Defaults to Applications.json in the parent
    folder of CacheRoot (C:\PAWFiles\AppInstall\Applications.json inside the PAW).

.PARAMETER Name
    Install only this application (Name in Applications.json). Used by
    New-PAWVM.ps1 to install one application at a time.

.PARAMETER ModulesOnly
    Install only the enabled PSGallery modules. Used by New-PAWVM.ps1 after the
    applications are installed. Cannot be combined with Name.

.EXAMPLE
    .\Invoke-PAWInstallApplications.ps1
    Installs every enabled application and module from the default cache.

.EXAMPLE
    .\Invoke-PAWInstallApplications.ps1 -Name '7-Zip'
    Installs only 7-Zip.

.EXAMPLE
    .\Invoke-PAWInstallApplications.ps1 -ModulesOnly
    Installs only the enabled PowerShell modules.

.NOTES
    Version : 2.0.0.4
    Author  : The Fantastic PAWDeploy Team
    Requires: PowerShell 5.1, administrator rights, the PAWUtility module
              (C:\PAWFiles\Functions\PAWUtility inside the PAW).
#>

[CmdletBinding()]
param(
    [string]$CacheRoot,
    [string]$ApplicationsPath,
    [Alias('PackageName')]
    [string]$Name,
    [switch]$ModulesOnly
)

if ($ModulesOnly -and -not [string]::IsNullOrWhiteSpace($Name)) {
    throw 'ModulesOnly cannot be combined with Name.'
}

# Set execution policy to Bypass for this process so that Import-Module and any
# script dot-sourcing works regardless of the machine's configured execution policy.
# This is safe here because the script content was already verified on the host before
# being transmitted to the VM via Invoke-Command -FilePath.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

$ErrorActionPreference = 'Stop'

# In remoting, Write-PAWHost can be duplicated or rendered with inconsistent colors.
# Normalize all host writes to plain output so the caller can render exactly once.
function Write-PAWHost {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [object[]]$Object,
        [object]$ForegroundColor,
        [object]$BackgroundColor,
        [switch]$NoNewline,
        [object]$Separator = ' '
    )

    $text = [string]::Join([string]$Separator, @($Object | ForEach-Object { [string]$_ }))
    if ($NoNewline) {
        Write-Output -NoEnumerate $text
    }
    else {
        Write-Output $text
    }
}

# $PSScriptRoot is empty when New-PAWVM.ps1 runs this script as a script block inside the PAW.
$scriptBasePath = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptBasePath)) {
    $scriptBasePath = 'C:\PAWFiles\AppInstall'
}
if ([string]::IsNullOrWhiteSpace($CacheRoot)) {
    $CacheRoot = Join-Path $scriptBasePath 'Downloads'
}
if ([string]::IsNullOrWhiteSpace($ApplicationsPath)) {
    $ApplicationsPath = Join-Path (Split-Path -Parent $CacheRoot) 'Applications.json'
}
$InstallRoot = Join-Path (Split-Path -Parent $CacheRoot) 'Applications'
$LocalRoot = Join-Path (Split-Path -Parent $CacheRoot) 'Local'
$AppInstallRoot = Split-Path -Parent $CacheRoot
$PackagesRoot = Join-Path $AppInstallRoot 'Packages'

if (-not (Get-Command -Name Get-PAWWinGetInstallCommand -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name Assert-PAWInstallerHash -ErrorAction SilentlyContinue)) {
    $PAWUtilityModuleCandidates = @('C:\PAWFiles\Functions\PAWUtility')
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $candidateParents = @(
            $PSScriptRoot,
            (Split-Path -Parent $PSScriptRoot),
            (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        ) | Select-Object -Unique

        foreach ($candidateParent in $candidateParents) {
            $PAWUtilityModuleCandidates += @(
                (Join-Path $candidateParent 'Functions\PAWUtility'),
                (Join-Path $candidateParent 'PAWFiles\Functions\PAWUtility')
            )
        }
    }

    $PAWUtilityModulePath = $PAWUtilityModuleCandidates |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -Path $_) } |
        Select-Object -First 1

    if ([string]::IsNullOrWhiteSpace($PAWUtilityModulePath)) {
        throw "Required PAWUtility module not found. Checked: $($PAWUtilityModuleCandidates -join ', ')"
    }

    Import-Module -Name $PAWUtilityModulePath -Force -ErrorAction Stop
}

$moduleCache = Join-Path $CacheRoot 'Modules'
$applications = @(Get-PAWApplicationDefinitions -Path $ApplicationsPath)

if (-not [string]::IsNullOrWhiteSpace($Name)) {
    $applications = @($applications | Where-Object { $_.Name -eq $Name })
    if ($applications.Count -eq 0) {
        throw "Application '$Name' was not found in '$ApplicationsPath'."
    }
    if (-not $applications[0].InstallEnabled) {
        Write-PAWHost "$Name has InstallEnabled set to false in $ApplicationsPath. Skipping."
        return
    }
}
else {
    $applications = @($applications | Where-Object { $_.InstallEnabled })
}

$installApplications = @()
if ($ModulesOnly) {
    $installApplications = @($applications | Where-Object { $_.Source -eq 'PSGallery' })
}
else {
    $installApplications = @($applications)
}

$defaultProgramFiles = $env:ProgramFiles
if ([string]::IsNullOrWhiteSpace($defaultProgramFiles)) {
    $defaultProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
}
if ([string]::IsNullOrWhiteSpace($defaultProgramFiles)) {
    throw 'Could not determine ProgramFiles path in this session. This is required for module destination defaults.'
}
$moduleDestinationPath = Join-Path $defaultProgramFiles 'WindowsPowerShell\Modules'

function Test-PAWApplicationInstalled {
    param(
        $Definition
    )

    foreach ($checkPath in @($Definition.Settings.InstallCheckPaths)) {
        $expandedPath = Expand-PAWAppInstallPath -Path $checkPath
        if (-not [string]::IsNullOrWhiteSpace($expandedPath) -and (Test-Path -Path $expandedPath)) {
            return "found $expandedPath"
        }
    }

    $productCode = [string]$Definition.Installer.ProductCode
    if (-not [string]::IsNullOrWhiteSpace($productCode)) {
        foreach ($uninstallRoot in @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )) {
            if (Test-Path -LiteralPath (Join-Path $uninstallRoot $productCode)) {
                return "product code $productCode is registered"
            }
        }
    }

    $null
}

function Invoke-PAWInstallerProcess {
    param(
        $Command,
        [string[]]$PostInstallKillProcess = @()
    )

    Write-PAWHost "  Command: $($Command.FilePath) $($Command.Arguments)"
    $startArguments = @{ FilePath = $Command.FilePath; PassThru = $true }
    if (-not [string]::IsNullOrWhiteSpace($Command.Arguments)) {
        $startArguments['ArgumentList'] = $Command.Arguments
    }
    $process = Start-Process @startArguments
    # Reading Handle keeps it open so that ExitCode is available after the process exits.
    $null = $process.Handle

    if ($PostInstallKillProcess.Count -gt 0) {
        Write-PAWHost "  Waiting 5 seconds for installer health check..."
        Start-Sleep -Seconds 5

        if ($process.HasExited -and $Command.SuccessExitCodes -notcontains [long]$process.ExitCode) {
            throw "Failed to install $($Command.Name). Installer exit code: $($process.ExitCode)"
        }

        foreach ($procName in $PostInstallKillProcess) {
            Write-PAWHost "  Waiting for post-install process '$procName' to start..."
            $processStartDeadline = [DateTime]::UtcNow.AddMinutes(3)
            $killedProcess = $false
            while (([DateTime]::UtcNow -lt $processStartDeadline) -and -not $process.HasExited) {
                $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($running) {
                    Write-PAWHost "  Killing post-install process '$procName'..."
                    $running | Stop-Process -Force
                    $killedProcess = $true
                    break
                }
                Start-Sleep -Seconds 2
            }
            if (-not $killedProcess) {
                # Some installers start the application right before they exit.
                $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($running) {
                    Write-PAWHost "  Killing post-install process '$procName'..."
                    $running | Stop-Process -Force
                }
                else {
                    Write-PAWHost "  Post-install process '$procName' did not start within timeout or installer exited before launch."
                }
            }
        }

        if (-not $process.HasExited) {
            Write-PAWHost "  Waiting for installer process to exit after post-install cleanup..."
            if (-not $process.WaitForExit(120000)) {
                try {
                    $process | Stop-Process -Force
                }
                catch {
                    # Ignore process-stop races if it exits between checks.
                }
                throw "Installer for $($Command.Name) did not exit after post-install cleanup."
            }
        }
    }
    else {
        $process.WaitForExit()
    }

    $exitCode = [long]$process.ExitCode
    if ($Command.SuccessExitCodes -notcontains $exitCode) {
        throw "Failed to install $($Command.Name). Installer exit code: $exitCode"
    }
    if ($exitCode -ne 0) {
        Write-PAWHost "  Installer exit code $exitCode is a success code."
    }
    if ($Command.RebootExitCodes -contains $exitCode) {
        Write-PAWHost "  A restart is required to complete the installation."
    }
}

function Invoke-PAWInstallCommand {
    param(
        $Definition,
        $Command
    )

    Write-PAWHost "  Installer type: $($Command.InstallerType)"
    if ($Command.SilentSource) {
        Write-PAWHost "  Silent switches from: $($Command.SilentSource)"
    }

    switch ($Command.Method) {
        'Process' {
            Invoke-PAWInstallerProcess -Command $Command -PostInstallKillProcess @($Definition.Settings.PostInstallKillProcess)
        }
        'Msix' {
            Write-PAWHost "  Provisioning package: $($Command.FilePath)"
            Add-AppxProvisionedPackage -Online -PackagePath $Command.FilePath -SkipLicense | Out-Null
        }
        'Portable' {
            $destinationPath = Expand-PAWAppInstallPath -Path $Command.DestinationPath
            Write-PAWHost "  Copying to: $destinationPath"
            if (-not (Test-Path -LiteralPath $destinationPath)) {
                New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
            }
            Copy-Item -LiteralPath $Command.FilePath -Destination $destinationPath -Force
        }
        'Zip' {
            $extractPath = Join-Path ([System.IO.Path]::GetTempPath()) ('PAWAppInstall\' + [System.IO.Path]::GetFileNameWithoutExtension($Command.FilePath))
            if (Test-Path -LiteralPath $extractPath) {
                Remove-Item -LiteralPath $extractPath -Recurse -Force
            }
            Write-PAWHost "  Extracting: $($Command.FilePath)"
            Expand-Archive -LiteralPath $Command.FilePath -DestinationPath $extractPath -Force
            try {
                $nestedType = ([string]$Command.NestedInstallerType).ToLowerInvariant()
                if ($nestedType -eq 'portable' -or [string]::IsNullOrWhiteSpace($nestedType)) {
                    $destinationPath = Expand-PAWAppInstallPath -Path $Command.DestinationPath
                    Write-PAWHost "  Copying extracted files to: $destinationPath"
                    if (-not (Test-Path -LiteralPath $destinationPath)) {
                        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
                    }
                    Copy-Item -Path (Join-Path $extractPath '*') -Destination $destinationPath -Recurse -Force
                    foreach ($relativeFile in @($Command.NestedInstallerFiles)) {
                        if (-not (Test-Path -LiteralPath (Join-Path $destinationPath $relativeFile))) {
                            throw "Expected file '$relativeFile' was not found in $destinationPath after extracting $($Command.FilePath)."
                        }
                    }
                }
                else {
                    $relativeFile = @($Command.NestedInstallerFiles) | Select-Object -First 1
                    if ([string]::IsNullOrWhiteSpace($relativeFile)) {
                        throw "The install file for '$($Definition.Name)' does not list the nested installer file (Installer.NestedInstallerFiles)."
                    }
                    $nestedPath = Join-Path $extractPath $relativeFile
                    if (-not (Test-Path -LiteralPath $nestedPath -PathType Leaf)) {
                        throw "Nested installer '$relativeFile' was not found in $($Command.FilePath)."
                    }
                    $nestedCommand = Get-PAWWinGetInstallCommand -InstallDefinition $Definition -InstallerPath $nestedPath -InstallerType $nestedType
                    Invoke-PAWInstallCommand -Definition $Definition -Command $nestedCommand
                }
            }
            finally {
                Remove-Item -LiteralPath $extractPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        default {
            throw "Unsupported install method '$($Command.Method)' for '$($Definition.Name)'."
        }
    }
}

function Install-PAWWinGetApplication {
    param($Application)

    $installFilePath = Get-PAWApplicationInstallFilePath -InstallRoot $InstallRoot -Name $Application.Name
    $definition = Get-PAWApplicationInstallFile -Path $installFilePath
    if ($Application.Source -eq 'Local') {
        $applicationFolder = Get-PAWLocalApplicationFolder -LocalRoot $LocalRoot -Name $Application.Name
    }
    else {
        $applicationFolder = Get-PAWWinGetCacheFolder -CacheRoot $CacheRoot -Name $Application.Name
    }
    $installerPath = Join-Path $applicationFolder $definition.Installer.InstallerFile
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        if ($Application.Source -eq 'Local') {
            throw "Installer not found: $installerPath. Place the installer in $applicationFolder on the host and run Invoke-PAWApplicationDownload.ps1 -Name '$($Application.Name)'."
        }
        throw "Installer not found: $installerPath. Run Invoke-PAWApplicationDownload.ps1 -Name '$($Application.Name)' -Force on the host."
    }

    Write-PAWHost "  $($Application.Source) package: $($definition.Id) $($definition.Installer.Version)"
    Write-PAWHost "  Install file: $installFilePath"
    Write-PAWHost "  Installer: $installerPath"

    $installedReason = Test-PAWApplicationInstalled -Definition $definition
    if ($installedReason) {
        Write-PAWHost "  $($Application.Name) is already installed ($installedReason). Skipping installation."
        return [PSCustomObject]@{ Status = 'Skipped'; Detail = 'AlreadyInstalled' }
    }

    if ($Application.Source -eq 'WinGet') {
        $summaryPath = Join-Path $applicationFolder 'PAWApplication.json'
        try { $summary = Get-Content -LiteralPath $summaryPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
        catch {
            throw "Cannot read installer integrity metadata for '$($Application.Name)' at '$summaryPath': $($_.Exception.Message). Run Invoke-PAWApplicationDownload.ps1 -Name '$($Application.Name)' -Force on the host and restage the application."
        }
        if ($summary.InstallerFile -ne $definition.Installer.InstallerFile) {
            throw "Installer metadata mismatch for '$($Application.Name)' at '$summaryPath'. Run Invoke-PAWApplicationDownload.ps1 -Name '$($Application.Name)' -Force on the host and restage the application."
        }
        Assert-PAWInstallerHash -Path $installerPath -ExpectedHash $summary.InstallerSha256 -ApplicationName $Application.Name
        Write-PAWHost "  Installer SHA256 verified: $installerPath"
    }
    $command = Get-PAWWinGetInstallCommand -InstallDefinition $definition -InstallerPath $installerPath
    Invoke-PAWInstallCommand -Definition $definition -Command $command
    [PSCustomObject]@{ Status = 'Success'; Detail = 'Installed' }
}

function Install-PAWModulesFromCache {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules
    )

    if (-not (Test-Path -LiteralPath $moduleCache)) {
        throw "Module cache not found: $moduleCache. Run Invoke-PAWApplicationDownload.ps1 on the host first."
    }
    if (-not (Test-Path -LiteralPath $moduleDestinationPath)) {
        New-Item -Path $moduleDestinationPath -ItemType Directory -Force | Out-Null
    }

    Write-PAWHost "Installing PowerShell modules from cache"
    Write-PAWHost "  Source: $moduleCache"
    Write-PAWHost "  Destination: $moduleDestinationPath"
    Write-PAWHost "  Modules: $($RequiredModules -join ', ')"

    # Resolve the latest cached version of each module and its required modules.
    $resolved = [ordered]@{}
    $queue = New-Object System.Collections.Generic.Queue[string]
    foreach ($moduleName in $RequiredModules) { $queue.Enqueue($moduleName) }
    while ($queue.Count -gt 0) {
        $moduleName = $queue.Dequeue()
        if ($resolved.Contains($moduleName)) {
            continue
        }

        $moduleFolder = Join-Path $moduleCache $moduleName
        $versionFolder = Get-ChildItem -LiteralPath $moduleFolder -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -as [version] } |
            Sort-Object { [version]$_.Name } -Descending |
            Select-Object -First 1
        if ($null -eq $versionFolder) {
            throw "Module '$moduleName' was not found in $moduleCache. Run Invoke-PAWApplicationDownload.ps1 on the host first."
        }
        $resolved[$moduleName] = $versionFolder

        $manifestPath = Join-Path $versionFolder.FullName "$moduleName.psd1"
        if (Test-Path -LiteralPath $manifestPath) {
            $moduleManifest = Import-PowerShellDataFile -Path $manifestPath
            foreach ($requiredModule in @($moduleManifest.RequiredModules)) {
                $requiredName = if ($requiredModule -is [hashtable]) { [string]$requiredModule.ModuleName } else { [string]$requiredModule }
                if (-not [string]::IsNullOrWhiteSpace($requiredName) -and -not $resolved.Contains($requiredName)) {
                    $queue.Enqueue($requiredName)
                }
            }
        }
    }

    foreach ($moduleName in $resolved.Keys) {
        $versionFolder = $resolved[$moduleName]
        $targetModuleFolder = Join-Path $moduleDestinationPath $moduleName
        $targetVersionFolder = Join-Path $targetModuleFolder $versionFolder.Name
        if (Test-Path -LiteralPath $targetVersionFolder) {
            Write-PAWHost "  $moduleName $($versionFolder.Name) is already installed. Skipping copy."
            continue
        }
        Write-PAWHost "  Copying $moduleName $($versionFolder.Name)"
        if (-not (Test-Path -LiteralPath $targetModuleFolder)) {
            New-Item -Path $targetModuleFolder -ItemType Directory -Force | Out-Null
        }
        Copy-Item -LiteralPath $versionFolder.FullName -Destination $targetModuleFolder -Recurse -Force
    }

    foreach ($moduleName in $RequiredModules) {
        if (Get-Module -ListAvailable -Name $moduleName) {
            Write-PAWHost "  $moduleName is available."
        }
        else {
            throw "Module $moduleName is still not available after copying from cache."
        }
    }
}

Write-PAWHost "Applications file: $ApplicationsPath"
Write-PAWHost "Cache root: $CacheRoot"
Write-PAWHost "Applications planned for install: $($installApplications.Count)"
foreach ($application in $installApplications) {
    Write-PAWHost "  - $($application.Name) [$($application.Source) $($application.Id)]"
}

$installTotal = $installApplications.Count
$installIndex = 0
$successCount = 0
$skippedCount = 0

foreach ($application in $installApplications) {
    $installIndex++
    $percentComplete = [int](($installIndex / [Math]::Max(1, $installTotal)) * 100)
    Write-Progress -Activity 'PAWAppInstall install stage' -Status ("{0}/{1} {2}" -f $installIndex, $installTotal, $application.Name) -PercentComplete $percentComplete

    $applicationTimer = [System.Diagnostics.Stopwatch]::StartNew()
    Write-PAWHost "Installing application: $($application.Name)"
    # Pass log lines through and keep the result object.
    $result = $null
    if ($application.Source -in @('Classic', 'WindowsComponent') -or
        ($application.Source -eq 'PSGallery' -and $null -ne $application.Options)) {
        $packageRoot = Join-Path $PackagesRoot ([string]$application.ApplicationId)
        Invoke-PAWTypedApplication -Application $application -PackageRoot $packageRoot | ForEach-Object {
            if ($_ -is [System.Management.Automation.PSCustomObject] -and $_.PSObject.Properties['Status']) {
                $result = $_
            }
            else {
                Write-PAWHost $_
            }
        }
        if ($null -eq $result) {
            throw "Typed installer '$($application.Name)' returned no result."
        }
    }
    elseif ($application.Source -eq 'PSGallery') {
        Install-PAWModulesFromCache -RequiredModules @($application.Id)
        $result = [PSCustomObject]@{ Status = 'Success'; Detail = 'Installed' }
    }
    else {
        Install-PAWWinGetApplication -Application $application | ForEach-Object {
            if ($_ -is [System.Management.Automation.PSCustomObject] -and $_.PSObject.Properties['Status']) { $result = $_ } else { $_ }
        }
    }
    $applicationTimer.Stop()

    switch ($result.Status) {
        'Success' {
            $successCount++
            Write-PAWHost -ForegroundColor Green "  Result: SUCCESS ($([Math]::Round($applicationTimer.Elapsed.TotalSeconds, 1)) sec)"
        }
        'Skipped' {
            $skippedCount++
            Write-PAWHost -ForegroundColor Yellow "  Result: SKIPPED ($($result.Detail))"
        }
    }
}

Write-Progress -Activity 'PAWAppInstall install stage' -Completed

if ($ModulesOnly -and $installApplications.Count -eq 0) {
    Write-PAWHost 'No enabled PSGallery modules found in Applications.json. Skipping module install.'
}

Write-PAWHost ''
Write-PAWHost "Install summary: success=$successCount skipped=$skippedCount applications=$installTotal"
