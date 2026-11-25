<#
.SYNOPSIS
    Lists and reads PAWDeploy logs without modifying them.
.DESCRIPTION
    With no Name, lists .log files, including hidden files, in the current
    user's TEMP\PAWDeploy folder.
    With Name, returns entries from that file, optionally filtered by level,
    timestamp and literal text. Continuation lines remain with their entry.
.PARAMETER Name
    Log filename from the log folder, for example New-PAWVM.log.
.PARAMETER Level
    One or more levels to include. Information/INFO and Warning/WARN are equivalent.
.PARAMETER Since
    Include entries at or after this local timestamp.
.PARAMETER Until
    Include entries at or before this local timestamp.
.PARAMETER Text
    Case-insensitive literal text to find in the complete entry.
.PARAMETER Tail
    Return only the last specified number of matching entries.
.PARAMETER LogFolder
    Alternate log directory. Defaults to the current user's TEMP\PAWDeploy.
.PARAMETER NoTitle
    Do not change the console title; used by the log viewer.
.EXAMPLE
    .\Tools\Get-PAWLogs.ps1
.EXAMPLE
    .\Tools\Get-PAWLogs.ps1 -Name New-PAWVM.log -Level ERROR -Tail 50
.NOTES
    Version : 2.0.0.2
    Author  : The Fantastic PAWDeploy Team
#>
[CmdletBinding()]
param(
    [string]$Name,
    [string[]]$Level,
    [datetime]$Since,
    [datetime]$Until,
    [string]$Text,
    [ValidateRange(1, 2147483647)][int]$Tail,
    [string]$LogFolder,
    [switch]$NoTitle
)

$ErrorActionPreference = 'Stop'
if (-not $NoTitle) {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'Functions\PAWUtility\PAWUtility.psd1') -ErrorAction Stop
    $null = Set-PAWScriptTitle -ScriptPath $PSCommandPath
}
if (-not $PSBoundParameters.ContainsKey('LogFolder')) {
    if ([string]::IsNullOrWhiteSpace($env:TEMP)) { throw 'TEMP is not set; unable to locate PAWDeploy logs.' }
    $LogFolder = Join-Path $env:TEMP 'PAWDeploy'
}
if (-not (Test-Path -LiteralPath $LogFolder -PathType Container)) {
    throw "Log folder not found: $LogFolder"
}
if (-not $PSBoundParameters.ContainsKey('Name')) {
    foreach ($filter in @('Level', 'Since', 'Until', 'Text', 'Tail')) {
        if ($PSBoundParameters.ContainsKey($filter)) { throw "Specify Name when using $filter." }
    }
    Get-ChildItem -LiteralPath $LogFolder -Filter '*.log' -File -Force -ErrorAction Stop |
        Where-Object { [IO.Path]::GetExtension($_.Name) -ieq '.log' } |
        Sort-Object Name |
        Select-Object Name, Length, LastWriteTime, @{ Name = 'Path'; Expression = { $_.FullName } }
    return
}
if ([string]::IsNullOrWhiteSpace($Name) -or [IO.Path]::GetFileName($Name) -cne $Name -or
    [IO.Path]::GetExtension($Name) -ine '.log') {
    throw 'Name must be a .log filename in the log folder, not a path.'
}
if ($PSBoundParameters.ContainsKey('Since') -and $PSBoundParameters.ContainsKey('Until') -and $Since -gt $Until) {
    throw 'Since must be earlier than or equal to Until.'
}
$path = Join-Path $LogFolder $Name
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Log file not found: $path" }

function ConvertTo-PAWLogLevel {
    param([string]$Value)
    switch ($Value.ToUpperInvariant()) {
        'INFORMATION' { 'INFO' }
        'WARNING' { 'WARN' }
        default { $Value.ToUpperInvariant() }
    }
}
$levels = @(foreach ($item in $Level) {
    if ([string]::IsNullOrWhiteSpace($item)) { throw 'Level must not be empty.' }
    ConvertTo-PAWLogLevel $item
})
$hasSince = $PSBoundParameters.ContainsKey('Since')
$hasUntil = $PSBoundParameters.ContainsKey('Until')
$hasTail = $PSBoundParameters.ContainsKey('Tail')
$queue = New-Object 'System.Collections.Generic.Queue[object]'
$emit = {
    param($entry)
    if ($null -eq $entry) { return }
    if ($levels.Count -and $entry.Level -notin $levels) { return }
    if ($hasSince -and ($null -eq $entry.Timestamp -or $entry.Timestamp -lt $Since)) { return }
    if ($hasUntil -and ($null -eq $entry.Timestamp -or $entry.Timestamp -gt $Until)) { return }
    if (-not [string]::IsNullOrEmpty($Text) -and $entry.RawText.IndexOf($Text, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }
    if ($hasTail) {
        $queue.Enqueue($entry)
        if ($queue.Count -gt $Tail) { $null = $queue.Dequeue() }
    }
    else { $entry }
}
$pattern = [regex]::new('^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[([^\]]+)\] (.*)$')
$reader = $null
$stream = $null
try {
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
    $entry = $null
    while ($null -ne ($line = $reader.ReadLine())) {
        $match = $pattern.Match($line)
        $timestamp = [datetime]::MinValue
        $isHeader = $match.Success -and [datetime]::TryParseExact($match.Groups[1].Value,
            'yyyy-MM-dd HH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$timestamp)
        if ($isHeader) {
            & $emit $entry
            $entry = [pscustomobject]@{
                Timestamp = $timestamp; Level = (ConvertTo-PAWLogLevel $match.Groups[2].Value)
                Message = $match.Groups[3].Value; RawText = $line; Name = $Name; Path = $path
            }
        }
        elseif ($null -eq $entry) {
            $entry = [pscustomobject]@{
                Timestamp = $null; Level = 'UNSTRUCTURED'; Message = $line; RawText = $line; Name = $Name; Path = $path
            }
        }
        else {
            $entry.Message += [Environment]::NewLine + $line
            $entry.RawText += [Environment]::NewLine + $line
        }
    }
    & $emit $entry
    if ($hasTail) { foreach ($result in $queue) { $result } }
}
finally {
    if ($null -ne $reader) { $reader.Dispose() }
    elseif ($null -ne $stream) { $stream.Dispose() }
}
